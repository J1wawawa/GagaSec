//! Start the window before opening a potentially large workspace. A stage is
//! complete only after its operation succeeds; errors keep the UI in recovery.
use crate::{collector, lan, maintenance, monitoring, store::Store};
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
use tauri::{Manager, State};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Step {
    id: String,
    title: String,
    detail: String,
    state: String,
    elapsed_ms: u64,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub state: String,
    steps: Vec<Step>,
    error: Option<String>,
    elapsed_ms: u64,
}
struct Data {
    snapshot: Snapshot,
    started: Instant,
    stage_started: Instant,
}
#[derive(Clone)]
pub struct Progress(Arc<Mutex<Data>>);
impl Progress {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Data {
            snapshot: Snapshot {
                state: "running".into(),
                steps: vec![],
                error: None,
                elapsed_ms: 0,
            },
            started: Instant::now(),
            stage_started: Instant::now(),
        })))
    }
    pub fn snapshot(&self) -> Result<Snapshot, String> {
        let data = self.0.lock().map_err(|_| "启动状态不可读")?;
        let mut value = data.snapshot.clone();
        if value.state == "running" {
            value.elapsed_ms = data.started.elapsed().as_millis() as u64;
            if let Some(step) = value.steps.last_mut().filter(|s| s.state == "running") {
                step.elapsed_ms = data.stage_started.elapsed().as_millis() as u64;
            }
        }
        Ok(value)
    }
    pub fn ready(&self) -> bool {
        self.snapshot().is_ok_and(|s| s.state == "ready")
    }
    fn run<T>(
        &self,
        id: &str,
        title: &str,
        detail: &str,
        operation: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        {
            let mut data = self.0.lock().map_err(|_| "启动状态不可写")?;
            if data.snapshot.state != "running" {
                return Err("初始化已经结束".into());
            }
            data.stage_started = Instant::now();
            data.snapshot.steps.push(Step {
                id: id.into(),
                title: title.into(),
                detail: detail.into(),
                state: "running".into(),
                elapsed_ms: 0,
            });
        }
        match operation() {
            Ok(value) => {
                let mut data = self.0.lock().map_err(|_| "启动状态不可写")?;
                let elapsed = data.stage_started.elapsed().as_millis() as u64;
                if let Some(step) = data.snapshot.steps.last_mut() {
                    step.state = "completed".into();
                    step.elapsed_ms = elapsed;
                }
                Ok(value)
            }
            Err(error) => {
                self.fail(error.clone());
                Err(error)
            }
        }
    }
    fn finish(&self) {
        if let Ok(mut data) = self.0.lock() {
            if data.snapshot.state == "running" {
                data.snapshot.elapsed_ms = data.started.elapsed().as_millis() as u64;
                data.snapshot.state = "ready".into();
            }
        }
    }
    pub fn fail(&self, error: String) {
        crate::runtime_log::event("error", "startup", "INITIALIZATION_FAILED", &error, None);
        if let Ok(mut data) = self.0.lock() {
            let elapsed = data.stage_started.elapsed().as_millis() as u64;
            if let Some(step) = data
                .snapshot
                .steps
                .last_mut()
                .filter(|s| s.state == "running")
            {
                step.state = "failed".into();
                step.elapsed_ms = elapsed;
            }
            data.snapshot.elapsed_ms = data.started.elapsed().as_millis() as u64;
            data.snapshot.state = "failed".into();
            data.snapshot.error = Some(error);
        }
    }
}

pub fn initialize(
    app: tauri::AppHandle,
    root_override: Option<PathBuf>,
    allow_mock: bool,
    workers: bool,
) {
    let progress = app.state::<Progress>().inner().clone();
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), String> {
            let root = progress.run(
                "workspace",
                "检查本地工作区",
                "确认工作区路径与恢复指针",
                || {
                    if let Some(root) = root_override {
                        return Ok(root);
                    }
                    let config = app.path().app_config_dir().map_err(|e| e.to_string())?;
                    if let Some(root) = maintenance::next_workspace(&config)? {
                        return Ok(root);
                    }
                    app.path().app_data_dir().map_err(|e| e.to_string())
                },
            )?;
            let store = progress.run(
                "database",
                "加载数据库",
                "打开 SQLite、校验结构并恢复本地记录",
                || {
                    let store = Store::open(root)?;
                    #[cfg(debug_assertions)]
                    let store = {
                        let mut store = store;
                        store.allow_mock_ai = allow_mock;
                        store
                    };
                    #[cfg(not(debug_assertions))]
                    let _ = allow_mock;
                    Ok(Arc::new(store))
                },
            )?;
            let lan = progress.run(
                "components",
                "加载安全组件",
                "恢复局域网身份与聊天存储；通讯默认关闭",
                || lan::Manager::new(store.clone()),
            )?;
            progress.run(
                "services",
                "注册本地服务",
                "连接采集、报告与后台调度组件",
                || {
                    if !app.manage(store.clone())
                        || !app.manage(lan)
                        || !app.manage(Arc::new(collector::Receiver::default()))
                    {
                        return Err("本地服务已存在，已停止重复初始化".into());
                    }
                    if workers {
                        monitoring::start_workers(store, app.clone());
                    }
                    Ok(())
                },
            )?;
            progress.finish();
            crate::runtime_log::event("info", "startup", "READY", "本地工作区初始化完成", None);
            Ok(())
        }));
    match result {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {} // The failing stage already recorded the error.
        Err(_) => progress.fail(
            "STARTUP-PANIC：本地组件初始化异常。请保留工作区并重新启动；不要删除原数据。".into(),
        ),
    }
}

#[tauri::command]
pub fn get_startup_state(progress: State<'_, Progress>) -> Result<Snapshot, String> {
    progress.snapshot()
}

#[tauri::command]
pub fn close_startup(app: tauri::AppHandle) {
    app.exit(0);
}

pub struct AuditRoot(pub Option<PathBuf>);
/// A failed database has no Store state, so startup verification uses only the
/// explicit debug audit directory. Normal workspaces cannot invoke this hook.
#[tauri::command]
pub fn startup_audit(
    result: Option<serde_json::Value>,
    window: tauri::WebviewWindow,
    root: State<'_, AuditRoot>,
    mode: State<'_, crate::SmokeMode>,
    progress: State<'_, Progress>,
) -> Result<serde_json::Value, String> {
    if !cfg!(debug_assertions) || !mode.0 {
        return Err("仅独立启动验收可用".into());
    }
    let root = root.0.as_ref().ok_or("缺少独立启动验收目录")?;
    if let Some(mut result) = result {
        result["version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
        result["backend"] =
            serde_json::to_value(progress.snapshot()?).map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?;
        if bytes.len() > 65536 {
            return Err("验收结果过大".into());
        }
        let name = if result["diagnostic"] == true {
            "startup-dom-diagnostic.json"
        } else {
            "native-startup-verification.json"
        };
        crate::file_commit::write_checked(
            &root.join(name),
            |f| {
                use std::io::Write;
                f.write_all(&bytes).map_err(|e| e.to_string())
            },
            || Ok(()),
        )?;
        Ok(serde_json::json!({"ok":true}))
    } else {
        let phase = std::fs::read_to_string(root.join("phase.txt")).map_err(|e| e.to_string())?;
        if phase.trim() == "hidden" {
            window.hide().map_err(|e| e.to_string())?;
        }
        Ok(serde_json::json!({"phase":phase.trim()}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_blocked_operation_is_visible_and_failure_never_marks_it_ready() {
        let progress = Progress::new();
        let worker = progress.clone();
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            worker.run("database", "加载数据库", "校验", || {
                entered.send(()).unwrap();
                release_rx.recv().unwrap();
                Err::<(), _>("synthetic database failure".into())
            })
        });
        entered_rx.recv().unwrap();
        let snapshot = progress.snapshot().unwrap();
        assert_eq!(snapshot.state, "running");
        assert_eq!(snapshot.steps[0].state, "running");
        assert!(!progress.ready());
        release.send(()).unwrap();
        assert!(thread.join().unwrap().is_err());
        progress.finish();
        let snapshot = progress.snapshot().unwrap();
        assert_eq!(snapshot.state, "failed");
        assert_eq!(snapshot.steps[0].state, "failed");
        assert_eq!(
            snapshot.error.as_deref(),
            Some("synthetic database failure")
        );
    }
    #[test]
    fn readiness_follows_successful_registration_and_durations_stop() {
        let progress = Progress::new();
        progress
            .run("database", "加载数据库", "校验", || Ok(()))
            .unwrap();
        assert!(!progress.ready());
        progress.finish();
        assert!(progress.ready());
        let a = progress.snapshot().unwrap();
        assert_eq!(a.steps[0].state, "completed");
        assert_eq!(a.elapsed_ms, progress.snapshot().unwrap().elapsed_ms);
    }
}
