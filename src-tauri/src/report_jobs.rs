//! 报告任务仅保存在当前进程。取消与进入最终提交共用状态锁：
//! 提交前取消保留旧文件，进入提交后拒绝取消，避免误报“已取消”。
use crate::store::Store;
use serde::Serialize;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use tauri::{Emitter, State};

pub const CANCELLED: &str = "报告导出已取消；原有文件保留。";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub id: String,
    pub case_id: String,
    pub format: String,
    pub output_path: String,
    pub state: String,
    pub phase: String,
    pub verified_bytes: u64,
    pub total_bytes: u64,
    pub revision: u64,
    pub error: Option<String>,
}
impl Progress {
    pub fn terminal(&self) -> bool {
        matches!(self.state.as_str(), "completed" | "cancelled" | "failed")
    }
}
pub struct Control {
    progress: Mutex<Progress>,
    app: Option<tauri::AppHandle>,
}
impl Control {
    fn new(
        case_id: String,
        format: String,
        output_path: String,
        app: Option<tauri::AppHandle>,
    ) -> Self {
        Self {
            progress: Mutex::new(Progress {
                id: uuid::Uuid::new_v4().to_string(),
                case_id,
                format,
                output_path,
                state: "running".into(),
                phase: "snapshot".into(),
                verified_bytes: 0,
                total_bytes: 0,
                revision: 1,
                error: None,
            }),
            app,
        }
    }
    #[cfg(any(test, debug_assertions))]
    pub fn detached() -> Self {
        Self::new(String::new(), String::new(), String::new(), None)
    }
    pub fn snapshot(&self) -> Result<Progress, String> {
        self.progress
            .lock()
            .map(|p| p.clone())
            .map_err(|e| e.to_string())
    }
    pub fn check(&self) -> Result<(), String> {
        if self.snapshot()?.state == "cancelling" {
            Err(CANCELLED.into())
        } else {
            Ok(())
        }
    }
    pub fn phase(&self, phase: &str) -> Result<(), String> {
        let mut p = self.progress.lock().map_err(|e| e.to_string())?;
        if p.state == "cancelling" {
            return Err(CANCELLED.into());
        }
        p.phase = phase.into();
        p.revision += 1;
        Ok(())
    }
    pub fn total(&self, bytes: u64) -> Result<(), String> {
        let mut p = self.progress.lock().map_err(|e| e.to_string())?;
        p.total_bytes = bytes;
        p.revision += 1;
        Ok(())
    }
    pub fn advance(&self, bytes: u64) -> Result<(), String> {
        let mut p = self.progress.lock().map_err(|e| e.to_string())?;
        if p.state == "cancelling" {
            return Err(CANCELLED.into());
        }
        if bytes > 0 {
            p.verified_bytes = p.verified_bytes.saturating_add(bytes);
            p.revision += 1;
        }
        Ok(())
    }
    pub fn cancel(&self) -> Result<(), String> {
        let mut p = self.progress.lock().map_err(|e| e.to_string())?;
        if p.terminal() {
            return Err("报告任务已结束。".into());
        }
        if p.phase == "committing" {
            return Err("报告正在最终提交，已无法取消；请等待提交结果。".into());
        }
        p.state = "cancelling".into();
        p.revision += 1;
        Ok(())
    }
    pub fn begin_commit(&self) -> Result<(), String> {
        let mut p = self.progress.lock().map_err(|e| e.to_string())?;
        if p.state == "cancelling" {
            return Err(CANCELLED.into());
        }
        p.phase = "committing".into();
        p.revision += 1;
        Ok(())
    }
    pub(crate) fn notify(&self) {
        if let Some(app) = &self.app {
            let _ = app.emit("report-export-updated", ());
        }
    }
    pub fn finish(&self, result: Result<(), String>) {
        if let Ok(mut p) = self.progress.lock() {
            match result {
                Ok(()) => {
                    p.state = "completed".into();
                    p.error = None;
                }
                Err(e) => {
                    p.state = if e == CANCELLED {
                        "cancelled"
                    } else {
                        "failed"
                    }
                    .into();
                    p.error = Some(e);
                }
            }
            p.revision += 1;
            crate::runtime_log::event(
                if p.state == "failed" { "error" } else { "info" },
                "report",
                &format!("EXPORT_{}", p.state.to_uppercase()),
                p.error.as_deref().unwrap_or("报告已写入并提交"),
                Some(&p.id),
            );
        }
        self.notify();
    }
}

#[derive(Default)]
pub struct Registry(Mutex<Vec<Arc<Control>>>);
impl Registry {
    pub(crate) fn begin(
        &self,
        case_id: String,
        format: String,
        output_path: String,
        app: Option<tauri::AppHandle>,
    ) -> Result<Arc<Control>, String> {
        if !matches!(format.as_str(), "html" | "docx") {
            return Err("不支持的导出格式。".into());
        }
        let mut jobs = self.0.lock().map_err(|e| e.to_string())?;
        for task in jobs.iter() {
            if !task.snapshot()?.terminal() {
                return Err("已有报告正在导出，请完成或取消后再开始。".into());
            }
        }
        let task = Arc::new(Control::new(case_id, format, output_path, app));
        jobs.insert(0, task.clone());
        jobs.truncate(20);
        Ok(task)
    }
    pub fn list(&self) -> Result<Vec<Progress>, String> {
        self.0
            .lock()
            .map_err(|e| e.to_string())?
            .iter()
            .map(|t| t.snapshot())
            .collect()
    }
    fn cancel(&self, id: &str) -> Result<(), String> {
        let job = self
            .0
            .lock()
            .map_err(|e| e.to_string())?
            .iter()
            .find(|t| t.snapshot().is_ok_and(|p| p.id == id))
            .cloned()
            .ok_or("报告任务不存在。")?;
        job.cancel()?;
        job.notify();
        Ok(())
    }
}

#[tauri::command]
pub fn get_report_exports(registry: State<'_, Registry>) -> Result<Vec<Progress>, String> {
    registry.list()
}

#[tauri::command]
pub fn cancel_report_export(id: String, registry: State<'_, Registry>) -> Result<(), String> {
    registry.cancel(&id)
}

#[tauri::command]
pub fn start_report_export(
    app: tauri::AppHandle,
    case_id: String,
    path: String,
    format: String,
    store: State<'_, Arc<Store>>,
    registry: State<'_, Registry>,
) -> Result<Progress, String> {
    let control = registry.begin(case_id.clone(), format.clone(), path.clone(), Some(app))?;
    let state = control.snapshot()?;
    control.notify();
    let store = store.inner().clone();
    tauri::async_runtime::spawn(async move {
        let task = control.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            task.check()?;
            let input = crate::report_input::capture(&store, &case_id)?;
            crate::report::export_input(&store, Path::new(&path), &format, input, &task)
        })
        .await
        .unwrap_or_else(|_| Err("报告工作线程异常结束，请检查输出后重试。".into()));
        control.finish(result);
    });
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_and_commit_have_a_single_order_and_do_not_reuse_finished_jobs() {
        let registry = Registry::default();
        let first = registry
            .begin("A".into(), "html".into(), "output".into(), None)
            .unwrap();
        assert!(registry
            .begin("B".into(), "docx".into(), "other".into(), None)
            .is_err());
        first.total(1024).unwrap();
        first.phase("verifying").unwrap();
        first.advance(256).unwrap();
        let id = first.snapshot().unwrap().id;
        registry.cancel(&id).unwrap();
        assert_eq!(first.advance(256).unwrap_err(), CANCELLED);
        assert_eq!(first.begin_commit().unwrap_err(), CANCELLED);
        assert_eq!(first.snapshot().unwrap().verified_bytes, 256);
        first.finish(Err(CANCELLED.into()));
        assert_eq!(registry.list().unwrap()[0].state, "cancelled");
        assert!(registry.cancel(&id).is_err());
        let second = registry
            .begin("B".into(), "docx".into(), "other".into(), None)
            .unwrap();
        second.begin_commit().unwrap();
        assert!(second.cancel().unwrap_err().contains("最终提交"));
        second.finish(Ok(()));
        assert_eq!(second.snapshot().unwrap().state, "completed");
        for _ in 0..24 {
            registry
                .begin("A".into(), "html".into(), "output".into(), None)
                .unwrap()
                .finish(Ok(()));
        }
        assert_eq!(registry.list().unwrap().len(), 20);
    }
}
