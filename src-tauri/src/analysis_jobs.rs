//! Durable local-analysis jobs. Cancellation and the final evidence commit use
//! the same lock, so a committed result is never labelled cancelled. Progress
//! snapshots are bounded and throttled; full log matches remain in SQLite.
use crate::{
    analysis_progress::{LogCounts, Observer},
    analyzers::Finding,
    store::{Evidence, Store},
};
use chrono::Utc;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tauri::{Emitter, State};

pub const CANCELLED: &str = "分析已取消；原始输入未修改，未保存为完整分析证据。";
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stage {
    pub phase: String,
    pub elapsed_ms: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub id: String,
    pub case_id: String,
    pub kind: String,
    pub name: String,
    pub state: String,
    pub phase: String,
    pub started_at: String,
    pub elapsed_ms: u64,
    pub revision: u64,
    pub total_bytes: u64,
    pub copied_bytes: u64,
    pub counts: LogCounts,
    pub previews: Vec<Finding>,
    #[serde(default)]
    pub stages: Vec<Stage>,
    pub evidence_id: Option<String>,
    pub error: Option<String>,
}
impl Job {
    fn terminal(&self) -> bool {
        matches!(
            self.state.as_str(),
            "completed" | "failed" | "cancelled" | "interrupted"
        )
    }
}
fn persist(store: &Store, job: &Job) -> Result<(), String> {
    store.db.lock().map_err(|e| e.to_string())?.execute(
        "INSERT INTO local_analysis_jobs(id,case_id,record) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET record=excluded.record",
        params![job.id, job.case_id, serde_json::to_string(job).map_err(|e| e.to_string())?]
    ).map_err(|e| e.to_string())?;
    Ok(())
}
struct Live {
    job: Job,
    last_saved: Instant,
}
pub struct Control {
    store: Arc<Store>,
    live: Mutex<Live>,
    clock: Instant,
    app: Option<tauri::AppHandle>,
}
impl Control {
    fn snapshot(&self) -> Result<Job, String> {
        self.live
            .lock()
            .map(|v| v.job.clone())
            .map_err(|e| e.to_string())
    }
    fn update(
        &self,
        force: bool,
        f: impl FnOnce(&mut Job) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut live = self.live.lock().map_err(|e| e.to_string())?;
        let previous_phase = live.job.phase.clone();
        f(&mut live.job)?;
        live.job.elapsed_ms = self.clock.elapsed().as_millis() as u64;
        if live.job.phase != previous_phase && live.job.stages.len() < 12 {
            let stage = Stage {
                phase: live.job.phase.clone(),
                elapsed_ms: live.job.elapsed_ms,
            };
            live.job.stages.push(stage);
        }
        // Keep counters current in memory, but bound disk writes and IPC to 5 Hz.
        if force || live.last_saved.elapsed() >= Duration::from_millis(200) {
            live.job.revision += 1;
            persist(&self.store, &live.job)?;
            live.last_saved = Instant::now();
            if let Some(app) = &self.app {
                let _ = app.emit("local-analysis-progress", &live.job);
            }
        }
        Ok(())
    }
    fn cancel(&self) -> Result<(), String> {
        self.update(true, |job| {
            if job.terminal() {
                return Err("分析任务已结束。".into());
            }
            if job.phase == "committing" {
                return Err("分析结果正在最终保存，已无法取消，请等待保存结果。".into());
            }
            job.state = "cancelling".into();
            Ok(())
        })
    }
    fn finish(&self, result: Result<Evidence, String>) {
        let result = self.update(true, |job| {
            match result {
                Ok(e) => {
                    job.state = "completed".into();
                    job.phase = "completed".into();
                    job.evidence_id = Some(e.id);
                    job.error = None;
                }
                Err(error) => {
                    job.state = if error == CANCELLED {
                        "cancelled"
                    } else {
                        "failed"
                    }
                    .into();
                    job.error = Some(error);
                }
            }
            crate::runtime_log::event(
                if job.state == "failed" {
                    "error"
                } else {
                    "info"
                },
                "analysis",
                &format!("LOCAL_{}", job.state.to_uppercase()),
                job.error.as_deref().unwrap_or("本地分析结果已保存"),
                Some(&job.id),
            );
            Ok(())
        });
        if let Err(error) = result {
            if let Ok(mut live) = self.live.lock() {
                let previous = live.job.error.clone().unwrap_or_default();
                live.job.error = Some(format!(
                    "{previous} 任务终态写入失败；本次结果状态仅在内存保留，重启后将复核证据。"
                ));
                live.job.revision += 1;
            }
            crate::runtime_log::event("error", "analysis", "JOB_STATE_SAVE_FAILED", &error, None);
        }
    }
}
fn check(job: &Job) -> Result<(), String> {
    if job.state == "cancelling" {
        Err(CANCELLED.into())
    } else {
        Ok(())
    }
}
impl Observer for Control {
    fn check(&self) -> Result<(), String> {
        check(&self.live.lock().map_err(|e| e.to_string())?.job)
    }
    fn phase(&self, phase: &str, total: u64) -> Result<(), String> {
        self.update(true, |job| {
            check(job)?;
            job.phase = phase.into();
            if total > 0 {
                job.total_bytes = total;
            }
            Ok(())
        })
    }
    fn copied(&self, bytes: u64) -> Result<(), String> {
        self.update(false, |job| {
            check(job)?;
            job.copied_bytes = bytes;
            Ok(())
        })
    }
    fn scanned(&self, counts: LogCounts, findings: &[Finding]) -> Result<(), String> {
        self.update(false, |job| {
            check(job)?;
            job.counts = counts;
            let length = findings.len().min(24);
            if job.previews.len() != length
                || job.previews.last().map(|f| &f.id)
                    != findings.get(length.wrapping_sub(1)).map(|f| &f.id)
            {
                job.previews = findings.iter().take(24).cloned().collect();
            }
            Ok(())
        })
    }
    fn findings(&self, findings: &[Finding]) -> Result<(), String> {
        self.update(true, |job| {
            check(job)?;
            job.previews = findings.iter().take(24).cloned().collect();
            Ok(())
        })
    }
    fn begin_commit(&self, evidence_id: &str) -> Result<(), String> {
        self.update(true, |job| {
            check(job)?;
            job.phase = "committing".into();
            job.evidence_id = Some(evidence_id.into());
            Ok(())
        })
    }
}
#[derive(Default)]
pub struct Registry {
    active: Mutex<HashMap<String, Arc<Control>>>,
    recent: Mutex<Vec<Job>>,
}
impl Registry {
    fn begin(
        &self,
        store: Arc<Store>,
        case_id: String,
        path: &str,
        kind: String,
        app: Option<tauri::AppHandle>,
    ) -> Result<Arc<Control>, String> {
        if !matches!(kind.as_str(), "logs" | "webshell" | "binary") {
            return Err("该类型未接入本地分析任务。".into());
        }
        if !store.cases()?.iter().any(|c| c.id == case_id) {
            return Err("事件不存在。".into());
        }
        let mut active = self.active.lock().map_err(|e| e.to_string())?;
        active.retain(|_, task| task.snapshot().map_or(true, |job| !job.terminal()));
        if !active.is_empty() {
            return Err("已有本地分析运行，请等待完成或停止后再开始。".into());
        }
        let id = uuid::Uuid::new_v4().to_string();
        let task = Arc::new(Control {
            store,
            clock: Instant::now(),
            app,
            live: Mutex::new(Live {
                last_saved: Instant::now(),
                job: Job {
                    id: id.clone(),
                    case_id,
                    kind,
                    name: std::path::Path::new(path)
                        .file_name()
                        .map(|v| v.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    state: "running".into(),
                    phase: "queued".into(),
                    started_at: Utc::now().to_rfc3339(),
                    elapsed_ms: 0,
                    revision: 1,
                    total_bytes: 0,
                    copied_bytes: 0,
                    counts: LogCounts::default(),
                    previews: vec![],
                    stages: vec![],
                    evidence_id: None,
                    error: None,
                },
            }),
        });
        let job = task.snapshot()?;
        // Keep only bounded terminal history per case. Active records are never pruned.
        task.store.db.lock().map_err(|e|e.to_string())?.execute("DELETE FROM local_analysis_jobs WHERE case_id=?1 AND id NOT IN (SELECT id FROM local_analysis_jobs WHERE case_id=?1 ORDER BY rowid DESC LIMIT 29)", [&job.case_id]).map_err(|e|e.to_string())?;
        persist(&task.store, &job)?;
        active.insert(id, task.clone());
        Ok(task)
    }
    fn release(&self, id: &str) {
        if let Ok(mut active) = self.active.lock() {
            if let Some(task) = active.remove(id) {
                if let (Ok(job), Ok(mut recent)) = (task.snapshot(), self.recent.lock()) {
                    recent.insert(0, job);
                    recent.truncate(20);
                }
            }
        }
    }
}
pub fn recover(store: &Store) -> Result<(), String> {
    let jobs = list(store, None, true)?;
    for mut job in jobs.into_iter().filter(|job| !job.terminal()) {
        let committed = job
            .evidence_id
            .as_ref()
            .is_some_and(|id| store.evidence_for_case(&job.case_id, id).is_ok());
        job.state = if committed {
            "completed"
        } else {
            "interrupted"
        }
        .into();
        job.error = (!committed).then(|| "上次退出时分析未完成；保留最后进度，未自动重试。".into());
        if committed {
            job.phase = "completed".into();
        }
        job.revision += 1;
        persist(store, &job)?;
    }
    Ok(())
}
fn list(store: &Store, case: Option<&str>, recovering: bool) -> Result<Vec<Job>, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut query=db.prepare("SELECT record FROM local_analysis_jobs WHERE (?1 IS NULL OR case_id=?1) AND (?2=0 OR json_extract(record,'$.state') IN ('running','cancelling')) ORDER BY rowid DESC LIMIT ?3").map_err(|e|e.to_string())?;
    let rows = query
        .query_map(
            params![case, recovering, if recovering { -1 } else { 80 }],
            |r| r.get::<_, String>(0),
        )
        .map_err(|e| e.to_string())?;
    rows.map(|r| serde_json::from_str(&r.map_err(|e| e.to_string())?).map_err(|e| e.to_string()))
        .collect()
}
#[tauri::command]
pub fn get_local_analysis_jobs(
    case_id: Option<String>,
    store: State<'_, Arc<Store>>,
    registry: State<'_, Arc<Registry>>,
) -> Result<Vec<Job>, String> {
    let mut jobs = list(&store, case_id.as_deref(), false)?;
    // Terminal in-memory snapshots also cover a failed final journal write.
    for job in registry.recent.lock().map_err(|e| e.to_string())?.iter() {
        if case_id.as_ref().is_some_and(|case| case != &job.case_id) {
            continue;
        }
        if let Some(index) = jobs.iter().position(|old| old.id == job.id) {
            if jobs[index].revision < job.revision {
                jobs[index] = job.clone();
            }
        } else {
            jobs.push(job.clone());
        }
    }
    jobs.sort_by(|a, b| {
        b.started_at
            .cmp(&a.started_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    jobs.truncate(80);
    Ok(jobs)
}
#[tauri::command]
pub fn cancel_local_analysis(
    id: String,
    case_id: String,
    registry: State<'_, Arc<Registry>>,
) -> Result<(), String> {
    let active = registry.active.lock().map_err(|e| e.to_string())?;
    let task = active
        .get(&id)
        .ok_or("任务已结束或当前进程无法取消该任务。")?;
    if task.snapshot()?.case_id != case_id {
        return Err("任务不属于指定事件。".into());
    }
    task.cancel()
}
#[tauri::command]
pub fn start_local_analysis(
    app: tauri::AppHandle,
    case_id: String,
    path: String,
    kind: String,
    store: State<'_, Arc<Store>>,
    registry: State<'_, Arc<Registry>>,
) -> Result<Job, String> {
    let registry = registry.inner().clone();
    let task = registry.begin(
        store.inner().clone(),
        case_id.clone(),
        &path,
        kind.clone(),
        Some(app),
    )?;
    let initial = task.snapshot()?;
    let id = initial.id.clone();
    tauri::async_runtime::spawn(async move {
        let worker = task.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            worker
                .store
                .analyze_file_observed(path, kind, case_id, worker.as_ref())
        })
        .await
        .unwrap_or_else(|_| Err("本地分析线程异常结束，未自动重试。".into()));
        task.finish(result);
        registry.release(&id);
    });
    Ok(initial)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    fn setup() -> (PathBuf, Arc<Store>, String) {
        let root = std::env::temp_dir().join(format!("gaga-local-jobs-{}", uuid::Uuid::new_v4()));
        let store = Arc::new(Store::open(root.join("workspace")).unwrap());
        let case = store.active().unwrap();
        fs::write(root.join("input.log"),"2026-10-30T10:21:00+08:00 host sshd[42]: Failed password for root from 192.0.2.7 port 40000 ssh2\n".repeat(4096)).unwrap();
        (root, store, case)
    }
    struct CancelAt<'a> {
        task: &'a Control,
        scanning: bool,
    }
    impl Observer for CancelAt<'_> {
        fn check(&self) -> Result<(), String> {
            self.task.check()
        }
        fn phase(&self, phase: &str, total: u64) -> Result<(), String> {
            self.task.phase(phase, total)
        }
        fn copied(&self, bytes: u64) -> Result<(), String> {
            self.task.copied(bytes)?;
            if !self.scanning && bytes >= 65536 {
                self.task.cancel()?;
            }
            self.task.check()
        }
        fn scanned(&self, counts: LogCounts, findings: &[Finding]) -> Result<(), String> {
            let stop = counts.lines >= 1024;
            self.task.scanned(counts, findings)?;
            if self.scanning && stop {
                self.task.cancel()?;
            }
            self.task.check()
        }
    }
    #[test]
    fn cancelled_archive_and_scan_leave_input_unchanged_and_no_partial_evidence() {
        for scanning in [false, true] {
            let (root, store, case) = setup();
            let original = fs::read(root.join("input.log")).unwrap();
            let registry = Registry::default();
            let path = root.join("input.log").display().to_string();
            let task = registry
                .begin(store.clone(), case.clone(), &path, "logs".into(), None)
                .unwrap();
            let observer = CancelAt {
                task: &task,
                scanning,
            };
            let result = store.analyze_file_observed(path, "logs".into(), case.clone(), &observer);
            assert_eq!(result.as_ref().err().unwrap(), CANCELLED);
            task.finish(result);
            assert_eq!(task.snapshot().unwrap().state, "cancelled");
            if scanning {
                assert!(task.snapshot().unwrap().counts.lines >= 1024);
            }
            assert_eq!(fs::read(root.join("input.log")).unwrap(), original);
            assert!(store.workspace().unwrap().evidence.is_empty());
            assert_eq!(
                fs::read_dir(store.root.join("evidence")).unwrap().count(),
                0
            );
            if scanning {
                let db = rusqlite::Connection::open(
                    store.root.join("log-index").join(format!("{case}.sqlite3")),
                )
                .unwrap();
                assert_eq!(
                    db.query_row::<u64, _, _>("SELECT count(*) FROM events", [], |r| r.get(0))
                        .unwrap(),
                    0
                );
            }
            drop(task);
            drop(registry);
            drop(store);
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn completed_log_task_retains_counts_bounded_previews_and_captured_case() {
        let (root, store, case) = setup();
        let registry = Registry::default();
        let path = root.join("input.log").display().to_string();
        let task = registry
            .begin(store.clone(), case.clone(), &path, "logs".into(), None)
            .unwrap();
        assert!(registry
            .begin(store.clone(), case.clone(), &path, "logs".into(), None)
            .is_err());
        let other = store.create_case("Other case".into()).unwrap();
        let result = store.analyze_file_observed(path, "logs".into(), case.clone(), task.as_ref());
        let evidence = result.as_ref().unwrap();
        assert_eq!(evidence.case_id, case);
        assert!(store.evidence_for_case(&other.id, &evidence.id).is_err());
        assert!(task.cancel().unwrap_err().contains("最终保存"));
        task.finish(result);
        let job = task.snapshot().unwrap();
        assert_eq!(job.state, "completed");
        assert_eq!(job.counts.lines, 4096);
        assert_eq!(job.counts.hits, 4096);
        assert_eq!(job.previews.len(), 24);
        assert_eq!(
            job.counts.bytes,
            fs::metadata(root.join("input.log")).unwrap().len()
        );
        assert_eq!(
            list(&store, Some(&case), false).unwrap()[0].evidence_id,
            job.evidence_id
        );
        assert!(list(&store, Some(&other.id), false).unwrap().is_empty());
        drop(task);
        drop(registry);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_evidence_commit_discards_derived_index_and_records_failure() {
        let (root, store, case) = setup();
        store.db.lock().unwrap().execute_batch("CREATE TRIGGER refuse_evidence BEFORE INSERT ON evidence BEGIN SELECT RAISE(FAIL,'synthetic evidence failure'); END;").unwrap();
        let registry = Registry::default();
        let path = root.join("input.log").display().to_string();
        let task = registry
            .begin(store.clone(), case.clone(), &path, "logs".into(), None)
            .unwrap();
        let result = store.analyze_file_observed(path, "logs".into(), case.clone(), task.as_ref());
        assert!(result
            .as_ref()
            .err()
            .unwrap()
            .contains("synthetic evidence failure"));
        task.finish(result);
        assert_eq!(task.snapshot().unwrap().state, "failed");
        assert_eq!(
            fs::read_dir(store.root.join("evidence")).unwrap().count(),
            0
        );
        let db = rusqlite::Connection::open(
            store.root.join("log-index").join(format!("{case}.sqlite3")),
        )
        .unwrap();
        assert_eq!(
            db.query_row::<u64, _, _>("SELECT count(*) FROM events", [], |r| r.get(0))
                .unwrap(),
            0
        );
        drop(db);
        drop(task);
        drop(registry);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn restart_distinguishes_committed_evidence_from_interrupted_work() {
        let (root, store, case) = setup();
        let registry = Registry::default();
        let path = root.join("input.log").display().to_string();
        let task = registry
            .begin(store.clone(), case.clone(), &path, "logs".into(), None)
            .unwrap();
        // Simulate exit after the evidence commit, before terminal job persistence.
        store
            .analyze_file_observed(path, "logs".into(), case, task.as_ref())
            .unwrap();
        let committed = task.snapshot().unwrap();
        let mut interrupted = committed.clone();
        interrupted.id = uuid::Uuid::new_v4().to_string();
        interrupted.phase = "scanning".into();
        interrupted.evidence_id = None;
        persist(&store, &interrupted).unwrap();
        drop(task);
        drop(registry);
        drop(store);
        let reopened = Store::open(root.join("workspace")).unwrap();
        let jobs = list(&reopened, None, false).unwrap();
        assert_eq!(
            jobs.iter().find(|j| j.id == committed.id).unwrap().state,
            "completed"
        );
        assert_eq!(
            jobs.iter().find(|j| j.id == interrupted.id).unwrap().state,
            "interrupted"
        );
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn cancellation_stops_only_the_worker_process_group() {
        let clock = Instant::now();
        let result = crate::sandbox::command_checked(
            std::path::Path::new("/bin/sh"),
            &["-c".into(), "sleep 10".into()],
            None,
            30,
            1024,
            || {
                if clock.elapsed() > Duration::from_millis(150) {
                    Err(CANCELLED.into())
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result.err().unwrap(), CANCELLED);
        assert!(clock.elapsed() < Duration::from_secs(5));
    }
}
