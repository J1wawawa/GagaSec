//! 任务持久化与事件版本。每次保存递增 revision，使界面能合并迟到快照。
use super::ACTIVE;
use crate::store::Store;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::Ordering;
use tauri::Emitter;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub at: String,
    pub title: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub id: String,
    pub tool: String,
    pub params: Value,
    pub sha256: String,
    pub preview: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub id: String,
    pub case_id: String,
    pub evidence_id: String,
    pub sample_sha256: String,
    pub created_at: String,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub config_revision: String,
    #[serde(default)]
    pub sample_name: String,
    #[serde(default)]
    pub request_sha256: Vec<String>,
    pub state: String,
    pub image_id: String,
    pub events: Vec<Event>,
    pub artifacts: Vec<Artifact>,
    pub model_requests: u32,
    #[serde(default)]
    pub tool_calls: u32,
    pub question: String,
    pub content: String,
    pub error: Option<String>,
    pub report_evidence_id: Option<String>,
    pub cleanup_confirmed: bool,
}
pub(super) fn save(
    store: &Store,
    app: Option<&tauri::AppHandle>,
    job: &mut Job,
) -> Result<(), String> {
    job.revision += 1;
    let db = store.db.lock().map_err(|e| e.to_string())?;
    db.execute(
        "INSERT INTO reverse_jobs(id,case_id,record) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET record=excluded.record",
        rusqlite::params![
            job.id,
            job.case_id,
            serde_json::to_string(job).map_err(|e| e.to_string())?
        ],
    )
    .map_err(|e| e.to_string())?;
    drop(db); // 发送 UI 事件前释放 SQLite 锁，前端刷新不应等待发送方。
    if let Some(error) = &job.error {
        crate::runtime_log::event("error", "reverse", "JOB_FAILED", error, Some(&job.id));
    }
    if let Some(app) = app {
        let _ = app.emit("reverse-progress", &*job);
    }
    Ok(())
}
pub(super) fn event(
    store: &Store,
    app: Option<&tauri::AppHandle>,
    job: &mut Job,
    title: &str,
) -> Result<(), String> {
    job.events.push(Event {
        at: Utc::now().to_rfc3339(),
        title: title.into(),
    });
    save(store, app, job)
}
pub fn jobs(store: &Store) -> Result<Vec<Job>, String> {
    let case = store.active()?;
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut q = db
        .prepare("SELECT record FROM reverse_jobs WHERE case_id=?1 ORDER BY json_extract(record,'$.createdAt') DESC,id DESC LIMIT 100")
        .map_err(|e| e.to_string())?;
    let result = q
        .query_map([case], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .map(|r| {
            r.map_err(|e| e.to_string())
                .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        })
        .collect();
    result
}
pub fn cancel(store: &Store, id: &str) -> Result<(), String> {
    // 取消按主键和事件直接校验，不能依赖有条数上限的历史列表。
    let case = store.active()?;
    let belongs: bool = store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM reverse_jobs WHERE id=?1 AND case_id=?2)",
            rusqlite::params![id, case],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !belongs {
        return Err("任务不属于当前事件".into());
    }
    let map = ACTIVE
        .get_or_init(Default::default)
        .lock()
        .map_err(|e| e.to_string())?;
    let flag = map.get(id).ok_or("此任务已经结束")?;
    flag.store(true, Ordering::SeqCst);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{atomic::AtomicBool, Arc};
    #[test]
    fn upsert_keeps_identity_and_cancel_is_not_limited_by_history_page() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let store = Store::open(root.clone()).unwrap();
        let case = store.active().unwrap();
        let mut first: Job = serde_json::from_value(json!({"id":"old-running","caseId":case,"evidenceId":"fixture",
            "sampleSha256":"hash","createdAt":"2020-01-01T00:00:00Z","state":"running","imageId":"image",
            "events":[],"artifacts":[],"modelRequests":0,"question":"test","content":"","error":null,
            "reportEvidenceId":null,"cleanupConfirmed":false})).unwrap();
        save(&store, None, &mut first).unwrap();
        let rowid: i64 = store
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT rowid FROM reverse_jobs WHERE id=?1",
                [&first.id],
                |r| r.get(0),
            )
            .unwrap();
        save(&store, None, &mut first).unwrap();
        assert_eq!(first.revision, 2);
        assert_eq!(
            rowid,
            store
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT rowid FROM reverse_jobs WHERE id=?1",
                    [&first.id],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap()
        );
        for n in 0..110 {
            let mut j = first.clone();
            j.id = format!("new-{n}");
            j.created_at = format!("2026-10-28T01:00:{:02}Z", n % 60);
            save(&store, None, &mut j).unwrap();
        }
        assert!(!jobs(&store).unwrap().iter().any(|j| j.id == first.id));
        let flag = Arc::new(AtomicBool::new(false));
        ACTIVE
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(first.id.clone(), flag.clone());
        cancel(&store, &first.id).unwrap();
        assert!(flag.load(Ordering::SeqCst));
        store.create_case("其他事件".into()).unwrap();
        assert!(cancel(&store, &first.id).is_err());
        ACTIVE.get().unwrap().lock().unwrap().remove(&first.id);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
