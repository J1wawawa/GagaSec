//! 事件处置动作：把计划、审批、执行、回执、回滚和恢复验证作为独立记录保存。
//! 动作只记录事实与人工确认，不直接执行封禁/删除等高风险系统操作。
use crate::store::Store;
use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseAction {
    pub id: String,
    pub case_id: String,
    pub title: String,
    pub action_type: String,
    pub target: String,
    pub description: String,
    pub requested_by: String,
    pub approved_by: Option<String>,
    pub executed_by: Option<String>,
    pub status: String,
    pub requested_at: String,
    pub approved_at: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub receipt: Option<String>,
    pub failure_reason: Option<String>,
    pub rollback_plan: Option<String>,
    pub rollback_at: Option<String>,
    pub verification: Option<String>,
    pub evidence_ids: Vec<String>,
    pub node_ids: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub fn init(store: &Store) -> Result<(), String> {
    store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS response_actions(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),record TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS response_actions_case ON response_actions(case_id);",
        )
        .map_err(|e| e.to_string())
}

fn now() -> String {
    Utc::now().to_rfc3339()
}
fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn clean(value: &str, max: usize, label: &str) -> Result<String, String> {
    clean_text(value, max, label, false)
}
// Investigation notes and command receipts are naturally multi-line. Permit
// ordinary whitespace while retaining bounds and rejecting other controls.
fn clean_text(value: &str, max: usize, label: &str, multiline: bool) -> Result<String, String> {
    let v = value.trim();
    if v.is_empty()
        || v.chars().count() > max
        || v.chars()
            .any(|c| c.is_control() && !(multiline && matches!(c, '\n' | '\r' | '\t')))
    {
        return Err(format!("{label}不能为空且不能超过 {max} 个字符。"));
    }
    Ok(v.to_owned())
}
fn allowed_transition(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("draft", "pending_approval")
            | ("pending_approval", "approved")
            | ("pending_approval", "cancelled")
            | ("approved", "executing")
            | ("approved", "cancelled")
            | ("executing", "succeeded")
            | ("executing", "failed")
            | ("executing", "rolled_back")
            | ("succeeded", "verified")
            | ("succeeded", "rolled_back")
            | ("failed", "rolled_back")
            | ("rolled_back", "verified")
    )
}
fn validate_case_refs(
    store: &Store,
    case_id: &str,
    evidence: &[String],
    nodes: &[String],
) -> Result<(), String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
            [case_id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !exists {
        return Err("事件不存在。".into());
    }
    for id in evidence {
        let ok: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM evidence WHERE id=?1 AND case_id=?2)",
                params![id, case_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !ok {
            return Err("处置动作引用了其他事件或不存在的证据。".into());
        }
    }
    for id in nodes {
        let ok: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=?1 AND case_id=?2)",
                params![id, case_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !ok {
            return Err("处置动作引用了其他事件或不存在的时间线节点。".into());
        }
    }
    Ok(())
}
fn save_locked(db: &rusqlite::Connection, action: &ResponseAction) -> Result<(), String> {
    db.execute("INSERT INTO response_actions(id,case_id,record) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET record=excluded.record", params![action.id, action.case_id, serde_json::to_string(action).map_err(|e| e.to_string())?]).map_err(|e| e.to_string())?;
    Ok(())
}
pub fn list(store: &Store, case_id: &str) -> Result<Vec<ResponseAction>, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut q = db.prepare("SELECT record FROM response_actions WHERE case_id=?1 ORDER BY json_extract(record,'$.requestedAt'),id").map_err(|e| e.to_string())?;
    let rows = q
        .query_map([case_id], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    rows.map(|r| serde_json::from_str(&r.map_err(|e| e.to_string())?).map_err(|e| e.to_string()))
        .collect()
}
pub fn create(store: &Store, mut action: ResponseAction) -> Result<ResponseAction, String> {
    action.id = id();
    action.title = clean(&action.title, 160, "动作标题")?;
    action.target = clean(&action.target, 500, "目标")?;
    action.description = clean_text(&action.description, 4000, "动作说明", true)?;
    action.requested_by = clean(&action.requested_by, 80, "申请人")?;
    action.action_type = clean(&action.action_type, 40, "动作类型")?;
    if !matches!(
        action.action_type.as_str(),
        "containment" | "block" | "eradication" | "recovery" | "verification"
    ) {
        return Err("不支持的处置动作类型。".into());
    }
    validate_case_refs(
        store,
        &action.case_id,
        &action.evidence_ids,
        &action.node_ids,
    )?;
    let stamp = now();
    action.status = "draft".into();
    action.requested_at = stamp.clone();
    action.created_at = stamp.clone();
    action.updated_at = stamp;
    action.approved_by = None;
    action.executed_by = None;
    action.approved_at = None;
    action.started_at = None;
    action.completed_at = None;
    action.receipt = None;
    action.failure_reason = None;
    action.rollback_at = None;
    action.verification = None;
    let db = store.db.lock().map_err(|e| e.to_string())?;
    save_locked(&db, &action)?;
    Ok(action)
}
pub fn update_status(
    store: &Store,
    action_id: &str,
    status: &str,
    actor: Option<String>,
    detail: Option<String>,
) -> Result<ResponseAction, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let raw: String = db
        .query_row(
            "SELECT record FROM response_actions WHERE id=?1",
            [action_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .ok_or("处置动作不存在。")?;
    let mut a: ResponseAction = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if !allowed_transition(&a.status, status) {
        return Err(format!("不能从 {} 转换为 {}。", a.status, status));
    }
    let stamp = now();
    match status {
        "approved" => {
            a.approved_by = Some(clean(actor.as_deref().unwrap_or(""), 80, "审批人")?);
            a.approved_at = Some(stamp.clone());
        }
        "executing" => {
            a.executed_by = Some(clean(actor.as_deref().unwrap_or(""), 80, "执行人")?);
            a.started_at = Some(stamp.clone());
        }
        "succeeded" | "failed" | "rolled_back" | "cancelled" => {
            a.completed_at = Some(stamp.clone());
            if status == "failed" {
                a.failure_reason = detail
                    .as_deref()
                    .map(|v| clean_text(v, 4000, "失败原因", true))
                    .transpose()?;
            }
            if status == "rolled_back" {
                a.rollback_at = Some(stamp.clone());
            }
        }
        "verified" => {
            a.verification = Some(clean_text(
                detail.as_deref().unwrap_or(""),
                4000,
                "恢复验证",
                true,
            )?);
        }
        _ => {}
    }
    a.status = status.into();
    a.updated_at = stamp;
    save_locked(&db, &a)?;
    Ok(a)
}
pub fn receipt(store: &Store, action_id: &str, value: String) -> Result<ResponseAction, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let raw: String = db
        .query_row(
            "SELECT record FROM response_actions WHERE id=?1",
            [action_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .ok_or("处置动作不存在。")?;
    let mut a: ResponseAction = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    a.receipt = Some(clean_text(&value, 12000, "执行回执", true)?);
    a.updated_at = now();
    save_locked(&db, &a)?;
    Ok(a)
}
pub fn rollback_plan(
    store: &Store,
    action_id: &str,
    value: String,
) -> Result<ResponseAction, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let raw: String = db
        .query_row(
            "SELECT record FROM response_actions WHERE id=?1",
            [action_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .ok_or("处置动作不存在。")?;
    let mut a: ResponseAction = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    a.rollback_plan = Some(clean_text(&value, 4000, "回滚方案", true)?);
    a.updated_at = now();
    save_locked(&db, &a)?;
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multiline_notes_allow_normal_whitespace_but_reject_hidden_controls() {
        let value = "first line\r\n\tsecond line";
        assert_eq!(clean_text(value, 100, "note", true).unwrap(), value);
        assert!(clean(value, 100, "title").is_err());
        assert!(clean_text("one\0two", 100, "note", true).is_err());
        assert!(clean_text("a".repeat(101).as_str(), 100, "note", true).is_err());
    }
    #[test]
    fn state_machine_rejects_skips() {
        assert!(allowed_transition("draft", "pending_approval"));
        assert!(!allowed_transition("draft", "executing"));
        assert!(allowed_transition("succeeded", "verified"));
    }
    #[test]
    fn action_persists_auditable_lifecycle() {
        let root = std::env::temp_dir().join(format!("gaga-response-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let case_id = store.active().unwrap();
        let created = create(
            &store,
            ResponseAction {
                id: String::new(),
                case_id: case_id.clone(),
                title: "隔离可疑主机".into(),
                action_type: "containment".into(),
                target: "10.0.0.7".into(),
                description: "记录网络侧隔离工单".into(),
                requested_by: "analyst".into(),
                approved_by: None,
                executed_by: None,
                status: String::new(),
                requested_at: String::new(),
                approved_at: None,
                started_at: None,
                completed_at: None,
                receipt: None,
                failure_reason: None,
                rollback_plan: None,
                rollback_at: None,
                verification: None,
                evidence_ids: vec![],
                node_ids: vec![],
                created_at: String::new(),
                updated_at: String::new(),
            },
        )
        .unwrap();
        let created = update_status(&store, &created.id, "pending_approval", None, None).unwrap();
        let created =
            update_status(&store, &created.id, "approved", Some("lead".into()), None).unwrap();
        let created = update_status(
            &store,
            &created.id,
            "executing",
            Some("operator".into()),
            None,
        )
        .unwrap();
        let created = update_status(&store, &created.id, "succeeded", None, None).unwrap();
        receipt(&store, &created.id, "firewall receipt #42".into()).unwrap();
        let created = update_status(
            &store,
            &created.id,
            "verified",
            Some("reviewer".into()),
            Some("回连观察 30 分钟无异常".into()),
        )
        .unwrap();
        assert_eq!(created.status, "verified");
        assert_eq!(
            list(&store, &case_id).unwrap()[0].receipt.as_deref(),
            Some("firewall receipt #42")
        );
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
