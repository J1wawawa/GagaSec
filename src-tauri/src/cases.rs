use crate::store::{Store, Workspace};
use rusqlite::params;
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;
#[tauri::command]
pub fn get_case_list(
    query: String,
    status: String,
    offset: u32,
    store: State<'_, Arc<Store>>,
) -> Result<Value, String> {
    if query.chars().count() > 120
        || !matches!(status.as_str(), "all" | "open" | "closed")
        || offset > 1_000_000
    {
        return Err("事件筛选无效".into());
    }
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let predicate=" FROM cases c WHERE instr(lower(c.title),lower(?1))>0 AND (?2='all' OR coalesce((SELECT value FROM settings WHERE key='case_status:'||c.id),'open')=?2)";
    let total: u64 = db
        .query_row(
            &format!("SELECT count(*){predicate}"),
            params![query, status],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let mut q=db.prepare(&format!("SELECT c.id,c.title,c.created_at,coalesce((SELECT value FROM settings WHERE key='case_status:'||c.id),'open'),(SELECT count(*) FROM evidence WHERE case_id=c.id),(SELECT count(*) FROM nodes WHERE case_id=c.id),(SELECT coalesce(sum(size),0) FROM evidence WHERE case_id=c.id),EXISTS(SELECT 1 FROM settings WHERE key='demo_case:'||c.id){predicate} ORDER BY c.created_at DESC,c.id LIMIT 50 OFFSET ?3")).map_err(|e|e.to_string())?;
    let rows=q.query_map(params![query,status,offset],|r|Ok(json!({"id":r.get::<_,String>(0)?,"title":r.get::<_,String>(1)?,"createdAt":r.get::<_,String>(2)?,"status":r.get::<_,String>(3)?,"evidence":r.get::<_,u64>(4)?,"nodes":r.get::<_,u64>(5)?,"bytes":r.get::<_,u64>(6)?,"demo":r.get::<_,bool>(7)?}))).map_err(|e|e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
    Ok(json!({"cases":rows,"total":total}))
}
#[tauri::command]
pub fn update_case(
    id: String,
    title: String,
    status: String,
    store: State<'_, Arc<Store>>,
) -> Result<Workspace, String> {
    if title.trim().is_empty()
        || title.chars().count() > 120
        || !matches!(status.as_str(), "open" | "closed")
    {
        return Err("事件名称或状态无效".into());
    }
    {
        let mut db = store.db.lock().map_err(|e| e.to_string())?;
        let tx = db.transaction().map_err(|e| e.to_string())?;
        let n = tx
            .execute(
                "UPDATE cases SET title=?1 WHERE id=?2",
                params![title.trim(), id],
            )
            .map_err(|e| e.to_string())?;
        if n != 1 {
            return Err("事件不存在".into());
        }
        tx.execute(
            "INSERT OR REPLACE INTO settings VALUES(?1,?2)",
            params![format!("case_status:{id}"), status],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
    }
    store.workspace()
}
