//! AI 外发锁按工作区保存，不是操作系统防火墙。锁定会停用自动 AI；
//! 解锁不恢复旧授权，已经进入发送阶段的请求仍可能完成。
use crate::store::Store;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{Emitter, State};

const KEY: &str = "ai_privacy";
pub const LOCKED: &str =
    "AI 外发已锁定；可继续本地分析与报告，在「AI 与设置 → 隐私与外发」解锁后再使用模型。";

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub ai_locked: bool,
}

pub(crate) fn read_db(db: &Connection) -> Result<Settings, String> {
    let text: Option<String> = db
        .query_row("SELECT value FROM settings WHERE key=?1", [KEY], |r| {
            r.get(0)
        })
        .optional()
        .map_err(|e| e.to_string())?;
    text.map(|s| {
        serde_json::from_str(&s)
            .map_err(|_| "隐私设置损坏，AI 外发已阻止；请在隐私与外发重新保存设置。".into())
    })
    .unwrap_or_else(|| Ok(Settings::default()))
}

pub fn get(store: &Store) -> Result<Settings, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    read_db(&db)
}

pub fn ensure_ai_allowed(store: &Store) -> Result<(), String> {
    if get(store)?.ai_locked {
        Err(LOCKED.into())
    } else {
        Ok(())
    }
}

pub fn save(store: &Store, settings: Settings) -> Result<Settings, String> {
    let mut db = store.db.lock().map_err(|e| e.to_string())?;
    let tx = db.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT OR REPLACE INTO settings VALUES(?1,?2)",
        rusqlite::params![
            KEY,
            serde_json::to_string(&settings).map_err(|e| e.to_string())?
        ],
    )
    .map_err(|e| e.to_string())?;
    if settings.ai_locked {
        // 保留合法的间隔/预算偏好；损坏的旧配置删除，不能妨碍用户锁定。
        tx.execute(
            "DELETE FROM settings WHERE key='monitor_ai_settings' AND NOT json_valid(value)",
            [],
        )
        .map_err(|e| e.to_string())?;
        tx.execute("UPDATE settings SET value=json_set(value,'$.enabled',json('false')) WHERE key='monitor_ai_settings'", []).map_err(|e|e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(settings)
}

#[tauri::command]
pub fn get_ai_privacy(store: State<'_, Arc<Store>>) -> Result<Settings, String> {
    get(&store)
}

#[tauri::command]
pub fn set_ai_privacy(
    app: tauri::AppHandle,
    settings: Settings,
    store: State<'_, Arc<Store>>,
) -> Result<Settings, String> {
    let settings = save(&store, settings)?;
    let _ = app.emit("ai-privacy-changed", &settings);
    let _ = app.emit("platform-updated", serde_json::json!({"kind":"privacy"}));
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lock_persists_and_unlock_never_resumes_automatic_ai() {
        let root = std::env::temp_dir().join(format!("gaga-privacy-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        assert!(!get(&store).unwrap().ai_locked);
        store
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO settings VALUES('monitor_ai_settings',?1)",
                [r#"{"enabled":true,"minIntervalSecs":60,"maxPerHour":1}"#],
            )
            .unwrap();
        save(&store, Settings { ai_locked: true }).unwrap();
        assert!(ensure_ai_allowed(&store).is_err());
        assert!(!crate::monitoring::ai_settings(&store).unwrap().enabled);
        // 本地分析和证据归档继续可用。
        store
            .analyze_http_pair(
                "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".into(),
                "".into(),
            )
            .unwrap();
        drop(store);
        let store = Store::open(root.clone()).unwrap();
        assert!(get(&store).unwrap().ai_locked);
        save(&store, Settings { ai_locked: false }).unwrap();
        assert!(!crate::monitoring::ai_settings(&store).unwrap().enabled);
        store
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE settings SET value='{broken' WHERE key='ai_privacy'",
                [],
            )
            .unwrap();
        assert!(ensure_ai_allowed(&store).is_err());
        save(&store, Settings { ai_locked: true }).unwrap();
        assert!(get(&store).unwrap().ai_locked);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn cloud_entrypoints_reject_lock_before_keys_network_or_docker() {
        let root =
            std::env::temp_dir().join(format!("gaga-privacy-entry-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let evidence = store
            .analyze_http_pair(
                "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".into(),
                "".into(),
            )
            .unwrap();
        save(&store, Settings { ai_locked: true }).unwrap();
        let cfg = crate::ai::AiConfig::default();
        let results = [
            tauri::async_runtime::block_on(crate::ai::test_connection(&store, "")).err(),
            tauri::async_runtime::block_on(crate::ai::review(
                &store,
                evidence.id,
                "material".into(),
                "question".into(),
            ))
            .err(),
            tauri::async_runtime::block_on(crate::ai::followup(
                &store,
                None,
                "missing".into(),
                "question".into(),
            ))
            .err(),
            tauri::async_runtime::block_on(crate::ai::agent_transport(
                &store,
                &cfg,
                serde_json::Value::Null,
                1,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ))
            .err(),
            crate::isolated::run(&store, None, "missing".into(), "question".into()).err(),
        ];
        assert!(
            results.iter().all(|e| e.as_deref() == Some(LOCKED)),
            "{results:?}"
        );
        assert!(store.workspace().unwrap().analysis_runs.is_empty());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
