//! 支持包采用字段白名单构建；不读取模型 Key，不输出 SQL 记录、文件名、IP、
//! 目录、事件标题、报文、样本或原始错误。备份与诊断是两种不同的数据导出。
use crate::store::Store;
use serde_json::{json, Value};
use std::{fs, io::Write, path::Path, sync::Arc};
use tauri::State;

pub fn report(store: &Store) -> Result<Value, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut counts = serde_json::Map::new();
    for table in [
        "cases",
        "evidence",
        "screenshots",
        "nodes",
        "ai_reviews",
        "reverse_jobs",
        "monitor_assets",
    ] {
        let count: u64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        counts.insert(table.into(), json!(count));
    }
    let integrity: String = db
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let schema: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    // 不将 SQLite 返回的潜在页内容作为错误输出，仅给出布尔健康状态。
    Ok(
        json!({"format":"gaga-diagnostics/1","version":env!("CARGO_PKG_VERSION"),"createdAt":chrono::Utc::now().to_rfc3339(),"platform":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH},"database":{"schemaVersion":schema,"quickCheckOk":integrity=="ok","counts":counts},"release":serde_json::from_str::<Value>(include_str!("../../src/release-manifest.json")).map_err(|e|e.to_string())?,"privacy":{"mode":"allowlist","rawEvidenceIncluded":false,"credentialsRead":false,"pathsIncluded":false,"rawErrorsIncluded":false}}),
    )
}
pub fn export(store: &Store, path: &Path) -> Result<(), String> {
    let value = report(store)?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| format!("诊断导出失败，请选择新文件名：{e}"))?;
    file.write_all(&serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn export_diagnostics(path: String, store: State<'_, Arc<Store>>) -> Result<(), String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || export(&store, Path::new(&path)))
        .await
        .map_err(|e| e.to_string())?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostics_never_serialize_workspace_records_or_private_files() {
        let root = std::env::temp_dir().join(format!("gaga-diagnostics-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        store.create_case("SENSITIVE-CASE-CANARY".into()).unwrap();
        fs::write(root.join("private-canary"), "SENSITIVE-KEY-CANARY").unwrap();
        let text = serde_json::to_string(&report(&store).unwrap()).unwrap();
        assert!(!text.contains("SENSITIVE-"));
        assert!(!text.contains(root.to_str().unwrap()));
        let path = root.join("diagnostic.json");
        export(&store, &path).unwrap();
        assert!(export(&store, &path).is_err());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
