//! 工作区维护只使用显式选择的路径。备份 SQLite 的一致快照，再复制快照引用的
//! 不可变证据；恢复始终创建新目录，不覆盖正在使用的工作区，不启动后台任务。
use crate::store::Store;
use rusqlite::{Connection, DatabaseName, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use tauri::{Manager, State};

const FORMAT: &str = "gaga-workspace-backup/1";
const LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const TOTAL_LIMIT: u64 = 256 * 1024 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    format: String,
    version: String,
    created_at: String,
    files: Vec<Entry>,
}
fn fail(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn directory(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(fail)
}
fn new_file(path: &Path) -> Result<fs::File, String> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map_err(fail)
}
fn hash_copy(source: &Path, target: Option<&Path>, maximum: u64) -> Result<Entry, String> {
    if !fs::symlink_metadata(source).map_err(fail)?.is_file() {
        return Err("拒绝链接或非普通备份文件".into());
    }
    let mut input = fs::File::open(source).map_err(fail)?;
    let mut output = target.map(new_file).transpose()?;
    let mut bytes = 0;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = input.read(&mut buf).map_err(fail)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > maximum {
            return Err("备份文件超过大小限制".into());
        }
        hash.update(&buf[..n]);
        if let Some(output) = output.as_mut() {
            output.write_all(&buf[..n]).map_err(fail)?;
        }
    }
    if let Some(output) = output.as_mut() {
        output.sync_all().map_err(fail)?;
    }
    Ok(Entry {
        path: String::new(),
        bytes,
        sha256: format!("{:x}", hash.finalize()),
    })
}
fn database_copy(db: &Connection, target: &Path) -> Result<(), String> {
    new_file(target)?;
    db.backup(DatabaseName::Main, target, None).map_err(fail)
}
/// 在改变旧结构之前留下数据库快照；原始证据仍保留在同一工作区。
pub fn migration_checkpoint(db: &Connection, root: &Path) -> Result<(), String> {
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(fail)?;
    if version > 1 {
        return Err("工作区来自较新版本，请使用相应客户端打开".into());
    }
    let existing: u64 = db
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='cases'",
            [],
            |r| r.get(0),
        )
        .map_err(fail)?;
    if version == 0 && existing > 0 {
        let dir = root.join("migration-backups");
        if !dir.exists() {
            directory(&dir)?;
        }
        database_copy(
            db,
            &dir.join(format!("before-v1-{}.sqlite3", uuid::Uuid::new_v4())),
        )?;
    }
    Ok(())
}
fn checked_db(path: &Path) -> Result<Connection, String> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(fail)?;
    db.execute_batch("PRAGMA trusted_schema=OFF;")
        .map_err(fail)?;
    let unsafe_objects: u64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE type IN ('trigger','view') OR lower(sql) LIKE '%create virtual table%'",[],|r|r.get(0)).map_err(fail)?;
    if unsafe_objects != 0 {
        return Err("备份含非预期触发器、视图或虚拟表".into());
    }
    let integrity: String = db
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(fail)?;
    if integrity != "ok" {
        return Err("备份数据库完整性检查失败".into());
    }
    let invalid = db
        .prepare("PRAGMA foreign_key_check")
        .map_err(fail)?
        .exists([])
        .map_err(fail)?;
    if invalid {
        return Err("备份数据库关联完整性检查失败".into());
    }
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(fail)?;
    if version != 1 {
        return Err("不支持此备份数据库版本".into());
    }
    Ok(db)
}
fn refs(db: &Connection) -> Result<Vec<(String, String)>, String> {
    let mut result = vec![];
    for (table, folder) in [("evidence", "evidence"), ("screenshots", "screenshots")] {
        let mut q = db
            .prepare(&format!("SELECT id,sha256 FROM {table}"))
            .map_err(fail)?;
        for row in q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(fail)?
        {
            let (id, hash) = row.map_err(fail)?;
            uuid::Uuid::parse_str(&id).map_err(|_| "证据标识无效")?;
            result.push((format!("{folder}/{id}"), hash));
        }
    }
    Ok(result)
}
fn allowed(path: &str) -> bool {
    if path == "workspace.sqlite3" {
        return true;
    }
    let parts: Vec<_> = path.split('/').collect();
    match parts.as_slice() {
        ["evidence" | "screenshots", id] => uuid::Uuid::parse_str(id).is_ok(),
        ["reverse-artifacts", job, file] => {
            uuid::Uuid::parse_str(job).is_ok()
                && !file.is_empty()
                && file.len() < 128
                && file
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
                && !file.starts_with('.')
        }
        ["sandbox-reports", file] => {
            file.ends_with(".json") && uuid::Uuid::parse_str(file.trim_end_matches(".json")).is_ok()
        }
        _ => false,
    }
}
fn target_parent(parent: &Path, source: &Path) -> Result<PathBuf, String> {
    let parent = parent.canonicalize().map_err(fail)?;
    if !parent.is_dir() || parent.starts_with(source.canonicalize().map_err(fail)?) {
        return Err("请选择工作区或备份目录之外的父文件夹".into());
    }
    Ok(parent)
}
pub fn backup(store: &Store, parent: &Path) -> Result<Value, String> {
    let parent = target_parent(parent, &store.root)?;
    let dest = parent.join(format!("gaga-backup-{}", uuid::Uuid::new_v4()));
    directory(&dest)?;
    let result = (|| {
        // 持有 DB 锁仅至快照结束；复制大证据时不阻塞报告保存。证据按 UUID 不可变。
        database_copy(
            &*store.db.lock().map_err(fail)?,
            &dest.join("workspace.sqlite3"),
        )?;
        {
            let backup_db = Connection::open(dest.join("workspace.sqlite3")).map_err(fail)?;
            crate::lan::redact_backup(&backup_db)?;
            backup_db.execute_batch("VACUUM;").map_err(fail)?;
        }
        let db = checked_db(&dest.join("workspace.sqlite3"))?;
        let mut inputs = refs(&db)?;
        for folder in ["reverse-artifacts", "sandbox-reports"] {
            let source = store.root.join(folder);
            if !source.exists() {
                continue;
            }
            let mut stack = vec![source];
            let mut visited = 0;
            while let Some(dir) = stack.pop() {
                visited += 1;
                if visited > 100000 {
                    return Err("备份目录过多".into());
                }
                if fs::symlink_metadata(&dir)
                    .map_err(fail)?
                    .file_type()
                    .is_symlink()
                {
                    return Err("备份拒绝符号链接目录".into());
                }
                for entry in fs::read_dir(dir).map_err(fail)? {
                    let entry = entry.map_err(fail)?;
                    let path = entry.path();
                    if entry.file_type().map_err(fail)?.is_dir() {
                        stack.push(path);
                    } else {
                        let rel = path
                            .strip_prefix(&store.root)
                            .map_err(fail)?
                            .to_string_lossy()
                            .replace('\\', "/");
                        if !allowed(&rel) {
                            return Err("非预期工件路径".into());
                        }
                        inputs.push((rel, String::new()));
                    }
                    if inputs.len() + stack.len() > 100000 {
                        return Err("备份文件数量超过限制".into());
                    }
                }
            }
        }
        let mut manifest = Manifest {
            format: FORMAT.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            files: vec![],
        };
        let mut database = hash_copy(&dest.join("workspace.sqlite3"), None, LIMIT)?;
        database.path = "workspace.sqlite3".into();
        let mut total = database.bytes;
        manifest.files.push(database);
        for (path, expected) in inputs {
            let target = dest.join(&path);
            fs::create_dir_all(target.parent().unwrap()).map_err(fail)?;
            let mut entry = hash_copy(&store.root.join(&path), Some(&target), LIMIT)?;
            entry.path = path;
            if !expected.is_empty() && entry.sha256 != expected {
                return Err("原始证据摘要不符，备份已中止".into());
            }
            total += entry.bytes;
            if total > TOTAL_LIMIT {
                return Err("备份总量超过 256 GiB".into());
            }
            manifest.files.push(entry);
        }
        let mut file = new_file(&dest.join("manifest.json"))?;
        file.write_all(&serde_json::to_vec_pretty(&manifest).map_err(fail)?)
            .map_err(fail)?;
        file.sync_all().map_err(fail)?;
        Ok(
            json!({"path":dest,"files":manifest.files.len(),"bytes":total,"createdAt":manifest.created_at}),
        )
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&dest);
    }
    result
}
pub fn restore(source: &Path, parent: &Path) -> Result<Value, String> {
    let parent = target_parent(parent, source)?;
    let mut bytes = Vec::new();
    fs::File::open(source.join("manifest.json"))
        .map_err(fail)?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(fail)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("备份清单过大".into());
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| "备份清单无效")?;
    if manifest.format != FORMAT || manifest.files.is_empty() || manifest.files.len() > 100000 {
        return Err("备份格式或文件数量无效".into());
    }
    let dest = parent.join(format!("gaga-restored-{}", uuid::Uuid::new_v4()));
    directory(&dest)?;
    let result = (|| {
        let mut seen = HashSet::new();
        let mut total = 0u64;
        for file in &manifest.files {
            if !allowed(&file.path)
                || !seen.insert(&file.path)
                || file.bytes > LIMIT
                || file.sha256.len() != 64
            {
                return Err("备份包含非法、重复路径或大小".into());
            }
            total = total.checked_add(file.bytes).ok_or("备份大小溢出")?;
            if total > TOTAL_LIMIT {
                return Err("备份总量超过限制".into());
            }
            let input = source.join(&file.path);
            // 检查所有父级，不能通过目录链接从清单允许路径跳到外部。
            let mut cursor = input.parent();
            while let Some(dir) = cursor {
                if dir == source {
                    break;
                }
                if fs::symlink_metadata(dir)
                    .map_err(fail)?
                    .file_type()
                    .is_symlink()
                {
                    return Err("备份目录含链接".into());
                }
                cursor = dir.parent();
            }
            let target = dest.join(&file.path);
            fs::create_dir_all(target.parent().unwrap()).map_err(fail)?;
            let copied = hash_copy(&input, Some(&target), file.bytes)?;
            if copied.bytes != file.bytes || copied.sha256 != file.sha256 {
                return Err("备份文件完整性校验失败".into());
            }
        }
        if !seen.contains(&"workspace.sqlite3".to_string()) {
            return Err("备份缺少数据库".into());
        }
        let db = checked_db(&dest.join("workspace.sqlite3"))?;
        for (path, hash) in refs(&db)? {
            if !manifest
                .files
                .iter()
                .any(|f| f.path == path && f.sha256 == hash)
            {
                return Err("备份缺少引用的原始证据".into());
            }
        }
        drop(db);
        let db = Connection::open(dest.join("workspace.sqlite3")).map_err(fail)?;
        // 恢复不自动联网、不继续旧任务；配置中的 hasKey 不能代表这台 PC 的钥匙串。
        db.execute_batch("PRAGMA trusted_schema=OFF; BEGIN; UPDATE monitor_assets SET enabled=0,running=0,record=json_set(record,'$.enabled',json('false')); DELETE FROM settings WHERE key='monitor_ai_settings' OR key='collector_receiver' OR key='ti_config_v1' OR key LIKE 'ai_config%' OR key LIKE 'ai_profile%'; UPDATE collector_tasks SET enabled=0; COMMIT;").map_err(fail)?;
        crate::lan::redact_backup(&db)?;
        Ok(
            json!({"path":dest,"files":manifest.files.len(),"bytes":total,"backgroundTasksDisabled":true,"credentialsIncluded":false}),
        )
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&dest);
    }
    result
}
pub fn information(store: &Store) -> Result<Value, String> {
    let (cases, schema_version): (u64, u32) = {
        let db = store.db.lock().map_err(fail)?;
        (
            db.query_row("SELECT count(*) FROM cases", [], |r| r.get(0))
                .map_err(fail)?,
            db.query_row("PRAGMA user_version", [], |r| r.get(0))
                .map_err(fail)?,
        )
    };
    let database_main = fs::metadata(store.root.join("workspace.sqlite3"))
        .map_err(fail)?
        .len();
    let sidecar = |name| match fs::metadata(store.root.join(name)) {
        Ok(meta) => Ok(meta.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(fail(e)),
    };
    let database_wal = sidecar("workspace.sqlite3-wal")?;
    let database_shm = sidecar("workspace.sqlite3-shm")?;
    let mut categories = vec![];
    for (id, title) in [
        ("evidence", "原始证据"),
        ("screenshots", "举证截图"),
        ("reverse-artifacts", "逆向工件"),
        ("sandbox-reports", "动态报告"),
        ("log-index", "可重建日志索引"),
        ("migration-backups", "升级前数据库快照"),
        ("lan-private", "局域网通信私有数据"),
    ] {
        let mut bytes = 0u64;
        let mut count = 0u64;
        let mut stack = vec![store.root.join(id)];
        let mut visited = 0;
        while let Some(path) = stack.pop() {
            visited += 1;
            if visited > 100000 {
                return Err("存储目录过多".into());
            }
            if !path.exists() {
                continue;
            }
            let meta = fs::symlink_metadata(&path).map_err(fail)?;
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                for item in fs::read_dir(path).map_err(fail)? {
                    stack.push(item.map_err(fail)?.path());
                }
            } else {
                bytes += meta.len();
                count += 1;
            }
            if count + stack.len() as u64 > 100000 {
                return Err("存储统计文件过多，请分工作区管理".into());
            }
        }
        categories.push(json!({"id":id,"title":title,"bytes":bytes,"files":count}));
    }

    Ok(
        json!({"path":store.root,"schemaVersion":schema_version,"cases":cases,
            "databaseBytes":database_main+database_wal+database_shm,
            "databaseMainBytes":database_main,"databaseWalBytes":database_wal,"databaseShmBytes":database_shm,
            "categories":categories}),
    )
}
#[tauri::command]
pub async fn workspace_maintenance(
    operation: String,
    path: Option<String>,
    parent: Option<String>,
    store: State<'_, Arc<Store>>,
) -> Result<Value, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || match operation.as_str() {
        "info" => information(&store),
        "backup" => backup(&store, Path::new(&parent.ok_or("请选择备份父目录")?)),
        "restore" => restore(
            Path::new(&path.ok_or("请选择备份目录")?),
            Path::new(&parent.ok_or("请选择恢复父目录")?),
        ),
        _ => Err("未知维护操作".into()),
    })
    .await
    .map_err(fail)?
}
pub fn next_workspace(config: &Path) -> Result<Option<PathBuf>, String> {
    let file = config.join("workspace-location.json");
    let mut input = match fs::File::open(&file) {
        Ok(input) => input.take(65537),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if config
                .join("workspace-location.previous.json")
                .try_exists()
                .map_err(fail)?
            {
                return Err("工作区位置配置缺失，但存在上次配置；请恢复 workspace-location.previous.json，拒绝静默打开默认工作区".into());
            }
            return Ok(None);
        }
        Err(e) => return Err(fail(e)),
    };
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).map_err(fail)?;
    if bytes.len() > 65536 {
        return Err("工作区位置配置过大".into());
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "工作区位置配置损坏，请使用同目录 previous 文件恢复")?;
    let path = PathBuf::from(value["path"].as_str().ok_or("工作区位置配置缺少路径")?);
    if !path.is_absolute() || !path.is_dir() {
        return Err(
            "已选择的工作区不可用，请连接对应磁盘，或恢复 workspace-location.previous.json 配置"
                .into(),
        );
    }
    Ok(Some(path))
}
fn save_workspace_location(config: &Path, path: &Path) -> Result<(), String> {
    let target = config.join("workspace-location.json");
    match fs::read(&target) {
        Ok(previous) => crate::file_commit::write_bytes(
            &config.join("workspace-location.previous.json"),
            &previous,
        )?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(fail(e)),
    }
    crate::file_commit::write_bytes(
        &target,
        &serde_json::to_vec(&json!({"path":path})).map_err(fail)?,
    )
}
#[tauri::command]
pub fn activate_workspace(
    app: tauri::AppHandle,
    path: String,
    store: State<'_, Arc<Store>>,
    smoke: State<'_, crate::SmokeMode>,
) -> Result<(), String> {
    let path = PathBuf::from(path).canonicalize().map_err(fail)?;
    checked_db(&path.join("workspace.sqlite3"))?;
    let config = if smoke.0 {
        store.root.join("test-app-config")
    } else {
        app.path().app_config_dir().map_err(fail)?
    };
    fs::create_dir_all(&config).map_err(fail)?;
    save_workspace_location(&config, &path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_071_storage_includes_uncheckpointed_database_files() {
        let (store, root) = fixture();
        store.db.lock().unwrap().execute_batch("PRAGMA wal_autocheckpoint=0; CREATE TABLE audit_growth(data BLOB); INSERT INTO audit_growth VALUES(zeroblob(1048576));").unwrap();
        let database = fs::metadata(store.root.join("workspace.sqlite3"))
            .unwrap()
            .len();
        let wal = fs::metadata(store.root.join("workspace.sqlite3-wal"))
            .unwrap()
            .len();
        let shm = fs::metadata(store.root.join("workspace.sqlite3-shm"))
            .unwrap()
            .len();
        assert!(wal > 1048576);
        let info = information(&store).unwrap();
        assert_eq!(info["databaseBytes"].as_u64(), Some(database + wal + shm));
        assert_eq!(info["databaseWalBytes"].as_u64(), Some(wal));
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn audit_071_missing_pointer_with_previous_cannot_open_default_workspace() {
        let root = std::env::temp_dir().join(format!("gaga-pointer-gap-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("workspace-location.previous.json"),
            r#"{"path":"/missing"}"#,
        )
        .unwrap();
        assert!(next_workspace(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn workspace_location_replacement_keeps_previous_selection() {
        let root =
            std::env::temp_dir().join(format!("gaga-pointer-write-{}", uuid::Uuid::new_v4()));
        let config = root.join("config");
        let first = root.join("first");
        let second = root.join("second");
        for dir in [&config, &first, &second] {
            fs::create_dir_all(dir).unwrap();
        }
        save_workspace_location(&config, &first).unwrap();
        assert_eq!(next_workspace(&config).unwrap(), Some(first.clone()));
        save_workspace_location(&config, &second).unwrap();
        assert_eq!(next_workspace(&config).unwrap(), Some(second));
        let previous: Value = serde_json::from_slice(
            &fs::read(config.join("workspace-location.previous.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(previous["path"], first.to_string_lossy().as_ref());
        assert_eq!(fs::read_dir(&config).unwrap().count(), 2);
        fs::remove_dir_all(root).unwrap();
    }
    fn fixture() -> (Store, PathBuf) {
        let root = std::env::temp_dir().join(format!("gaga-maint-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let store = Store::open(root.join("live")).unwrap();
        store
            .analyze_http_pair(
                "GET /.env HTTP/1.1\r\nHost: example.test\r\n\r\n".into(),
                "HTTP/1.1 403 Forbidden\r\n\r\n".into(),
            )
            .unwrap();
        (store, root)
    }
    #[test]
    fn snapshot_restores_complete_case_into_new_directory_and_preserves_original() {
        let (store, root) = fixture();
        fs::write(
            store.root.join("test-secret-identity"),
            "must-not-be-backed-up",
        )
        .unwrap();
        crate::monitoring::import_assets(&store, "https://example.test", 60).unwrap();
        let asset = crate::monitoring::assets(&store, None).unwrap().remove(0);
        crate::monitoring::toggle_asset(&store, &asset.id, true).unwrap();
        let saved = backup(&store, &root).unwrap();
        let source = Path::new(saved["path"].as_str().unwrap());
        let restored = restore(source, &root).unwrap();
        let copy = Store::open(PathBuf::from(restored["path"].as_str().unwrap())).unwrap();
        assert!(!crate::monitoring::assets(&copy, None).unwrap()[0].enabled);
        assert!(crate::monitoring::assets(&store, None).unwrap()[0].enabled);
        assert_eq!(copy.workspace().unwrap().evidence.len(), 1);
        assert_eq!(store.workspace().unwrap().evidence.len(), 1);
        assert!(!source.join("test-secret-identity").exists());
        assert!(!copy.root.join("test-secret-identity").exists());
        drop(copy);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn tampering_and_traversal_never_publish_a_restored_workspace() {
        let (store, root) = fixture();
        let saved = backup(&store, &root).unwrap();
        let source = Path::new(saved["path"].as_str().unwrap());
        let path = source.join("manifest.json");
        let mut m: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        m.files[0].sha256 = "0".repeat(64);
        fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(restore(source, &root).is_err());
        m.files[0].path = "../escaped".into();
        fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(restore(source, &root).is_err());
        assert!(!root.join("escaped").exists());
        assert!(!fs::read_dir(&root).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("gaga-restored-")));
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn modified_original_evidence_aborts_backup() {
        let (store, root) = fixture();
        let e = store.workspace().unwrap().evidence.remove(0);
        crate::store::test_overwrite_archive(store.root.join("evidence").join(e.id), "changed")
            .unwrap();
        assert!(backup(&store, &root).is_err());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn schema_upgrade_saves_one_checkpoint_and_rejects_future_versions() {
        let (store, root) = fixture();
        store
            .db
            .lock()
            .unwrap()
            .execute_batch("PRAGMA user_version=0;")
            .unwrap();
        let workspace = store.root.clone();
        drop(store);
        let upgraded = Store::open(workspace.clone()).unwrap();
        assert_eq!(
            fs::read_dir(workspace.join("migration-backups"))
                .unwrap()
                .count(),
            1
        );
        drop(upgraded);
        let reopened = Store::open(workspace.clone()).unwrap();
        assert_eq!(
            fs::read_dir(workspace.join("migration-backups"))
                .unwrap()
                .count(),
            1
        );
        reopened
            .db
            .lock()
            .unwrap()
            .execute_batch("PRAGMA user_version=2;")
            .unwrap();
        drop(reopened);
        assert!(Store::open(workspace).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn linked_backup_subdirectory_is_rejected_without_external_reads() {
        let (store, root) = fixture();
        let saved = backup(&store, &root).unwrap();
        let source = Path::new(saved["path"].as_str().unwrap());
        fs::rename(source.join("evidence"), root.join("outside")).unwrap();
        std::os::unix::fs::symlink(root.join("outside"), source.join("evidence")).unwrap();
        assert!(restore(source, &root).is_err());
        assert!(root.join("outside").exists());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn unavailable_workspace_pointer_cannot_silently_open_an_empty_workspace() {
        let root = std::env::temp_dir().join(format!("gaga-pointer-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        assert!(next_workspace(&root).unwrap().is_none());
        fs::write(root.join("workspace-location.json"), "{broken").unwrap();
        assert!(next_workspace(&root).is_err());
        fs::write(
            root.join("workspace-location.json"),
            r#"{"path":"relative/missing"}"#,
        )
        .unwrap();
        assert!(next_workspace(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
