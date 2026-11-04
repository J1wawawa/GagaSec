use crate::collector_crypto::PrivateKey;
use crate::store::{Evidence, Store};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tauri::Emitter;
pub fn init(store: &Store) -> Result<(), String> {
    store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .execute(
            "INSERT OR IGNORE INTO settings VALUES('collector_secret_namespace',?1)",
            [uuid::Uuid::new_v4().to_string()],
        )
        .map_err(|e| e.to_string())?;
    store.db.lock().map_err(|e|e.to_string())?.execute_batch(
"CREATE TABLE IF NOT EXISTS collector_tasks(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),enabled INTEGER NOT NULL,expires_at TEXT NOT NULL,token_box TEXT NOT NULL,record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS collector_batches(task_id TEXT NOT NULL REFERENCES collector_tasks(id),sequence TEXT NOT NULL,created_at TEXT NOT NULL,state TEXT NOT NULL,evidence_id TEXT,sha256 TEXT NOT NULL,PRIMARY KEY(task_id,sequence));
CREATE TABLE IF NOT EXISTS flow_windows(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),task_id TEXT NOT NULL REFERENCES collector_tasks(id),created_at TEXT NOT NULL,evidence_id TEXT NOT NULL REFERENCES evidence(id),record TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS collector_tasks_case ON collector_tasks(case_id);
CREATE INDEX IF NOT EXISTS collector_batches_task_state_time ON collector_batches(task_id,state,created_at);
CREATE INDEX IF NOT EXISTS flow_windows_case_time ON flow_windows(case_id,created_at DESC);
UPDATE collector_batches SET state='interrupted' WHERE state='processing';").map_err(|e|e.to_string())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub id: String,
    pub public_key: String,
    pub fingerprint: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Task {
    pub id: String,
    pub case_id: String,
    pub name: String,
    pub target: String,
    pub mode: String,
    pub architecture: String,
    pub interface: String,
    pub duration_seconds: u64,
    pub batch_seconds: u64,
    pub snaplen: u32,
    pub include_http: bool,
    pub expires_at: String,
    pub created_at: String,
    pub enabled: bool,
    pub client_fingerprint: String,
    pub batches: u64,
    pub last_seen: Option<String>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TaskInput {
    pub name: String,
    pub target: String,
    pub mode: String,
    pub architecture: String,
    pub interface: String,
    pub duration_seconds: u64,
    pub batch_seconds: u64,
    pub snaplen: u32,
    pub include_http: bool,
    pub hours: u64,
    pub online: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    format: String,
    task_id: String,
    sequence: String,
    created_at: String,
    encrypted_key: String,
    nonce: String,
    ciphertext: String,
    mac: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiverConfig {
    pub bind: String,
    pub callback_url: String,
    pub certificate: String,
}

/// Atomically reserve one receiver worker slot.
///
/// A separate `load` followed by `fetch_add` lets concurrent accepts all see
/// the same free slot and exceed the intended bound.  CAS keeps the limit
/// enforceable even when the listener is handling several clients at once.
fn try_acquire_connection_slot(connections: &AtomicUsize, limit: usize) -> bool {
    let mut current = connections.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return false;
        }
        match connections.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

/// Persist an encrypted collector package with a complete-file commit.
///
/// Retries for the same task sequence may replace an existing ordinary file,
/// but a pre-existing link or directory is rejected before any write.  The
/// atomic rename also means a concurrent replacement can never write through
/// a link into an unrelated path.
fn persist_inbox_package(
    store: &Store,
    task_id: &str,
    sequence: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let dir = store.root.join("collector-inbox");
    match fs::symlink_metadata(&dir) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err("采集回包目录不是受信任的普通目录。".into())
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let metadata = fs::symlink_metadata(&dir).map_err(|e| e.to_string())?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("采集回包目录创建后状态异常。".into());
            }
        }
        Err(error) => return Err(error.to_string()),
    }
    let path = dir.join(format!("{}-{}.encrypted.json", task_id, sequence));
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("采集回包目标不是普通文件。".into());
        }
    }
    crate::file_commit::write_atomic(&path, |file| {
        file.write_all(bytes).map_err(|e| e.to_string())
    })
}
impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:3443".into(),
            callback_url: "https://localhost:3443".into(),
            certificate: String::new(),
        }
    }
}
#[derive(Default)]
pub struct Receiver {
    running: AtomicBool,
    stop: Mutex<Option<Arc<AtomicBool>>>,
}
impl Receiver {
    pub fn running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
    pub fn stop(&self) {
        if let Ok(s) = self.stop.lock() {
            if let Some(s) = s.as_ref() {
                s.store(true, Ordering::SeqCst);
            }
        }
        for _ in 0..30 {
            if !self.running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
#[cfg(not(test))]
fn secret_account(store: &Store, purpose: &str) -> String {
    let namespace = store.db.lock().ok().and_then(|db| {
        db.query_row(
            "SELECT value FROM settings WHERE key='collector_secret_namespace'",
            [],
            |r| r.get::<_, String>(0),
        )
        .ok()
    });
    match namespace {
        Some(id) if uuid::Uuid::parse_str(&id).is_ok() => format!("{purpose}-workspace-{id}"),
        _ => legacy_secret_account(store, purpose),
    }
}
#[cfg(not(test))]
fn legacy_secret_account(store: &Store, purpose: &str) -> String {
    format!(
        "{}-{:x}",
        purpose,
        Sha256::digest(store.root.to_string_lossy().as_bytes())
    )
}
#[cfg(not(test))]
fn secret_write(store: &Store, purpose: &str, value: &str) -> Result<(), String> {
    keyring::Entry::new(
        "team.j4.gaga-assistant.collector",
        &secret_account(store, purpose),
    )
    .map_err(|_| "无法访问系统凭据")?
    .set_password(value)
    .map_err(|_| "无法保存采集私钥到系统凭据；尚未生成任务。".into())
}
#[cfg(not(test))]
fn secret_read(store: &Store, purpose: &str) -> Result<String, String> {
    let stable = keyring::Entry::new(
        "team.j4.gaga-assistant.collector",
        &secret_account(store, purpose),
    )
    .map_err(|_| "无法访问系统凭据")?;
    match stable.get_password() {
        Ok(value) => Ok(value),
        Err(keyring::Error::NoEntry) => {
            let old = keyring::Entry::new(
                "team.j4.gaga-assistant.collector",
                &legacy_secret_account(store, purpose),
            )
            .map_err(|_| "无法访问原系统凭据")?;
            let value = old
                .get_password()
                .map_err(|_| "采集私钥 / TLS 私钥不可用；请恢复原系统凭据，不会自动替换旧密钥。")?;
            stable
                .set_password(&value)
                .map_err(|_| "原凭据读取成功，但无法迁移到稳定的工作区标识。")?;
            Ok(value)
        }
        Err(_) => Err("系统凭据暂不可访问；没有替换或覆盖现有私钥。".into()),
    }
}

pub fn cleanup_smoke_credentials(store: &Store) {
    #[cfg(all(
        debug_assertions,
        not(test),
        any(target_os = "macos", target_os = "windows")
    ))]
    for purpose in ["identity", "receiver-tls"] {
        if let Ok(entry) = keyring::Entry::new(
            "team.j4.gaga-assistant.collector",
            &secret_account(store, purpose),
        ) {
            let _ = entry.delete_credential();
        }
        if let Ok(entry) = keyring::Entry::new(
            "team.j4.gaga-assistant.collector",
            &legacy_secret_account(store, purpose),
        ) {
            let _ = entry.delete_credential();
        }
    }
    let _ = store;
}

#[cfg(all(debug_assertions, not(test)))]
pub fn audit_isolated_credentials(parent: &Store) -> Result<serde_json::Value, String> {
    let original = parent
        .root
        .join(format!("credential-audit-{}", uuid::Uuid::new_v4()));
    let moved = original.with_extension("moved");
    let store = Store::open(original.clone())?;
    let expected = ensure_identity(&store)?;
    let stable = keyring::Entry::new(
        "team.j4.gaga-assistant.collector",
        &secret_account(&store, "identity"),
    )
    .map_err(|e| e.to_string())?;
    let legacy = keyring::Entry::new(
        "team.j4.gaga-assistant.collector",
        &legacy_secret_account(&store, "identity"),
    )
    .map_err(|e| e.to_string())?;
    let value = stable.get_password().map_err(|e| e.to_string())?;
    legacy.set_password(&value).map_err(|e| e.to_string())?;
    stable.delete_credential().map_err(|e| e.to_string())?;
    let migrated = ensure_identity(&store)?.public_key == expected.public_key;
    let _ = legacy.delete_credential();
    drop(store);
    fs::rename(&original, &moved).map_err(|e| e.to_string())?;
    let reopened = Store::open(moved.clone())?;
    let relocated = ensure_identity(&reopened)?.public_key == expected.public_key;
    cleanup_smoke_credentials(&reopened);
    drop(reopened);
    fs::remove_dir_all(moved).map_err(|e| e.to_string())?;
    if !migrated || !relocated {
        return Err("隔离凭据迁移 / 移动工作区检查失败".into());
    }
    Ok(
        serde_json::json!({"legacyMigration":migrated,"workspaceRelocation":relocated,"isolatedOnly":true}),
    )
}

#[cfg(test)]
fn secret_write(store: &Store, purpose: &str, value: &str) -> Result<(), String> {
    fs::write(store.root.join(format!("test-secret-{purpose}")), value).map_err(|e| e.to_string())
}
#[cfg(test)]
fn secret_read(store: &Store, purpose: &str) -> Result<String, String> {
    fs::read_to_string(store.root.join(format!("test-secret-{purpose}"))).map_err(|e| e.to_string())
}
pub fn identity(store: &Store) -> Result<Option<Identity>, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let s: Option<String> = db
        .query_row(
            "SELECT value FROM settings WHERE key='collector_identity'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    s.map(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        .transpose()
}
pub fn ensure_identity(store: &Store) -> Result<Identity, String> {
    static LOCK: Mutex<()> = Mutex::new(());
    let _lock = LOCK.lock().map_err(|e| e.to_string())?;
    if let Some(i) = identity(store)? {
        let key = private_key(store)?;
        if public_key(&key)? != i.public_key {
            return Err("本客户端公私钥不匹配，已拒绝生成任务。".into());
        }
        return Ok(i);
    }
    let key = PrivateKey::generate()?;
    let public = public_key(&key)?;
    secret_write(store, "identity", key.private_pem()?.as_str())?;
    let i = Identity {
        id: uuid::Uuid::new_v4().to_string(),
        fingerprint: format!("{:x}", Sha256::digest(public.as_bytes())),
        public_key: public,
    };
    store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .execute(
            "INSERT INTO settings VALUES('collector_identity',?1)",
            [serde_json::to_string(&i).unwrap()],
        )
        .map_err(|e| e.to_string())?;
    Ok(i)
}
fn private_key(store: &Store) -> Result<PrivateKey, String> {
    PrivateKey::from_pem(&secret_read(store, "identity")?)
        .map_err(|_| "本地采集私钥格式无效。".into())
}
fn public_key(key: &PrivateKey) -> Result<String, String> {
    key.public_pem()
}
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("十六进制字段无效".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
pub fn receiver_config(store: &Store) -> Result<ReceiverConfig, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let s: Option<String> = db
        .query_row(
            "SELECT value FROM settings WHERE key='collector_receiver'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    s.map(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        .unwrap_or_else(|| Ok(ReceiverConfig::default()))
}
pub fn configure_receiver(
    store: &Store,
    bind: String,
    callback_url: String,
    running: bool,
) -> Result<ReceiverConfig, String> {
    if running {
        return Err("请先停止接收端，再变更监听地址 / 证书。".into());
    }
    let address: SocketAddr = bind.parse().map_err(|_| "监听地址需为 IP:端口")?;
    if address.port() < 1024 {
        return Err("请使用 1024 以上端口。".into());
    }
    let u = reqwest::Url::parse(&callback_url).map_err(|_| "回传地址无效")?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.path() != "/"
    {
        return Err("回传地址需为 HTTPS 根地址，不得含凭据、路径或查询参数。".into());
    }
    let old = receiver_config(store)?;
    let certificate = if old.callback_url == callback_url.trim_end_matches('/')
        && !old.certificate.is_empty()
    {
        old.certificate
    } else {
        let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![u
            .host_str()
            .unwrap()
            .trim_matches(['[', ']'])
            .to_owned()])
        .map_err(|e| e.to_string())?;
        secret_write(store, "receiver-tls", &signing_key.serialize_pem())?;
        cert.pem()
    };
    let cfg = ReceiverConfig {
        bind,
        callback_url: callback_url.trim_end_matches('/').into(),
        certificate,
    };
    store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .execute(
            "INSERT OR REPLACE INTO settings VALUES('collector_receiver',?1)",
            [serde_json::to_string(&cfg).unwrap()],
        )
        .map_err(|e| e.to_string())?;
    Ok(cfg)
}
pub fn tasks(store: &Store, case: &str) -> Result<Vec<Task>, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut q=db.prepare("SELECT record,enabled,(SELECT count(*) FROM collector_batches b WHERE b.task_id=t.id AND b.state='completed'),(SELECT max(created_at) FROM collector_batches b WHERE b.task_id=t.id AND b.state='completed') FROM collector_tasks t WHERE case_id=?1 ORDER BY rowid DESC LIMIT 100").map_err(|e|e.to_string())?;
    let rows = q
        .query_map([case], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    rows.map(|r| {
        let (s, enabled, batches, last) = r.map_err(|e| e.to_string())?;
        let mut t: Task = serde_json::from_str(&s).map_err(|e| e.to_string())?;
        t.enabled = enabled;
        t.batches = batches;
        t.last_seen = last;
        Ok(t)
    })
    .collect()
}
fn task_token(store: &Store, key: &PrivateKey, id: &str) -> Result<(Task, Vec<u8>), String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let (s, boxed, enabled): (String, String, bool) = db
        .query_row(
            "SELECT record,token_box,enabled FROM collector_tasks WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|_| "任务不存在或凭据无效")?;
    let t: Task = serde_json::from_str(&s).map_err(|e| e.to_string())?;
    if !enabled
        || chrono::DateTime::parse_from_rfc3339(&t.expires_at).map_err(|_| "任务时间无效")?
            <= Utc::now()
    {
        return Err("任务已失效或已撤销。".into());
    }
    let token = key
        .decrypt(
            "gaga-task-token/1",
            &STANDARD.decode(boxed).map_err(|_| "任务凭据无效")?,
        )
        .map_err(|_| "本客户端无法解封任务凭据")?;
    Ok((t, token))
}
pub fn revoke(store: &Store, id: &str) -> Result<(), String> {
    let case = store.active()?;
    let n = store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .execute(
            "UPDATE collector_tasks SET enabled=0 WHERE id=?1 AND case_id=?2",
            params![id, case],
        )
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("任务不属于当前事件".into());
    }
    Ok(())
}
// Debug fixtures retain a convenience wrapper; production passes the case
// captured before the save dialog/keychain wait, never a later active case.
#[cfg(any(test, debug_assertions))]
pub fn generate(
    store: &Store,
    input: TaskInput,
    path: &Path,
    templates: &Path,
) -> Result<Task, String> {
    generate_for_case(store, &store.active()?, input, path, templates)
}
pub fn generate_for_case(
    store: &Store,
    case_id: &str,
    input: TaskInput,
    path: &Path,
    templates: &Path,
) -> Result<Task, String> {
    if input.name.trim().is_empty()
        || input.name.len() > 200
        || input.target.len() > 200
        || !matches!(input.mode.as_str(), "snapshot" | "ebpf")
        || !matches!(
            input.architecture.as_str(),
            "linux-amd64" | "linux-arm64" | "windows-amd64"
        )
        || !(5..=86400).contains(&input.duration_seconds)
        || !(5..=300).contains(&input.batch_seconds)
        || !(128..=4096).contains(&input.snaplen)
        || !(1..=168).contains(&input.hours)
        || input.interface.is_empty()
        || input.interface.len() > 40
        || !input
            .interface
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b':'))
    {
        return Err("任务字段无效；采集 5 秒–24 小时，批次 5–300 秒，截取 128–4096 字节，有效期 1–168 小时。".into());
    }
    if input.mode == "ebpf" && !input.architecture.starts_with("linux-") {
        return Err("eBPF 需要 Linux 目标主机。".into());
    }
    crate::report::validate_output(store, path)?;
    if !path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
    {
        return Err("Agent 任务包需保存为 .zip 文件。".into());
    }
    let exists: bool = store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
            [case_id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !exists {
        return Err("采集任务所属事件不存在，请重新选择事件。".into());
    }
    let executable = if input.architecture.starts_with("windows") {
        format!("gaga-agent-{}.exe", input.architecture)
    } else {
        format!("gaga-agent-{}", input.architecture)
    };
    let binary = templates.join(&executable);
    if !binary.is_file() {
        return Err("安装包缺少对应架构 Agent 模板；请重新构建资源。".into());
    }
    let bytes = fs::read(binary).map_err(|e| e.to_string())?;
    let identity = ensure_identity(store)?;
    let key = private_key(store)?;
    let case = case_id.to_owned();
    let cfg = receiver_config(store)?;
    if input.online && cfg.certificate.is_empty() {
        return Err("请先配置 HTTPS 接收端和证书，或选择离线回收。".into());
    }
    let mut token = [0; 32];
    OsRng.fill_bytes(&mut token);
    let t = Task {
        id: uuid::Uuid::new_v4().to_string(),
        case_id: case.clone(),
        name: input.name,
        target: input.target,
        mode: input.mode,
        architecture: input.architecture,
        interface: input.interface,
        duration_seconds: input.duration_seconds,
        batch_seconds: input.batch_seconds,
        snaplen: input.snaplen,
        include_http: input.include_http,
        created_at: Utc::now().to_rfc3339(),
        expires_at: (Utc::now() + chrono::Duration::hours(input.hours as i64))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        enabled: true,
        client_fingerprint: identity.fingerprint.clone(),
        batches: 0,
        last_seen: None,
    };
    let config = json!({"format":"gaga-task/1","taskId":t.id,"publicKey":identity.public_key,"token":hex(&token),"expiresAt":t.expires_at,"mode":t.mode,"interface":t.interface,"durationSeconds":t.duration_seconds,"batchSeconds":t.batch_seconds,"snaplen":t.snaplen,"includeHttp":t.include_http,"callbackUrl":if input.online{cfg.callback_url.as_str()}else{""},"certificate":if input.online{cfg.certificate.as_str()}else{""},"maxOutputBytes":128*1024*1024});
    let final_name = if t.architecture.starts_with("windows") {
        "gaga-agent.exe"
    } else {
        "gaga-agent"
    };
    let config_bytes = serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?;
    let boxed = key
        .encrypt("gaga-task-token/1", &token)
        .map_err(|e| e.to_string())?;
    let record = serde_json::to_string(&t).map_err(|e| e.to_string())?;
    let mut registered = false;
    let result = crate::file_commit::write_checked(
        path,
        |file| {
            let mut archive = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o755);
            archive
                .start_file(final_name, options)
                .map_err(|e| e.to_string())?;
            archive.write_all(&bytes).map_err(|e| e.to_string())?;
            archive
                .start_file("gaga-task.json", options.unix_permissions(0o600))
                .map_err(|e| e.to_string())?;
            archive
                .write_all(&config_bytes)
                .map_err(|e| e.to_string())?;
            archive
                .start_file("README.txt", options.unix_permissions(0o644))
                .map_err(|e| e.to_string())?;
            archive.write_all(format!("嘎嘎安全助手 · J4team\n任务 {} / {}\n客户端公钥指纹 {}\n目标 {}；有效期 {}\n\n先运行 ./{final_name} -config gaga-task.json -check\n在已授权的目标主机运行 ./{final_name} -config gaga-task.json -out ./gaga-output\nLinux eBPF 需要相应内核 / CAP_BPF 或 CAP_SYS_ADMIN 及 CAP_NET_RAW；本工具不修改权限或 sysctl。\n只采集当前网络命名空间；不解密 TLS、不做 TCP 重组、不关联 PID，不承诺零丢包或完整流量。\n快照为固定只读元数据采集，不是任意远程命令执行。\n输出文件仅含加密包，只有持有原客户端私钥的一端可解密。任务包含任务凭据，应妥善保管；持有凭据并不证明目标主机可信。\n离线包导回原客户端，或使用任务内配置的 HTTPS 地址回传。在线传输校验证书，失败保留离线副本。\n输出上限 128 MiB；达到上限停止。客户端和接收端需要保持运行。\n采集数据解密后在客户端证据库明文保存；此版未提供采集私钥备份 / 恢复 UI，原系统凭据丢失后无法恢复旧包。\n",t.id,t.name,identity.fingerprint,t.target,t.expires_at).as_bytes()).map_err(|e|e.to_string())?;
            archive.finish().map_err(|e| e.to_string())?;
            Ok(())
        },
        || {
            store.db.lock().map_err(|e| e.to_string())?.execute(
            "INSERT INTO collector_tasks(id,case_id,enabled,expires_at,token_box,record) VALUES(?1,?2,1,?3,?4,?5)",
            params![t.id,t.case_id,t.expires_at,STANDARD.encode(&boxed),record],
        ).map_err(|e| e.to_string())?;
            registered = true;
            Ok(())
        },
    );
    if let Err(error) = result {
        if registered {
            let cleanup = store.db.lock().map_err(|e| e.to_string()).and_then(|db| {
                db.execute("DELETE FROM collector_tasks WHERE id=?1", [&t.id])
                    .map_err(|e| e.to_string())
            });
            if let Err(cleanup_error) = cleanup {
                return Err(format!("任务包未提交，任务记录回收失败，请停用该任务并检查工作区：{error}；{cleanup_error}"));
            }
        }
        return Err(error);
    }
    Ok(t)
}
fn open_envelope(key: &PrivateKey, token: &[u8], e: &Envelope) -> Result<Value, String> {
    if e.format != "gaga-envelope/1"
        || e.sequence.len() != 32
        || !e.sequence.bytes().all(|c| c.is_ascii_hexdigit())
        || e.ciphertext.len() > 24 * 1024 * 1024
    {
        return Err("采集包格式、批次或大小无效。".into());
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token).map_err(|_| "任务凭据无效")?;
    mac.update(
        [
            &e.task_id,
            &e.sequence,
            &e.created_at,
            &e.encrypted_key,
            &e.nonce,
            &e.ciphertext,
        ]
        .map(|s| s.as_str())
        .join("\n")
        .as_bytes(),
    );
    mac.verify_slice(&unhex(&e.mac)?)
        .map_err(|_| "任务凭据签名不匹配，已拒绝入库。")?;
    let symmetric = key
        .decrypt(
            "gaga-envelope/1",
            &STANDARD
                .decode(&e.encrypted_key)
                .map_err(|_| "密钥封装无效")?,
        )
        .map_err(|_| "只有原客户端能够解密此包。")?;
    let nonce = STANDARD.decode(&e.nonce).map_err(|_| "随机数无效")?;
    if nonce.len() != 12 {
        return Err("随机数长度无效".into());
    }
    let aad = [&e.task_id, &e.sequence, &e.created_at]
        .map(|s| s.as_str())
        .join("\n");
    let decrypted = Aes256Gcm::new_from_slice(&symmetric)
        .map_err(|_| "内容密钥无效")?
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &STANDARD.decode(&e.ciphertext).map_err(|_| "密文无效")?,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "密文完整性校验失败")?;
    let mut plaintext = Vec::new();
    flate2::read::GzDecoder::new(decrypted.as_slice())
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut plaintext)
        .map_err(|_| "加密内容解压失败")?;
    if plaintext.len() > 16 * 1024 * 1024 {
        return Err("解密内容超过 16 MiB。".into());
    }
    let payload: Value = serde_json::from_slice(&plaintext).map_err(|_| "采集内容 JSON 无效")?;
    if payload["taskId"] != e.task_id || payload["format"] != "gaga-collection/1" {
        return Err("内外任务标识不匹配。".into());
    }
    Ok(payload)
}
pub fn ingest(
    store: &Store,
    app: Option<&tauri::AppHandle>,
    bytes: &[u8],
    http_token: Option<&str>,
) -> Result<Evidence, String> {
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("加密包上限 32 MiB。".into());
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| "采集包 JSON 无效")?;
    let key = private_key(store)?;
    let (task, token) = task_token(store, &key, &envelope.task_id)?;
    if let Some(header) = http_token {
        let mut check = <Hmac<Sha256> as Mac>::new_from_slice(&token).unwrap();
        check.update(b"receiver authorization");
        let expected = check.finalize().into_bytes();
        let supplied = unhex(header)?;
        let mut check =
            <Hmac<Sha256> as Mac>::new_from_slice(&supplied).map_err(|_| "任务凭据无效")?;
        check.update(b"receiver authorization");
        check.verify_slice(&expected).map_err(|_| "接收凭据无效")?;
    }
    let mut payload = open_envelope(&key, &token, &envelope)?;
    if payload["kind"].as_str() != Some(task.mode.as_str()) {
        return Err("采集模式与任务计划不匹配。".into());
    }
    let digest = format!("{:x}", Sha256::digest(bytes));
    let claimed=store.db.lock().map_err(|e|e.to_string())?.execute("INSERT OR IGNORE INTO collector_batches(task_id,sequence,created_at,state,sha256) VALUES(?1,?2,?3,'processing',?4)",params![task.id,envelope.sequence,Utc::now().to_rfc3339(),digest]).map_err(|e|e.to_string())?;
    let mut existing_evidence = None;
    if claimed == 0 {
        let db = store.db.lock().map_err(|e| e.to_string())?;
        let(state,hash,evidence):(String,String,Option<String>)=db.query_row("SELECT state,sha256,evidence_id FROM collector_batches WHERE task_id=?1 AND sequence=?2",params![task.id,envelope.sequence],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|e|e.to_string())?;
        if state == "completed" {
            return Err("duplicate: 该任务批次已接收，拒绝重放。".into());
        }
        if hash != digest || !matches!(state.as_str(), "failed" | "interrupted") {
            return Err("该批次正在处理或摘要不匹配，请保留原加密包稍后重试。".into());
        }
        let n=db.execute("UPDATE collector_batches SET state='processing' WHERE task_id=?1 AND sequence=?2 AND state IN ('failed','interrupted')",params![task.id,envelope.sequence]).map_err(|e|e.to_string())?;
        if n != 1 {
            return Err("批次已被其他接收请求占用。".into());
        }
        existing_evidence = evidence;
    }
    let result = (|| -> Result<Evidence, String> {
        let mut hit_count = 0;
        let mut hits = Vec::new();
        let mut ai_flows = Vec::new();
        if task.mode == "ebpf" {
            let flows = payload["body"]["flows"].as_array().ok_or("缺少流量窗口")?;
            if flows.len() > 2000 {
                return Err("单窗口流数超过 2000。".into());
            }
            let mut cache: std::collections::BTreeMap<String, Value> =
                std::collections::BTreeMap::new();
            for flow in flows {
                for field in ["sourceIp", "destinationIp"] {
                    if let Some(ip) = flow[field].as_str() {
                        let (_, value) = crate::intelligence::normalize("ip", ip)?;
                        let matched = if let Some(v) = cache.get(&value) {
                            v.clone()
                        } else {
                            let v =
                                crate::intelligence::matches(store, "ip", &value, &task.case_id)?;
                            cache.insert(value.clone(), v.clone());
                            v
                        };
                        if matched["allow"] == true
                            || matched["deny"] == true
                            || matches!(
                                matched["knowledge"]["verdict"].as_str(),
                                Some("malicious" | "suspicious")
                            )
                        {
                            hit_count += 1;
                            if hits.len() < 100 {
                                hits.push(json!({"value":value,"match":matched}));
                            }
                        }
                    }
                }
                if ai_flows.len() < 100 {
                    ai_flows.push(flow.clone());
                }
            }
        }
        let summary = if task.mode == "ebpf" {
            format!("目标 {} 流量窗口：{} 个观测包，{} 个聚合流，内核丢包 {}、未解析 {}、省略流量包 {}；名单命中 {} 项。",task.target,payload["body"]["observedPackets"],payload["body"]["flows"].as_array().map_or(0,Vec::len),payload["body"]["kernelDrops"],payload["body"]["unparsedPackets"],payload["body"]["omittedFlowPackets"],hit_count)
        } else {
            format!("目标 {} 的只读元数据快照已通过加密完整性和任务凭据校验，采集范围受权限与工具可用性影响。",task.target)
        };
        payload["summary"] = json!(summary);
        payload["verification"] = json!({"recipientFingerprint":task.client_fingerprint,"taskCredentialVerified":true,"sourceHostIndependentlyVerified":false,"ciphertextSha256":format!("{:x}",Sha256::digest(bytes)),"sequence":envelope.sequence});
        payload["listMatches"] = json!(hits);
        let e = if let Some(id) = &existing_evidence {
            store.evidence_for_case(&task.case_id, id)?
        } else {
            let e = store.archive_record(&task.case_id, "Agent采集", &payload)?;
            store
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .execute(
                    "UPDATE collector_batches SET evidence_id=?3 WHERE task_id=?1 AND sequence=?2",
                    params![task.id, envelope.sequence, e.id],
                )
                .map_err(|e| e.to_string())?;
            e
        };
        persist_inbox_package(store, &task.id, &envelope.sequence, bytes)?;
        if task.mode == "ebpf" {
            let record = json!({"id":envelope.sequence,"taskId":task.id,"target":task.target,"createdAt":envelope.created_at,"evidenceId":e.id,"observedPackets":payload["body"]["observedPackets"],"kernelDrops":payload["body"]["kernelDrops"],"unparsedPackets":payload["body"]["unparsedPackets"],"omittedFlowPackets":payload["body"]["omittedFlowPackets"],"flowCount":payload["body"]["flows"].as_array().map_or(0,Vec::len),"listHitCount":hit_count,"flows":ai_flows,"listMatches":hits});
            store.db.lock().map_err(|e|e.to_string())?.execute("INSERT OR IGNORE INTO flow_windows(id,case_id,task_id,created_at,evidence_id,record) VALUES(?1,?2,?3,?4,?5,?6)",params![envelope.sequence,task.case_id,task.id,Utc::now().to_rfc3339(),e.id,serde_json::to_string(&record).unwrap()]).map_err(|e|e.to_string())?;
            if !has_observation(store, &e.id, &task.mode)? {
                crate::monitoring::record_observation(
                    store,
                    "ebpf",
                    task.name.clone(),
                    summary,
                    &e,
                    record,
                )?;
            }
        } else {
            if !has_observation(store, &e.id, &task.mode)? {
                crate::monitoring::record_observation(
                    store,
                    "snapshot",
                    task.name.clone(),
                    summary,
                    &e,
                    json!({"taskId":task.id,"hostname":payload["hostname"],"os":payload["os"],"architecture":payload["architecture"],"commands":payload["body"]["commands"].as_array().map(|items|items.iter().map(|i|json!({"command":i["command"],"error":i["error"],"truncated":i["truncated"]})).collect::<Vec<_>>()),"notice":"自动 AI 仅发送元数据摘要，不含文件与完整命令输出。"}),
                )?;
            }
        }
        Ok(e)
    })();
    match &result {
        Ok(e) => {
            store.db.lock().map_err(|e|e.to_string())?.execute("UPDATE collector_batches SET state='completed',evidence_id=?3 WHERE task_id=?1 AND sequence=?2",params![task.id,envelope.sequence,e.id]).map_err(|e|e.to_string())?;
            if let Some(app) = app {
                let _ = app.emit(
                    "platform-updated",
                    json!({"caseId":task.case_id,"kind":task.mode}),
                );
            }
        }
        Err(_) => {
            let _=store.db.lock().map_err(|e|e.to_string())?.execute("UPDATE collector_batches SET state='failed' WHERE task_id=?1 AND sequence=?2 AND state='processing'",params![task.id,envelope.sequence]);
        }
    }
    result
}
fn has_observation(store: &Store, evidence: &str, kind: &str) -> Result<bool, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let count: u64 = db
        .query_row(
            "SELECT count(*) FROM monitor_observations WHERE evidence_id=?1 AND kind=?2",
            params![evidence, kind],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(count > 0)
}
pub fn flow_windows(store: &Store, case: &str) -> Result<Vec<Value>, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut q = db
        .prepare(
            "SELECT record FROM flow_windows WHERE case_id=?1 ORDER BY created_at DESC LIMIT 100",
        )
        .map_err(|e| e.to_string())?;
    let rows = q
        .query_map([case], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    rows.map(|r| serde_json::from_str(&r.map_err(|e| e.to_string())?).map_err(|e| e.to_string()))
        .collect()
}
fn request(stream: &mut impl Read) -> Result<(String, String, Vec<u8>), String> {
    let mut header = Vec::new();
    let mut byte = [0];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 8192 {
            return Err("请求头超过限制".into());
        }
        stream
            .read_exact(&mut byte)
            .map_err(|e| format!("读取请求失败：{e}"))?;
        header.push(byte[0]);
    }
    let header = String::from_utf8(header).map_err(|_| "请求头无效")?;
    let mut lines = header.lines();
    let first = lines.next().ok_or("请求无效")?;
    let parts: Vec<_> = first.split_whitespace().collect();
    if parts.len() != 3 || parts[0] != "POST" || !parts[1].starts_with("/v1/collect/") {
        return Err("只接受采集 POST 请求。".into());
    }
    let id = parts[1].strip_prefix("/v1/collect/").unwrap().to_string();
    uuid::Uuid::parse_str(&id).map_err(|_| "任务路径无效")?;
    let mut length = None;
    let mut token = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            match name.to_ascii_lowercase().as_str() {
                "content-length" => {
                    if length.is_some() {
                        return Err("重复长度字段".into());
                    }
                    length = Some(value.trim().parse::<usize>().map_err(|_| "长度无效")?);
                }
                "authorization" => {
                    if token.is_some() {
                        return Err("重复认证字段".into());
                    }
                    token = value.trim().strip_prefix("Bearer ").map(str::to_string);
                }
                "transfer-encoding" => return Err("不支持分块上传".into()),
                _ => (),
            }
        }
    }
    let size = length.ok_or("需要 Content-Length")?;
    if size > 32 * 1024 * 1024 {
        return Err("加密包过大".into());
    }
    let token = token.ok_or("需要任务凭据")?;
    if token.len() != 64 {
        return Err("任务凭据无效".into());
    }
    let mut body = vec![0; size];
    stream.read_exact(&mut body).map_err(|_| "请求正文不完整")?;
    let e: Envelope = serde_json::from_slice(&body).map_err(|_| "包格式无效")?;
    if e.task_id != id {
        return Err("任务路径不匹配".into());
    }
    Ok((id, token, body))
}
pub fn start_receiver(
    store: Arc<Store>,
    app: tauri::AppHandle,
    runtime: Arc<Receiver>,
) -> Result<String, String> {
    if runtime.running.swap(true, Ordering::SeqCst) {
        return Err("接收端已在运行".into());
    }
    let result = (|| -> Result<String, String> {
        let cfg = receiver_config(&store)?;
        if cfg.certificate.is_empty() {
            return Err("请先保存 HTTPS 接收配置。".into());
        }
        use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
        let certs = CertificateDer::pem_slice_iter(cfg.certificate.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let key = PrivateKeyDer::from_pem_slice(secret_read(&store, "receiver-tls")?.as_bytes())
            .map_err(|e| e.to_string())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| e.to_string())?;
        let tls = Arc::new(tls);
        let listener = TcpListener::bind(&cfg.bind).map_err(|e| format!("HTTPS 监听失败：{e}"))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        *runtime.stop.lock().map_err(|e| e.to_string())? = Some(stop.clone());
        let runtime = runtime.clone();
        let connections = Arc::new(AtomicUsize::new(0));
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        // BSD/macOS may inherit O_NONBLOCK from the listening socket.
                        if socket.set_nonblocking(false).is_err() {
                            continue;
                        }
                        if !try_acquire_connection_slot(&connections, 4) {
                            drop(socket);
                            continue;
                        }
                        let tls = tls.clone();
                        let store = store.clone();
                        let app = app.clone();
                        let connections = connections.clone();
                        std::thread::spawn(move || {
                            let socket = crate::connection::DeadlineSocket::new(
                                socket,
                                Duration::from_secs(90),
                                Duration::from_secs(15),
                            );
                            if let Ok(session) = rustls::ServerConnection::new(tls) {
                                let mut stream = rustls::StreamOwned::new(session, socket);
                                let result = request(&mut stream).and_then(|(_, token, body)| {
                                    ingest(&store, Some(&app), &body, Some(&token))
                                });
                                if let Err(error) = &result {
                                    crate::runtime_log::event(
                                        "error",
                                        "collector",
                                        "UPLOAD_REJECTED",
                                        error,
                                        None,
                                    );
                                    eprintln!("GAGA_COLLECTOR_REJECTED: {error}");
                                }
                                let status = match result {
                                    Ok(_) => "202 Accepted",
                                    Err(e) if e.starts_with("duplicate:") => "409 Conflict",
                                    Err(_) => "400 Bad Request",
                                };
                                let _=write!(stream,"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                                let _ = stream.flush();
                                stream.conn.send_close_notify();
                                let _ = stream.flush();
                            }
                            connections.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(80))
                    }
                    Err(_) => break,
                }
            }
            runtime.running.store(false, Ordering::SeqCst);
        });
        Ok(cfg.bind)
    })();
    if result.is_err() {
        runtime.running.store(false, Ordering::SeqCst);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Store, Vec<u8>) {
        let store = Store::open(
            std::env::temp_dir().join(format!("gaga-crypto-test-{}", uuid::Uuid::new_v4())),
        )
        .unwrap();
        let private = include_str!("../../fixtures/agent-interop/test-only-private.pem");
        secret_write(&store, "identity", private).unwrap();
        let key = private_key(&store).unwrap();
        let public = public_key(&key).unwrap();
        let identity = Identity {
            id: "test-only-fixture".into(),
            fingerprint: format!("{:x}", Sha256::digest(public.as_bytes())),
            public_key: public,
        };
        store
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO settings VALUES('collector_identity',?1)",
                [serde_json::to_string(&identity).unwrap()],
            )
            .unwrap();
        let task = Task {
            id: "37b6d5e5-4e54-42c2-a1b3-3ae109733d2f".into(),
            case_id: store.active().unwrap(),
            name: "test-only-task".into(),
            target: "localhost fixture".into(),
            mode: "snapshot".into(),
            architecture: "linux-amd64".into(),
            interface: "any".into(),
            duration_seconds: 60,
            batch_seconds: 5,
            snaplen: 512,
            include_http: false,
            expires_at: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            created_at: Utc::now().to_rfc3339(),
            enabled: true,
            client_fingerprint: identity.fingerprint,
            batches: 0,
            last_seen: None,
        };
        let boxed = key.encrypt("gaga-task-token/1", &[7; 32]).unwrap();
        store
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO collector_tasks VALUES(?1,?2,1,?3,?4,?5)",
                params![
                    task.id,
                    task.case_id,
                    task.expires_at,
                    STANDARD.encode(boxed),
                    serde_json::to_string(&task).unwrap()
                ],
            )
            .unwrap();
        (
            store,
            include_bytes!("../../fixtures/agent-interop/envelope.json").to_vec(),
        )
    }
    #[test]
    fn go_envelope_decrypts_once_and_rejects_tampering_wrong_client_and_revocation() {
        let (store, bytes) = fixture();
        let envelope: Envelope = serde_json::from_slice(&bytes).unwrap();
        let key = private_key(&store).unwrap();
        let value = open_envelope(&key, &[7; 32], &envelope).unwrap();
        assert!(value["body"]["fixture"]
            .as_str()
            .unwrap()
            .contains("Go-generated"));
        let mut tampered: Envelope = serde_json::from_slice(&bytes).unwrap();
        tampered.created_at.push('x');
        assert!(open_envelope(&key, &[7; 32], &tampered).is_err());
        assert!(open_envelope(&key, &[8; 32], &envelope).is_err());
        let wrong = PrivateKey::generate().unwrap();
        assert!(open_envelope(&wrong, &[7; 32], &envelope).is_err());
        assert!(ingest(&store, None, &bytes, Some(&hex(&[8; 32]))).is_err());
        let e = ingest(&store, None, &bytes, Some(&hex(&[7; 32]))).unwrap();
        assert!(store.root.join("evidence").join(e.id).exists());
        assert!(ingest(&store, None, &bytes, None)
            .err()
            .unwrap()
            .starts_with("duplicate:"));
        store
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE collector_batches SET state='interrupted' WHERE task_id=?1",
                [&envelope.task_id],
            )
            .unwrap();
        let recovered = ingest(&store, None, &bytes, None).unwrap();
        assert_eq!(store.workspace().unwrap().evidence.len(), 1);
        assert!(!recovered.id.is_empty());
        assert_eq!(
            crate::monitoring::observations(&store, &store.active().unwrap())
                .unwrap()
                .len(),
            1
        );
        revoke(&store, &envelope.task_id).unwrap();
        assert!(ingest(&store, None, &bytes, None)
            .err()
            .unwrap()
            .contains("失效"));
        std::fs::remove_dir_all(&store.root).unwrap();
    }
    #[test]
    fn malformed_receive_headers_are_bounded() {
        let id = "37b6d5e5-4e54-42c2-a1b3-3ae109733d2f";
        let header=format!("POST /v1/collect/{id} HTTP/1.1\r\nContent-Length: 40000000\r\nAuthorization: Bearer {}\r\n\r\n",hex(&[7;32]));
        assert!(request(&mut header.as_bytes())
            .err()
            .unwrap()
            .contains("过大"));
        let duplicate = format!(
            "POST /v1/collect/{id} HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"
        );
        assert!(request(&mut duplicate.as_bytes())
            .err()
            .unwrap()
            .contains("重复"));
    }

    #[test]
    fn receiver_connection_slots_remain_bounded_under_contention() {
        let slots = Arc::new(AtomicUsize::new(0));
        let acquired = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(33));
        let workers: Vec<_> = (0..32)
            .map(|_| {
                let slots = slots.clone();
                let acquired = acquired.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let owns_slot = try_acquire_connection_slot(&slots, 4);
                    if owns_slot {
                        acquired.fetch_add(1, Ordering::Relaxed);
                    }
                    barrier.wait();
                    if owns_slot {
                        slots.fetch_sub(1, Ordering::Release);
                    }
                })
            })
            .collect();
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(acquired.load(Ordering::Relaxed), 4);
        assert_eq!(slots.load(Ordering::Acquire), 0);
    }

    #[cfg(unix)]
    #[test]
    fn collector_inbox_rejects_links_and_supports_same_sequence_retry() {
        let (store, _) = fixture();
        let dir = store.root.join("collector-inbox");
        fs::create_dir_all(&dir).unwrap();
        let outside = store.root.with_extension("collector-outside");
        fs::write(&outside, b"must remain untouched").unwrap();
        let target = dir.join("task-sequence.encrypted.json");
        std::os::unix::fs::symlink(&outside, &target).unwrap();
        assert!(
            persist_inbox_package(&store, "task", "sequence", b"blocked")
                .unwrap_err()
                .contains("普通文件")
        );
        assert_eq!(fs::read(&outside).unwrap(), b"must remain untouched");
        fs::remove_file(&target).unwrap();
        persist_inbox_package(&store, "task", "sequence", b"first").unwrap();
        persist_inbox_package(&store, "task", "sequence", b"retry").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"retry");
        drop(store);
        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }
    #[test]
    fn package_failures_preserve_previous_output_and_do_not_leave_registered_tasks() {
        let (store, _) = fixture();
        let templates = store.root.join("templates");
        fs::create_dir(&templates).unwrap();
        fs::write(
            templates.join("gaga-agent-linux-amd64"),
            b"inert fixture, never executed",
        )
        .unwrap();
        let input = TaskInput {
            name: "fixture".into(),
            target: "test".into(),
            mode: "snapshot".into(),
            architecture: "linux-amd64".into(),
            interface: "any".into(),
            duration_seconds: 60,
            batch_seconds: 5,
            snaplen: 512,
            include_http: false,
            hours: 1,
            online: false,
        };
        let count = || {
            store
                .db
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM collector_tasks", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap()
        };
        let baseline = count();
        let path = store.root.join("old-package.zip");
        fs::write(&path, b"previous package").unwrap();
        store.db.lock().unwrap().execute_batch("CREATE TRIGGER reject_test_task BEFORE INSERT ON collector_tasks BEGIN SELECT RAISE(ABORT,'synthetic database failure'); END;").unwrap();
        assert!(generate(&store, input.clone(), &path, &templates)
            .err()
            .unwrap()
            .contains("synthetic database failure"));
        assert_eq!(fs::read(&path).unwrap(), b"previous package");
        assert_eq!(count(), baseline);
        store
            .db
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_test_task;")
            .unwrap();
        let directory = store.root.join("directory.zip");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("canary"), b"preserved directory").unwrap();
        assert!(generate(&store, input.clone(), &directory, &templates).is_err());
        assert_eq!(
            count(),
            baseline,
            "Failed file commit must compensate task registration"
        );
        assert_eq!(
            fs::read(directory.join("canary")).unwrap(),
            b"preserved directory"
        );
        for folder in ["evidence", "migration-backups"] {
            fs::create_dir_all(store.root.join(folder)).unwrap();
            let target = store.root.join(folder).join("internal.zip");
            fs::write(&target, b"internal evidence").unwrap();
            assert!(generate(&store, input.clone(), &target, &templates).is_err());
            assert_eq!(fs::read(target).unwrap(), b"internal evidence");
        }
        assert!(!fs::read_dir(&store.root).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".partial")));
        let a = store.active().unwrap();
        let b = store.create_case("Other case".into()).unwrap();
        let task = generate_for_case(&store, &a, input.clone(), &path, &templates).unwrap();
        assert_eq!(task.case_id, a);
        assert_eq!(store.active().unwrap(), b.id);
        assert_eq!(count(), baseline + 1);
        assert!(generate_for_case(&store, "missing-case", input, &path, &templates).is_err());
        drop(store);
        // Store's workspace lock must close before deleting the directory on Windows.
        let root = path.parent().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn package_contains_public_key_and_task_credential_but_no_private_key() {
        let (store, _) = fixture();
        let templates = store.root.join("templates");
        fs::create_dir(&templates).unwrap();
        fs::write(
            templates.join("gaga-agent-linux-amd64"),
            b"test-placeholder-not-executed",
        )
        .unwrap();
        let input = TaskInput {
            name: "fixture".into(),
            target: "test".into(),
            mode: "ebpf".into(),
            architecture: "linux-amd64".into(),
            interface: "any".into(),
            duration_seconds: 60,
            batch_seconds: 5,
            snaplen: 512,
            include_http: false,
            hours: 1,
            online: false,
        };
        let path = store.root.join("task.zip");
        let task = generate(&store, input, &path, &templates).unwrap();
        let mut zip = zip::ZipArchive::new(fs::File::open(path).unwrap()).unwrap();
        let mut config = String::new();
        zip.by_name("gaga-task.json")
            .unwrap()
            .read_to_string(&mut config)
            .unwrap();
        assert!(!config.contains("PRIVATE KEY"));
        let cfg: Value = serde_json::from_str(&config).unwrap();
        assert_eq!(cfg["taskId"], task.id);
        assert_eq!(cfg["token"].as_str().unwrap().len(), 64);
        assert_eq!(cfg["callbackUrl"], "");
        std::fs::remove_dir_all(&store.root).unwrap();
    }
}
