//! Optional, read-only enrichment. Remote verdicts never mutate analyst IOC
//! classifications. Jobs retain their event, query scope and source timestamp;
//! no lookup failure can cause an upload, rescan, sample download or report.
use crate::{
    intelligence,
    store::{Evidence, Store},
};
use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tauri::{Emitter, State};

const CONFIG: &str = "ti_config_v1";
const LIMIT: usize = 2 * 1024 * 1024;
const IDS: [&str; 4] = ["threatbook", "rdap", "abuseipdb", "virustotal"];
static CONFIG_GUARD: Mutex<()> = Mutex::new(());
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    pub id: String,
    pub enabled: bool,
    pub has_key: bool,
    pub authorized: bool,
    pub revision: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub locked: bool,
    pub providers: Vec<Provider>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            locked: true,
            providers: IDS
                .iter()
                .map(|id| Provider {
                    id: id.to_string(),
                    enabled: false,
                    has_key: false,
                    authorized: false,
                    revision: uuid::Uuid::new_v4().to_string(),
                })
                .collect(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub id: String,
    pub case_id: String,
    pub source_evidence_id: Option<String>,
    pub provider: String,
    pub operation: String,
    pub kind: String,
    pub indicator: String,
    pub config_revision: String,
    pub current_only: bool,
    pub created_at: String,
    pub state: String,
    pub outcome: String,
    pub message: String,
    pub fetched_at: Option<String>,
    pub source_url: String,
    pub source_job_id: Option<String>,
    pub result: Option<Value>,
    pub result_sha256: Option<String>,
    pub result_evidence_id: Option<String>,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Query {
    pub case_id: String,
    pub evidence_id: Option<String>,
    pub provider: String,
    pub operation: String,
    pub kind: String,
    pub indicators: Vec<String>,
    pub current_only: bool,
    pub fresh: bool,
    pub consent: bool,
}
fn db_error(_: impl std::fmt::Display) -> String {
    "TI-STORAGE：情报记录读写失败，请检查数据与维护。".into()
}
pub fn init(store: &Store) -> Result<(), String> {
    store.db.lock().map_err(db_error)?.execute_batch(
        "CREATE TABLE IF NOT EXISTS enrichment_jobs(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),record TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS enrichment_case ON enrichment_jobs(case_id);
        UPDATE enrichment_jobs SET record=json_set(record,'$.state','interrupted','$.message','上次退出时查询未完成，未自动重试。') WHERE json_extract(record,'$.state') IN ('queued','running');"
    ).map_err(db_error)
}
fn config(store: &Store) -> Result<Config, String> {
    let raw: Option<String> = store
        .db
        .lock()
        .map_err(db_error)?
        .query_row("SELECT value FROM settings WHERE key=?1", [CONFIG], |r| {
            r.get(0)
        })
        .optional()
        .map_err(db_error)?;
    let cfg: Config = raw
        .map(|s| {
            serde_json::from_str(&s)
                .map_err(|_| "TI-CONFIG：情报设置损坏，外发已阻止。".to_string())
        })
        .unwrap_or_else(|| Ok(Config::default()))?;
    if cfg.providers.len() != IDS.len()
        || IDS
            .iter()
            .any(|id| cfg.providers.iter().filter(|p| p.id == *id).count() != 1)
    {
        return Err("TI-CONFIG：服务配置无效，外发已阻止。".into());
    }
    Ok(cfg)
}
fn write_config(store: &Store, cfg: &Config) -> Result<(), String> {
    store
        .db
        .lock()
        .map_err(db_error)?
        .execute(
            "INSERT OR REPLACE INTO settings VALUES(?1,?2)",
            params![CONFIG, serde_json::to_string(cfg).map_err(db_error)?],
        )
        .map_err(db_error)?;
    Ok(())
}
fn provider(store: &Store, id: &str) -> Result<Provider, String> {
    let cfg = config(store)?;
    if cfg.locked {
        return Err("TI-LOCKED：情报外发已锁定，请在设置 → 情报服务中解锁。".into());
    }
    let p = cfg
        .providers
        .into_iter()
        .find(|p| p.id == id)
        .ok_or("TI-PROVIDER：不支持的服务。")?;
    if !p.enabled || !p.authorized {
        return Err("TI-DISABLED：请先确认服务授权并启用此服务。".into());
    }
    if id != "rdap" && !p.has_key {
        return Err("TI-KEY：此服务尚未配置系统凭据。".into());
    }
    Ok(p)
}
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn credential(store: &Store, id: &str) -> Result<keyring::Entry, String> {
    // Workspace-specific entry: importing somebody else's database does not
    // grant access to their account, and keys are absent from SQLite/backups.
    let account = format!(
        "{:x}-{id}",
        Sha256::digest(store.root.to_string_lossy().as_bytes())
    );
    keyring::Entry::new("team.j4.gaga-assistant.threat-intel", &account)
        .map_err(|_| "TI-KEYSTORE：系统凭据服务不可用。".into())
}
#[tauri::command]
pub fn get_intel_config(store: State<'_, Arc<Store>>) -> Result<Config, String> {
    config(&store)
}
#[tauri::command]
pub async fn save_intel_provider(
    app: tauri::AppHandle,
    store: State<'_, Arc<Store>>,
    id: String,
    enabled: bool,
    authorized: bool,
    api_key: String,
    remove_key: bool,
) -> Result<Config, String> {
    let store = store.inner().clone();
    let cfg = tauri::async_runtime::spawn_blocking(move || {
        save_provider(&store, &id, enabled, authorized, &api_key, remove_key)
    })
    .await
    .map_err(|_| "TI-KEYSTORE：凭据保存任务失败。")??;
    let _ = app.emit("intel-config-changed", ());
    Ok(cfg)
}
fn save_provider(
    store: &Store,
    id: &str,
    enabled: bool,
    authorized: bool,
    key: &str,
    remove_key: bool,
) -> Result<Config, String> {
    if !IDS.contains(&id) || key.len() > 4096 || key.chars().any(char::is_control) {
        return Err("TI-CONFIG：服务或密钥格式无效。".into());
    }
    if enabled && !authorized {
        return Err("TI-AUTHORIZATION：启用前需确认使用、保存和报告引用的授权。".into());
    }
    if id == "rdap" && !key.is_empty() {
        return Err("RDAP 无需密钥。".into());
    }
    let mut cfg = config(store)?;
    let p = cfg
        .providers
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or("TI-PROVIDER：服务不存在。")?;
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    if id != "rdap" {
        if remove_key {
            match credential(store, id)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(_) => return Err("TI-KEYSTORE：删除凭据失败。".into()),
            }
            p.has_key = false;
        } else if !key.trim().is_empty() {
            credential(store, id)?
                .set_password(key.trim())
                .map_err(|_| "TI-KEYSTORE：保存凭据失败，密钥未写入数据库。")?;
            p.has_key = true;
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    if !key.is_empty() {
        return Err("TI-KEYSTORE：当前系统尚未接入凭据库。".into());
    }
    let has_key = p.has_key;
    // Keychain authorization may take time. Re-read under a short config lock
    // so saving a provider cannot undo a lock set while the dialog was open.
    let _guard = CONFIG_GUARD.lock().map_err(db_error)?;
    let mut latest = config(store)?;
    let p = latest
        .providers
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or("TI-PROVIDER：服务不存在。")?;
    p.has_key = has_key;
    p.enabled = enabled;
    p.authorized = authorized;
    p.revision = uuid::Uuid::new_v4().to_string();
    write_config(store, &latest)?;
    Ok(latest)
}
#[tauri::command]
pub fn set_intel_lock(
    app: tauri::AppHandle,
    store: State<'_, Arc<Store>>,
    locked: bool,
) -> Result<Config, String> {
    let _guard = CONFIG_GUARD.lock().map_err(db_error)?;
    let mut cfg = config(&store)?;
    cfg.locked = locked;
    write_config(&store, &cfg)?;
    if locked {
        store.db.lock().map_err(db_error)?.execute("UPDATE enrichment_jobs SET record=json_set(record,'$.state','cancelled','$.message','情报外发锁定；已发送的数据不能撤回。') WHERE json_extract(record,'$.state') IN ('queued','running')", []).map_err(db_error)?;
    }
    let _ = app.emit("intel-config-changed", ());
    Ok(cfg)
}
fn ensure_case(store: &Store, case: &str) -> Result<(), String> {
    if store.active()? != case {
        Err("TI-CASE：事件已切换，请在当前事件重新操作。".into())
    } else {
        Ok(())
    }
}
fn jobs(store: &Store, case: &str) -> Result<Vec<Job>, String> {
    let db = store.db.lock().map_err(db_error)?;
    let mut stmt = db.prepare("SELECT json_remove(record,'$.result') FROM enrichment_jobs WHERE case_id=?1 ORDER BY json_extract(record,'$.createdAt') DESC,id DESC LIMIT 200").map_err(db_error)?;
    let rows = stmt
        .query_map([case], |r| r.get::<_, String>(0))
        .map_err(db_error)?;
    rows.map(|r| serde_json::from_str(&r.map_err(db_error)?).map_err(db_error))
        .collect()
}
fn get_job(store: &Store, id: &str) -> Result<Job, String> {
    let raw: String = store
        .db
        .lock()
        .map_err(db_error)?
        .query_row(
            "SELECT record FROM enrichment_jobs WHERE id=?1",
            [id],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    serde_json::from_str(&raw).map_err(db_error)
}
#[cfg(test)]
fn put(store: &Store, j: &Job) -> Result<(), String> {
    store
        .db
        .lock()
        .map_err(db_error)?
        .execute(
            "INSERT INTO enrichment_jobs VALUES(?1,?2,?3)",
            params![j.id, j.case_id, serde_json::to_string(j).map_err(db_error)?],
        )
        .map_err(db_error)?;
    Ok(())
}
// Conditional update is essential: a late response cannot undo cancellation or
// overwrite the immutable evidence pointer after the user has cited a result.
fn update_active(store: &Store, j: &Job) -> Result<(), String> {
    store.db.lock().map_err(db_error)?.execute("UPDATE enrichment_jobs SET record=?1 WHERE id=?2 AND json_extract(record,'$.state') IN ('queued','running')", params![serde_json::to_string(j).map_err(db_error)?, j.id]).map_err(db_error)?;
    Ok(())
}
#[tauri::command]
pub fn get_intel_jobs(store: State<'_, Arc<Store>>, case_id: String) -> Result<Vec<Job>, String> {
    ensure_case(&store, &case_id)?;
    jobs(&store, &case_id)
}
#[tauri::command]
pub fn get_intel_job(
    store: State<'_, Arc<Store>>,
    case_id: String,
    id: String,
) -> Result<Job, String> {
    ensure_case(&store, &case_id)?;
    let j = get_job(&store, &id)?;
    if j.case_id != case_id {
        return Err("TI-CASE：情报不属于当前事件。".into());
    }
    Ok(j)
}
#[tauri::command]
pub fn cancel_intel_job(store: State<'_, Arc<Store>>, id: String) -> Result<(), String> {
    let _guard = CONFIG_GUARD.lock().map_err(db_error)?;
    let mut j = get_job(&store, &id)?;
    ensure_case(&store, &j.case_id)?;
    j.state = "cancelled".into();
    j.message = "已取消后续处理；已发送的数据不能撤回。".into();
    update_active(&store, &j)
}
fn live(store: &Store, j: &Job) -> bool {
    get_job(store, &j.id).is_ok_and(|s| matches!(s.state.as_str(), "queued" | "running"))
}
fn ensure_dispatch_allowed(store: &Store, j: &Job) -> Result<(), String> {
    if !live(store, j) {
        return Err("TI-CANCELLED：查询已终止，未发送后续请求。".into());
    }
    if provider(store, &j.provider)?.revision != j.config_revision {
        return Err("TI-CONFIG-CHANGED：服务配置已变更，未发送后续请求。".into());
    }
    Ok(())
}
// IPv4-mapped IPv6 is checked as IPv4, so ::ffff:127.0.0.1 cannot bypass
// either IOC egress filtering or RDAP endpoint/DNS validation.
fn public_ip(ip: IpAddr) -> bool {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return public_ip(IpAddr::V4(v4));
        }
    }
    let forbidden = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3",
        "::/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ];
    if forbidden
        .iter()
        .any(|cidr| cidr.parse::<ipnet::IpNet>().is_ok_and(|n| n.contains(&ip)))
    {
        return false;
    }
    !matches!(ip, IpAddr::V6(v) if !(v.segments()[0] & 0xe000 == 0x2000))
}
fn normalize(kind: &str, input: &str) -> Result<(String, String), String> {
    let (k, v) =
        intelligence::normalize(kind, input).map_err(|_| "指标格式不正确。".to_string())?;
    match k.as_str() {
        "ip" if !v.parse::<IpAddr>().is_ok_and(public_ip) => {
            return Err("私网、回环、链路本地或保留地址未外发。".into())
        }
        "domain" => {
            if [
                "localhost",
                "local",
                "internal",
                "lan",
                "home",
                "test",
                "invalid",
                "example",
                "onion",
            ]
            .iter()
            .any(|s| v == *s || v.ends_with(&format!(".{s}")))
                || ["example.com", "example.net", "example.org", "home.arpa"]
                    .iter()
                    .any(|s| v == *s || v.ends_with(&format!(".{s}")))
            {
                return Err("本地、测试或特殊用途域名未外发。".into());
            }
        }
        "ip" | "md5" | "sha1" | "sha256" => {}
        _ => return Err("首批只查询公网 IP、域名与文件 Hash；不发送完整 URL 或样本。".into()),
    }
    Ok((k, v))
}
fn supported(p: &str, op: &str, kind: &str) -> bool {
    match (p, op) {
        ("threatbook", "inbound" | "ip_context") => kind == "ip",
        ("threatbook", "outbound") => matches!(kind, "ip" | "domain"),
        ("threatbook", "domain_context") | ("rdap", "registration") => kind == "domain",
        ("threatbook", "hash") | ("virustotal", "hash") => {
            matches!(kind, "md5" | "sha1" | "sha256")
        }
        ("abuseipdb", "reports") => kind == "ip",
        _ => false,
    }
}
fn cached(store: &Store, j: &Job) -> Result<Option<Job>, String> {
    let db = store.db.lock().map_err(db_error)?;
    let mut s = db.prepare("SELECT record FROM enrichment_jobs WHERE case_id=?1 AND json_extract(record,'$.provider')=?2 AND json_extract(record,'$.indicator')=?3 AND json_extract(record,'$.operation')=?4 AND json_extract(record,'$.configRevision')=?5 AND json_extract(record,'$.currentOnly')=?6 AND json_extract(record,'$.state')='completed' AND json_extract(record,'$.sourceJobId') IS NULL ORDER BY json_extract(record,'$.fetchedAt') DESC LIMIT 1").map_err(db_error)?;
    let raw: Option<String> = s
        .query_row(
            params![
                j.case_id,
                j.provider,
                j.indicator,
                j.operation,
                j.config_revision,
                j.current_only
            ],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?;
    let old = raw
        .map(|s| serde_json::from_str::<Job>(&s).map_err(db_error))
        .transpose()?;
    Ok(old.filter(|s| {
        let age = s
            .fetched_at
            .as_ref()
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|t| Utc::now().signed_duration_since(t).num_seconds());
        matches!(s.outcome.as_str(), "data" | "no_data")
            && age.is_some_and(|a| (0..3600).contains(&a))
    }))
}
#[tauri::command]
pub async fn start_intel_query(
    app: tauri::AppHandle,
    store: State<'_, Arc<Store>>,
    query: Query,
) -> Result<Vec<Job>, String> {
    let store = store.inner().clone();
    let created = prepare(&store, query)?;
    let queued: Vec<Job> = created
        .iter()
        .filter(|j| j.state == "queued")
        .cloned()
        .collect();
    if !queued.is_empty() {
        tauri::async_runtime::spawn(async move {
            let mut stop_reason: Option<String> = None;
            for job in queued {
                if let Some(reason) = &stop_reason {
                    let mut stopped = job;
                    stopped.state = "cancelled".into();
                    stopped.message = format!("本批后续查询已停止：{reason}；未自动重试。");
                    let _ = update_active(&store, &stopped);
                    continue;
                }
                if let Err(error) = run(&store, job.clone()).await {
                    stop_reason = Some(error.clone());
                    let mut failed = job;
                    failed.state = "failed".into();
                    failed.message = error;
                    crate::runtime_log::event(
                        "warn",
                        "threat-intelligence",
                        "TI_QUERY_FAILED",
                        &failed.message,
                        None,
                    );
                    let _ = update_active(&store, &failed);
                } else if let Ok(done) = get_job(&store, &job.id) {
                    if matches!(
                        done.outcome.as_str(),
                        "quota" | "forbidden" | "unauthorized" | "ip_not_bound" | "expired"
                    ) {
                        crate::runtime_log::event(
                            "warn",
                            "threat-intelligence",
                            "TI_PROVIDER_REJECTED",
                            &done.message,
                            None,
                        );
                        stop_reason = Some(done.message);
                    }
                }
                let _ = app.emit("intel-jobs-changed", ());
            }
        });
    }
    Ok(created
        .into_iter()
        .map(|mut j| {
            j.result = None;
            j
        })
        .collect())
}
fn prepare(store: &Store, q: Query) -> Result<Vec<Job>, String> {
    ensure_case(store, &q.case_id)?;
    if !q.consent {
        return Err("TI-CONSENT：请确认所选指标可发送给此服务。".into());
    }
    if q.indicators.is_empty()
        || q.indicators.len() > 20
        || q.indicators.iter().any(|s| s.len() > 4096)
    {
        return Err("TI-LIMIT：每批需要 1–20 个指标。".into());
    }
    if let Some(id) = &q.evidence_id {
        store.evidence_for_case(&q.case_id, id)?;
    }
    if !supported(&q.provider, &q.operation, &q.kind) {
        return Err("TI-CAPABILITY：当前服务/操作不支持此指标类型。".into());
    }
    // Serialize admission with inserts, independent of the long-lived HTTP gate.
    static ADMISSION: Mutex<()> = Mutex::new(());
    let _admission = ADMISSION.lock().map_err(db_error)?;
    let _config_guard = CONFIG_GUARD.lock().map_err(db_error)?;
    let p = provider(store, &q.provider)?;
    let pending: u64 = store.db.lock().map_err(db_error)?.query_row("SELECT count(*) FROM enrichment_jobs WHERE json_extract(record,'$.state') IN ('queued','running')", [], |r| r.get(0)).map_err(db_error)?;
    if pending + q.indicators.len() as u64 > 40 {
        return Err("TI-QUEUE：待处理指标已达上限，请等待或取消已有任务。".into());
    }
    let mut unique = std::collections::BTreeSet::new();
    let mut rows = Vec::new();
    for input in q.indicators {
        let parsed = normalize(&q.kind, &input);
        let value = parsed
            .as_ref()
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|_| input.trim().to_string());
        if !unique.insert(value.clone()) {
            continue;
        }
        let mut j = Job {
            id: uuid::Uuid::new_v4().to_string(),
            case_id: q.case_id.clone(),
            source_evidence_id: q.evidence_id.clone(),
            provider: q.provider.clone(),
            operation: q.operation.clone(),
            kind: q.kind.clone(),
            indicator: value,
            config_revision: p.revision.clone(),
            current_only: q.current_only,
            created_at: Utc::now().to_rfc3339(),
            state: "queued".into(),
            outcome: "unknown".into(),
            message: "等待查询；可能消耗服务额度。".into(),
            fetched_at: None,
            source_url: String::new(),
            source_job_id: None,
            result: None,
            result_sha256: None,
            result_evidence_id: None,
        };
        if let Err(reason) = parsed {
            j.state = "skipped".into();
            j.message = reason;
        } else if !q.fresh {
            if let Some(old) = cached(store, &j)? {
                j.state = "completed".into();
                j.outcome = old.outcome;
                j.result = old.result;
                j.source_url = old.source_url;
                j.fetched_at = old.fetched_at;
                j.result_sha256 = old.result_sha256;
                j.source_job_id = Some(old.id);
                j.message = "使用一小时内缓存；保留原查询时间，不代表情报仍有效。".into();
            }
        }
        rows.push(j);
    }
    let mut db = store.db.lock().map_err(db_error)?;
    let tx = db.transaction().map_err(db_error)?;
    for j in &rows {
        tx.execute(
            "INSERT INTO enrichment_jobs VALUES(?1,?2,?3)",
            params![j.id, j.case_id, serde_json::to_string(j).map_err(db_error)?],
        )
        .map_err(db_error)?;
    }
    tx.commit().map_err(db_error)?;
    Ok(rows)
}

async fn read_key(store: Arc<Store>, id: String) -> Result<String, String> {
    if id == "rdap" {
        return Ok(String::new());
    }
    static ACCESS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let permit = ACCESS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| "TI-KEYSTORE：系统凭据仍在等待授权，请处理系统弹窗。")?;
    let task = tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            credential(&store, &id)?
                .get_password()
                .map_err(|_| "TI-KEYSTORE：读取凭据失败，请在情报服务中重新保存。".to_string())
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = (store, id);
            Err("TI-KEYSTORE：当前平台不支持凭据库。".into())
        }
    });
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .map_err(|_| "TI-KEYSTORE：读取系统凭据超时，尚未发送查询；请检查系统授权。")?
        .map_err(|_| "TI-KEYSTORE：读取任务失败。")?
}
async fn run(store: &Arc<Store>, mut j: Job) -> Result<(), String> {
    // One bounded global lane also prevents rapid-click batches from bypassing
    // provider pacing. The documented VT Public limit is respected conservatively.
    static LANE: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    static LAST: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    let _permit = LANE
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)))
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| "TI-QUEUE：队列已关闭。")?;
    if !live(store, &j) {
        return Ok(());
    }
    let p = provider(store, &j.provider)?;
    if p.revision != j.config_revision {
        return Err("TI-CONFIG-CHANGED：服务配置已变更，请重新发起查询。".into());
    }
    let delay = if j.provider == "virustotal" { 16 } else { 2 };
    let wait = LAST
        .get_or_init(Default::default)
        .lock()
        .map_err(db_error)?
        .get(&j.provider)
        .map(|t| Duration::from_secs(delay).saturating_sub(t.elapsed()))
        .unwrap_or_default();
    tokio::time::sleep(wait).await;
    if !live(store, &j) {
        return Ok(());
    }
    j.state = "running".into();
    j.message = "正在读取凭据并查询官方服务。".into();
    update_active(store, &j)?;
    let key = read_key(store.clone(), j.provider.clone()).await?;
    if !live(store, &j) {
        return Ok(());
    }
    if provider(store, &j.provider)?.revision != j.config_revision {
        return Err("TI-CONFIG-CHANGED：发送前配置已变更，查询未发送。".into());
    }
    LAST.get()
        .unwrap()
        .lock()
        .map_err(db_error)?
        .insert(j.provider.clone(), Instant::now());
    let response = tokio::time::timeout(Duration::from_secs(40), async {
        if j.provider == "rdap" {
            rdap(store, &j).await
        } else {
            lookup(store, &j, &key).await
        }
    })
    .await
    .map_err(|_| "TI-TIMEOUT：官方服务查询超过总时间预算，未自动重试。")??;
    j.fetched_at = Some(Utc::now().to_rfc3339());
    j.source_url = response.0;
    let (outcome, message) = classify(&j.provider, &j.operation, response.1, &response.2);
    j.state = if matches!(outcome.as_str(), "data" | "no_data" | "pending" | "partial") {
        "completed"
    } else {
        "failed"
    }
    .into();
    j.outcome = outcome;
    j.message = message;
    let bytes = serde_json::to_vec(&response.2).map_err(db_error)?;
    j.result_sha256 = Some(format!("{:x}", Sha256::digest(&bytes)));
    j.result = Some(response.2);
    update_active(store, &j)
}

/// Resolve and pin every destination. Redirects are handled explicitly only
/// for RDAP (which carries no API key); other services cannot forward secrets.
async fn client_for(url: &reqwest::Url) -> Result<reqwest::Client, String> {
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("TI-TARGET：拒绝非官方 HTTPS 查询目标或不安全的注册服务地址。".into());
    }
    let host = url.host_str().ok_or("TI-TARGET：地址无主机名。")?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|_| "TI-DNS：解析服务地址失败。")?
        .collect();
    if addrs.is_empty() || addrs.iter().any(|a| !public_ip(a.ip())) {
        return Err("TI-TARGET：服务地址解析到本地或保留网络，已阻止。".into());
    }
    reqwest::Client::builder()
        .no_proxy()
        .resolve_to_addrs(host, &addrs)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(25))
        .connect_timeout(Duration::from_secs(8))
        .user_agent(concat!("GagaSecurityAssistant/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| "TI-NETWORK：创建查询连接失败。".into())
}
async fn receive(mut response: reqwest::Response, key: &str) -> Result<(u16, Value), String> {
    let status = response.status().as_u16();
    if response.content_length().is_some_and(|n| n > LIMIT as u64) {
        return Err("TI-SIZE：服务响应超过 2 MiB，已停止读取。".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "TI-NETWORK：读取服务响应失败。")?
    {
        if bytes.len() + chunk.len() > LIMIT {
            return Err("TI-SIZE：服务响应超过 2 MiB，已停止读取。".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    // Never retain bodies for authentication/quota/server errors. A provider
    // error page can echo headers, request URLs or tokens.
    if !(200..300).contains(&status) {
        return Ok((status, json!({"httpStatus":status})));
    }
    let mut text = String::from_utf8(bytes).map_err(|_| "TI-FORMAT：响应不是 UTF-8 JSON。")?;
    if !key.is_empty() {
        text = text.replace(key, "[密钥已隐藏]");
    }
    let mut value: Value =
        serde_json::from_str(&text).map_err(|_| "TI-FORMAT：服务未返回有效 JSON。")?;
    if !value.is_object() {
        return Err("TI-FORMAT：响应对象格式不正确。".into());
    }
    sanitize(&mut value, key);
    Ok((status, value))
}
fn sanitize(v: &mut Value, key: &str) {
    match v {
        Value::Object(map) => {
            map.retain(|name, _| {
                !matches!(
                    name.to_ascii_lowercase().replace(['-', '_'], "").as_str(),
                    "apikey"
                        | "authorization"
                        | "cookie"
                        | "setcookie"
                        | "password"
                        | "token"
                        | "headers"
                        | "requestheaders"
                )
            });
            for value in map.values_mut() {
                sanitize(value, key);
            }
        }
        Value::Array(rows) => {
            for row in rows {
                sanitize(row, key);
            }
        }
        Value::String(s) if !key.is_empty() => *s = s.replace(key, "[密钥已隐藏]"),
        _ => {}
    }
}
fn endpoint(j: &Job) -> Result<String, String> {
    Ok(match (j.provider.as_str(), j.operation.as_str()) {
        ("threatbook", "inbound") => "https://api.threatbook.cn/v3/scene/ip_reputation".into(),
        ("threatbook", "outbound") => "https://api.threatbook.cn/v3/scene/ioc".into(),
        ("threatbook", "ip_context") => "https://api.threatbook.cn/v3/ip/query".into(),
        ("threatbook", "domain_context") => "https://api.threatbook.cn/v3/domain/query".into(),
        ("threatbook", "hash") => "https://api.threatbook.cn/v3/file/report".into(),
        ("virustotal", "hash") => {
            format!("https://www.virustotal.com/api/v3/files/{}", j.indicator)
        }
        ("abuseipdb", "reports") => "https://api.abuseipdb.com/api/v2/check".into(),
        _ => return Err("TI-CAPABILITY：未实现此只读操作。".into()),
    })
}
fn request(
    client: &reqwest::Client,
    url: reqwest::Url,
    j: &Job,
    key: &str,
) -> reqwest::RequestBuilder {
    match j.provider.as_str() {
        "threatbook" => {
            let mut fields = vec![
                ("apikey", key.to_string()),
                ("resource", j.indicator.clone()),
                ("lang", "zh".into()),
            ];
            if matches!(j.operation.as_str(), "inbound" | "outbound") {
                fields.push(("realtime_verdict", j.current_only.to_string()));
            }
            client.post(url).form(&fields)
        }
        "virustotal" => client.get(url).header("x-apikey", key),
        _ => client
            .get(url)
            .header("Key", key)
            .header("Accept", "application/json")
            .query(&[("ipAddress", j.indicator.as_str()), ("maxAgeInDays", "30")]),
    }
}
// Keep destination preparation and sending together: DNS/registrar discovery
// may yield while the user cancels, locks egress or changes the provider.
async fn guarded_send(
    store: &Store,
    j: &Job,
    prepare: impl std::future::Future<Output = Result<reqwest::RequestBuilder, String>>,
) -> Result<reqwest::Response, String> {
    ensure_dispatch_allowed(store, j)?;
    let request = prepare.await?;
    // The preparation future may perform DNS or registrar discovery. Recheck
    // after it yields as well, before a Request is ever polled and connected.
    ensure_dispatch_allowed(store, j)?;
    let mut sending = std::pin::pin!(async { request.send().await });
    let mut started = false;
    // Order the first poll with lock/config changes. No mutex is held across
    // a network wait. Once dispatch has begun it is in-flight and cannot be
    // retracted; every subsequent RDAP hop must pass this gate again.
    let response = std::future::poll_fn(|cx| {
        use std::future::Future;
        if !started {
            let _guard = match CONFIG_GUARD.lock() {
                Ok(guard) => guard,
                Err(e) => return std::task::Poll::Ready(Err(db_error(e))),
            };
            if let Err(e) = ensure_dispatch_allowed(store, j) {
                return std::task::Poll::Ready(Err(e));
            }
            started = true;
            return sending.as_mut().poll(cx).map(|result| {
                result.map_err(|_| "TI-NETWORK：查询连接失败或超时，未自动重试。".into())
            });
        }
        sending
            .as_mut()
            .poll(cx)
            .map(|result| result.map_err(|_| "TI-NETWORK：查询连接失败或超时，未自动重试。".into()))
    })
    .await;
    response
}
async fn lookup(store: &Store, j: &Job, key: &str) -> Result<(String, u16, Value), String> {
    let endpoint = endpoint(j)?;
    let url = reqwest::Url::parse(&endpoint).map_err(|_| "TI-TARGET：接口地址无效。")?;
    let response = guarded_send(store, j, async {
        let client = client_for(&url).await?;
        Ok(request(&client, url, j, key))
    })
    .await?;
    let (status, value) = receive(response, key).await?;
    Ok((endpoint, status, value))
}
async fn rdap(store: &Store, j: &Job) -> Result<(String, u16, Value), String> {
    let domain = &j.indicator;
    let bootstrap = reqwest::Url::parse("https://data.iana.org/rdap/dns.json").unwrap();
    let r = guarded_send(store, j, async {
        Ok(client_for(&bootstrap).await?.get(bootstrap))
    })
    .await?;
    let (status, v) = receive(r, "").await?;
    if status != 200 {
        return Err("TI-RDAP：IANA 注册服务表暂不可用。".into());
    }
    let tld = domain.rsplit('.').next().unwrap_or_default();
    let base = v["services"]
        .as_array()
        .and_then(|rows| {
            rows.iter().find(|row| {
                row[0]
                    .as_array()
                    .is_some_and(|names| names.iter().any(|n| n.as_str() == Some(tld)))
            })
        })
        .and_then(|row| row[1][0].as_str())
        .ok_or("TI-RDAP：该顶级域暂无可用注册服务。")?;
    let mut url = reqwest::Url::parse(base).map_err(|_| "TI-RDAP：注册服务地址无效。")?;
    url.path_segments_mut()
        .map_err(|_| "TI-RDAP：注册服务地址无效。")?
        .pop_if_empty()
        .push("domain")
        .push(domain);
    for _ in 0..4 {
        let response = guarded_send(store, j, async {
            Ok(client_for(&url)
                .await?
                .get(url.clone())
                .header("Accept", "application/rdap+json, application/json"))
        })
        .await?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get("location")
                .and_then(|s| s.to_str().ok())
                .ok_or("TI-RDAP：重定向缺少目标。")?;
            url = url
                .join(location)
                .map_err(|_| "TI-RDAP：重定向地址无效。")?;
            continue;
        }
        let (status, value) = receive(response, "").await?;
        return Ok((url.to_string(), status, value));
    }
    Err("TI-RDAP：重定向超过上限，已停止。".into())
}
fn classify(p: &str, op: &str, http: u16, v: &Value) -> (String, String) {
    let (state, message) = match http {
        401 => ("unauthorized", "服务拒绝凭据，请检查密钥或账号。"),
        403 => (
            "forbidden",
            "服务拒绝访问，请检查接口权限、账号或出口 IP 绑定。",
        ),
        429 => ("quota", "服务限频或额度不足；未自动重试。"),
        404 if matches!(p, "virustotal" | "rdap") => {
            ("no_data", "未查到记录；不代表安全，也不会自动上传样本。")
        }
        300..=399 => ("redirect_blocked", "情报接口发生重定向，已阻止凭据转发。"),
        500..=599 => ("unavailable", "服务暂不可用；未自动重试。"),
        200..=299 if p == "threatbook" => match v["response_code"].as_i64() {
            Some(0) if v.get("data").is_some_and(|d| !d.is_null()) => {
                ("data", "已取得情报；请核对来源、时间和适用范围。")
            }
            Some(1) => (
                "partial",
                "部分结果；请检查原始响应中的缺失项，不据此判断安全。",
            ),
            Some(2 | 4 | 5) => ("no_data", "暂无数据或报告；不会自动上传样本。"),
            Some(3 | 7) => (
                "pending",
                "服务报告尚未完成；未自动轮询，重查可能消耗额度。",
            ),
            Some(-4) => ("quota", "服务限频或日/月/总配额不足；未自动重试。"),
            Some(-1) => {
                let msg = v["verbose_msg"]
                    .as_str()
                    .or_else(|| v["msg"].as_str())
                    .unwrap_or_default();
                if msg.contains("Invalid Access IP") {
                    (
                        "ip_not_bound",
                        "当前出口 IP 未绑定，请在微步控制台更新允许的出口。",
                    )
                } else if msg.contains("NO_AUTHORITY") || msg.contains("No Access") {
                    (
                        "forbidden",
                        "没有此接口或隐私报告的权限；不会自动上传样本。",
                    )
                } else if msg.contains("Expired") {
                    ("expired", "服务密钥或授权已到期。")
                } else {
                    ("unauthorized", "密钥、账号或参数无效，请核对服务设置。")
                }
            }
            _ => (
                "provider_error",
                "微步返回失败或无法识别的业务状态，请查看来源快照。",
            ),
        },
        200..=299
            if p == "virustotal"
                && v["data"]["type"] == "file"
                && v["data"]["attributes"].is_object() =>
        {
            (
                "data",
                "已取得既有文件报告；零检出或历史标签均不代替现场研判。",
            )
        }
        200..=299 if p == "abuseipdb" && v["data"]["abuseConfidenceScore"].is_number() => {
            ("data", "已取得最近 30 天举报背景；社区评分不证明攻击成功。")
        }
        200..=299 if p == "rdap" && v["objectClassName"] == "domain" => (
            "data",
            "已取得当前域名注册信息；可能脱敏，不等于历史 WHOIS 或真实控制人。",
        ),
        _ => (
            "provider_error",
            "服务返回了不符合预期的结果；不能作为安全结论。",
        ),
    };
    let suffix = if p == "threatbook" && op == "inbound" {
        " 入站信誉不覆盖所有出站 C2 线索。"
    } else {
        ""
    };
    (state.into(), format!("{message}{suffix}"))
}
#[tauri::command]
pub async fn archive_intel_result(
    store: State<'_, Arc<Store>>,
    id: String,
) -> Result<Evidence, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || archive(&store, &id))
        .await
        .map_err(|_| "TI-STORAGE：情报举证任务失败。")?
}
fn archive(store: &Store, id: &str) -> Result<Evidence, String> {
    static ARCHIVE: Mutex<()> = Mutex::new(());
    let _guard = ARCHIVE.lock().map_err(db_error)?;
    let j = get_job(store, id)?;
    ensure_case(store, &j.case_id)?;
    if let Some(e) = j.result_evidence_id {
        return store.evidence_for_case(&j.case_id, &e);
    }
    if j.state != "completed"
        || !matches!(j.outcome.as_str(), "data" | "no_data" | "partial")
        || j.result.is_none()
    {
        return Err("TI-EVIDENCE：此任务没有可引用的完成结果。".into());
    }
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&j.result).map_err(db_error)?)
    );
    if j.result_sha256.as_deref() != Some(&digest) {
        return Err("TI-INTEGRITY：结果摘要校验失败，已阻止举证。".into());
    }
    let e = store.archive_record(&j.case_id, "官方情报查询快照", &json!({"format":"gaga-enrichment/1","query":j,"limitations":"服务情报是外部背景，不等于本机已失陷；查询时间不是事件发生时间。未修改人工 IOC 判断。"}))?;
    store.db.lock().map_err(db_error)?.execute("UPDATE enrichment_jobs SET record=json_set(record,'$.resultEvidenceId',?1) WHERE id=?2", params![e.id,id]).map_err(db_error)?;
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    struct Lab {
        store: Store,
        root: std::path::PathBuf,
    }
    impl Lab {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("gaga-ti-{}", uuid::Uuid::new_v4()));
            Self {
                store: Store::open(root.clone()).unwrap(),
                root,
            }
        }
        fn enable(&self, id: &str) {
            let mut cfg = config(&self.store).unwrap();
            cfg.locked = false;
            let p = cfg.providers.iter_mut().find(|p| p.id == id).unwrap();
            p.enabled = true;
            p.authorized = true;
            p.has_key = id != "rdap";
            write_config(&self.store, &cfg).unwrap();
        }
        fn query(&self, provider: &str, operation: &str, kind: &str, values: &[&str]) -> Query {
            Query {
                case_id: self.store.active().unwrap(),
                evidence_id: None,
                provider: provider.into(),
                operation: operation.into(),
                kind: kind.into(),
                indicators: values.iter().map(|s| s.to_string()).collect(),
                current_only: true,
                fresh: false,
                consent: true,
            }
        }
    }
    impl Drop for Lab {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn complete(store: &Store, mut j: Job, result: Value) -> Job {
        j.state = "completed".into();
        j.outcome = "data".into();
        j.fetched_at = Some(Utc::now().to_rfc3339());
        j.result_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&result).unwrap())
        ));
        j.result = Some(result);
        update_active(store, &j).unwrap();
        j
    }
    #[test]
    fn default_lock_consent_and_capabilities_prevent_egress() {
        let lab = Lab::new();
        assert!(prepare(
            &lab.store,
            lab.query("rdap", "registration", "domain", &["icann.org"])
        )
        .unwrap_err()
        .contains("TI-LOCKED"));
        lab.enable("rdap");
        let mut q = lab.query("rdap", "registration", "domain", &["icann.org"]);
        q.consent = false;
        assert!(prepare(&lab.store, q).unwrap_err().contains("TI-CONSENT"));
        assert!(prepare(
            &lab.store,
            lab.query("rdap", "file_submit", "domain", &["icann.org"])
        )
        .unwrap_err()
        .contains("TI-CAPABILITY"));
        assert!(prepare(
            &lab.store,
            lab.query("rdap", "registration", "domain", &vec!["icann.org"; 21])
        )
        .unwrap_err()
        .contains("TI-LIMIT"));
        assert!(jobs(&lab.store, &lab.store.active().unwrap())
            .unwrap()
            .is_empty());
    }
    #[test]
    fn private_reserved_mapped_and_local_indicators_are_not_sent() {
        for ip in [
            "10.1.2.3",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.1.2.3",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "2001:db8::1",
            "2002:7f00:1::1",
        ] {
            assert!(normalize("ip", ip).is_err(), "{ip}");
        }
        for name in [
            "host.local",
            "a.internal",
            "localhost",
            "example.com",
            "x.example.org",
            "host.test",
            "x.onion",
            "home.arpa",
        ] {
            assert!(normalize("domain", name).is_err(), "{name}");
        }
        assert_eq!(normalize("domain", "ICANN.ORG.").unwrap().1, "icann.org");
        assert!(normalize("ip", "8.8.8.8").is_ok());
        assert!(normalize("ip", "2606:4700:4700::1111").is_ok());
        assert!(normalize("url", "https://icann.org/?token=private").is_err());
        let lab = Lab::new();
        lab.enable("threatbook");
        let rows = prepare(
            &lab.store,
            lab.query(
                "threatbook",
                "inbound",
                "ip",
                &["10.1.2.3", "8.8.8.8", "8.8.8.8"],
            ),
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].state, "skipped");
        assert_eq!(rows[1].state, "queued");
    }
    #[test]
    fn business_codes_do_not_turn_failures_or_empty_results_into_clean_verdicts() {
        for (code, msg, expected) in [
            (0, "OK", "data"),
            (1, "OK", "partial"),
            (2, "No Data", "no_data"),
            (3, "In Progress", "pending"),
            (4, "No Report Found", "no_data"),
            (5, "No MultiEngines Data", "no_data"),
            (7, "URL Downloading", "pending"),
            (-1, "Invalid Access IP", "ip_not_bound"),
            (-1, "NO_AUTHORITY", "forbidden"),
            (-1, "No Access to API Method", "forbidden"),
            (-1, "Invalid API Key", "unauthorized"),
            (-1, "Expired API Key", "expired"),
            (-4, "Frequent Limitation", "quota"),
            (-5, "System Error", "provider_error"),
        ] {
            assert_eq!(
                classify(
                    "threatbook",
                    "inbound",
                    200,
                    &json!({"response_code":code,"verbose_msg":msg,"data":{"indicator":{}}})
                )
                .0,
                expected
            );
        }
        for (http, expected) in [
            (401, "unauthorized"),
            (403, "forbidden"),
            (429, "quota"),
            (503, "unavailable"),
            (302, "redirect_blocked"),
        ] {
            assert_eq!(classify("threatbook", "hash", http, &json!({})).0, expected);
        }
        assert_eq!(classify("virustotal", "hash", 404, &json!({})).0, "no_data");
        assert_eq!(
            classify("threatbook", "hash", 404, &json!({})).0,
            "provider_error"
        );
        assert_eq!(
            classify("virustotal", "hash", 200, &json!({"unexpected":true})).0,
            "provider_error"
        );
        assert_eq!(
            classify(
                "rdap",
                "registration",
                200,
                &json!({"objectClassName":"domain"})
            )
            .0,
            "data"
        );
    }
    #[test]
    fn requests_are_only_documented_read_operations_and_keys_stay_out_of_urls() {
        let lab = Lab::new();
        lab.enable("threatbook");
        let mut j = prepare(
            &lab.store,
            lab.query("threatbook", "inbound", "ip", &["8.8.8.8"]),
        )
        .unwrap()
        .remove(0);
        let client = reqwest::Client::new();
        for (p, op, method, path) in [
            ("threatbook", "inbound", "POST", "/v3/scene/ip_reputation"),
            ("threatbook", "outbound", "POST", "/v3/scene/ioc"),
            ("threatbook", "ip_context", "POST", "/v3/ip/query"),
            ("threatbook", "domain_context", "POST", "/v3/domain/query"),
            ("threatbook", "hash", "POST", "/v3/file/report"),
            ("virustotal", "hash", "GET", "/api/v3/files/8.8.8.8"),
            ("abuseipdb", "reports", "GET", "/api/v2/check"),
        ] {
            j.provider = p.into();
            j.operation = op.into();
            let url = endpoint(&j).unwrap();
            let req = request(&client, url.parse().unwrap(), &j, "inert-contract-token")
                .build()
                .unwrap();
            assert_eq!(req.method(), method);
            assert_eq!(req.url().path(), path);
            assert!(!req.url().as_str().contains("inert-contract-token"));
            if p == "threatbook" {
                let body =
                    String::from_utf8(req.body().unwrap().as_bytes().unwrap().to_vec()).unwrap();
                assert!(body.contains("apikey=inert-contract-token"));
                assert!(!body.contains("file="));
            }
            if p == "virustotal" {
                assert_eq!(req.headers()["x-apikey"], "inert-contract-token");
            }
        }
        j.operation = "upload".into();
        assert!(endpoint(&j).is_err());
    }
    #[test]
    fn cache_retains_source_time_and_isolated_by_case_revision_and_query_scope() {
        let lab = Lab::new();
        lab.enable("threatbook");
        let q = lab.query("threatbook", "inbound", "ip", &["8.8.8.8"]);
        let first = prepare(&lab.store, q.clone()).unwrap().remove(0);
        let first = complete(
            &lab.store,
            first,
            json!({"response_code":0,"data":{"8.8.8.8":{"is_malicious":false}}}),
        );
        let cached = prepare(&lab.store, q.clone()).unwrap().remove(0);
        assert_eq!(cached.source_job_id.as_deref(), Some(first.id.as_str()));
        assert_eq!(cached.fetched_at, first.fetched_at);
        let mut other = q.clone();
        other.current_only = false;
        assert_eq!(prepare(&lab.store, other).unwrap()[0].state, "queued");
        let mut fresh = q.clone();
        fresh.fresh = true;
        assert_eq!(prepare(&lab.store, fresh).unwrap()[0].state, "queued");
        let mut cfg = config(&lab.store).unwrap();
        cfg.providers[0].revision = "changed-account".into();
        write_config(&lab.store, &cfg).unwrap();
        assert_eq!(prepare(&lab.store, q.clone()).unwrap()[0].state, "queued");
        let next = lab.store.create_case("another event".into()).unwrap();
        let mut other = q;
        other.case_id = next.id;
        assert_eq!(prepare(&lab.store, other).unwrap()[0].state, "queued");
        assert!(ensure_case(&lab.store, &first.case_id).is_err());
        assert!(archive(&lab.store, &first.id).is_err());
    }
    #[test]
    fn cancellation_and_restart_block_late_updates_and_automatic_retries() {
        let lab = Lab::new();
        lab.enable("rdap");
        let mut j = prepare(
            &lab.store,
            lab.query("rdap", "registration", "domain", &["icann.org"]),
        )
        .unwrap()
        .remove(0);
        let mut cancelled = j.clone();
        cancelled.state = "cancelled".into();
        update_active(&lab.store, &cancelled).unwrap();
        j.state = "completed".into();
        update_active(&lab.store, &j).unwrap();
        assert_eq!(get_job(&lab.store, &j.id).unwrap().state, "cancelled");
        j.id = uuid::Uuid::new_v4().to_string();
        j.state = "running".into();
        put(&lab.store, &j).unwrap();
        init(&lab.store).unwrap();
        assert_eq!(get_job(&lab.store, &j.id).unwrap().state, "interrupted");
        assert!(!live(&lab.store, &j));
    }
    #[test]
    fn dispatch_rechecks_authority_after_async_preparation_before_connecting() {
        // A real loopback listener proves that refusing the late result alone
        // is insufficient: a revoked request must not establish a connection.
        // Only this test supplies a local transport; production URLs still use
        // the HTTPS/public-DNS validation in client_for.
        for change in ["lock", "cancel", "revision", "disable"] {
            let lab = Lab::new();
            lab.enable("rdap");
            let j = prepare(
                &lab.store,
                lab.query("rdap", "registration", "domain", &["icann.org"]),
            )
            .unwrap()
            .remove(0);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let result = tauri::async_runtime::block_on(guarded_send(&lab.store, &j, async {
                tokio::task::yield_now().await;
                if change == "cancel" {
                    let mut cancelled = j.clone();
                    cancelled.state = "cancelled".into();
                    update_active(&lab.store, &cancelled).unwrap();
                } else {
                    let mut cfg = config(&lab.store).unwrap();
                    match change {
                        "lock" => cfg.locked = true,
                        "revision" => cfg.providers[1].revision = "replacement".into(),
                        "disable" => cfg.providers[1].enabled = false,
                        _ => unreachable!(),
                    }
                    write_config(&lab.store, &cfg).unwrap();
                }
                Ok(reqwest::Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_millis(250))
                    .build()
                    .unwrap()
                    .get(format!("http://{address}/not-sent")))
            }));
            let connected = listener.accept().is_ok();
            assert!(!connected, "{change}: revoked request opened a connection");
            assert!(result.unwrap_err().starts_with("TI-"));
        }
    }
    #[test]
    fn report_evidence_is_idempotent_hash_verified_and_keeps_local_verdict() {
        let lab = Lab::new();
        lab.enable("rdap");
        let iid = intelligence::upsert(&lab.store, "domain", "icann.org").unwrap();
        intelligence::annotate(
            &lab.store,
            iid.clone(),
            "benign".into(),
            "reviewed".into(),
            "analyst decision".into(),
        )
        .unwrap();
        let j = prepare(
            &lab.store,
            lab.query("rdap", "registration", "domain", &["icann.org"]),
        )
        .unwrap()
        .remove(0);
        let j = complete(
            &lab.store,
            j,
            json!({"objectClassName":"domain","ldhName":"icann.org","remarks":[{"description":["<script>untrusted</script>"]}]}),
        );
        let evidence = archive(&lab.store, &j.id).unwrap();
        let again = archive(&lab.store, &j.id).unwrap();
        assert_eq!(evidence.id, again.id);
        let indexed = intelligence::query(&lab.store, "icann.org").unwrap();
        assert_eq!(
            indexed.iter().find(|i| i.id == iid).unwrap().verdict,
            "benign"
        );
        let snapshot: Value = serde_json::from_slice(
            &std::fs::read(lab.store.root.join("evidence").join(&evidence.id)).unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot["query"]["fetchedAt"], j.fetched_at.unwrap());
        assert_eq!(snapshot["query"]["resultSha256"], j.result_sha256.unwrap());
        let list = jobs(&lab.store, &j.case_id).unwrap();
        assert!(list.iter().all(|j| j.result.is_none()));
        let mut broken = prepare(
            &lab.store,
            lab.query("rdap", "registration", "domain", &["iana.org"]),
        )
        .unwrap()
        .remove(0);
        broken = complete(&lab.store, broken, json!({"objectClassName":"domain"}));
        lab.store.db.lock().unwrap().execute("UPDATE enrichment_jobs SET record=json_set(record,'$.result.objectClassName','tampered') WHERE id=?1",[broken.id.clone()]).unwrap();
        assert!(archive(&lab.store, &broken.id)
            .err()
            .unwrap()
            .contains("TI-INTEGRITY"));
    }
    #[test]
    fn http_response_limits_and_secret_redaction_use_a_real_local_transport() {
        fn response(status: u16, body: String, key: &str) -> Result<(u16, Value), String> {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let thread = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                let head=format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body.as_bytes());
            });
            let result = tauri::async_runtime::block_on(async {
                let r = reqwest::get(format!("http://{address}/")).await.unwrap();
                receive(r, key).await
            });
            thread.join().unwrap();
            result
        }
        let v=response(200,r#"{"apikey":"inert-secret","note":"inert-\u0073ecret","nested":{"Authorization":"Bearer inert-secret"}}"#.into(),"inert-secret").unwrap().1;
        assert!(!v.to_string().contains("inert-secret"));
        assert!(v.get("apikey").is_none());
        assert_eq!(
            response(403, "echo of inert-secret".into(), "inert-secret")
                .unwrap()
                .1,
            json!({"httpStatus":403})
        );
        assert!(response(200, "not-json".into(), "")
            .unwrap_err()
            .contains("TI-FORMAT"));
        assert!(response(200, " ".repeat(LIMIT + 1), "")
            .unwrap_err()
            .contains("TI-SIZE"));
        let refused =
            tauri::async_runtime::block_on(client_for(&"https://127.0.0.1/".parse().unwrap()));
        assert!(refused.is_err());
        assert!(
            tauri::async_runtime::block_on(client_for(&"http://icann.org/".parse().unwrap()))
                .is_err()
        );
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    #[test]
    fn restored_backup_resets_service_authority_and_preserves_local_results() {
        let root = std::env::temp_dir().join(format!("gaga-ti-restore-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("backup")).unwrap();
        std::fs::create_dir_all(root.join("restored")).unwrap();
        let store = Store::open(root.join("source")).unwrap();
        let mut cfg = Config {
            locked: false,
            ..Config::default()
        };
        cfg.providers[1].enabled = true;
        cfg.providers[1].authorized = true;
        write_config(&store, &cfg).unwrap();
        let q = Query {
            case_id: store.active().unwrap(),
            evidence_id: None,
            provider: "rdap".into(),
            operation: "registration".into(),
            kind: "domain".into(),
            indicators: vec!["icann.org".into()],
            current_only: true,
            fresh: false,
            consent: true,
        };
        let j = prepare(&store, q).unwrap().remove(0);
        let backup = crate::maintenance::backup(&store, &root.join("backup")).unwrap();
        let restored = crate::maintenance::restore(
            std::path::Path::new(backup["path"].as_str().unwrap()),
            &root.join("restored"),
        )
        .unwrap();
        let other = Store::open(restored["path"].as_str().unwrap().into()).unwrap();
        assert!(config(&other).unwrap().locked);
        assert!(config(&other)
            .unwrap()
            .providers
            .iter()
            .all(|p| !p.enabled && !p.has_key));
        assert_eq!(get_job(&other, &j.id).unwrap().state, "interrupted");
        drop(other);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }
}
