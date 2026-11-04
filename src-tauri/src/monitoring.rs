use crate::store::{Evidence, Store};
use chrono::{Duration as ChronoDuration, Utc};
use rusqlite::{params, OptionalExtension};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};
use tauri::Emitter;
pub fn init(store: &Store) -> Result<(), String> {
    // 巡检记录会长期累积。索引匹配资产历史、事件队列和到期领取，避免
    // 每次刷新/调度都扫描全部历史；已有工作区在打开时幂等补齐。
    store.db.lock().map_err(|e|e.to_string())?.execute_batch(
"CREATE TABLE IF NOT EXISTS monitor_assets(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),enabled INTEGER NOT NULL,next_at TEXT NOT NULL,running INTEGER NOT NULL DEFAULT 0,record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS monitor_snapshots(id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES monitor_assets(id),created_at TEXT NOT NULL,evidence_id TEXT NOT NULL REFERENCES evidence(id),record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS monitor_observations(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),kind TEXT NOT NULL,created_at TEXT NOT NULL,evidence_id TEXT NOT NULL REFERENCES evidence(id),ai_state TEXT NOT NULL DEFAULT 'pending',review_id TEXT,record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS monitor_ai_calls(id TEXT PRIMARY KEY,started_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS monitor_assets_case ON monitor_assets(case_id);
CREATE INDEX IF NOT EXISTS monitor_assets_due ON monitor_assets(next_at) WHERE enabled=1 AND running=0;
CREATE INDEX IF NOT EXISTS monitor_snapshots_asset_time ON monitor_snapshots(asset_id,created_at DESC);
CREATE INDEX IF NOT EXISTS monitor_observations_case_time ON monitor_observations(case_id,created_at DESC);
CREATE INDEX IF NOT EXISTS monitor_observations_state_case ON monitor_observations(ai_state,case_id);
CREATE INDEX IF NOT EXISTS monitor_observations_evidence_kind ON monitor_observations(evidence_id,kind);
CREATE INDEX IF NOT EXISTS monitor_ai_calls_time ON monitor_ai_calls(started_at);
UPDATE monitor_assets SET running=0;
UPDATE monitor_observations SET ai_state='interrupted' WHERE ai_state='running';").map_err(|e|e.to_string())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    pub id: String,
    pub case_id: String,
    pub name: String,
    pub url: String,
    pub interval_secs: u64,
    pub enabled: bool,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default)]
    pub auto_screenshot: bool,
    pub baseline_id: Option<String>,
    pub last_snapshot_id: Option<String>,
    pub last_status: String,
    pub last_checked: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Script {
    pub url: String,
    pub sha256: Option<String>,
    pub bytes: usize,
    pub error: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub id: String,
    pub asset_id: String,
    pub created_at: String,
    pub evidence_id: String,
    pub status: Option<u16>,
    pub title: String,
    pub sha256: String,
    pub scripts: Vec<Script>,
    pub external_links: Vec<String>,
    pub hidden_links: Vec<String>,
    #[serde(default)]
    pub coverage_gaps: Vec<String>,
    #[serde(default)]
    pub final_url: String,
    #[serde(default)]
    pub redirects: Vec<Value>,
    #[serde(default)]
    pub screenshot: Option<crate::store::Screenshot>,
    #[serde(default)]
    pub screenshot_error: Option<String>,
    #[serde(default)]
    pub browser_final_url: Option<String>,
    #[serde(default)]
    pub browser_navigations: Vec<Value>,
    #[serde(default)]
    pub dom_sha256: Option<String>,
    pub changes: Vec<String>,
    pub error: Option<String>,
    pub elapsed_ms: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub id: String,
    pub case_id: String,
    pub kind: String,
    pub subject: String,
    pub summary: String,
    pub created_at: String,
    pub evidence_id: String,
    pub ai_state: String,
    pub review_id: Option<String>,
    pub error: Option<String>,
    pub detail: Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiSettings {
    pub enabled: bool,
    pub min_interval_secs: u64,
    pub max_per_hour: u64,
    #[serde(default)]
    pub scope_case_id: Option<String>,
    #[serde(default)]
    pub enabled_after: Option<String>,
    #[serde(default)]
    pub after_rowid: Option<i64>,
    #[serde(default)]
    pub revision: String,
    #[serde(default)]
    pub needs_confirmation: bool,
}
impl Default for AiSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            min_interval_secs: 60,
            max_per_hour: 60,
            scope_case_id: None,
            enabled_after: None,
            after_rowid: None,
            revision: String::new(),
            needs_confirmation: false,
        }
    }
}
pub fn ai_settings(store: &Store) -> Result<AiSettings, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    ai_settings_db(&db)
}
fn ai_settings_db(db: &rusqlite::Connection) -> Result<AiSettings, String> {
    let text: Option<String> = db
        .query_row(
            "SELECT value FROM settings WHERE key='monitor_ai_settings'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let mut cfg: AiSettings = text
        .map(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        .unwrap_or_else(|| Ok(AiSettings::default()))?;
    // 旧版的全工作区授权不能自动迁移成新事件授权，升级后需要明确重新启用。
    if cfg.enabled
        && (cfg.scope_case_id.is_none()
            || cfg.revision.is_empty()
            || !cfg.after_rowid.is_some_and(|n| n >= 0)
            || !cfg
                .enabled_after
                .as_ref()
                .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok()))
    {
        cfg.enabled = false;
        cfg.needs_confirmation = true;
    }
    Ok(cfg)
}
pub fn save_ai_settings(store: &Store, mut cfg: AiSettings) -> Result<(), String> {
    if !(15..=3600).contains(&cfg.min_interval_secs) || !(1..=240).contains(&cfg.max_per_hour) {
        return Err("自动 AI 间隔 15–3600 秒，预算 1–240 次 / 小时。".into());
    }
    if cfg.enabled && crate::ai::config(store)?.endpoint.is_empty() {
        return Err("请先配置模型 API，再启用自动研判。".into());
    }
    cfg.scope_case_id = if cfg.enabled {
        Some(store.active()?)
    } else {
        None
    };
    cfg.enabled_after = cfg.enabled.then(|| Utc::now().to_rfc3339());
    cfg.revision = uuid::Uuid::new_v4().to_string();
    cfg.needs_confirmation = false;
    let db = store.db.lock().map_err(|e| e.to_string())?;
    // 用数据库插入边界而非墙钟筛选新观测，系统时间回拨不会重放历史材料。
    cfg.after_rowid = if cfg.enabled {
        Some(
            db.query_row(
                "SELECT coalesce(max(rowid),0) FROM monitor_observations",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    if cfg.enabled && crate::privacy::read_db(&db)?.ai_locked {
        return Err(crate::privacy::LOCKED.into());
    }
    db.execute(
        "INSERT OR REPLACE INTO settings VALUES('monitor_ai_settings',?1)",
        [serde_json::to_string(&cfg).unwrap()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
pub fn validate_url(url: &str) -> Result<reqwest::Url, String> {
    let u = reqwest::Url::parse(url.trim()).map_err(|_| "资产 URL 无效")?;
    if !matches!(u.scheme(), "http" | "https")
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
    {
        return Err("资产需要完整 HTTP / HTTPS URL，不得内嵌凭据或片段。".into());
    }
    let host = u.host_str().unwrap();
    if host == "169.254.169.254" || host == "metadata.google.internal" || host == "[fd00:ec2::254]"
    {
        return Err("不支持云实例元数据地址作为巡检资产。".into());
    }
    Ok(u)
}
pub fn assets(store: &Store, case: Option<&str>) -> Result<Vec<Asset>, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    // 不用 OR 混合全局/事件条件，让 SQLite 可以按事件索引读取最近记录。
    let query = if case.is_some_and(|c| !c.is_empty()) {
        "SELECT record FROM monitor_assets WHERE case_id=?1 ORDER BY rowid DESC LIMIT 500"
    } else {
        "SELECT record FROM monitor_assets WHERE ?1='' ORDER BY rowid DESC LIMIT 500"
    };
    let mut q = db.prepare(query).map_err(|e| e.to_string())?;
    let rows = q
        .query_map([case.unwrap_or("")], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    rows.map(|r| serde_json::from_str(&r.map_err(|e| e.to_string())?).map_err(|e| e.to_string()))
        .collect()
}
fn save_asset(store: &Store, a: &Asset, next: Option<String>) -> Result<(), String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    db.execute("INSERT INTO monitor_assets(id,case_id,enabled,next_at,record) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,next_at=excluded.next_at,record=excluded.record",params![a.id,a.case_id,a.enabled,next.unwrap_or_else(||Utc::now().to_rfc3339()),serde_json::to_string(a).unwrap()]).map_err(|e|e.to_string())?;
    Ok(())
}
pub fn import_assets(store: &Store, text: &str, interval: u64) -> Result<usize, String> {
    import_configured(store, text, interval, false, false)
}
pub fn import_configured(
    store: &Store,
    text: &str,
    interval: u64,
    follow_redirects: bool,
    auto_screenshot: bool,
) -> Result<usize, String> {
    if text.len() > 128000 || !(60..=86400).contains(&interval) {
        return Err("最多导入 128 KiB，巡检间隔 60–86400 秒。".into());
    }
    let case = store.active()?;
    let existing = assets(store, Some(&case))?;
    let mut values = Vec::new();
    let mut seen = BTreeSet::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (name, url) = line
            .split_once(',')
            .map_or((line, line), |(a, b)| (a.trim(), b.trim()));
        let url = validate_url(url)?.to_string();
        if seen.insert(url.clone()) && !existing.iter().any(|a| a.url == url) {
            if name.len() > 200 {
                return Err("资产名称过长。".into());
            }
            values.push((name.to_string(), url));
        }
    }
    if values.len() + existing.len() > 100 {
        return Err("每个事件最多 100 个资产。".into());
    }
    let count = values.len();
    for (name, url) in values {
        save_asset(
            store,
            &Asset {
                id: uuid::Uuid::new_v4().to_string(),
                case_id: case.clone(),
                name,
                url,
                interval_secs: interval,
                enabled: false,
                follow_redirects,
                auto_screenshot,
                baseline_id: None,
                last_snapshot_id: None,
                last_status: "尚未巡检".into(),
                last_checked: None,
            },
            None,
        )?;
    }
    Ok(count)
}
pub fn toggle_asset(store: &Store, id: &str, enabled: bool) -> Result<(), String> {
    let case = store.active()?;
    let changed = store.db.lock().map_err(|e|e.to_string())?.execute(
        "UPDATE monitor_assets SET enabled=?3,record=json_set(record,'$.enabled',json(?4)),next_at=?5 WHERE id=?1 AND case_id=?2",
        params![id,case,enabled,if enabled {"true"} else {"false"},Utc::now().to_rfc3339()]
    ).map_err(|e|e.to_string())?;
    if changed == 0 {
        return Err("资产不属于当前事件".into());
    }
    Ok(())
}
/// JSON field updates preserve scheduling/baselines while a capture is running.
pub fn configure_asset(
    store: &Store,
    id: &str,
    follow: bool,
    screenshot: bool,
) -> Result<(), String> {
    let case = store.active()?;
    let n = store.db.lock().map_err(|e|e.to_string())?.execute("UPDATE monitor_assets SET record=json_set(record,'$.followRedirects',json(?3),'$.autoScreenshot',json(?4)) WHERE id=?1 AND case_id=?2",params![id,case,if follow {"true"} else {"false"},if screenshot {"true"} else {"false"}]).map_err(|e|e.to_string())?;
    if n == 0 {
        return Err("资产不属于当前事件".into());
    }
    Ok(())
}
pub fn snapshots(store: &Store, asset: &str) -> Result<Vec<Snapshot>, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut q=db.prepare("SELECT record FROM monitor_snapshots WHERE asset_id=?1 ORDER BY created_at DESC LIMIT 30").map_err(|e|e.to_string())?;
    let rows = q
        .query_map([asset], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    rows.map(|r| serde_json::from_str(&r.map_err(|e| e.to_string())?).map_err(|e| e.to_string()))
        .collect()
}
/// 巡检历史只按页读取；截图/证据正文由进入详情时单独请求。
pub fn snapshots_page(
    store: &Store,
    asset: &str,
    offset: u64,
    limit: u64,
) -> Result<Value, String> {
    let limit = limit.clamp(1, 100);
    let offset = offset.min(10_000_000);
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let total: u64 = db
        .query_row(
            "SELECT count(*) FROM monitor_snapshots WHERE asset_id=?1",
            [asset],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let mut q = db.prepare("SELECT record FROM monitor_snapshots WHERE asset_id=?1 ORDER BY created_at DESC,id DESC LIMIT ?2 OFFSET ?3").map_err(|e| e.to_string())?;
    let rows = q
        .query_map(params![asset, limit, offset], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let rows = rows
        .map(|r| {
            serde_json::from_str::<Snapshot>(&r.map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({"rows":rows,"total":total,"offset":offset,"limit":limit}))
}
#[tauri::command]
pub fn get_monitor_snapshots_page(
    asset_id: String,
    offset: u64,
    limit: u64,
    store: tauri::State<'_, Arc<Store>>,
) -> Result<Value, String> {
    // A snapshot identifier is not authority to read another event's history.
    if !assets(&store, Some(&store.active()?))?
        .iter()
        .any(|a| a.id == asset_id)
    {
        return Err("资产不属于当前事件".into());
    }
    snapshots_page(&store, &asset_id, offset, limit)
}
fn snapshot_by_id(store: &Store, id: &str) -> Result<Snapshot, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let s: String = db
        .query_row(
            "SELECT record FROM monitor_snapshots WHERE id=?1",
            [id],
            |r| r.get(0),
        )
        .map_err(|_| "基线记录不存在")?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}
pub fn accept_baseline(store: &Store, asset: &str, snapshot: &str) -> Result<(), String> {
    let a = assets(store, Some(&store.active()?))?
        .into_iter()
        .find(|a| a.id == asset)
        .ok_or("资产不属于当前事件")?;
    let s = snapshot_by_id(store, snapshot)?;
    if s.asset_id != asset
        || s.error.is_some()
        || !s.status.is_some_and(|v| (200..300).contains(&v))
    {
        return Err("只能将本资产无采集错误的 2xx 快照设为人工确认基线。".into());
    }
    store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .execute(
            "UPDATE monitor_assets SET record=json_set(record,'$.baselineId',?2) WHERE id=?1",
            params![a.id, s.id],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}
pub fn observations(store: &Store, case: &str) -> Result<Vec<Observation>, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut q=db.prepare("SELECT record,ai_state,review_id FROM monitor_observations WHERE case_id=?1 ORDER BY created_at DESC LIMIT 200").map_err(|e|e.to_string())?;
    let rows = q
        .query_map([case], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    rows.map(|r| {
        let (s, state, review) = r.map_err(|e| e.to_string())?;
        let mut o: Observation = serde_json::from_str(&s).map_err(|e| e.to_string())?;
        o.ai_state = state;
        o.review_id = review;
        Ok(o)
    })
    .collect()
}
pub fn queue_stats(store: &Store, case: &str) -> Result<Value, String> {
    let cfg = ai_settings(store)?;
    let db = store.db.lock().map_err(|e| e.to_string())?;
    db.query_row("SELECT (SELECT count(*) FROM monitor_observations WHERE case_id=?1 AND ai_state='pending'),(SELECT count(*) FROM monitor_observations WHERE case_id=?1 AND review_id IS NOT NULL),(SELECT count(*) FROM monitor_observations WHERE ai_state='pending'),(SELECT count(*) FROM monitor_observations WHERE case_id=?1 AND case_id=?2 AND rowid>?3 AND ai_state='pending' AND ?4)",params![case,cfg.scope_case_id,cfg.after_rowid,cfg.enabled],|r| {
        let pending:u64=r.get(0)?; let eligible:u64=r.get(3)?;
        Ok(json!({"pending":pending,"reviewed":r.get::<_,u64>(1)?,"globalPending":r.get::<_,u64>(2)?,"eligible":eligible,"retained":pending.saturating_sub(eligible)}))
    }).map_err(|e|e.to_string())
}

pub fn record_observation(
    store: &Store,
    kind: &str,
    subject: String,
    summary: String,
    e: &Evidence,
    detail: Value,
) -> Result<Observation, String> {
    let o = Observation {
        id: uuid::Uuid::new_v4().to_string(),
        case_id: e.case_id.clone(),
        kind: kind.into(),
        subject,
        summary,
        created_at: Utc::now().to_rfc3339(),
        evidence_id: e.id.clone(),
        ai_state: "pending".into(),
        review_id: None,
        error: None,
        detail,
    };
    let db = store.db.lock().map_err(|e| e.to_string())?;
    db.execute("INSERT INTO monitor_observations(id,case_id,kind,created_at,evidence_id,record) VALUES(?1,?2,?3,?4,?5,?6)",params![o.id,o.case_id,o.kind,o.created_at,o.evidence_id,serde_json::to_string(&o).unwrap()]).map_err(|e|e.to_string())?;
    Ok(o)
}
async fn fetch(
    client: &reqwest::Client,
    url: &reqwest::Url,
    limit: usize,
) -> Result<(u16, Vec<u8>, Option<String>), String> {
    let mut response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|_| "连接失败或超时")?;
    let status = response.status().as_u16();
    let redirect = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "响应读取失败")? {
        if bytes.len() + chunk.len() > limit {
            return Err(format!("响应超过 {} KiB 上限", limit / 1024));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes, redirect))
}
#[derive(Default)]
pub struct Page {
    pub title: String,
    pub scripts: Vec<String>,
    pub external: Vec<String>,
    pub hidden: Vec<String>,
    pub coverage_gaps: Vec<String>,
}
pub fn inspect_page(url: &reqwest::Url, html: &str) -> Page {
    let doc = Html::parse_document(html);
    let mut page = Page {
        title: doc
            .select(&Selector::parse("title").unwrap())
            .next()
            .map(|e| crate::analyzers::cut(&e.text().collect::<String>(), 300))
            .unwrap_or_default(),
        ..Page::default()
    };
    let mut scripts = BTreeSet::new();
    // HTTP 200 can be a navigation stub rather than the intended page. Record
    // the missing browser step without evaluating untrusted JavaScript or
    // following a client-side redirect (including HTTPS downgrades).
    let meta_refresh = |document: &Html| {
        document
            .select(&Selector::parse("meta[http-equiv]").unwrap())
            .any(|n| {
                n.value()
                    .attr("http-equiv")
                    .is_some_and(|v| v.eq_ignore_ascii_case("refresh"))
            })
    };
    if meta_refresh(&doc)
        || doc.select(&Selector::parse("noscript").unwrap()).any(|n| {
            // The normal HTML parser treats head/noscript as raw text when scripting
            // is enabled. Inspect that fallback as markup too; never execute it.
            meta_refresh(&Html::parse_fragment(&n.text().collect::<String>()))
        })
    {
        page.coverage_gaps.push(
            "HTTP 静态原文包含 meta refresh；此响应尚未采到目标页面，浏览器结果另行记录。".into(),
        );
    }
    static NAVIGATION: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)(?:window\s*\.\s*)?location\s*(?:\.\s*(?:replace|assign)\s*\(|(?:\.\s*href\s*)?=[^=])").unwrap()
    });
    if doc
        .select(&Selector::parse("script:not([src])").unwrap())
        .any(|n| NAVIGATION.is_match(&n.text().collect::<String>()))
    {
        page.coverage_gaps.push(
            "HTTP 静态原文包含脚本跳转线索；此原文未执行脚本，独立浏览器的最终地址与截图另行记录。"
                .into(),
        );
    }
    let mut external = BTreeSet::new();
    let mut hidden = BTreeSet::new();
    for node in doc.select(&Selector::parse("script[src]").unwrap()) {
        if let Some(src) = node
            .value()
            .attr("src")
            .and_then(|s| url.join(s).ok())
            .filter(|u| matches!(u.scheme(), "http" | "https"))
        {
            scripts.insert(src.to_string());
        }
    }
    for node in doc
        .select(&Selector::parse("a[href],iframe[src]").unwrap())
        .take(10000)
    {
        let e = node.value();
        if let Some(link) = e
            .attr("href")
            .or_else(|| e.attr("src"))
            .and_then(|s| url.join(s).ok())
            .filter(|u| matches!(u.scheme(), "http" | "https"))
        {
            if link.origin() != url.origin() {
                external.insert(link.to_string());
            }
            let hidden_node = std::iter::once(node)
                .chain(node.ancestors().filter_map(scraper::ElementRef::wrap))
                .take(12)
                .any(|n| {
                    let e = n.value();
                    let style = e
                        .attr("style")
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .replace(' ', "");
                    e.attr("hidden").is_some()
                        || e.attr("aria-hidden") == Some("true")
                        || style.contains("display:none")
                        || style.contains("visibility:hidden")
                        || style.contains("opacity:0")
                        || style.contains("font-size:0")
                });
            if hidden_node {
                hidden.insert(link.to_string());
            }
        }
    }
    page.scripts = scripts.into_iter().take(100).collect();
    page.external = external.into_iter().take(200).collect();
    page.hidden = hidden.into_iter().take(200).collect();
    page
}
/// Parse only declarative meta refresh; arbitrary JavaScript belongs in the
/// disposable browser. Never evaluate a redirect expression on the desktop.
fn meta_target(html: &str) -> Option<String> {
    let doc = Html::parse_document(html);
    for node in doc.select(&Selector::parse("meta[http-equiv]").unwrap()) {
        if !node
            .value()
            .attr("http-equiv")
            .is_some_and(|s| s.eq_ignore_ascii_case("refresh"))
        {
            continue;
        }
        let content = node.value().attr("content")?;
        if let Some((_, target)) = content.split_once(';') {
            if let Some((key, value)) = target.trim().split_once('=') {
                if key.trim().eq_ignore_ascii_case("url") {
                    return Some(value.trim().trim_matches(['\'', '"']).to_string());
                }
            }
        }
    }
    None
}
async fn public_redirect_host(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let Ok(addresses) =
        tokio::net::lookup_host((host, url.port_or_known_default().unwrap_or(443))).await
    else {
        return false;
    };
    let ips: Vec<_> = addresses.map(|a| a.ip()).collect();
    !ips.is_empty()
        && ips.into_iter().all(|ip| match ip {
            std::net::IpAddr::V4(v) => {
                !v.is_private()
                    && !v.is_loopback()
                    && !v.is_link_local()
                    && !v.is_unspecified()
                    && !v.is_multicast()
                    && v.octets()[0] >= 1
                    && v.octets()[0] < 224
            }
            std::net::IpAddr::V6(v) => {
                !v.is_loopback()
                    && !v.is_unspecified()
                    && !v.is_multicast()
                    && (v.segments()[0] & 0xfe00 != 0xfc00)
                    && (v.segments()[0] & 0xffc0 != 0xfe80)
                    && v.to_ipv4_mapped().is_none()
            }
        })
}
fn changes(base: Option<&Snapshot>, current: &Snapshot) -> Vec<String> {
    let mut result = Vec::new();
    for gap in &current.coverage_gaps {
        result.push(format!("页面覆盖受限：{gap}"));
    }
    if let Some(error) = &current.error {
        result.push(format!("采集失败：{error}"));
    }
    // 子资源失败也是覆盖缺口，不能将相同的失败摘要解释为页面安全。
    for script in &current.scripts {
        if let Some(error) = &script.error {
            result.push(format!("脚本覆盖受限：{} · {error}", script.url));
        }
    }
    if let Some(base) = base {
        if base.status != current.status {
            result.push(format!(
                "HTTP 状态变化：{:?} → {:?}",
                base.status, current.status
            ));
        }
        if base.final_url != current.final_url {
            result.push(format!(
                "HTTP 最终地址变化：{} → {}",
                base.final_url, current.final_url
            ));
        }
        if base.browser_final_url != current.browser_final_url
            && current.browser_final_url.is_some()
        {
            result.push(format!(
                "浏览器最终地址变化：{:?} → {:?}",
                base.browser_final_url, current.browser_final_url
            ));
        }
        if base.dom_sha256.is_some()
            && current.dom_sha256.is_some()
            && base.dom_sha256 != current.dom_sha256
        {
            result.push("渲染 DOM 摘要变化；动态内容或正常发布也会变化，需复核。".into());
        }
        if base.sha256 != current.sha256 {
            result.push(format!(
                "页面字节摘要变化：{} → {}；变化不自动判定劫持",
                base.sha256, current.sha256
            ));
        }
        for script in &current.scripts {
            match base.scripts.iter().find(|s| s.url == script.url) {
                None => result.push(format!("新增脚本来源：{}", script.url)),
                Some(old) if old.sha256 != script.sha256 => {
                    result.push(format!("脚本摘要或采集状态变化：{}", script.url))
                }
                _ => (),
            }
        }
        for old in &base.scripts {
            if !current.scripts.iter().any(|s| s.url == old.url) {
                result.push(format!("移除脚本：{}", old.url));
            }
        }
        for link in &current.external_links {
            if !base.external_links.contains(link) {
                result.push(format!("新增外链 / iframe：{link}"));
            }
        }
        for link in &current.hidden_links {
            if !base.hidden_links.contains(link) {
                result.push(format!("新增静态隐藏链接线索：{link}"));
            }
        }
    } else {
        result.push("尚无人工确认基线；首次观测需复核，不能自动视为可信。".into());
    }
    result.truncate(100);
    result
}
struct CapturedPage {
    snapshot: Snapshot,
    raw: Vec<u8>,
    scripts: Vec<Value>,
    redirect: Option<String>,
    redirect_responses: Vec<Value>,
}
/// 页面及每个脚本均受大小/超时限制。非法子资源只降低覆盖，不丢弃已采集页面。
async fn capture_page(
    url: &reqwest::Url,
    asset_id: &str,
    follow: bool,
) -> Result<CapturedPage, String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(12))
        .user_agent("GagaSecurityAssistant/0.7.0 authorized asset monitor")
        .build()
        .map_err(|e| e.to_string())?;
    let mut captured = CapturedPage {
        snapshot: Snapshot {
            id: uuid::Uuid::new_v4().to_string(),
            asset_id: asset_id.into(),
            created_at: Utc::now().to_rfc3339(),
            evidence_id: String::new(),
            status: None,
            title: String::new(),
            sha256: String::new(),
            scripts: vec![],
            external_links: vec![],
            hidden_links: vec![],
            coverage_gaps: vec![],
            final_url: url.to_string(),
            redirects: vec![],
            screenshot: None,
            screenshot_error: None,
            browser_final_url: None,
            browser_navigations: vec![],
            dom_sha256: None,
            changes: vec![],
            error: None,
            elapsed_ms: 0,
        },
        raw: vec![],
        scripts: vec![],
        redirect: None,
        redirect_responses: vec![],
    };
    let s = &mut captured.snapshot;
    let mut target_url = url.clone();
    let mut visited = BTreeSet::new();
    let (status, bytes, redirect) = loop {
        if !visited.insert(target_url.to_string()) || visited.len() > 8 {
            s.error = Some("页面跳转循环或超过 8 跳上限".into());
            return Ok(captured);
        }
        s.final_url = target_url.to_string();
        let (code, bytes, location) = match fetch(&client, &target_url, 1024 * 1024).await {
            Ok(v) => v,
            Err(error) => {
                s.error = Some(error);
                return Ok(captured);
            }
        };
        let html = String::from_utf8_lossy(&bytes);
        let meta = meta_target(&html);
        let next = if (300..400).contains(&code) {
            location.clone()
        } else {
            meta
        };
        if let Some(next) = next {
            use base64::Engine;
            let hop = json!({"url":target_url,"status":code,"location":next,"sha256":format!("{:x}",Sha256::digest(&bytes))});
            s.redirects.push(hop.clone());
            let mut raw = hop;
            raw["rawHtmlBase64"] = json!(base64::engine::general_purpose::STANDARD.encode(&bytes));
            captured.redirect_responses.push(raw);
            if follow {
                let next = match target_url
                    .join(&next)
                    .map_err(|e| e.to_string())
                    .and_then(|u| validate_url(u.as_str()))
                {
                    Ok(v) => v,
                    Err(e) => {
                        s.error = Some(format!("跳转地址被拒绝：{e}"));
                        return Ok(captured);
                    }
                };
                // Explicit assets may be private, but an unrelated redirect cannot
                // pivot into loopback/private networks or a credential endpoint.
                if next.host_str() != target_url.host_str() && !public_redirect_host(&next).await {
                    s.error = Some("跨主机跳转指向本地、私有或无法解析的地址，已阻止".into());
                    return Ok(captured);
                }
                target_url = next;
                continue;
            }
            s.coverage_gaps
                .push("跟随跳转已关闭；最终页面未采集。".into());
        }
        break (code, bytes, location);
    };
    s.final_url = target_url.to_string();
    s.status = Some(status);
    s.sha256 = format!("{:x}", Sha256::digest(&bytes));
    let page = inspect_page(&target_url, &String::from_utf8_lossy(&bytes));
    s.title = page.title;
    s.external_links = page.external;
    s.hidden_links = page.hidden;
    s.coverage_gaps.extend(page.coverage_gaps);
    captured.raw = bytes;
    captured.redirect = redirect;
    let mut fetched = 0;
    for src in page.scripts {
        let mut script = Script {
            url: src.clone(),
            sha256: None,
            bytes: 0,
            error: None,
        };
        let target = match validate_url(&src) {
            Ok(target) => target,
            Err(error) => {
                script.error = Some(format!("脚本地址被拒绝：{error}"));
                s.scripts.push(script);
                continue;
            }
        };
        if target.origin() != target_url.origin() {
            script.error = Some("跨源脚本只记录来源，不自动抓取；可显式登记该来源资产。".into());
        } else if fetched >= 8 {
            script.error = Some("本页脚本抓取上限 8 个，未抓取。".into());
        } else {
            fetched += 1;
            match fetch(&client, &target, 512 * 1024).await {
                Ok((code, bytes, location)) if (200..300).contains(&code) => {
                    script.sha256 = Some(format!("{:x}", Sha256::digest(&bytes)));
                    script.bytes = bytes.len();
                    let indicators: Vec<_> =
                        crate::intelligence::parse(&String::from_utf8_lossy(&bytes))
                            .into_iter()
                            .take(100)
                            .collect();
                    use base64::Engine;
                    captured.scripts.push(json!({"url":src,"sha256":script.sha256,"rawBodyBase64":base64::engine::general_purpose::STANDARD.encode(&bytes),"indicators":indicators,"redirect":location}));
                }
                Ok((code, _, location)) => {
                    script.error = Some(format!("脚本 HTTP {code}；重定向 {location:?}，未跟随"))
                }
                Err(error) => script.error = Some(error),
            }
        }
        s.scripts.push(script);
    }
    Ok(captured)
}
fn page_list_hits(store: &Store, case: &str, snapshot: &Snapshot) -> Result<Vec<Value>, String> {
    let mut hits = vec![];
    let mut seen = BTreeSet::new();
    // The destination itself is also an IOC: a redirect can leave no external
    // links in its final HTML. Apply the same global/case list precedence.
    let mut links: Vec<String> = snapshot
        .external_links
        .iter()
        .chain(snapshot.hidden_links.iter())
        .chain(snapshot.scripts.iter().map(|s| &s.url))
        .cloned()
        .collect();
    if !snapshot.final_url.is_empty() {
        links.push(snapshot.final_url.clone());
    }
    if let Some(url) = &snapshot.browser_final_url {
        links.push(url.clone());
    }
    for hop in &snapshot.redirects {
        if let (Some(base), Some(target)) = (hop["url"].as_str(), hop["location"].as_str()) {
            if let Ok(url) = reqwest::Url::parse(base).and_then(|u| u.join(target)) {
                links.push(url.to_string());
            }
        }
    }
    for link in &links {
        let mut indicators = vec![("url", link.clone())];
        if let Ok(url) = reqwest::Url::parse(link) {
            if let Some(host) = url.host_str() {
                indicators.push((
                    if host.parse::<std::net::IpAddr>().is_ok() {
                        "ip"
                    } else {
                        "domain"
                    },
                    host.into(),
                ));
            }
        }
        for (kind, value) in indicators {
            if !seen.insert((kind, value.clone())) {
                continue;
            }
            // 无效、带凭据的 URL 仍保留于原始页面与脚本覆盖记录；不作为合法 IOC 入库。
            if crate::intelligence::normalize(kind, &value).is_err() {
                continue;
            }
            let matched = crate::intelligence::matches(store, kind, &value, case)?;
            if matched["allow"] == true
                || matched["deny"] == true
                || matches!(
                    matched["knowledge"]["verdict"].as_str(),
                    Some("malicious" | "suspicious")
                )
            {
                hits.push(json!({"value":value,"match":matched}));
            }
        }
    }
    Ok(hits)
}
/// 启动时捕获 asset.case_id；调查切换不会改变后台快照和观测的事件归属。
/// HTTP 原文与容器浏览器分别留存；失败只降低对应覆盖，不丢弃已有材料。
pub async fn check_asset(
    store: &Store,
    app: Option<&tauri::AppHandle>,
    id: &str,
    manual: bool,
) -> Result<Snapshot, String> {
    let active = if manual { Some(store.active()?) } else { None };
    // 读取配置与领取任务在同一把锁内完成，重新检查启用和到期状态。
    // 调度器取出的 ID 可能已经被用户停用，不能把它当作持续有效的执行许可。
    let (asset, schedule_at): (Asset, String) = {
        let db = store.db.lock().map_err(|e| e.to_string())?;
        let (record, next_at): (String, String) = db
            .query_row(
                "SELECT record,next_at FROM monitor_assets WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "资产不存在")?;
        let asset: Asset = serde_json::from_str(&record).map_err(|e| e.to_string())?;
        if active.as_ref().is_some_and(|case| case != &asset.case_id) {
            return Err("资产不属于当前事件".into());
        }
        let claimed = db.execute(
            "UPDATE monitor_assets SET running=1 WHERE id=?1 AND running=0 AND (?2 OR (enabled=1 AND next_at<=?3))",
            params![id, manual, Utc::now().to_rfc3339()],
        ).map_err(|e| e.to_string())?;
        if claimed == 0 {
            return Err("资产正在巡检、已停用或尚未到期。".into());
        }
        (asset, next_at)
    };
    let started = Instant::now();
    let result = async {
        let url = validate_url(&asset.url)?;
        let captured = capture_page(&url, id, asset.follow_redirects).await?;
        let mut snapshot = captured.snapshot;
        let mut browser_record = Value::Null;
        let mut screenshot_png = None;
        if asset.auto_screenshot {
            let root = store.root.clone();
            let browser_url = asset.url.clone();
            let follow = asset.follow_redirects;
            // Docker CLI is blocking; keep the async HTTP scheduler responsive.
            let browser = tauri::async_runtime::spawn_blocking(move || {
                crate::monitor_browser::capture_root(&root, &browser_url, follow)
            }).await.map_err(|e| e.to_string()).and_then(|v| v);
            match browser {
                Ok(mut value) => {
                    use base64::Engine;
                    let png = value.as_object_mut().and_then(|o|o.remove("pngBase64")).and_then(|v|v.as_str().map(str::to_owned)).ok_or("截图容器缺少图像").and_then(|v|base64::engine::general_purpose::STANDARD.decode(v).map_err(|_|"截图编码无效"));
                    match png {
                        Ok(bytes) => { value["screenshotSha256"] = json!(format!("{:x}", Sha256::digest(&bytes))); screenshot_png = Some(bytes); },
                        Err(e) => snapshot.screenshot_error = Some(e.into()),
                    }
                    if let Some(note) = value["navigationError"].as_str() { snapshot.coverage_gaps.push(format!("浏览器加载未完整完成：{note}；截图仅记录当前可见状态。")); }
                    if let Some(gaps) = value["coverageGaps"].as_array() { snapshot.coverage_gaps.extend(gaps.iter().filter_map(Value::as_str).map(str::to_owned)); }
                    snapshot.browser_final_url = value["finalUrl"].as_str().map(str::to_owned);
                    snapshot.browser_navigations = value["navigations"].as_array().cloned().unwrap_or_default();
                    snapshot.dom_sha256 = value["domSha256"].as_str().map(str::to_owned);
                    browser_record = value;
                },
                Err(error) => snapshot.screenshot_error = Some(error),
            }
            if let Some(error) = &snapshot.screenshot_error {
                snapshot.coverage_gaps.push(format!("自动截图失败：{error}"));
                crate::runtime_log::event("error","monitoring","SCREENSHOT_FAILED",error,Some(id));
            }
        }
        let baseline = asset.baseline_id.as_deref().map(|id| snapshot_by_id(store, id)).transpose()?;
        snapshot.changes = changes(baseline.as_ref(), &snapshot);
        if let Some(location) = captured.redirect {
            if !asset.follow_redirects { snapshot.changes.push(format!("页面返回重定向：{location}；跟随跳转已关闭")); }
        }
        snapshot.elapsed_ms = started.elapsed().as_millis() as u64;
        let hits = page_list_hits(store, &asset.case_id, &snapshot)?;
        let summary = format!("资产 {} · HTTP {:?} · {} 项变化 / 待复核线索 · {} 个名单匹配；静态页面与同源 JS 检查。",
            asset.name, snapshot.status, snapshot.changes.len(), hits.len());
        use base64::Engine;
        let record = json!({"format":"gaga-monitor/1","kind":"web","assetId":asset.id,"assetUrl":asset.url,
            "summary":summary,"snapshot":snapshot,"listMatches":hits,
            "rawHtmlBase64":base64::engine::general_purpose::STANDARD.encode(&captured.raw),"scripts":captured.scripts,"redirectResponses":captured.redirect_responses,"browser":browser_record,"options":{"followRedirects":asset.follow_redirects,"autoScreenshot":asset.auto_screenshot},
            "limitations":["HTTP 原文与容器浏览器分别请求；浏览器按设置跟随 HTTP / JS 跳转，截图为 1440×900 视口，不含登录态。",
                "HTTP 最多 8 跳及 8 个同源脚本；脚本子资源的重定向只记录，不递归爬站。",
                "页面变化或名单命中仅为待复核线索，CDN 与正常发布也会改变摘要。"]});
        let evidence = store.archive_record(&asset.case_id, "资产巡检", &record)?;
        snapshot.evidence_id = evidence.id.clone();
        if let Some(png) = screenshot_png {
            match store.archive_monitor_screenshot(&asset.case_id, &evidence.id, &png,
                browser_record["capturedAt"].as_str().unwrap_or(&snapshot.created_at),
                browser_record["finalUrl"].as_str().unwrap_or(&asset.url), &snapshot.sha256) {
                Ok(shot) => snapshot.screenshot = Some(shot),
                Err(error) => { snapshot.screenshot_error = Some(format!("截图归档失败：{error}")); snapshot.changes.push(format!("截图归档失败：{error}")); crate::runtime_log::event("error","monitoring","SCREENSHOT_ARCHIVE_FAILED",&error,Some(id)); }
            }
        }

        store.db.lock().map_err(|e| e.to_string())?.execute(
            "INSERT INTO monitor_snapshots(id,asset_id,created_at,evidence_id,record) VALUES(?1,?2,?3,?4,?5)",
            params![snapshot.id,snapshot.asset_id,snapshot.created_at,snapshot.evidence_id,serde_json::to_string(&snapshot).map_err(|e|e.to_string())?]
        ).map_err(|e| e.to_string())?;
        if !snapshot.changes.is_empty() || !hits.is_empty() {
            record_observation(store,"web",asset.name.clone(),summary,&evidence,
                json!({"assetId":asset.id,"changes":snapshot.changes,"listMatches":hits,"status":snapshot.status,
                    "sha256":snapshot.sha256,"scriptSources":snapshot.scripts,"hiddenLinks":snapshot.hidden_links}))?;
        }
        let status = if snapshot.error.is_some() {"采集失败"} else if snapshot.changes.is_empty() {"与基线一致"} else {"发现变化 / 待复核"};
        // 只更新采集字段；并发点击停用或确认基线不会被任务启动时的旧 Asset 覆盖。
        store.db.lock().map_err(|e|e.to_string())?.execute(
            "UPDATE monitor_assets SET record=json_set(record,'$.lastSnapshotId',?2,'$.lastStatus',?3,'$.lastChecked',?4) WHERE id=?1",
            params![asset.id,snapshot.id,status,snapshot.created_at]
        ).map_err(|e|e.to_string())?;
        if let Some(app) = app { let _ = app.emit("platform-updated",json!({"caseId":asset.case_id,"kind":"web"})); }
        Ok::<Snapshot,String>(snapshot)
    }.await;
    // 用户在采集期间停用或重新启用会改写 next_at；旧任务只能推进自己领取时的调度。
    store.db.lock().map_err(|e| e.to_string())?.execute(
        "UPDATE monitor_assets SET running=0,next_at=CASE WHEN next_at=?3 THEN ?2 ELSE next_at END WHERE id=?1",
        params![
            id,
            (Utc::now() + ChronoDuration::seconds(asset.interval_secs as i64)).to_rfc3339(),
            schedule_at
        ],
    ).map_err(|e|e.to_string())?;
    result
}
async fn ai_tick(store: &Store, app: Option<&tauri::AppHandle>) -> Result<(), String> {
    let cfg = ai_settings(store)?;
    if !cfg.enabled || crate::privacy::get(store)?.ai_locked {
        return Ok(());
    }
    let Some(o) = claim_ai_observation(store, &cfg)? else {
        return Ok(());
    };
    let result = async {
        let e = store.evidence_for_case(&o.case_id, &o.evidence_id)?;
        let material=crate::ai::redact_http_material(&format!("自动监控研判，仅包含观测摘要；不含完整网页、JS、包载荷或采集文件。\n观测 ID：{}\n原始证据：{} / {}\n{}\n{}",o.id,e.id,e.sha256,o.summary,crate::analyzers::cut(&o.detail.to_string(),14000)));
        crate::ai::review_record(store,app,e,material,"请核对当前监控观测的风险与证据缺口，不能把变化、名单命中或模型推断直接当成入侵；逐项引用实际来源。".into()).await
    }.await;
    let (state, review, error) = match result {
        Ok(r) => ("completed", Some(r.id), None),
        Err(error) => ("failed", None, Some(error)),
    };
    let mut saved = o.clone();
    if let Some(error) = &error {
        crate::runtime_log::event(
            "error",
            "monitoring",
            "AI_REVIEW_FAILED",
            error,
            Some(&o.id),
        );
    }
    saved.error = error;
    store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .execute(
            "UPDATE monitor_observations SET ai_state=?2,review_id=?3,record=?4 WHERE id=?1",
            params![
                o.id,
                state,
                review,
                serde_json::to_string(&saved).map_err(|e| e.to_string())?
            ],
        )
        .map_err(|e| e.to_string())?;
    if let Some(app) = app {
        let _ = app.emit("platform-updated", json!({"caseId":o.case_id,"kind":"ai"}));
    }
    Ok(())
}

/// 将授权复核、预算检查和领取合并在一次事务中。旧授权、历史积压和其他事件
/// 都不进入自动外发队列；人工仍可从证据页逐条预览后发送。
fn claim_ai_observation(store: &Store, cfg: &AiSettings) -> Result<Option<Observation>, String> {
    let since = (Utc::now() - ChronoDuration::hours(1)).to_rfc3339();
    let mut db = store.db.lock().map_err(|e| e.to_string())?;
    let tx = db.transaction().map_err(|e| e.to_string())?;
    let current = ai_settings_db(&tx)?;
    if !current.enabled
        || current.revision != cfg.revision
        || crate::privacy::read_db(&tx)?.ai_locked
    {
        return Ok(None);
    }
    let count: u64 = tx
        .query_row(
            "SELECT count(*) FROM monitor_ai_calls WHERE started_at>?1",
            [&since],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let last: Option<String> = tx
        .query_row("SELECT max(started_at) FROM monitor_ai_calls", [], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())?;
    if count >= cfg.max_per_hour
        || last
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok())
            .is_some_and(|t| {
                (Utc::now() - t.with_timezone(&Utc)).num_seconds() < cfg.min_interval_secs as i64
            })
    {
        return Ok(None);
    }
    let record:Option<String>=tx.query_row("SELECT record FROM monitor_observations WHERE ai_state='pending' AND case_id=?1 AND rowid>?2 ORDER BY rowid LIMIT 1",params![current.scope_case_id,current.after_rowid],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
    let Some(record) = record else {
        return Ok(None);
    };
    let o: Observation = serde_json::from_str(&record).map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE monitor_observations SET ai_state='running' WHERE id=?1 AND ai_state='pending'",
        [&o.id],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO monitor_ai_calls VALUES(?1,?2)",
        params![uuid::Uuid::new_v4().to_string(), Utc::now().to_rfc3339()],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(Some(o))
}
pub fn start_workers(store: Arc<Store>, app: tauri::AppHandle) {
    let slots = Arc::new(tokio::sync::Semaphore::new(4));
    let ai_slot = Arc::new(tokio::sync::Semaphore::new(1));
    tauri::async_runtime::spawn(async move {
        loop {
            let due: Vec<String> = {
                let db = store.db.lock();
                if let Ok(db) = db {
                    db.prepare("SELECT id FROM monitor_assets WHERE enabled=1 AND running=0 AND next_at<=?1 LIMIT 100").ok().and_then(|mut q|q.query_map([Utc::now().to_rfc3339()],|r|r.get::<_,String>(0)).ok().map(|rows|rows.filter_map(Result::ok).collect())).unwrap_or_default()
                } else {
                    vec![]
                }
            };
            for id in due {
                if let Ok(permit) = slots.clone().try_acquire_owned() {
                    let store = store.clone();
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let _permit = permit;
                        if let Err(error) = check_asset(&store, Some(&app), &id, false).await {
                            crate::runtime_log::event(
                                "error",
                                "monitoring",
                                "ASSET_CHECK_FAILED",
                                &error,
                                None,
                            );
                        }
                    });
                } else {
                    break;
                }
            }
            if let Ok(permit) = ai_slot.clone().try_acquire_owned() {
                let store = store.clone();
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = ai_tick(&store, Some(&app)).await {
                        crate::runtime_log::event(
                            "error",
                            "monitoring",
                            "AUTO_AI_FAILED",
                            &error,
                            None,
                        );
                    }
                });
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    fn store() -> Store {
        Store::open(
            std::env::temp_dir().join(format!("gaga-monitor-test-{}", uuid::Uuid::new_v4())),
        )
        .unwrap()
    }
    #[test]
    fn static_hidden_links_and_script_sources_are_extracted() {
        let url = validate_url("https://example.test/").unwrap();
        let page=inspect_page(&url,"<title>Fixture</title><script src='/app.js'></script><script src='https://cdn.test/x.js'></script><a hidden href='https://hidden.test/'>x</a><div style='display: none'><a href='https://nested.test/'>x</a></div>");
        assert_eq!(page.title, "Fixture");
        assert_eq!(page.hidden.len(), 2);
        assert_eq!(page.scripts.len(), 2);
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("https://u:p@example.test/").is_err());
        assert!(validate_url("http://169.254.169.254/").is_err());
    }
    #[test]
    fn unchanged_navigation_stub_keeps_its_coverage_gap() {
        let url = validate_url("https://example.test/").unwrap();
        let html = r#"<script>location.replace(location.href.replace("https://","http://"));</script><noscript><meta HTTP-EQUIV="Refresh" content="0;url=http://example.test/"></noscript>"#;
        let page = inspect_page(&url, html);
        assert_eq!(page.coverage_gaps.len(), 2);
        let mut snapshot: Snapshot = serde_json::from_value(json!({"id":"s", "assetId":"a", "createdAt":"2026-10-31T00:00:00Z", "evidenceId":"e", "status":200, "title":"", "sha256":"same", "scripts":[], "externalLinks":[], "hiddenLinks":[], "changes":[], "error":null, "elapsedMs":1})).unwrap();
        assert!(snapshot.coverage_gaps.is_empty()); // Older snapshots still load.
        snapshot.coverage_gaps = page.coverage_gaps;
        assert_eq!(changes(Some(&snapshot), &snapshot).len(), 2);
        assert!(changes(Some(&snapshot), &snapshot)
            .iter()
            .all(|c| c.contains("页面覆盖受限")));
    }
    #[test]
    fn real_http_baseline_js_change_and_redirect_are_archived() {
        let store = store();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let version = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let v = version.clone();
        let server = std::thread::spawn(move || {
            for _ in 0..5 {
                let (mut s, _) = listener.accept().unwrap();
                let mut buf = [0; 4096];
                let n = s.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let data = if req.starts_with("GET /app.js ") {
                    format!(
                        "let revision={}; let callback='https://ioc.example.test/path';",
                        v.load(std::sync::atomic::Ordering::SeqCst)
                    )
                } else if req.starts_with("GET /redirect ") {
                    s.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://external.example.test/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                    continue;
                } else {
                    format!("<title>Local fixture</title><script src='/app.js'></script><script src='https://cdn.example.test/external.js'></script><a hidden href='https://hidden.example.test/{}'>hidden</a>",v.load(std::sync::atomic::Ordering::SeqCst))
                };
                write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    data.len(),
                    data
                )
                .unwrap();
            }
        });
        import_assets(&store, &format!("fixture,{base}/"), 60).unwrap();
        let a = assets(&store, Some(&store.active().unwrap())).unwrap()[0].clone();
        assert!(!a.enabled);
        let first = tauri::async_runtime::block_on(check_asset(&store, None, &a.id, true)).unwrap();
        assert_eq!(first.scripts.len(), 2);
        assert!(first
            .scripts
            .iter()
            .any(|s| s.error.as_ref().is_some_and(|e| e.contains("跨源"))));
        accept_baseline(&store, &a.id, &first.id).unwrap();
        version.store(2, std::sync::atomic::Ordering::SeqCst);
        let second =
            tauri::async_runtime::block_on(check_asset(&store, None, &a.id, true)).unwrap();
        assert!(second.changes.iter().any(|s| s.contains("脚本摘要")));
        assert!(second.changes.iter().any(|s| s.contains("隐藏")));
        let raw = std::fs::read(store.root.join("evidence").join(&second.evidence_id)).unwrap();
        let record: Value = serde_json::from_slice(&raw).unwrap();
        assert!(record["rawHtmlBase64"].as_str().unwrap().len() > 10);
        assert!(record["scripts"][0]["rawBodyBase64"].is_string());
        assert!(crate::ai::material(&store, &second.evidence_id)
            .unwrap()
            .contains("脚本摘要"));
        import_assets(&store, &format!("redirect,{base}/redirect"), 60).unwrap();
        let redirect = assets(&store, None)
            .unwrap()
            .into_iter()
            .find(|a| a.name == "redirect")
            .unwrap();
        let r =
            tauri::async_runtime::block_on(check_asset(&store, None, &redirect.id, true)).unwrap();
        assert_eq!(r.status, Some(302));
        assert!(accept_baseline(&store, &redirect.id, &r.id).is_err());
        server.join().unwrap();
        let old = store.active().unwrap();
        store.create_case("other".into()).unwrap();
        assert!(tauri::async_runtime::block_on(check_asset(&store, None, &a.id, true)).is_err());
        let bg = store
            .archive_record(
                &old,
                "background-fixture",
                &json!({"format":"gaga-monitor/1","kind":"web","summary":"fixture"}),
            )
            .unwrap();
        assert_eq!(bg.case_id, old);
        std::fs::remove_dir_all(&store.root).unwrap();
    }
    #[test]
    fn configurable_redirects_archive_each_hop_and_reject_loops() {
        let store = store();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for _ in 0..6 {
                let (mut s, _) = listener.accept().unwrap();
                let mut buf = [0; 4096];
                let n = s.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                if req.starts_with("GET /start ") || req.starts_with("GET /loop ") {
                    let dest = if req.starts_with("GET /loop ") {
                        "/loop"
                    } else {
                        "/meta"
                    };
                    write!(s,"HTTP/1.1 302 Found\r\nLocation: {dest}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                } else {
                    let data = if req.starts_with("GET /meta ") {
                        "<meta http-equiv='Refresh' content='0;url=/final'>"
                    } else {
                        "<title>Final page</title><h1>Captured</h1>"
                    };
                    write!(
                        s,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        data.len(),
                        data
                    )
                    .unwrap();
                }
            }
        });
        import_configured(
            &store,
            &format!("fixture,{base}/start\nloop,{base}/loop"),
            60,
            true,
            false,
        )
        .unwrap();
        let all = assets(&store, None).unwrap();
        let a = all.iter().find(|a| a.name == "fixture").unwrap();
        let first = tauri::async_runtime::block_on(check_asset(&store, None, &a.id, true)).unwrap();
        assert_eq!(first.title, "Final page");
        assert!(first.final_url.ends_with("/final"));
        assert_eq!(first.redirects.len(), 2);
        assert!(first.redirects[1]["rawHtmlBase64"].is_null());
        let raw: Value = serde_json::from_slice(
            &std::fs::read(store.root.join("evidence").join(&first.evidence_id)).unwrap(),
        )
        .unwrap();
        assert!(
            raw["redirectResponses"][1]["rawHtmlBase64"]
                .as_str()
                .unwrap()
                .len()
                > 10
        );
        configure_asset(&store, &a.id, false, false).unwrap();
        let second =
            tauri::async_runtime::block_on(check_asset(&store, None, &a.id, true)).unwrap();
        assert_eq!(second.status, Some(302));
        assert!(second.coverage_gaps.iter().any(|g| g.contains("关闭")));
        let lo = all.iter().find(|a| a.name == "loop").unwrap();
        let result =
            tauri::async_runtime::block_on(check_asset(&store, None, &lo.id, true)).unwrap();
        assert!(result.error.unwrap().contains("循环"));
        // A final direct request verifies the server's expected request count.
        tauri::async_runtime::block_on(capture_page(
            &validate_url(&format!("{base}/final")).unwrap(),
            "fixture",
            false,
        ))
        .unwrap();
        server.join().unwrap();
        let original_case = store.active().unwrap();
        store.create_case("other".into()).unwrap();
        assert!(configure_asset(&store, &a.id, true, true).is_err());
        assert_eq!(assets(&store, Some(&original_case)).unwrap().len(), 2);
        std::fs::remove_dir_all(&store.root).unwrap();
    }
    #[test]
    fn automatic_screenshot_is_bound_to_capture_case_and_report_after_switch() {
        use base64::Engine;
        let store = store();
        let case = store.active().unwrap();
        let evidence = store
            .archive_record(
                &case,
                "fixture",
                &json!({"format":"gaga-monitor/1","kind":"web","summary":"fixture"}),
            )
            .unwrap();
        let other = store.create_case("other".into()).unwrap().id;
        let png = base64::engine::general_purpose::STANDARD.decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=").unwrap();
        let shot = store
            .archive_monitor_screenshot(
                &case,
                &evidence.id,
                &png,
                "2026-10-31T10:21:00+08:00",
                "https://example.test/",
                "abc",
            )
            .unwrap();
        assert!(store.screenshot_data(shot.id.clone()).is_err());
        assert!(store
            .archive_monitor_screenshot(
                &other,
                &evidence.id,
                &png,
                "2026-10-31T10:21:00+08:00",
                "https://example.test/",
                "abc"
            )
            .is_err());
        store.switch_case(case.clone()).unwrap();
        assert!(store
            .screenshot_data(shot.id)
            .unwrap()
            .starts_with("data:image/png;base64,"));
        assert_eq!(store.workspace().unwrap().nodes[0].screenshots.len(), 1);
        std::fs::remove_dir_all(&store.root).unwrap();
    }
    #[test]
    fn ai_budget_failure_and_background_case_are_preserved() {
        let store = store();
        let case = store.active().unwrap();
        let e = store
            .archive_record(
                &case,
                "fixture",
                &json!({"format":"gaga-monitor/1","kind":"web","summary":"local test observation"}),
            )
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let _ = s.read(&mut request);
            s.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        crate::ai::save_config(&store, endpoint, "fixture".into(), "".into(), false).unwrap();
        save_ai_settings(
            &store,
            AiSettings {
                enabled: true,
                min_interval_secs: 15,
                max_per_hour: 1,
                ..Default::default()
            },
        )
        .unwrap();
        record_observation(
            &store,
            "web",
            "fixture".into(),
            "test observation".into(),
            &e,
            json!({"status":200}),
        )
        .unwrap();
        store.create_case("different active case".into()).unwrap();
        tauri::async_runtime::block_on(ai_tick(&store, None)).unwrap();
        server.join().unwrap();
        let obs = observations(&store, &case).unwrap();
        assert_eq!(obs[0].ai_state, "failed");
        assert!(obs[0].error.as_ref().unwrap().contains("503"));
        let run: crate::investigation::AnalysisRun = serde_json::from_str(
            &store
                .db
                .lock()
                .unwrap()
                .query_row::<String, _, _>("SELECT record FROM analysis_runs", [], |r| r.get(0))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(run.case_id, case);
        assert_eq!(run.state, "failed");
        record_observation(
            &store,
            "web",
            "second".into(),
            "queue".into(),
            &e,
            json!({}),
        )
        .unwrap();
        tauri::async_runtime::block_on(ai_tick(&store, None)).unwrap();
        assert_eq!(
            observations(&store, &case)
                .unwrap()
                .iter()
                .filter(|o| o.ai_state == "pending")
                .count(),
            1
        );
        std::fs::remove_dir_all(&store.root).unwrap();
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn audit_072_enabling_auto_ai_does_not_send_historical_observations() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let store = Store::open(root.clone()).unwrap();
        let case = store.active().unwrap();
        let e = store
            .archive_record(
                &case,
                "old",
                &json!({"format":"gaga-monitor/1","kind":"web","summary":"old observation"}),
            )
            .unwrap();
        record_observation(
            &store,
            "web",
            "old".into(),
            "must stay local until manually selected".into(),
            &e,
            json!({}),
        )
        .unwrap();
        crate::ai::save_config(
            &store,
            "http://127.0.0.1:9/v1".into(),
            "fixture".into(),
            "".into(),
            false,
        )
        .unwrap();
        save_ai_settings(
            &store,
            AiSettings {
                enabled: true,
                min_interval_secs: 15,
                max_per_hour: 1,
                ..Default::default()
            },
        )
        .unwrap();
        tauri::async_runtime::block_on(ai_tick(&store, None)).unwrap();
        let calls: u64 = store
            .db
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM monitor_ai_calls", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            calls, 0,
            "enabling auto AI must not send its historical backlog"
        );
        assert_eq!(observations(&store, &case).unwrap()[0].ai_state, "pending");
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn scoped_auto_ai_rejects_legacy_stale_and_foreign_authorizations() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let store = Store::open(root.clone()).unwrap();
        store
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO settings VALUES('monitor_ai_settings',?1)",
                [r#"{"enabled":true,"minIntervalSecs":60,"maxPerHour":1}"#],
            )
            .unwrap();
        assert!(!ai_settings(&store).unwrap().enabled);
        assert!(ai_settings(&store).unwrap().needs_confirmation);
        crate::ai::save_config(
            &store,
            "http://127.0.0.1:9/v1".into(),
            "fixture".into(),
            "".into(),
            false,
        )
        .unwrap();
        let selected = store.active().unwrap();
        let cfg = AiSettings {
            enabled: true,
            min_interval_secs: 15,
            max_per_hour: 1,
            scope_case_id: Some("forged".into()),
            enabled_after: Some("2000-01-01T00:00:00Z".into()),
            ..Default::default()
        };
        save_ai_settings(&store, cfg.clone()).unwrap();
        let granted = ai_settings(&store).unwrap();
        assert_eq!(granted.scope_case_id.as_deref(), Some(selected.as_str()));
        assert_ne!(granted.enabled_after, cfg.enabled_after);
        let e = store
            .archive_record(
                &selected,
                "new",
                &json!({"format":"gaga-monitor/1","kind":"web","summary":"new"}),
            )
            .unwrap();
        record_observation(&store, "web", "new".into(), "new".into(), &e, json!({})).unwrap();
        assert_eq!(queue_stats(&store, &selected).unwrap()["eligible"], 1);
        save_ai_settings(&store, AiSettings::default()).unwrap();
        assert!(claim_ai_observation(&store, &granted).unwrap().is_none());
        save_ai_settings(&store, cfg).unwrap();
        let current = ai_settings(&store).unwrap();
        assert!(claim_ai_observation(&store, &granted).unwrap().is_none());
        assert!(
            claim_ai_observation(&store, &current).unwrap().is_none(),
            "re-enable must not replay earlier observations"
        );
        let foreign = store.create_case("foreign".into()).unwrap().id;
        let e = store
            .archive_record(
                &foreign,
                "foreign",
                &json!({"format":"gaga-monitor/1","kind":"web","summary":"foreign"}),
            )
            .unwrap();
        record_observation(
            &store,
            "web",
            "foreign".into(),
            "foreign".into(),
            &e,
            json!({}),
        )
        .unwrap();
        assert!(claim_ai_observation(&store, &current).unwrap().is_none());
        assert_eq!(queue_stats(&store, &foreign).unwrap()["retained"], 1);
        crate::privacy::save(&store, crate::privacy::Settings { ai_locked: true }).unwrap();
        assert!(save_ai_settings(
            &store,
            AiSettings {
                enabled: true,
                ..Default::default()
            }
        )
        .is_err());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn concurrent_auto_claims_share_one_budget() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let store = Arc::new(Store::open(root.clone()).unwrap());
        crate::ai::save_config(
            &store,
            "http://127.0.0.1:9/v1".into(),
            "fixture".into(),
            "".into(),
            false,
        )
        .unwrap();
        save_ai_settings(
            &store,
            AiSettings {
                enabled: true,
                max_per_hour: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let cfg = ai_settings(&store).unwrap();
        let case = store.active().unwrap();
        let e = store
            .archive_record(
                &case,
                "new",
                &json!({"format":"gaga-monitor/1","kind":"web","summary":"new"}),
            )
            .unwrap();
        for _ in 0..2 {
            record_observation(&store, "web", "new".into(), "new".into(), &e, json!({})).unwrap();
        }
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let cfg = cfg.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    claim_ai_observation(&store, &cfg).unwrap().is_some()
                })
            })
            .collect();
        let count = workers
            .into_iter()
            .filter_map(|w| w.join().unwrap().then_some(()))
            .count();
        assert_eq!(count, 1);
        assert_eq!(
            observations(&store, &case)
                .unwrap()
                .iter()
                .filter(|o| o.ai_state == "running")
                .count(),
            1
        );
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn auto_authorization_boundary_survives_wall_clock_changes() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let store = Store::open(root.clone()).unwrap();
        let case = store.active().unwrap();
        let e = store
            .archive_record(
                &case,
                "fixture",
                &json!({"format":"gaga-monitor/1","kind":"web","summary":"fixture"}),
            )
            .unwrap();
        let old =
            record_observation(&store, "web", "old".into(), "old".into(), &e, json!({})).unwrap();
        store
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE monitor_observations SET created_at='2099-01-01T00:00:00Z' WHERE id=?1",
                [old.id],
            )
            .unwrap();
        crate::ai::save_config(
            &store,
            "http://127.0.0.1:9/v1".into(),
            "fixture".into(),
            "".into(),
            false,
        )
        .unwrap();
        save_ai_settings(
            &store,
            AiSettings {
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
        let new =
            record_observation(&store, "web", "new".into(), "new".into(), &e, json!({})).unwrap();
        store
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE monitor_observations SET created_at='2000-01-01T00:00:00Z' WHERE id=?1",
                [&new.id],
            )
            .unwrap();
        let claimed = claim_ai_observation(&store, &ai_settings(&store).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(claimed.id, new.id);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn audit_071_stale_scheduler_cannot_run_a_disabled_asset() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let store = Store::open(root.clone()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        drop(listener);
        import_assets(&store, &url, 60).unwrap();
        let asset = assets(&store, None).unwrap().remove(0);
        toggle_asset(&store, &asset.id, true).unwrap();
        // The scheduler already holds this ID when the user disables the asset.
        toggle_asset(&store, &asset.id, false).unwrap();
        let result = tauri::async_runtime::block_on(check_asset(&store, None, &asset.id, false));
        assert!(result.is_err(), "disabled asset was contacted and archived");
        assert!(store.workspace().unwrap().evidence.is_empty());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn audit_071_running_check_preserves_reenable_schedule() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let store = Arc::new(Store::open(root.clone()).unwrap());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        import_assets(
            &store,
            &format!("http://{}/", listener.local_addr().unwrap()),
            3600,
        )
        .unwrap();
        let asset = assets(&store, None).unwrap().remove(0);
        toggle_asset(&store, &asset.id, true).unwrap();
        let worker_store = store.clone();
        let id = asset.id.clone();
        let worker = std::thread::spawn(move || {
            tauri::async_runtime::block_on(check_asset(&worker_store, None, &id, false))
        });
        let started = Instant::now();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && started.elapsed() < Duration::from_secs(5) =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                other => panic!("巡检未启动：{other:?}"),
            }
        };
        toggle_asset(&store, &asset.id, false).unwrap();
        toggle_asset(&store, &asset.id, true).unwrap();
        let schedule: String = store
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT next_at FROM monitor_assets WHERE id=?1",
                [&asset.id],
                |r| r.get(0),
            )
            .unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\ninert")
            .unwrap();
        drop(stream);
        worker.join().unwrap().unwrap();
        let current: (String, u32) = store
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT next_at,running FROM monitor_assets WHERE id=?1",
                [&asset.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(current, (schedule, 0));
        assert!(assets(&store, None).unwrap()[0].enabled);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn invalid_subresource_retains_page_evidence_and_never_becomes_clear() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let store = Store::open(root.clone()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for body in ["<title>fixture</title><script src='http://169.254.169.254/meta.js'></script><script src='/ok.js'></script>", "console.log('inert');"] {
                let (mut stream,_)=listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut request=[0;4096];let _=stream.read(&mut request);
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        import_assets(&store, &url, 60).unwrap();
        let asset = assets(&store, None).unwrap().remove(0);
        let snapshot =
            tauri::async_runtime::block_on(check_asset(&store, None, &asset.id, true)).unwrap();
        server.join().unwrap();
        assert!(snapshot.error.is_none());
        assert_eq!(snapshot.title, "fixture");
        assert_eq!(snapshot.scripts.len(), 2);
        assert!(snapshot
            .scripts
            .iter()
            .any(|s| s.error.as_deref().is_some_and(|v| v.contains("地址被拒绝"))));
        assert!(snapshot.scripts.iter().any(|s| s.sha256.is_some()));
        let changed = changes(Some(&snapshot), &snapshot);
        assert!(changed.iter().any(|s| s.contains("覆盖受限")));
        let evidence = store
            .evidence_for_case(&asset.case_id, &snapshot.evidence_id)
            .unwrap();
        assert!(
            std::fs::read_to_string(root.join("evidence").join(evidence.id))
                .unwrap()
                .contains("rawHtmlBase64")
        );
        toggle_asset(&store, &asset.id, true).unwrap();
        accept_baseline(&store, &asset.id, &snapshot.id).unwrap();
        toggle_asset(&store, &asset.id, false).unwrap();
        let updated = assets(&store, None).unwrap().remove(0);
        assert!(!updated.enabled);
        assert_eq!(updated.baseline_id, Some(snapshot.id.clone()));
        assert_eq!(updated.last_snapshot_id, Some(snapshot.id));
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
