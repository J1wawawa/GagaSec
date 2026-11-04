use crate::{
    analyzers,
    store::{Store, Workspace},
};
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tauri::State;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub line: usize,
    pub raw_time: String,
    pub at: Option<String>,
    pub source_ip: Option<String>,
    pub kind: String,
    pub title: String,
    pub level: String,
    pub excerpt: String,
    pub tags: Vec<String>,
    pub time_basis: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    pub reference_year: Option<i32>,
    pub offset_minutes: Option<i32>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    pub evidence_id: Option<String>,
    pub source_ip: Option<String>,
    pub kind: Option<String>,
    pub after: Option<Cursor>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    pub at: String,
    pub evidence_id: String,
    pub line: u64,
}
pub fn event(
    line: usize,
    text: &str,
    source_ip: Option<String>,
    rules: Vec<(&str, &str)>,
) -> Event {
    static COMMON: OnceLock<regex::Regex> = OnceLock::new();
    static SYS: OnceLock<regex::Regex> = OnceLock::new();
    let common = COMMON.get_or_init(|| {
        regex::Regex::new(r"\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]").unwrap()
    });
    let sys = SYS.get_or_init(|| {
        regex::Regex::new(
            r"^(?:([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(\d{4}-\d{2}-\d{2}T\S+))",
        )
        .unwrap()
    });
    let raw_time = common
        .captures(text)
        .map(|c| c[1].to_owned())
        .or_else(|| {
            sys.captures(text)
                .map(|c| c.get(1).or_else(|| c.get(2)).unwrap().as_str().to_owned())
        })
        .or_else(|| {
            let v: Value = serde_json::from_str(text).ok()?;
            ["timestamp", "@timestamp", "time", "time_local"]
                .iter()
                .find_map(|k| v.get(*k).and_then(Value::as_str).map(str::to_owned))
        })
        .unwrap_or_default();
    let title = rules[0].1.to_owned();
    let kind = if title.contains("认证失败") {
        "ssh_failure"
    } else if title.contains("登录成功") {
        "ssh_success"
    } else if title.contains("sudo") {
        "sudo"
    } else if title.contains("定时") {
        "cron"
    } else if title.contains("上传目录") {
        "script_access"
    } else if title.contains("敏感配置") {
        "sensitive_path"
    } else if title.contains("路径穿越") {
        "traversal"
    } else {
        "injection"
    };
    let level = if rules.iter().any(|(l, _)| *l == "high") {
        "high"
    } else if rules.iter().any(|(l, _)| *l == "medium") {
        "medium"
    } else {
        "low"
    };
    let mut e = Event {
        line,
        raw_time,
        at: None,
        source_ip,
        kind: kind.into(),
        title,
        level: level.into(),
        excerpt: analyzers::cut(text, 2000),
        tags: rules.iter().map(|(_, t)| t.to_string()).collect(),
        time_basis: String::new(),
    };
    normalize(&mut e, &Options::default());
    e
}
fn normalize(e: &mut Event, o: &Options) {
    let raw = e.raw_time.trim();
    let explicit = DateTime::parse_from_rfc3339(raw)
        .ok()
        .or_else(|| DateTime::parse_from_str(raw, "%d/%b/%Y:%H:%M:%S %z").ok());
    let provided = || -> Option<DateTime<FixedOffset>> {
        let offset = FixedOffset::east_opt(o.offset_minutes? * 60)?;
        let naive = NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S")
            .ok()
            .or_else(|| {
                NaiveDateTime::parse_from_str(
                    &format!("{} {raw}", o.reference_year?),
                    "%Y %b %e %H:%M:%S",
                )
                .ok()
            })?;
        offset.from_local_datetime(&naive).single()
    };
    let parsed = explicit.or_else(provided);
    e.time_basis = if explicit.is_some() {
        "原文包含年份和时区"
    } else if parsed.is_some() {
        "使用用户补充的年份 / 时区；需核对跨年与主机时钟"
    } else {
        "时间未确定：缺少年份、时区或有效时间，未猜测发生时间"
    }
    .into();
    e.at = parsed.map(|d| {
        d.with_timezone(&Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    });
}
fn connection(store: &Store, case: &str) -> Result<Connection, String> {
    uuid::Uuid::parse_str(case).map_err(|_| "事件标识无效")?;
    let dir = store.root.join("log-index");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let db = Connection::open(dir.join(format!("{case}.sqlite3"))).map_err(|e| e.to_string())?;
    db.busy_timeout(Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-4096;
      CREATE TABLE IF NOT EXISTS events(evidence_id TEXT NOT NULL,line INTEGER NOT NULL,at TEXT,source_ip TEXT,kind TEXT NOT NULL,record TEXT NOT NULL,PRIMARY KEY(evidence_id,line));
      CREATE INDEX IF NOT EXISTS events_time ON events(coalesce(at,'~'),evidence_id,line);
      CREATE INDEX IF NOT EXISTS events_source ON events(source_ip,kind,at);
      CREATE TABLE IF NOT EXISTS metadata(evidence_id TEXT PRIMARY KEY,record TEXT NOT NULL);").map_err(|e|e.to_string())?;
    Ok(db)
}
/// Remove only this failed import's derived rows. Raw input is never changed.
pub fn discard_import(store: &Store, case: &str, id: &str) -> Result<(), String> {
    let mut db = connection(store, case)?;
    let tx = db.transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM events WHERE evidence_id=?1", [id])
        .map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM metadata WHERE evidence_id=?1", [id])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}
pub fn index(
    store: &Store,
    path: &Path,
    case: &str,
    id: &str,
    options: Options,
) -> Result<analyzers::AnalysisReport, String> {
    index_observed(
        store,
        path,
        case,
        id,
        options,
        &crate::analysis_progress::Silent,
    )
}
pub fn index_observed(
    store: &Store,
    path: &Path,
    case: &str,
    id: &str,
    options: Options,
    observer: &dyn crate::analysis_progress::Observer,
) -> Result<analyzers::AnalysisReport, String> {
    if options
        .reference_year
        .is_some_and(|y| !(1970..=2200).contains(&y))
        || options
            .offset_minutes
            .is_some_and(|o| !(-720..=840).contains(&o))
    {
        return Err("年份或时区范围无效".into());
    }
    let mut db = connection(store, case)?;
    let tx = db.transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM events WHERE evidence_id=?1", [id])
        .map_err(|e| e.to_string())?;
    let mut total = 0u64;
    let mut unknown = 0u64;
    let mut kinds = std::collections::BTreeMap::<String, u64>::new();
    let mut insert = tx
        .prepare("INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6)")
        .map_err(|e| e.to_string())?;
    let mut report = analyzers::analyze_log_observed(
        path,
        |mut event| {
            normalize(&mut event, &options);
            total += 1;
            unknown += u64::from(event.at.is_none());
            *kinds.entry(event.kind.clone()).or_default() += 1;
            insert
                .execute(params![
                    id,
                    event.line as i64,
                    event.at,
                    event.source_ip,
                    event.kind,
                    serde_json::to_string(&event).map_err(|e| e.to_string())?
                ])
                .map_err(|e| e.to_string())?;
            Ok(())
        },
        observer,
    )?;
    drop(insert);
    let meta = json!({"events":total,"unknownTimes":unknown,"kinds":kinds,"options":options,"indexedAt":Utc::now().to_rfc3339(),"version":1,"scope":"每个本地规则命中行均入索引，非完整主机活动；未命中行仍在原始归档中"});
    tx.execute(
        "INSERT OR REPLACE INTO metadata VALUES(?1,?2)",
        params![id, meta.to_string()],
    )
    .map_err(|e| e.to_string())?;
    observer.phase("indexing", 0)?;
    tx.commit().map_err(|e| e.to_string())?;
    report.engine = "J4team log-timeline/0.6.0".into();
    report.metrics.push(analyzers::metric("时间线线索", total));
    report
        .metrics
        .push(analyzers::metric("时间待补充", unknown));
    report.details.insert(0,analyzers::detail("日志时间线索引",format!("{total} 条命中行全部保存到独立 SQLite 索引，按 100 条分页；{unknown} 条时间待补充。原文件完整归档，列表中的 100 条 / 规则限制不限制时间线索引。")));
    Ok(report)
}
fn allowed_filter(store: &Store, filter: &Filter) -> Result<(String, Connection), String> {
    let case = store.active()?;
    if let Some(id) = &filter.evidence_id {
        let e = store.evidence_for_case(&case, id)?;
        if e.kind != "logs" {
            return Err("请选择日志证据".into());
        }
    }
    if filter
        .source_ip
        .as_ref()
        .is_some_and(|s| s.parse::<std::net::IpAddr>().is_err())
        || filter.kind.as_ref().is_some_and(|s| s.len() > 60)
    {
        return Err("筛选参数无效".into());
    }
    if filter.after.as_ref().is_some_and(|c| {
        c.at.len() > 40
            || uuid::Uuid::parse_str(&c.evidence_id).is_err()
            || c.line > i64::MAX as u64
            || (c.at != "~" && DateTime::parse_from_rfc3339(&c.at).is_err())
    }) {
        return Err("时间线分页参数无效".into());
    }
    let db = connection(store, &case)?;
    db.execute(
        "ATTACH DATABASE ?1 AS source",
        [store
            .root
            .join("workspace.sqlite3")
            .to_string_lossy()
            .as_ref()],
    )
    .map_err(|e| e.to_string())?;
    Ok((case, db))
}
const VALID:&str=" FROM events e JOIN source.evidence s ON s.id=e.evidence_id WHERE s.case_id=?1 AND s.kind='logs' AND (?2='' OR e.evidence_id=?2) AND (?3='' OR e.source_ip=?3) AND (?4='' OR e.kind=?4)";
pub fn query(store: &Store, filter: Filter) -> Result<Value, String> {
    let (case, db) = allowed_filter(store, &filter)?;
    let id = filter.evidence_id.as_deref().unwrap_or("");
    let ip = filter.source_ip.as_deref().unwrap_or("");
    let kind = filter.kind.as_deref().unwrap_or("");
    let cursor = filter.after.unwrap_or(Cursor {
        at: String::new(),
        evidence_id: String::new(),
        line: 0,
    });
    let query=format!("SELECT e.evidence_id,s.name,e.record {VALID} AND (coalesce(e.at,'~'),e.evidence_id,e.line)>(?5,?6,?7) ORDER BY coalesce(e.at,'~'),e.evidence_id,e.line LIMIT 101");
    let mut q = db.prepare(&query).map_err(|e| e.to_string())?;
    let mut events = q
        .query_map(
            params![
                case,
                id,
                ip,
                kind,
                cursor.at,
                cursor.evidence_id,
                cursor.line
            ],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(|e| e.to_string())?
        .map(|r| {
            let (id, name, record) = r.map_err(|e| e.to_string())?;
            let mut v: Value = serde_json::from_str(&record).map_err(|e| e.to_string())?;
            v["evidenceId"] = json!(id);
            v["evidenceName"] = json!(name);
            Ok(v)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let has_more = events.len() > 100;
    events.truncate(100);
    let next = if has_more {
        events.last().map(|e|json!({"at":e["at"].as_str().unwrap_or("~"),"evidenceId":e["evidenceId"],"line":e["line"]}))
    } else {
        None
    };
    let count: u64 = db
        .query_row(
            &format!("SELECT count(*) {VALID}"),
            params![case, id, ip, kind],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let unknown: u64 = db
        .query_row(
            &format!("SELECT count(*) {VALID} AND e.at IS NULL"),
            params![case, id, ip, kind],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let mut q=db.prepare("SELECT s.id,s.name,m.record FROM source.evidence s LEFT JOIN metadata m ON m.evidence_id=s.id WHERE s.case_id=?1 AND s.kind='logs' AND (?2='' OR s.id=?2) ORDER BY s.created_at").map_err(|e|e.to_string())?;
    let sources=q.query_map(params![case,id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?))).map_err(|e|e.to_string())?.map(|r|{let(id,name,m)=r.map_err(|e|e.to_string())?;Ok(json!({"id":id,"name":name,"indexed":m.is_some(),"metadata":m.and_then(|m|serde_json::from_str::<Value>(&m).ok())}))}).collect::<Result<Vec<_>,String>>()?;
    Ok(
        json!({"events":events,"next":next,"total":count,"unknownTimes":unknown,"sources":sources,"scope":"仅当前事件。每个规则命中行入库；无法由日志证明不存在的行为。缺时间记录排在最后，不按导入时间代替。"}),
    )
}
pub fn material(store: &Store, id: &str) -> Result<String, String> {
    let e = store.evidence_for_case(&store.active()?, id)?;
    let (_, db) = allowed_filter(
        store,
        &Filter {
            evidence_id: Some(id.into()),
            ..Default::default()
        },
    )?;
    let mut s=format!("日志攻击链复核材料。关联证据标识：{}\n文件：{}\nSHA-256：{}\n{}\n引用整份日志时，refs 每项单独填写此证据 ID，不附加行号或索引字段；原文行号与索引定位写在 claim / basis 中。下面是抽样事件，不是全量活动；不把访问脚本当作文件落地，不把认证成功当作未授权入侵。\n",e.id,e.name,e.sha256,e.report.summary);
    let meta: Option<String> = db
        .query_row(
            "SELECT record FROM metadata WHERE evidence_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    s.push_str(&format!(
        "索引覆盖：{}\n",
        meta.unwrap_or_else(|| "此旧记录尚未建立完整命中行索引".into())
    ));
    // First and last representative from every category, including late rows omitted by findings sampling.
    let mut q=db.prepare("SELECT record FROM events WHERE evidence_id=?1 AND line IN (SELECT min(line) FROM events WHERE evidence_id=?1 GROUP BY kind UNION SELECT max(line) FROM events WHERE evidence_id=?1 GROUP BY kind) ORDER BY coalesce(at,'~'),line LIMIT 24").map_err(|e|e.to_string())?;
    for r in q
        .query_map([id], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
    {
        let event: Event =
            serde_json::from_str(&r.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        s.push_str(&format!(
            "\n原文第 {} 行 · {} · {} · {}\n{}\n",
            event.line,
            event.at.as_deref().unwrap_or(&event.raw_time),
            event.time_basis,
            event.title,
            event.excerpt
        ));
    }
    s.push_str("\n请按可确定时间还原已观察到的行为，关联相同源 IP，区分事实、关联推测、合法操作与证据缺口；给出需补充的响应、主机文件、进程与认证证据。不能证明完整攻击链时明确写出断点。\n");
    Ok(crate::ai::redact_http_material(&analyzers::cut(&s, 18000)))
}
#[tauri::command]
pub async fn query_log_timeline(
    filter: Filter,
    store: State<'_, Arc<Store>>,
) -> Result<Value, String> {
    let s = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || query(&s, filter))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn rebuild_log_timeline(
    evidence_id: String,
    options: Options,
    store: State<'_, Arc<Store>>,
) -> Result<Value, String> {
    let s = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let e = s.evidence_for_case(&s.active()?, &evidence_id)?;
        if e.kind != "logs" {
            return Err("仅支持日志证据".into());
        }
        verify_archive(&s, &e)?;
        // Rebuilding changes derived time interpretation, never the original report references or raw evidence.
        index(
            &s,
            &s.root.join("evidence").join(&e.id),
            &e.case_id,
            &e.id,
            options,
        )?;
        query(
            &s,
            Filter {
                evidence_id: Some(e.id),
                ..Default::default()
            },
        )
    })
    .await
    .map_err(|e| e.to_string())?
}
pub fn verify_archive(store: &Store, e: &crate::store::Evidence) -> Result<(), String> {
    verify_archive_at(&store.root, e)
}
pub fn verify_archive_at(root: &Path, e: &crate::store::Evidence) -> Result<(), String> {
    verify_archive_progress(root, e, |_| Ok(()))
}

/// 每个有界读取块前后均留出取消/进度检查点，不把整个大日志读入内存。
pub fn verify_archive_progress(
    root: &Path,
    e: &crate::store::Evidence,
    mut progress: impl FnMut(u64) -> Result<(), String>,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let path = root.join("evidence").join(&e.id);
    let mut file = crate::store::open_regular_read(&path)
        .map_err(|_| "原始归档不是普通文件，拒绝使用链接或特殊文件作为证据。".to_string())?;
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 256 * 1024];
    let mut size = 0u64;
    loop {
        progress(0)?;
        let n = file.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > e.size {
            return Err("原始归档大小已改变，拒绝校验。".into());
        }
        hash.update(&chunk[..n]);
        progress(n as u64)?;
    }
    if size != e.size || format!("{:x}", hash.finalize()) != e.sha256 {
        return Err("原始归档的大小或 SHA-256 已改变，拒绝使用被修改的证据。".into());
    }
    Ok(())
}
#[tauri::command]
pub async fn get_log_event(
    evidence_id: String,
    line: u64,
    store: State<'_, Arc<Store>>,
) -> Result<Event, String> {
    let s = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let e = s.evidence_for_case(&s.active()?, &evidence_id)?;
        let db = connection(&s, &e.case_id)?;
        let raw: String = db
            .query_row(
                "SELECT record FROM events WHERE evidence_id=?1 AND line=?2",
                params![e.id, line],
                |r| r.get(0),
            )
            .map_err(|_| "该条旧记录尚无时间索引，请到行为时间线建立索引。")?;
        serde_json::from_str(&raw).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn log_ai_material(
    evidence_id: String,
    store: State<'_, Arc<Store>>,
) -> Result<crate::ai::AiSendPreview, String> {
    let s = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || crate::ai::send_preview(&s, &evidence_id))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
pub fn record_log_event(
    evidence_id: String,
    line: u64,
    actor: String,
    store: State<'_, Arc<Store>>,
) -> Result<Workspace, String> {
    let e = store.evidence_for_case(&store.active()?, &evidence_id)?;
    let db = connection(&store, &e.case_id)?;
    let record: String = db
        .query_row(
            "SELECT record FROM events WHERE evidence_id=?1 AND line=?2",
            params![evidence_id, line],
            |r| r.get(0),
        )
        .map_err(|_| "日志事件不存在")?;
    let event: Event = serde_json::from_str(&record).map_err(|e| e.to_string())?;
    let at = event
        .at
        .ok_or("该条时间缺少年份或时区，请补充来源时间后再加入正式时间线。")?;
    store.add_node(format!("[日志线索] {}",event.title),format!("{} · 原文第 {} 行\n原文时间：{}\n时间依据：{}\n源 IP：{}\n\n{}\n\n此为日志记录，不自动证明攻击成功；截图待补。",e.name,event.line,event.raw_time,event.time_basis,event.source_ip.unwrap_or_default(),event.excerpt),at,actor,Some(e.id),None)?;
    store.workspace()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn time_is_never_replaced_with_import_time() {
        let mut e = event(
            1,
            "Oct 27 10:21:00 host sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2",
            None,
            vec![("medium", "SSH 认证失败")],
        );
        assert!(e.at.is_none());
        normalize(
            &mut e,
            &Options {
                reference_year: Some(2026),
                offset_minutes: Some(480),
            },
        );
        assert_eq!(e.at.as_deref(), Some("2026-10-27T02:21:00.000Z"));
        let e = event(
            2,
            "203.0.113.1 - - [27/Oct/2026:10:21:00 +0800] \"GET /.env HTTP/1.1\" 200 0",
            None,
            vec![("medium", "敏感配置路径请求")],
        );
        assert_eq!(e.at.as_deref(), Some("2026-10-27T02:21:00.000Z"));
    }
    #[test]
    fn index_keeps_all_hits_keyset_and_case_boundary() {
        let root = std::env::temp_dir().join(format!("gaga-log-index-{}", uuid::Uuid::new_v4()));
        let s = Store::open(root.clone()).unwrap();
        let p = root.join("input.log");
        std::fs::write(
            &p,
            "203.0.113.1 - - [27/Oct/2026:10:21:00 +0800] \"GET /.env HTTP/1.1\" 200 0\n"
                .repeat(1205),
        )
        .unwrap();
        let e = s
            .analyze_file(p.display().to_string(), "logs".into())
            .unwrap();
        let first = query(&s, Filter::default()).unwrap();
        assert_eq!(first["total"], 1205);
        assert_eq!(first["events"].as_array().unwrap().len(), 100);
        let cursor: Cursor = serde_json::from_value(first["next"].clone()).unwrap();
        let second = query(
            &s,
            Filter {
                after: Some(cursor),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(second["events"][0]["line"], 101);
        assert_eq!(e.report.findings.len(), 100);
        s.create_case("第二事件".into()).unwrap();
        assert_eq!(query(&s, Filter::default()).unwrap()["total"], 0);
        assert!(query(
            &s,
            Filter {
                evidence_id: Some(e.id),
                ..Default::default()
            }
        )
        .is_err());
        drop(s);
        std::fs::remove_dir_all(root).unwrap();
    }
}
