use crate::store::{Evidence, Store};
use chrono::Utc;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, net::IpAddr};

pub fn init(store: &Store) -> Result<(), String> {
    store.db.lock().map_err(|e|e.to_string())?.execute_batch(
"CREATE TABLE IF NOT EXISTS intel_indicators(id TEXT PRIMARY KEY,kind TEXT NOT NULL,value TEXT NOT NULL,verdict TEXT NOT NULL DEFAULT 'unknown',labels TEXT NOT NULL DEFAULT '',notes TEXT NOT NULL DEFAULT '',first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,UNIQUE(kind,value));
CREATE TABLE IF NOT EXISTS intel_observations(id TEXT PRIMARY KEY,indicator_id TEXT NOT NULL REFERENCES intel_indicators(id),case_id TEXT NOT NULL REFERENCES cases(id),evidence_id TEXT NOT NULL REFERENCES evidence(id),location TEXT NOT NULL,observed_at TEXT NOT NULL,UNIQUE(indicator_id,evidence_id,location));
CREATE TABLE IF NOT EXISTS indicator_rules(id TEXT PRIMARY KEY,list TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,scope TEXT NOT NULL,expires_at TEXT,notes TEXT NOT NULL,created_at TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS malware_cases(id TEXT PRIMARY KEY,title TEXT NOT NULL,family TEXT NOT NULL,hashes TEXT NOT NULL,verdict TEXT NOT NULL,notes TEXT NOT NULL,evidence_id TEXT,case_id TEXT NOT NULL REFERENCES cases(id),created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS intel_observation_case ON intel_observations(case_id,evidence_id);").map_err(|e|e.to_string())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ioc {
    pub id: String,
    pub kind: String,
    pub value: String,
    pub verdict: String,
    pub labels: String,
    pub notes: String,
    pub first_seen: String,
    pub last_seen: String,
    pub observations: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub list: String,
    pub kind: String,
    pub value: String,
    pub scope: String,
    pub expires_at: Option<String>,
    pub notes: String,
    pub enabled: bool,
}
pub fn normalize(kind: &str, value: &str) -> Result<(String, String), String> {
    let kind = match kind.to_ascii_lowercase().as_str() {
        "ipv4" | "ipv6" | "ip" => "ip",
        "domain" | "域名候选" => "domain",
        "url" => "url",
        "md5" => "md5",
        "sha1" | "sha-1" => "sha1",
        "sha256" | "sha-256" => "sha256",
        "cidr" => "cidr",
        _ => return Err("支持 IP、CIDR、域名、URL、MD5、SHA1、SHA256。".into()),
    };
    let value = value
        .trim()
        .replace("[.]", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://");
    if value.is_empty() || value.len() > 4096 {
        return Err("IOC 为空或超过长度限制。".into());
    }
    let normalized = match kind {
        "ip" => value
            .parse::<IpAddr>()
            .map_err(|_| "IP 地址无效")?
            .to_string(),
        "cidr" => value
            .parse::<ipnet::IpNet>()
            .map_err(|_| "CIDR 无效")?
            .trunc()
            .to_string(),
        "domain" => {
            let host = reqwest::Url::parse(&format!("https://{}/", value.trim_end_matches('.')))
                .map_err(|_| "域名无效")?;
            if host.path() != "/"
                || host.query().is_some()
                || !host.username().is_empty()
                || host.port().is_some()
            {
                return Err("请输入纯域名。".into());
            }
            let name = host.host_str().ok_or("域名无效")?.to_ascii_lowercase();
            if !name.contains('.') || name.parse::<IpAddr>().is_ok() {
                return Err("请输入有效域名。".into());
            }
            name
        }
        "url" => {
            let mut u = reqwest::Url::parse(&value).map_err(|_| "URL 无效")?;
            if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
                return Err("只支持 HTTP / HTTPS URL。".into());
            }
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_fragment(None);
            u.to_string()
        }
        _ => {
            let n = match kind {
                "md5" => 32,
                "sha1" => 40,
                _ => 64,
            };
            if value.len() != n || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("Hash 长度或字符无效。".into());
            }
            value.to_ascii_lowercase()
        }
    };
    Ok((kind.into(), normalized))
}
pub fn parse(text: &str) -> Vec<(String, String)> {
    let clean = text
        .replace("[.]", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://");
    let mut values = BTreeSet::new();
    for i in crate::analyzers::extract_indicators(&clean) {
        if let Ok(i) = normalize(&i.kind, &i.value) {
            values.insert(i);
        }
    }
    for token in clean.split(|c: char| {
        c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\'' | '(' | ')' | '<' | '>')
    }) {
        let token = token.trim_matches(['[', ']']);
        if let Ok(ip) = token.parse::<IpAddr>() {
            values.insert(("ip".into(), ip.to_string()));
        }
        if token.contains('/') && !token.contains("://") {
            if let Ok(i) = normalize("cidr", token) {
                values.insert(i);
            }
        }
    }
    values.into_iter().take(5000).collect()
}
fn id(kind: &str, value: &str) -> String {
    format!(
        "ioc-{:x}",
        Sha256::digest(format!("{kind}\0{value}").as_bytes())
    )
}
pub fn upsert(store: &Store, kind: &str, value: &str) -> Result<String, String> {
    let (kind, value) = normalize(kind, value)?;
    let id = id(&kind, &value);
    let now = Utc::now().to_rfc3339();
    let db = store.db.lock().map_err(|e| e.to_string())?;
    db.execute("INSERT INTO intel_indicators(id,kind,value,first_seen,last_seen) VALUES(?1,?2,?3,?4,?4) ON CONFLICT(kind,value) DO UPDATE SET last_seen=excluded.last_seen",params![id,kind,value,now]).map_err(|e|e.to_string())?;
    Ok(id)
}
pub fn index_evidence(store: &Store, e: &Evidence) -> Result<usize, String> {
    let mut found = BTreeSet::new();
    for i in &e.report.indicators {
        if let Ok((k, v)) = normalize(&i.kind, &i.value) {
            found.insert((k, v, i.source.clone()));
        }
    }
    for f in &e.report.findings {
        for (k, v) in parse(&f.excerpt) {
            found.insert((k, v, f.location.clone()));
        }
    }
    for exchange in &e.report.http_exchanges {
        for (k, v) in parse(&format!("{}\n{}", exchange.url, exchange.request.raw)) {
            found.insert((k, v, exchange.request.source.clone()));
        }
        if let Some(response) = &exchange.response {
            for (k, v) in parse(&response.raw) {
                found.insert((k, v, response.source.clone()));
            }
        }
    }
    found.insert((
        "sha256".into(),
        e.sha256.clone(),
        "归档文件 SHA-256；不等于恶意样本".into(),
    ));
    if e.kind == "binary" {
        let bytes =
            std::fs::read(store.root.join("evidence").join(&e.id)).map_err(|e| e.to_string())?;
        use md5::Md5;
        use sha1::Sha1;
        found.insert((
            "md5".into(),
            format!("{:x}", Md5::digest(&bytes)),
            "样本文件 MD5".into(),
        ));
        found.insert((
            "sha1".into(),
            format!("{:x}", Sha1::digest(&bytes)),
            "样本文件 SHA1".into(),
        ));
    }
    let count = found.len();
    for (k, v, location) in found {
        let iid = upsert(store, &k, &v)?;
        store.db.lock().map_err(|e|e.to_string())?.execute("INSERT OR IGNORE INTO intel_observations(id,indicator_id,case_id,evidence_id,location,observed_at) VALUES(?1,?2,?3,?4,?5,?6)",params![uuid::Uuid::new_v4().to_string(),iid,e.case_id,e.id,location,Utc::now().to_rfc3339()]).map_err(|e|e.to_string())?;
    }
    Ok(count)
}
pub fn query(store: &Store, search: &str) -> Result<Vec<Ioc>, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut q=db.prepare("SELECT i.id,i.kind,i.value,i.verdict,i.labels,i.notes,i.first_seen,i.last_seen,(SELECT count(*) FROM intel_observations o WHERE o.indicator_id=i.id) FROM intel_indicators i WHERE (?1='' OR instr(lower(i.value||' '||i.labels||' '||i.notes),lower(?1))>0) ORDER BY i.last_seen DESC LIMIT 500").map_err(|e|e.to_string())?;
    let rows = q
        .query_map([search], |r| {
            Ok(Ioc {
                id: r.get(0)?,
                kind: r.get(1)?,
                value: r.get(2)?,
                verdict: r.get(3)?,
                labels: r.get(4)?,
                notes: r.get(5)?,
                first_seen: r.get(6)?,
                last_seen: r.get(7)?,
                observations: r.get(8)?,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}
pub fn origins(store: &Store, iid: &str) -> Result<Vec<Value>, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut q=db.prepare("SELECT case_id,evidence_id,location,observed_at FROM intel_observations WHERE indicator_id=?1 ORDER BY observed_at DESC LIMIT 200").map_err(|e|e.to_string())?;
    let rows=q.query_map([iid],|r|Ok(json!({"caseId":r.get::<_,String>(0)?,"evidenceId":r.get::<_,String>(1)?,"location":r.get::<_,String>(2)?,"observedAt":r.get::<_,String>(3)?}))).map_err(|e|e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}
pub fn annotate(
    store: &Store,
    iid: String,
    verdict: String,
    labels: String,
    notes: String,
) -> Result<(), String> {
    if !["unknown", "suspicious", "malicious", "benign"].contains(&verdict.as_str())
        || labels.len() > 1000
        || notes.len() > 10000
    {
        return Err("情报字段无效或过长。".into());
    }
    if verdict == "malicious" && notes.trim().is_empty() {
        return Err("标记恶意情报必须填写判断依据。".into());
    }
    let count = store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .execute(
            "UPDATE intel_indicators SET verdict=?1,labels=?2,notes=?3 WHERE id=?4",
            params![verdict, labels, notes, iid],
        )
        .map_err(|e| e.to_string())?;
    if count == 0 {
        return Err("IOC 不存在。".into());
    }
    Ok(())
}
pub fn rules(store: &Store, case: &str) -> Result<Vec<Rule>, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut q=db.prepare("SELECT id,list,kind,value,scope,expires_at,notes,enabled FROM indicator_rules WHERE scope='global' OR scope=?1 ORDER BY created_at DESC").map_err(|e|e.to_string())?;
    let rows = q
        .query_map([case], |r| {
            Ok(Rule {
                id: r.get(0)?,
                list: r.get(1)?,
                kind: r.get(2)?,
                value: r.get(3)?,
                scope: r.get(4)?,
                expires_at: r.get(5)?,
                notes: r.get(6)?,
                enabled: r.get(7)?,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}
pub fn add_rule(
    store: &Store,
    list: String,
    kind: String,
    value: String,
    scope: String,
    expires_at: Option<String>,
    notes: String,
) -> Result<(), String> {
    if !["allow", "deny"].contains(&list.as_str()) || notes.trim().is_empty() || notes.len() > 3000
    {
        return Err("请选择名单并填写依据，最多 3000 字节。".into());
    }
    if scope != "global" && scope != store.active()? {
        return Err("名单范围须为全局或当前事件。".into());
    }
    if let Some(exp) = &expires_at {
        if chrono::DateTime::parse_from_rfc3339(exp).map_err(|_| "失效时间需为 ISO 8601")?
            <= Utc::now()
        {
            return Err("失效时间必须晚于当前时间。".into());
        }
    }
    let (kind, value) = normalize(&kind, &value)?;
    store.db.lock().map_err(|e|e.to_string())?.execute("INSERT INTO indicator_rules(id,list,kind,value,scope,expires_at,notes,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![uuid::Uuid::new_v4().to_string(),list,kind,value,scope,expires_at,notes,Utc::now().to_rfc3339()]).map_err(|e|e.to_string())?;
    Ok(())
}
pub fn rule_matches(rule: &Rule, kind: &str, value: &str, case: &str) -> bool {
    if !rule.enabled || rule.scope != "global" && rule.scope != case {
        return false;
    }
    if rule
        .expires_at
        .as_ref()
        .is_some_and(|t| chrono::DateTime::parse_from_rfc3339(t).map_or(true, |v| v <= Utc::now()))
    {
        return false;
    }
    if rule.kind == "cidr" && kind == "ip" {
        return rule
            .value
            .parse::<ipnet::IpNet>()
            .ok()
            .zip(value.parse::<IpAddr>().ok())
            .is_some_and(|(n, a)| n.contains(&a));
    }
    rule.kind == kind && rule.value == value
}
/// Promote only the selected event's explicit rule; never broaden all historical
/// exceptions during startup or silently alter a rule's expiry and rationale.
pub fn promote_rule(store: &Store, id: &str) -> Result<(), String> {
    let case = store.active()?;
    let changed = store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .execute(
            "UPDATE indicator_rules SET scope='global' WHERE id=?1 AND scope=?2",
            params![id, case],
        )
        .map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err("只能将当前事件的规则设为全局。".into());
    }
    Ok(())
}
pub fn matches(store: &Store, kind: &str, value: &str, case: &str) -> Result<Value, String> {
    let (kind, value) = normalize(kind, value)?;
    let hits: Vec<_> = rules(store, case)?
        .into_iter()
        .filter(|r| rule_matches(r, &kind, &value, case))
        .collect();
    let allow = hits.iter().any(|r| r.list == "allow");
    let deny = hits.iter().any(|r| r.list == "deny");
    let knowledge: Option<Value> = {
        use rusqlite::OptionalExtension;
        let db = store.db.lock().map_err(|e| e.to_string())?;
        db.query_row("SELECT id,verdict,labels FROM intel_indicators WHERE kind=?1 AND value=?2",params![kind,value],|r|Ok(json!({"id":r.get::<_,String>(0)?,"verdict":r.get::<_,String>(1)?,"labels":r.get::<_,String>(2)?}))).optional().map_err(|e|e.to_string())?
    };
    Ok(
        json!({"allow":allow,"deny":deny,"conflict":allow&&deny,"rules":hits,"knowledge":knowledge,"action":"记录命中；不自动封禁，不删除白名单命中证据"}),
    )
}
pub fn import(store: &Store, text: &str) -> Result<usize, String> {
    if text.len() > 4 * 1024 * 1024 {
        return Err("情报导入上限 4 MiB。".into());
    }
    let mut found = BTreeSet::new();
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        if let Some(items) = v["indicators"].as_array() {
            for item in items.iter().take(5000) {
                if let (Some(k), Some(v)) = (item["kind"].as_str(), item["value"].as_str()) {
                    if let Ok(pair) = normalize(k, v) {
                        found.insert(pair);
                    }
                }
            }
        }
        if v["type"] == "bundle" {
            let re=regex::Regex::new(r"(?:ipv4-addr:value|ipv6-addr:value|domain-name:value|url:value|file:hashes\.'(?:MD5|SHA-1|SHA-256)')\s*=\s*'([^']+)'").unwrap();
            for item in v["objects"].as_array().into_iter().flatten().take(5000) {
                if let Some(pattern) = item["pattern"].as_str() {
                    for cap in re.captures_iter(pattern) {
                        let k = if cap[0].starts_with("ipv") {
                            "ip"
                        } else if cap[0].starts_with("domain") {
                            "domain"
                        } else if cap[0].starts_with("url") {
                            "url"
                        } else if cap[0].contains("MD5") {
                            "md5"
                        } else if cap[0].contains("SHA-1") {
                            "sha1"
                        } else {
                            "sha256"
                        };
                        if let Ok(pair) = normalize(k, &cap[1]) {
                            found.insert(pair);
                        }
                    }
                }
            }
        }
    } else {
        found.extend(parse(text));
    }
    if found.is_empty() {
        return Err("未解析出有效 IOC。支持文本 / CSV、嘎嘎 JSON、STIX 2.1 基础等值指标和 OpenIOC 中的明文指标；不执行模式表达式。".into());
    }
    let count = found.len();
    for (k, v) in found {
        upsert(store, &k, &v)?;
    }
    Ok(count)
}
pub fn export(store: &Store, format: &str, ids: &[String]) -> Result<String, String> {
    if ids.is_empty() || ids.len() > 500 {
        return Err("请选择 1–500 条 IOC。".into());
    }
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let placeholders = vec!["?"; ids.len()].join(",");
    let mut q=db.prepare(&format!("SELECT id,kind,value,verdict,labels,notes,first_seen,last_seen,0 FROM intel_indicators WHERE id IN ({placeholders}) ORDER BY last_seen DESC")).map_err(|e|e.to_string())?;
    let items = q
        .query_map(rusqlite::params_from_iter(ids), |r| {
            Ok(Ioc {
                id: r.get(0)?,
                kind: r.get(1)?,
                value: r.get(2)?,
                verdict: r.get(3)?,
                labels: r.get(4)?,
                notes: r.get(5)?,
                first_seen: r.get(6)?,
                last_seen: r.get(7)?,
                observations: r.get(8)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let requested: std::collections::HashSet<_> = ids.iter().collect();
    if items.len() != requested.len() {
        return Err("部分所选 IOC 已不存在，请刷新后重试。".into());
    }
    if items.is_empty() {
        return Err("请选择要分享的 IOC，本次最多 500 条。".into());
    }
    match format{
    "json"=>Ok(serde_json::to_string_pretty(&json!({"format":"gaga-intelligence/1","exportedAt":Utc::now().to_rfc3339(),"indicators":items.iter().map(|i|json!({"kind":i.kind,"value":i.value,"verdict":i.verdict,"labels":i.labels,"firstSeen":i.first_seen,"lastSeen":i.last_seen})).collect::<Vec<_>>(),"notice":"不包含原始证据、备注、模型密钥或样本字节；导入方须独立复核可信度。"})).unwrap()),
    "csv"=>{fn cell(s:&str)->String{let safe=if s.starts_with(['=','+','-','@','\t','\r']){format!("'{s}")}else{s.into()};format!("\"{}\"",safe.replace('"',"\"\""))}Ok("kind,value,verdict,labels\r\n".to_string()+&items.iter().map(|i|[&i.kind,&i.value,&i.verdict,&i.labels].map(|v|cell(v)).join(",")).collect::<Vec<_>>().join("\r\n"))},
    "stix"=>{let objects:Vec<Value>=items.iter().filter_map(|i|{let field=match i.kind.as_str(){"ip"=>if i.value.contains(':'){"ipv6-addr:value"}else{"ipv4-addr:value"},"domain"=>"domain-name:value","url"=>"url:value","md5"=>"file:hashes.'MD5'","sha1"=>"file:hashes.'SHA-1'","sha256"=>"file:hashes.'SHA-256'",_=>return None};Some(json!({"type":"indicator","spec_version":"2.1","id":format!("indicator--{}",uuid::Uuid::new_v4()),"created":i.first_seen,"modified":i.last_seen,"valid_from":i.first_seen,"name":i.value,"pattern_type":"stix","pattern":format!("[{field} = '{}']",i.value.replace('\\',"\\\\").replace('\'',"\\'")),"x_gaga_verdict":i.verdict}))}).collect();Ok(serde_json::to_string_pretty(&json!({"type":"bundle","id":format!("bundle--{}",uuid::Uuid::new_v4()),"objects":objects})).unwrap())},_=>Err("支持 JSON、CSV、STIX 导出。".into())}
}
pub fn sample_cases(store: &Store) -> Result<Vec<Value>, String> {
    let case = store.active()?;
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut q=db.prepare("SELECT id,title,family,hashes,verdict,notes,evidence_id,case_id,created_at FROM malware_cases WHERE case_id=?1 ORDER BY created_at DESC LIMIT 500").map_err(|e|e.to_string())?;
    let rows=q.query_map([case],|r|Ok(json!({"id":r.get::<_,String>(0)?,"title":r.get::<_,String>(1)?,"family":r.get::<_,String>(2)?,"hashes":r.get::<_,String>(3)?,"verdict":r.get::<_,String>(4)?,"notes":r.get::<_,String>(5)?,"evidenceId":r.get::<_,Option<String>>(6)?,"caseId":r.get::<_,String>(7)?,"createdAt":r.get::<_,String>(8)?}))).map_err(|e|e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}
pub fn add_case(
    store: &Store,
    title: String,
    family: String,
    hashes: String,
    verdict: String,
    notes: String,
    evidence_id: Option<String>,
) -> Result<(), String> {
    if title.trim().is_empty()
        || title.len() > 300
        || family.len() > 200
        || notes.len() > 20000
        || !matches!(
            verdict.as_str(),
            "unknown" | "suspicious" | "malicious" | "benign"
        )
    {
        return Err("案例字段无效。".into());
    }
    let hashes: Vec<_> = parse(&hashes)
        .into_iter()
        .filter(|(k, _)| matches!(k.as_str(), "md5" | "sha1" | "sha256"))
        .collect();
    if hashes.is_empty() {
        return Err("至少填写一个有效 MD5 / SHA1 / SHA256。".into());
    }
    if verdict == "malicious" && notes.trim().is_empty() {
        return Err("标记恶意必须填写依据。".into());
    }
    let case_id = store.active()?;
    if let Some(e) = &evidence_id {
        store.evidence_for_case(&case_id, e)?;
    }
    for (k, v) in &hashes {
        upsert(store, k, v)?;
    }
    store.db.lock().map_err(|e|e.to_string())?.execute("INSERT INTO malware_cases(id,title,family,hashes,verdict,notes,evidence_id,case_id,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![uuid::Uuid::new_v4().to_string(),title,family,serde_json::to_string(&hashes).unwrap(),verdict,notes,evidence_id,case_id,Utc::now().to_rfc3339()]).map_err(|e|e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn store() -> Store {
        Store::open(std::env::temp_dir().join(format!("gaga-intel-test-{}", uuid::Uuid::new_v4())))
            .unwrap()
    }
    #[test]
    fn normalization_parser_and_bad_values() {
        let list=parse("hxxps://EXAMPLE[.]org/path 2001:db8::1 203.0.113.9/24 d41d8cd98f00b204e9800998ecf8427e");
        assert!(list.contains(&("url".into(), "https://example.org/path".into())));
        assert!(list.contains(&("ip".into(), "2001:db8::1".into())));
        assert!(list.contains(&("cidr".into(), "203.0.113.0/24".into())));
        assert!(list.contains(&("md5".into(), "d41d8cd98f00b204e9800998ecf8427e".into())));
        assert!(normalize("md5", "123").is_err());
        assert!(normalize("ip", "999.0.0.1").is_err());
        assert!(normalize("domain", "host.test/path").is_err());
    }
    #[test]
    fn paired_http_sources_and_binary_hashes_are_indexed() {
        let store = store();
        let e = store
            .analyze_http_pair(
                "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".into(),
                "HTTP/1.1 200 OK\r\n\r\ncallback=203.0.113.9".into(),
            )
            .unwrap();
        let i = query(&store, "203.0.113.9")
            .unwrap()
            .into_iter()
            .find(|i| i.kind == "ip")
            .unwrap();
        assert_eq!(i.verdict, "unknown");
        let origins = origins(&store, &i.id).unwrap();
        assert!(origins.iter().any(|o| o["evidenceId"] == e.id
            && o["location"] == e.report.http_exchanges[0].response.as_ref().unwrap().source));
        let path = store.root.join("sample.bin");
        std::fs::write(&path, b"abc").unwrap();
        store
            .analyze_file(path.display().to_string(), "binary".into())
            .unwrap();
        assert!(query(&store, "900150983cd24fb0d6963f7d28e17f72")
            .unwrap()
            .iter()
            .any(|i| i.kind == "md5"));
        assert!(query(&store, "a9993e364706816aba3e25717850c26c9cd0d89d")
            .unwrap()
            .iter()
            .any(|i| i.kind == "sha1"));
        std::fs::remove_dir_all(&store.root).unwrap();
    }
    #[test]
    fn scoped_expiring_rules_show_conflict_without_erasing_evidence() {
        let store = store();
        let case = store.active().unwrap();
        for list in ["allow", "deny"] {
            add_rule(
                &store,
                list.into(),
                "cidr".into(),
                "203.0.113.0/24".into(),
                case.clone(),
                None,
                "fixture reviewed basis".into(),
            )
            .unwrap();
        }
        let m = matches(&store, "ip", "203.0.113.3", &case).unwrap();
        assert_eq!(m["conflict"], true);
        assert_eq!(
            matches(&store, "ip", "203.0.113.3", "other").unwrap()["deny"],
            false
        );
        let mut r = rules(&store, &case).unwrap()[0].clone();
        r.expires_at = Some("2000-01-01T00:00:00Z".into());
        assert!(!rule_matches(&r, "ip", "203.0.113.3", &case));
        std::fs::remove_dir_all(&store.root).unwrap();
    }
    #[test]
    fn global_rules_follow_every_event_without_enforcement() {
        let store = store();
        let case = store.active().unwrap();
        add_rule(
            &store,
            "deny".into(),
            "ip".into(),
            "203.0.113.44".into(),
            "global".into(),
            None,
            "共享情报库人工确认".into(),
        )
        .unwrap();
        for other in [case.as_str(), "another-event"] {
            let matched = matches(&store, "ip", "203.0.113.44", other).unwrap();
            assert_eq!(matched["deny"], true);
            assert_eq!(
                matched["action"],
                "记录命中；不自动封禁，不删除白名单命中证据"
            );
        }
        std::fs::remove_dir_all(&store.root).unwrap();
    }
    #[test]
    fn promoting_one_rule_preserves_limits_and_requires_its_event() {
        let store = store();
        let first = store.active().unwrap();
        let expires = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        add_rule(
            &store,
            "allow".into(),
            "ip".into(),
            "192.0.2.44".into(),
            first.clone(),
            Some(expires.clone()),
            "已核对授权巡检工单".into(),
        )
        .unwrap();
        let selected = rules(&store, &first).unwrap().remove(0);
        store.create_case("第二事件".into()).unwrap();
        assert!(promote_rule(&store, &selected.id).is_err());
        store.switch_case(first.clone()).unwrap();
        promote_rule(&store, &selected.id).unwrap();
        let promoted = rules(&store, &first).unwrap().remove(0);
        assert_eq!(promoted.id, selected.id);
        assert_eq!(promoted.expires_at, Some(expires));
        assert_eq!(promoted.notes, selected.notes);
        assert!(promoted.enabled);
        add_rule(
            &store,
            "deny".into(),
            "ip".into(),
            "192.0.2.44".into(),
            "global".into(),
            None,
            "关联异常请求，需人工解决冲突".into(),
        )
        .unwrap();
        let hits = matches(&store, "ip", "192.0.2.44", "independent-event").unwrap();
        assert_eq!(hits["conflict"], true);
        assert_eq!(hits["allow"], true);
        assert_eq!(hits["deny"], true);
        let mut expired = promoted.clone();
        expired.expires_at = Some((Utc::now() - chrono::Duration::seconds(1)).to_rfc3339());
        assert!(!rule_matches(
            &expired,
            "ip",
            "192.0.2.44",
            "independent-event"
        ));
        let mut disabled = promoted;
        disabled.enabled = false;
        assert!(!rule_matches(
            &disabled,
            "ip",
            "192.0.2.44",
            "independent-event"
        ));
        assert!(add_rule(
            &store,
            "allow".into(),
            "ip".into(),
            "192.0.2.45".into(),
            "".into(),
            None,
            "必须显式选择作用域".into()
        )
        .is_err());
        std::fs::remove_dir_all(&store.root).unwrap();
    }
    #[test]
    fn sharing_roundtrip_resets_trust_omits_private_notes_and_escapes_csv() {
        let store = store();
        let id = upsert(&store, "ip", "203.0.113.8").unwrap();
        annotate(
            &store,
            id.clone(),
            "malicious".into(),
            "=formula".into(),
            "private-fixture-note".into(),
        )
        .unwrap();
        let ids = vec![id];
        let json = export(&store, "json", &ids).unwrap();
        assert!(!json.contains("private-fixture-note"));
        let csv = export(&store, "csv", &ids).unwrap();
        assert!(csv.contains("'=formula"));
        let other = self::store();
        import(&other, &json).unwrap();
        assert_eq!(query(&other, "").unwrap()[0].verdict, "unknown");
        let stix = export(&store, "stix", &ids).unwrap();
        import(&other, &stix).unwrap();
        assert_eq!(query(&other, "").unwrap().len(), 1);
        assert!(annotate(
            &store,
            ids[0].clone(),
            "malicious".into(),
            "".into(),
            "".into()
        )
        .is_err());
        add_case(
            &store,
            "fixture".into(),
            "unconfirmed".into(),
            "d41d8cd98f00b204e9800998ecf8427e".into(),
            "unknown".into(),
            "".into(),
            None,
        )
        .unwrap();
        assert_eq!(sample_cases(&store).unwrap().len(), 1);
        store
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE intel_indicators SET last_seen='1970-01-01T00:00:00Z' WHERE id=?1",
                [&ids[0]],
            )
            .unwrap();
        for n in 0..501 {
            upsert(&store, "domain", &format!("fixture{n}.example.test")).unwrap();
        }
        assert!(!query(&store, "").unwrap().iter().any(|i| i.id == ids[0]));
        let older: Value = serde_json::from_str(&export(&store, "json", &ids).unwrap()).unwrap();
        assert_eq!(older["indicators"].as_array().unwrap().len(), 1);
        assert_eq!(older["indicators"][0]["value"], "203.0.113.8");
        std::fs::remove_dir_all(&store.root).unwrap();
        std::fs::remove_dir_all(&other.root).unwrap();
    }
}
