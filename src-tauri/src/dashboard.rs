use crate::{
    investigation,
    store::{Store, Workspace},
};
use chrono::{DateTime, Duration, FixedOffset, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tauri::State;

// A single database lock keeps the counters, charts and lists on one snapshot.
const SCOPE: &str = "WITH scoped AS (SELECT id FROM cases c WHERE (?1<>'' AND c.id=?1) OR (?1='' AND NOT EXISTS(SELECT 1 FROM settings s WHERE s.key='demo_case:'||c.id))) ";
const LATEST: &str = ", latest AS (SELECT a.*,e.case_id,e.kind,e.name FROM ai_reviews a JOIN evidence e ON e.id=a.evidence_id WHERE e.case_id IN(SELECT id FROM scoped) AND NOT EXISTS(SELECT 1 FROM ai_reviews n WHERE n.evidence_id=a.evidence_id AND n.rowid>a.rowid)), pending AS (SELECT a.* FROM latest a WHERE coalesce((SELECT json_extract(f.record,'$.disposition') FROM review_feedback f WHERE f.review_id=a.id ORDER BY f.rowid DESC LIMIT 1),'pending') IN ('pending','investigate')) ";
fn sql(tail: &str) -> String {
    format!("{SCOPE}{tail}")
}
fn pending_sql(tail: &str) -> String {
    format!("{}{LATEST}{tail}", SCOPE.trim_end())
}
fn count(db: &Connection, case: &str, tail: &str) -> Result<u64, String> {
    db.query_row(&sql(tail), [case], |r| r.get(0))
        .map_err(|e| e.to_string())
}
fn groups(db: &Connection, case: &str, tail: &str) -> Result<Vec<Value>, String> {
    let mut q = db.prepare(&sql(tail)).map_err(|e| e.to_string())?;
    let rows = q
        .query_map([case], |r| {
            Ok(json!({"key":r.get::<_,String>(0)?,"count":r.get::<_,u64>(1)?}))
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}
fn records(db: &Connection, case: &str, query: &str) -> Result<Vec<Value>, String> {
    let mut q = db.prepare(query).map_err(|e| e.to_string())?;
    let rows=q.query_map([case],|r|Ok(json!({"id":r.get::<_,String>(0)?,"caseId":r.get::<_,String>(1)?,"caseTitle":r.get::<_,String>(2)?,"title":r.get::<_,String>(3)?,"createdAt":r.get::<_,String>(4)?,"category":r.get::<_,String>(5)?,"module":r.get::<_,String>(6)?,"evidenceId":r.get::<_,Option<String>>(7)?,"detail":r.get::<_,String>(8)?}))).map_err(|e|e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}
pub fn snapshot(
    store: &Store,
    case_id: &str,
    scope: &str,
    days: u32,
    now: DateTime<Utc>,
    receiver_running: bool,
) -> Result<Value, String> {
    if !matches!(scope, "case" | "all") || !matches!(days, 7 | 30) {
        return Err("总览范围或趋势天数无效。".into());
    }
    let selected = if scope == "case" { case_id } else { "" };
    let db = store.db.lock().map_err(|e| e.to_string())?;
    if !db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
            [case_id],
            |r| r.get::<_, bool>(0),
        )
        .map_err(|e| e.to_string())?
    {
        return Err("事件不存在，请刷新工作区。".into());
    }
    let demo = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM settings WHERE key='demo_case:'||?1)",
            [case_id],
            |r| r.get::<_, bool>(0),
        )
        .map_err(|e| e.to_string())?;
    let evidence = count(
        &db,
        selected,
        "SELECT count(*) FROM evidence WHERE case_id IN(SELECT id FROM scoped)",
    )?;
    let bytes = count(
        &db,
        selected,
        "SELECT coalesce(sum(size),0) FROM evidence WHERE case_id IN(SELECT id FROM scoped)",
    )?;
    let findings=groups(&db,selected,"SELECT coalesce(json_extract(f.value,'$.level'),'unknown'),count(*) FROM evidence e,json_each(e.report,'$.findings') f WHERE e.case_id IN(SELECT id FROM scoped) GROUP BY 1 ORDER BY count(*) DESC")?;
    let pending = db
        .query_row(
            &pending_sql("SELECT count(*) FROM pending"),
            [selected],
            |r| r.get::<_, u64>(0),
        )
        .map_err(|e| e.to_string())?;
    let ai_latest = db
        .query_row(
            &pending_sql("SELECT count(*) FROM latest"),
            [selected],
            |r| r.get::<_, u64>(0),
        )
        .map_err(|e| e.to_string())?;
    let ai_count=count(&db,selected,"SELECT count(*) FROM ai_reviews a JOIN evidence e ON e.id=a.evidence_id WHERE e.case_id IN(SELECT id FROM scoped)")?;
    let assets = count(
        &db,
        selected,
        "SELECT count(*) FROM monitor_assets WHERE case_id IN(SELECT id FROM scoped)",
    )?;
    let enabled = count(
        &db,
        selected,
        "SELECT count(*) FROM monitor_assets WHERE enabled=1 AND case_id IN(SELECT id FROM scoped)",
    )?;
    let asset_failures=count(&db,selected,"SELECT count(*) FROM monitor_assets a JOIN monitor_snapshots s ON s.id=json_extract(a.record,'$.lastSnapshotId') WHERE a.case_id IN(SELECT id FROM scoped) AND json_extract(s.record,'$.error') IS NOT NULL")?;
    // Current case: evidence-linked indicators. All business cases: exclude demo-only indicators.
    let ioc_predicate="((?1<>'' AND EXISTS(SELECT 1 FROM intel_observations o WHERE o.indicator_id=i.id AND o.case_id IN(SELECT id FROM scoped))) OR (?1='' AND (NOT EXISTS(SELECT 1 FROM intel_observations o WHERE o.indicator_id=i.id) OR EXISTS(SELECT 1 FROM intel_observations o WHERE o.indicator_id=i.id AND o.case_id IN(SELECT id FROM scoped)))))";
    let iocs = count(
        &db,
        selected,
        &format!("SELECT count(*) FROM intel_indicators i WHERE {ioc_predicate}"),
    )?;
    let reviewed=count(&db,selected,&format!("SELECT count(*) FROM intel_indicators i WHERE {ioc_predicate} AND i.verdict<>'unknown'"))?;
    let ioc_kinds=groups(&db,selected,&format!("SELECT i.kind,count(*) FROM intel_indicators i WHERE {ioc_predicate} GROUP BY i.kind ORDER BY count(*) DESC"))?;
    let queue=groups(&db,selected,"SELECT ai_state,count(*) FROM monitor_observations WHERE case_id IN(SELECT id FROM scoped) GROUP BY ai_state")?;
    let runs=groups(&db,selected,"SELECT coalesce(json_extract(record,'$.state'),'unknown'),count(*) FROM analysis_runs WHERE case_id IN(SELECT id FROM scoped) GROUP BY 1")?;
    let sandbox=groups(&db,selected,"SELECT coalesce(json_extract(record,'$.state'),'unknown'),count(*) FROM sandbox_jobs WHERE case_id IN(SELECT id FROM scoped) GROUP BY 1")?;
    let task_counts: (u64,u64)=db.query_row(&sql("SELECT count(*),coalesce(sum(enabled=1 AND julianday(expires_at)>julianday(?2)),0) FROM collector_tasks WHERE case_id IN(SELECT id FROM scoped)"),params![selected,now.to_rfc3339()],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|e|e.to_string())?;
    let missing_shots=count(&db,selected,"SELECT count(*) FROM nodes n WHERE n.included=1 AND n.case_id IN(SELECT id FROM scoped) AND NOT EXISTS(SELECT 1 FROM screenshots s WHERE s.node_id=n.id)")?;
    let nodes = count(
        &db,
        selected,
        "SELECT count(*) FROM nodes WHERE case_id IN(SELECT id FROM scoped)",
    )?;
    let kind_counts=groups(&db,selected,"SELECT kind,count(*) FROM evidence WHERE case_id IN(SELECT id FROM scoped) GROUP BY kind ORDER BY count(*) DESC")?;
    let china = FixedOffset::east_opt(8 * 3600).unwrap();
    let today = now.with_timezone(&china).date_naive();
    let first = today - Duration::days((days - 1) as i64);
    let mut series = std::collections::BTreeMap::new();
    for day in 0..days {
        series.insert(
            (first + Duration::days(day as i64)).to_string(),
            (0u64, 0u64, 0u64),
        );
    }
    let mut q=db.prepare(&sql("SELECT day,category,count(*) FROM (SELECT date(created_at,'+8 hours') AS day,'evidence' AS category FROM evidence WHERE case_id IN(SELECT id FROM scoped) UNION ALL SELECT date(json_extract(record,'$.startedAt'),'+8 hours'),CASE WHEN json_extract(record,'$.state')='failed' THEN 'failed' ELSE 'analysis' END FROM analysis_runs WHERE case_id IN(SELECT id FROM scoped)) WHERE day>=?2 AND day<=?3 GROUP BY day,category")).map_err(|e|e.to_string())?;
    let grouped = q
        .query_map(
            params![selected, first.to_string(), today.to_string()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            },
        )
        .map_err(|e| e.to_string())?;
    for row in grouped {
        let (day, kind, n) = row.map_err(|e| e.to_string())?;
        if let Some(v) = series.get_mut(&day) {
            match kind.as_str() {
                "evidence" => v.0 = n,
                "failed" => {
                    v.1 += n;
                    v.2 = n
                }
                _ => v.1 += n,
            }
        }
    }
    let series:Vec<_>=series.into_iter().map(|(day,(evidence,analyses,failed))|json!({"day":day,"evidence":evidence,"analyses":analyses,"failed":failed})).collect();
    let failures=records(&db,selected,&sql("SELECT r.id,r.case_id,c.title,e.name,json_extract(r.record,'$.startedAt'),'failure',e.kind,e.id,coalesce(json_extract(r.record,'$.error'),'执行失败') FROM analysis_runs r JOIN evidence e ON e.id=r.evidence_id JOIN cases c ON c.id=r.case_id WHERE r.case_id IN(SELECT id FROM scoped) AND json_extract(r.record,'$.state')='failed' ORDER BY julianday(json_extract(r.record,'$.startedAt')) DESC LIMIT 20"))?;
    let pending_records=records(&db,selected,&pending_sql("SELECT a.id,a.case_id,c.title,a.name,json_extract(a.record,'$.createdAt'),'review',a.kind,a.evidence_id,coalesce(json_extract(a.record,'$.assessment.category'),'AI 结果待人工复核') FROM pending a JOIN cases c ON c.id=a.case_id ORDER BY julianday(json_extract(a.record,'$.createdAt')) DESC LIMIT 20"))?;
    let activity=records(&db,selected,&sql("SELECT id,case_id,case_title,title,at,category,module,evidence_id,detail FROM (
      SELECT e.id,e.case_id,c.title AS case_title,e.name AS title,e.created_at AS at,'evidence' AS category,e.kind AS module,e.id AS evidence_id,'原始材料已归档' AS detail FROM evidence e JOIN cases c ON c.id=e.case_id WHERE e.case_id IN(SELECT id FROM scoped)
      UNION ALL SELECT a.id,e.case_id,c.title,e.name,json_extract(a.record,'$.createdAt'),'review',e.kind,e.id,coalesce(json_extract(a.record,'$.assessment.category'),'AI 草稿已保存') FROM ai_reviews a JOIN evidence e ON e.id=a.evidence_id JOIN cases c ON c.id=e.case_id WHERE e.case_id IN(SELECT id FROM scoped)
      UNION ALL SELECT r.id,r.case_id,c.title,e.name,json_extract(r.record,'$.startedAt'),'failure',e.kind,e.id,coalesce(json_extract(r.record,'$.error'),'执行失败') FROM analysis_runs r JOIN evidence e ON e.id=r.evidence_id JOIN cases c ON c.id=r.case_id WHERE r.case_id IN(SELECT id FROM scoped) AND json_extract(r.record,'$.state')='failed'
      UNION ALL SELECT n.id,n.case_id,c.title,n.title,n.recorded_at,'timeline','timeline',n.evidence_id,'人工记录已保存' FROM nodes n JOIN cases c ON c.id=n.case_id WHERE n.case_id IN(SELECT id FROM scoped)
      UNION ALL SELECT o.id,o.case_id,c.title,json_extract(o.record,'$.subject'),o.created_at,'monitor','triage',o.evidence_id,json_extract(o.record,'$.summary') FROM monitor_observations o JOIN cases c ON c.id=o.case_id WHERE o.case_id IN(SELECT id FROM scoped)
    ) ORDER BY julianday(at) DESC,id DESC LIMIT 20"))?;
    let auto_ai: Option<String> = db
        .query_row(
            "SELECT value FROM settings WHERE key='monitor_ai_settings'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let auto_ai = auto_ai
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .is_some_and(|s| s["enabled"] == true);
    let mut case_query=db.prepare(&sql("SELECT c.id,c.title,c.created_at,(SELECT count(*) FROM evidence e WHERE e.case_id=c.id),(SELECT count(*) FROM monitor_assets a WHERE a.case_id=c.id) FROM cases c WHERE c.id IN(SELECT id FROM scoped) ORDER BY julianday(c.created_at) DESC")).map_err(|e|e.to_string())?;
    let case_rows=case_query.query_map([selected],|r|Ok(json!({"id":r.get::<_,String>(0)?,"title":r.get::<_,String>(1)?,"createdAt":r.get::<_,String>(2)?,"evidence":r.get::<_,u64>(3)?,"assets":r.get::<_,u64>(4)?}))).map_err(|e|e.to_string())?;
    let case_summaries = case_rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let demo_complete = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM settings WHERE key='dashboard_demo_case')",
            [],
            |r| r.get::<_, bool>(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"scope":scope,"caseId":case_id,"isDemo":demo&&scope=="case","hasDemo":demo_complete,"updatedAt":now.to_rfc3339(),"days":days,"cases":case_summaries,"counts":{"evidence":evidence,"bytes":bytes,"pendingReviews":pending,"latestReviews":ai_latest,"reviews":ai_count,"assets":assets,"assetsEnabled":enabled,"assetFailures":asset_failures,"indicators":iocs,"indicatorsReviewed":reviewed,"tasks":task_counts.0,"validTasks":task_counts.1,"nodes":nodes,"nodesMissingScreenshots":missing_shots,"flows":count(&db,selected,"SELECT count(*) FROM flow_windows WHERE case_id IN(SELECT id FROM scoped)")?},"findings":findings,"evidenceKinds":kind_counts,"indicatorKinds":ioc_kinds,"queue":queue,"runs":runs,"sandbox":sandbox,"series":series,"activity":activity,"pending":pending_records,"failures":failures,"runtime":{"receiverRunning":receiver_running,"autoAiEnabled":auto_ai},"timezone":"Asia/Shanghai"}),
    )
}
#[tauri::command]
pub async fn get_dashboard(
    case_id: String,
    scope: String,
    days: u32,
    store: State<'_, Arc<Store>>,
    receiver: State<'_, Arc<crate::collector::Receiver>>,
) -> Result<Value, String> {
    let store = store.inner().clone();
    let running = receiver.running();
    tauri::async_runtime::spawn_blocking(move || {
        snapshot(&store, &case_id, &scope, days, Utc::now(), running)
    })
    .await
    .map_err(|e| e.to_string())?
}

pub fn seed_demo(store: &Store) -> Result<Workspace, String> {
    static LOCK: Mutex<()> = Mutex::new(());
    let _lock = LOCK.lock().map_err(|e| e.to_string())?;
    let existing: Option<String> = store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .query_row(
            "SELECT value FROM settings WHERE key='dashboard_demo_case'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if let Some(id) = existing {
        store.switch_case(id)?;
        return store.workspace();
    }
    let previous = store.active()?;
    let case = store.create_case("[演示] Web 线索调查 · 本地样例".into())?;
    store
        .db
        .lock()
        .map_err(|e| e.to_string())?
        .execute(
            "INSERT INTO settings VALUES(?1,'true')",
            [format!("demo_case:{}", case.id)],
        )
        .map_err(|e| e.to_string())?;
    let result = (|| -> Result<(), String> {
        for (kind, name, text) in [
            (
                "http",
                "HTTP 交互.har",
                include_str!("../../fixtures/demo-http.har"),
            ),
            (
                "logs",
                "Web 访问.log",
                include_str!("../../fixtures/demo-access.log"),
            ),
            (
                "webshell",
                "源码静态线索.php",
                include_str!("../../fixtures/demo-source.php"),
            ),
            (
                "containers",
                "容器配置.json",
                include_str!("../../fixtures/demo-inspect.json"),
            ),
        ] {
            let dir = store.root.join("demo-input");
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let path = dir.join(format!("[演示] {name}"));
            std::fs::write(&path, text).map_err(|e| e.to_string())?;
            let analyzed = investigation::local_analyze(store, None, || {
                store.analyze_file(path.to_string_lossy().into_owned(), kind.into())
            });
            let _ = std::fs::remove_file(path);
            let evidence = analyzed?;
            if let Some(f) = evidence.report.findings.first() {
                store.add_node(
                    format!("[演示] {} · 待复核", f.title),
                    format!(
                        "本地演示数据，不代表真实事件。\n证据：{}\n位置：{}\n原文：{}\n{}",
                        evidence.name, f.location, f.excerpt, f.description
                    ),
                    Utc::now().to_rfc3339(),
                    "演示分析员（未认证身份）".into(),
                    Some(evidence.id),
                    Some(f.id.clone()),
                )?;
            }
        }
        investigation::local_analyze(store, None, || {
            store.analyze_alert_text("[演示] NDR 敏感路径访问告警；源 IP 203.0.113.44；无原始 proof，需补充请求响应；本条不是实际攻击。".into())
        })?;
        crate::monitoring::import_assets(store,"演示站点 A,https://asset-a.example.test\n演示站点 B,https://asset-b.example.test\n演示站点 C,https://asset-c.example.test",300)?;
        crate::intelligence::add_rule(
            store,
            "deny".into(),
            "ip".into(),
            "203.0.113.44".into(),
            case.id.clone(),
            None,
            "演示名单；保留地址，不代表真实攻击者。".into(),
        )?;
        store
            .db
            .lock()
            .map_err(|e| e.to_string())?
            .execute(
                "INSERT OR REPLACE INTO settings VALUES('dashboard_demo_case',?1)",
                [&case.id],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = store.switch_case(previous);
        return Err(error);
    }
    store.workspace()
}
#[tauri::command]
pub async fn create_demo_event(
    store: State<'_, Arc<Store>>,
    mode: State<'_, crate::SmokeMode>,
) -> Result<Workspace, String> {
    if !cfg!(debug_assertions) || !mode.0 {
        return Err("正式工作区不提供演示数据注入。".into());
    }
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || seed_demo(&store))
        .await
        .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fresh() -> Store {
        Store::open(std::env::temp_dir().join(format!("gaga-dashboard-{}", uuid::Uuid::new_v4())))
            .unwrap()
    }
    #[test]
    fn demo_uses_real_analyzers_is_idempotent_and_is_excluded_from_business_totals() {
        let store = fresh();
        let original = store.active().unwrap();
        let w = seed_demo(&store).unwrap();
        let id = w.active_case.clone();
        assert_eq!(w.evidence.len(), 5);
        assert!(!w.nodes.is_empty());
        let data = snapshot(&store, &id, "case", 7, Utc::now(), false).unwrap();
        assert_eq!(data["counts"]["evidence"], 5);
        assert!(data["counts"]["indicators"].as_u64().unwrap() > 0);
        assert_eq!(data["counts"]["assets"], 3);
        assert_eq!(data["counts"]["assetsEnabled"], 0);
        assert_eq!(data["counts"]["reviews"], 0);
        assert_eq!(data["counts"]["tasks"], 0);
        assert_eq!(data["isDemo"], true);
        assert_eq!(
            data["series"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["evidence"].as_u64().unwrap())
                .sum::<u64>(),
            5
        );
        let total = snapshot(&store, &original, "all", 7, Utc::now(), false).unwrap();
        for key in ["evidence", "assets", "nodes", "indicators"] {
            assert_eq!(total["counts"][key], 0, "{key}");
        }
        assert_eq!(seed_demo(&store).unwrap().active_case, id);
        assert_eq!(store.workspace().unwrap().evidence.len(), 5);
        assert!(crate::monitoring::assets(&store, Some(&id))
            .unwrap()
            .iter()
            .all(|a| !a.enabled));
        std::fs::remove_dir_all(store.root).unwrap();
    }
    #[test]
    fn totals_use_all_rows_and_shanghai_calendar_and_keep_cases_isolated() {
        let store = fresh();
        let id = store.active().unwrap();
        let e = store
            .analyze_alert_text("仪表盘范围测试，203.0.113.88".into())
            .unwrap();
        let now = DateTime::parse_from_rfc3339("2026-10-27T00:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        {
            let db = store.db.lock().unwrap();
            db.execute(
                "UPDATE evidence SET created_at='2026-10-26T17:00:00Z' WHERE id=?1",
                [&e.id],
            )
            .unwrap();
            for n in 0..520 {
                db.execute("INSERT INTO monitor_observations(id,case_id,kind,created_at,evidence_id,ai_state,record) VALUES(?1,?2,'web',?3,?4,'pending',?5)",params![format!("o{n}"),id,now.to_rfc3339(),e.id,json!({"subject":"fixture","summary":"bounded test metadata"}).to_string()]).unwrap();
            }
            for (n, time) in [(1, "2026-10-26T15:59:59Z"), (2, "2026-10-26T16:00:00Z")] {
                db.execute(
                    "INSERT INTO analysis_runs VALUES(?1,?2,?3,?4)",
                    params![
                        format!("r{n}"),
                        e.id,
                        id,
                        json!({"state":"failed","startedAt":time,"error":"fixture network error"})
                            .to_string()
                    ],
                )
                .unwrap();
            }
        }
        let d = snapshot(&store, &id, "case", 7, now, true).unwrap();
        assert_eq!(d["queue"][0]["count"], 520);
        let last = d["series"].as_array().unwrap().last().unwrap();
        assert_eq!(last["day"], "2026-10-27");
        assert_eq!(last["evidence"], 1);
        assert_eq!(last["failed"], 1);
        assert_eq!(d["series"][5]["failed"], 1);
        assert_eq!(d["runtime"]["receiverRunning"], true);
        assert_eq!(d["activity"].as_array().unwrap().len(), 20);
        let other = store.create_case("Other business case".into()).unwrap();
        assert_eq!(
            snapshot(&store, &other.id, "case", 7, now, false).unwrap()["counts"]["evidence"],
            0
        );
        assert_eq!(
            snapshot(&store, &other.id, "all", 30, now, false).unwrap()["counts"]["evidence"],
            1
        );
        assert!(snapshot(&store, "missing", "case", 7, now, false).is_err());
        assert!(snapshot(&store, &id, "invalid", 7, now, false).is_err());
        assert!(snapshot(&store, &id, "case", 365, now, false).is_err());
        std::fs::remove_dir_all(store.root).unwrap();
    }
    #[test]
    fn pending_review_counts_latest_evidence_revision_and_latest_manual_disposition() {
        let store = fresh();
        let id = store.active().unwrap();
        let e = store.analyze_alert_text("test".into()).unwrap();
        {
            let db = store.db.lock().unwrap();
            for n in 1..=3 {
                db.execute("INSERT INTO ai_reviews VALUES(?1,?2,?3)",params![format!("a{n}"),e.id,json!({"createdAt":Utc::now().to_rfc3339(),"assessment":{"category":"fixture"}}).to_string()]).unwrap();
            }
        }
        let d = snapshot(&store, &id, "case", 7, Utc::now(), false).unwrap();
        assert_eq!(d["counts"]["reviews"], 3);
        assert_eq!(d["counts"]["latestReviews"], 1);
        assert_eq!(d["counts"]["pendingReviews"], 1);
        {
            let db = store.db.lock().unwrap();
            for (n, disposition) in [(1, "ignore"), (2, "investigate")] {
                db.execute(
                    "INSERT INTO review_feedback VALUES(?1,'a3',?2)",
                    params![
                        format!("f{n}"),
                        json!({"disposition":disposition}).to_string()
                    ],
                )
                .unwrap();
            }
        }
        assert_eq!(
            snapshot(&store, &id, "case", 7, Utc::now(), false).unwrap()["counts"]
                ["pendingReviews"],
            1
        );
        store.db.lock().unwrap().execute("INSERT INTO review_feedback VALUES('f3','a3','{\"disposition\":\"false_positive\"}')",[]).unwrap();
        assert_eq!(
            snapshot(&store, &id, "case", 7, Utc::now(), false).unwrap()["counts"]
                ["pendingReviews"],
            0
        );
        std::fs::remove_dir_all(store.root).unwrap();
    }
}
