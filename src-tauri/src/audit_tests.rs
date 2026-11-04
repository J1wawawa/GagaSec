use crate::{coverage, intelligence, logbook, report, store::Store};
use std::fs;
fn store() -> Store {
    Store::open(std::env::temp_dir().join(format!("gaga-audit-{}", uuid::Uuid::new_v4()))).unwrap()
}
#[test]
fn malformed_inspect_fields_never_establish_clear_and_cap_prefix_is_recognized() {
    let s = store();
    let p = s.root.join("inspect.json");
    fs::write(
        &p,
        r#"{"HostConfig":{"CapAdd":[123],"SecurityOpt":[42]},"Mounts":[{}]}"#,
    )
    .unwrap();
    let r = coverage::analyze(&p).unwrap();
    assert!(r
        .coverage
        .iter()
        .all(|c| c.status == "unknown" || c.status == "not_covered"));
    fs::write(
        &p,
        r#"{"HostConfig":{"CapAdd":[123,"CAP_SYS_ADMIN"]},"Mounts":[{}, {"Source":"/proc/1"}]}"#,
    )
    .unwrap();
    let r = coverage::analyze(&p).unwrap();
    assert_eq!(r.coverage.iter().filter(|c| c.status == "risk").count(), 2);
    let root = s.root.clone();
    drop(s);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn cross_file_chronology_filters_and_archive_integrity() {
    let s = store();
    let p = s.root.join("late.log");
    fs::write(&p, "2026-10-27T10:33:00+08:00 host sshd[1]: Accepted publickey for analyst from 2001:db8::42 port 2222 ssh2\n").unwrap();
    let late = s
        .analyze_file(p.display().to_string(), "logs".into())
        .unwrap();
    let p = s.root.join("early.log");
    fs::write(&p, "203.0.113.1 - - [27/Oct/2026:10:21:00 +0800] \"GET /.env HTTP/1.1\" 200 0\n  {\"timestamp\":\"2026-10-27T10:22:00+08:00\",\"remote_addr\":\"203.0.113.2\",\"request\":\"GET /.env HTTP/1.1\",\"status\":200}\n").unwrap();
    let early = s
        .analyze_file(p.display().to_string(), "logs".into())
        .unwrap();
    let q = logbook::query(&s, Default::default()).unwrap();
    assert_eq!(q["events"][0]["evidenceId"], early.id);
    assert_eq!(q["events"][2]["evidenceId"], late.id);
    assert_eq!(q["events"][1]["at"], "2026-10-27T02:22:00.000Z");
    assert_eq!(
        early
            .report
            .metrics
            .iter()
            .find(|m| m.label == "结构化解析")
            .map(|m| m.value.as_str()),
        Some("2")
    );
    let q = logbook::query(
        &s,
        logbook::Filter {
            source_ip: Some("2001:db8::42".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(q["total"], 1);
    assert!(logbook::query(
        &s,
        logbook::Filter {
            after: Some(logbook::Cursor {
                at: "x".repeat(100),
                evidence_id: early.id.clone(),
                line: u64::MAX
            }),
            ..Default::default()
        }
    )
    .is_err());
    logbook::verify_archive(&s, &early).unwrap();
    assert!(fs::metadata(s.root.join("evidence").join(&early.id))
        .unwrap()
        .permissions()
        .readonly());
    assert!(fs::write(
        s.root.join("evidence").join(&early.id),
        "must not overwrite"
    )
    .is_err());
    crate::store::test_overwrite_archive(s.root.join("evidence").join(&early.id), "changed")
        .unwrap();
    assert!(logbook::verify_archive(&s, &early).is_err());
    let root = s.root.clone();
    drop(s);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn screenshot_case_boundary_hash_and_report_embedding() {
    let s = store();
    let a = s.active().unwrap();
    s.add_node(
        "A 证据".into(),
        "原文".into(),
        "2026-10-27T10:21:00+08:00".into(),
        "审计".into(),
        None,
        None,
    )
    .unwrap();
    let node = s.workspace().unwrap().nodes[0].id.clone();
    let p = s.root.join("image.png");
    image::RgbaImage::from_pixel(4, 4, image::Rgba([120, 130, 140, 255]))
        .save(&p)
        .unwrap();
    s.add_screenshot(node.clone(), p.display().to_string(), "粘贴举证图注".into())
        .unwrap();
    let shot = s.workspace().unwrap().nodes[0].screenshots[0].clone();
    assert!(fs::metadata(s.root.join("screenshots").join(&shot.id))
        .unwrap()
        .permissions()
        .readonly());
    assert!(s
        .screenshot_data(shot.id.clone())
        .unwrap()
        .starts_with("data:image/png;base64,"));
    let html = s.root.join("a.html");
    report::export_html(&s, &html).unwrap();
    assert!(fs::read_to_string(&html)
        .unwrap()
        .contains("data:image/png;base64,"));
    s.create_case("B 独立事件".into()).unwrap();
    assert!(s.screenshot_data(shot.id.clone()).is_err());
    assert!(s
        .add_screenshot(node, p.display().to_string(), "跨事件".into())
        .is_err());
    assert!(report::export_html(&s, &s.root.join("b.html")).is_err());
    s.switch_case(a).unwrap();
    crate::store::test_overwrite_archive(s.root.join("screenshots").join(&shot.id), "tampered")
        .unwrap();
    assert!(s.screenshot_data(shot.id).is_err());
    assert!(report::export_html(&s, &html).is_err());
    assert!(report::export_docx(&s, &s.root.join("a.docx")).is_err());
    let root = s.root.clone();
    drop(s);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn malware_cases_are_incident_scoped_while_ioc_is_shared() {
    let s = store();
    let a = s.active().unwrap();
    intelligence::add_case(
        &s,
        "A sample".into(),
        "fixture".into(),
        "d41d8cd98f00b204e9800998ecf8427e".into(),
        "unknown".into(),
        "test".into(),
        None,
    )
    .unwrap();
    assert_eq!(intelligence::sample_cases(&s).unwrap().len(), 1);
    s.create_case("B".into()).unwrap();
    assert!(intelligence::sample_cases(&s).unwrap().is_empty());
    assert!(!intelligence::query(&s, "").unwrap().is_empty());
    s.switch_case(a).unwrap();
    assert_eq!(intelligence::sample_cases(&s).unwrap().len(), 1);
    let root = s.root.clone();
    drop(s);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn workspace_rejects_second_writer_and_releases_lock_on_close() {
    let s = store();
    let root = s.root.clone();
    assert!(Store::open(root.clone()).is_err());
    drop(s);
    let reopened = Store::open(root.clone()).unwrap();
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn historical_deny_rule_survives_more_than_one_thousand_new_rules() {
    let s = store();
    let case = s.active().unwrap();
    intelligence::add_rule(
        &s,
        "deny".into(),
        "ip".into(),
        "203.0.113.44".into(),
        "global".into(),
        None,
        "old rule".into(),
    )
    .unwrap();
    {
        let mut db = s.db.lock().unwrap();
        let tx = db.transaction().unwrap();
        for i in 0..1005 {
            tx.execute("INSERT INTO indicator_rules VALUES(?1,'allow','domain',?2,'global',NULL,'new rule','2099-01-01T00:00:00Z',1)",rusqlite::params![format!("rule-{i}"),format!("{i}.example.test")]).unwrap();
        }
        tx.commit().unwrap();
    }
    assert_eq!(
        intelligence::matches(&s, "ip", "203.0.113.44", &case).unwrap()["deny"],
        true
    );
    let root = s.root.clone();
    drop(s);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ai_rejects_modified_archive_before_any_model_request_and_records_failure() {
    let s = store();
    let e = s
        .analyze_alert_text("NDR sensitive path alert, no packets".into())
        .unwrap();
    s.db.lock().unwrap().execute("INSERT OR REPLACE INTO settings VALUES('ai_config',?1)",[r#"{"endpoint":"http://127.0.0.1:9/v1","model":"fixed-audit-fixture","hasKey":false}"#]).unwrap();
    crate::store::test_overwrite_archive(s.root.join("evidence").join(&e.id), "modified archive")
        .unwrap();
    let error = tauri::async_runtime::block_on(crate::ai::review(
        &s,
        e.id,
        "test material".into(),
        "review".into(),
    ))
    .err()
    .expect("modified archive must fail");
    assert!(error.contains("SHA-256"));
    let w = s.workspace().unwrap();
    assert!(w.ai_reviews.is_empty());
    assert_eq!(w.analysis_runs[0].state, "failed");
    assert_eq!(w.analysis_runs[0].stages[0].status, "failed");
    assert_eq!(w.analysis_runs[0].stages[5].status, "skipped");
    let root = s.root.clone();
    drop(s);
    fs::remove_dir_all(root).unwrap();
}
