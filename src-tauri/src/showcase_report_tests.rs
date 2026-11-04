//! Explicit public showcase: actual analysis/export code, inert materials, no model credentials.
//! Run only with a prepared GAGA_SHOWCASE_SPEC. The personal workspace is never opened.
use crate::{
    investigation, logbook, maintenance, record_entry, report, report_draft, store::Store,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, path::PathBuf};

#[test]
#[ignore = "explicit synthetic showcase; requires prepared materials and a local static-analysis Docker image"]
fn export_reproducible_public_case() {
    let spec_path =
        PathBuf::from(std::env::var_os("GAGA_SHOWCASE_SPEC").expect("Set GAGA_SHOWCASE_SPEC"));
    let out = spec_path.parent().unwrap();
    let spec: Value = serde_json::from_slice(&fs::read(&spec_path).unwrap()).unwrap();
    let node_count = spec["nodes"].as_array().unwrap().len();
    assert_eq!(spec["format"], "gaga-showcase/1");
    assert_eq!(spec["synthetic"], true);
    let root = std::env::temp_dir().join(format!("gaga-public-case-{}", uuid::Uuid::new_v4()));
    let store = Store::open(root.clone()).unwrap();
    let case = store
        .create_case(spec["title"].as_str().unwrap().into())
        .unwrap();
    let mut items = HashMap::new();
    let mut traces = vec![];
    let mut checks = vec![];
    for input in spec["evidence"].as_array().unwrap() {
        let file = input["file"].as_str().unwrap();
        assert!(!file.contains(['/', '\\']));
        let path = out.join("原始材料").join(file);
        assert_eq!(
            format!("{:x}", Sha256::digest(fs::read(&path).unwrap())),
            input["sha256"].as_str().unwrap()
        );
        let item = investigation::local_analyze(&store, None, || {
            store.analyze_file(
                path.to_string_lossy().into_owned(),
                input["kind"].as_str().unwrap().into(),
            )
        })
        .unwrap();
        assert_eq!(item.sha256, input["sha256"]);
        assert_eq!(item.case_id, case.id);
        if item.kind == "logs" {
            let timeline = logbook::query(
                &store,
                logbook::Filter {
                    evidence_id: Some(item.id.clone()),
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(timeline["total"].as_u64().unwrap() > 0);
            assert_eq!(timeline["unknownTimes"], 0);
            traces.push(json!({"evidence":input["key"],"timeline":timeline}));
        }
        items.insert(input["key"].as_str().unwrap().to_owned(), item);
    }
    assert!(items["E-001"]
        .report
        .findings
        .iter()
        .any(|f| f.title == "响应含敏感配置字段"));
    assert_eq!(items["E-001"].report.http_exchanges.len(), 3);
    assert!(items["E-004"]
        .report
        .findings
        .iter()
        .any(|f| f.title == "动态代码执行" && f.line == Some(3)));
    assert!(items["E-004"]
        .report
        .findings
        .iter()
        .any(|f| f.title == "系统命令调用" && f.line == Some(4)));
    assert!(items["E-005"]
        .report
        .coverage
        .iter()
        .any(|c| c.status == "risk" && c.title == "挂载敏感宿主机资源"));
    assert!(items["E-005"]
        .report
        .coverage
        .iter()
        .any(|c| c.status == "unknown"));
    assert!(items["E-005"]
        .report
        .coverage
        .iter()
        .any(|c| c.status == "not_covered"));
    assert_eq!(items["E-007"].report.http_exchanges.len(), 2);
    checks.extend([
        "Seven original hashes verified after real archive",
        "HTTP pairs parsed; sensitive response field located",
        "Two logs indexed with source timestamps",
        "Static comment-only source analyzed in container without execution",
        "Container risk, unknown and not-covered remain distinct",
        "Two retest HTTP exchanges parsed",
    ]);
    let mut draft = report_draft::load(&store, &case.id).unwrap();
    draft.title = spec["reportTitle"].as_str().unwrap().into();
    draft.author = "J4team · 产品演示案例 / 人工编排".into();
    draft.watermark.name = "J4team · 公开案例交付版".into();
    draft.event_type = "Web 配置暴露与主机容器关联调查（合成演练）".into();
    draft.discovered_at = "2026-10-29T10:21:00+08:00".into();
    draft.discovered_by = "赵敏（演练角色）".into();
    draft.severity = "高（演练优先级）".into();
    draft.harm =
        "提供的 HTTP 响应包含测试配置字段；数据库访问、脚本执行、主机控制及容器逃逸均未证实。"
            .into();
    draft.summary = spec["summary"].as_str().unwrap().into();
    draft.scope="仅限案例包中的 7 份合成材料；IP 和域名为文档用途。容器静态分析实际运行，未执行样本；未调用模型、在线情报或真实防火墙。正文为人工复核与编排，不能当作真实客户事故证据。".into();
    draft.recommendations="优先 1｜Web 维护人：在真实环境关闭配置暴露路径、轮换受影响凭据，提交变更工单与复测材料。\n优先 2｜主机与容器维护人：核对公钥授权、会话进程、文件清单与实际网络连接，收敛 Socket 挂载及额外能力。\n优先 3｜调查负责人：把新材料补入独立事件，更新调查假设；仅在取得对应证据后关闭待办。\n上述均为建议，演练未执行这些生产操作。".into();
    draft.steps = serde_json::from_value(spec["steps"].clone()).unwrap();
    report_draft::save(&store, &case.id, &mut draft).unwrap();
    for n in spec["nodes"].as_array().unwrap() {
        let key = n["key"].as_str().unwrap();
        let item = &items[key];
        let finding = if let Some(line) = n["line"].as_u64() {
            item.report
                .findings
                .iter()
                .find(|f| f.line == Some(line as usize))
        } else {
            n["finding"].as_str().and_then(|title| {
                item.report
                    .findings
                    .iter()
                    .find(|f| f.title.contains(title))
            })
        };
        if n.get("finding").is_some() || n.get("line").is_some() {
            assert!(finding.is_some(), "Missing actual finding for {key}");
        }
        let occurred_at = format!("2026-10-29T{}+08:00", n["time"].as_str().unwrap());
        if let Some(line) = n["line"].as_u64() {
            let timeline = logbook::query(
                &store,
                logbook::Filter {
                    evidence_id: Some(item.id.clone()),
                    ..Default::default()
                },
            )
            .unwrap();
            let event = timeline["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["line"].as_u64() == Some(line))
                .unwrap();
            assert_eq!(
                chrono::DateTime::parse_from_rfc3339(event["at"].as_str().unwrap()).unwrap(),
                chrono::DateTime::parse_from_rfc3339(&occurred_at).unwrap()
            );
        }
        let image = out.join("举证图").join(format!("{key}.png"));
        let input=record_entry::Entry{id:uuid::Uuid::new_v4().to_string(),case_id:case.id.clone(),title:n["title"].as_str().unwrap().into(),body:n["body"].as_str().unwrap().into(),actor:n["actor"].as_str().unwrap().into(),occurred_at,evidence_id:Some(item.id.clone()),finding_id:finding.map(|f|f.id.clone()),section_ids:vec![n["section"].as_str().unwrap().into()],new_section_title:String::new(),report_version:report_draft::load(&store,&case.id).unwrap().updated_at,screenshot:Some(record_entry::Shot{data_url:format!("data:image/png;base64,{}",STANDARD.encode(fs::read(image).unwrap())),caption:format!("{key} 合成材料阅读视图截图，非客户现场截图；仅为原件阅读举证，最终以原始文件和 SHA-256 核对。")})};
        let id = record_entry::save(&store, input.clone()).unwrap();
        assert_eq!(record_entry::save(&store, input).unwrap(), id);
    }
    checks.push("Captioned figures and report references committed idempotently");
    let w = store.workspace().unwrap();
    assert_eq!(w.evidence.len(), 7);
    assert_eq!(w.nodes.len(), node_count);
    assert!(w.nodes.iter().all(|n| n.screenshots.len() == 1));
    assert!(w.ai_reviews.is_empty());
    let saved = report_draft::load(&store, &case.id).unwrap();
    assert_eq!(saved.steps.len(), 10);
    assert_eq!(
        saved.steps.iter().map(|s| s.node_ids.len()).sum::<usize>(),
        node_count
    );
    fs::write(out.join("实际分析结果.json"),serde_json::to_vec_pretty(&json!({"synthetic":true,"softwareVersion":env!("CARGO_PKG_VERSION"),"analysisMode":"local rules plus human review; no AI request","evidence":spec["evidence"].as_array().unwrap().iter().map(|e|json!({"label":e["key"],"archived":items[e["key"].as_str().unwrap()]})).collect::<Vec<_>>(),"logTimelines":traces,"nodes":w.nodes,"reportDraft":saved})).unwrap()).unwrap();
    report::export_html(&store, &out.join("案例报告.html")).unwrap();
    report::export_docx(&store, &out.join("案例报告.docx")).unwrap();
    checks.push("Actual report engine exported HTML and editable DOCX");
    let insights = crate::report_insights::summarize(&w, &saved);
    assert_eq!(insights.capsules.len(), node_count);
    assert_eq!(
        insights
            .metrics
            .iter()
            .find(|m| m.key == "evidence")
            .unwrap()
            .value,
        "7"
    );
    fs::write(
        out.join("报告统计.json"),
        serde_json::to_vec_pretty(&insights).unwrap(),
    )
    .unwrap();
    for filename in ["案例报告.html", "案例报告.docx"] {
        assert_eq!(
            crate::report_watermark::inspect(&store, &out.join(filename))
                .unwrap()
                .watermark
                .unwrap()
                .name,
            draft.watermark.name
        );
    }
    checks.push(
        "Shared report metrics, ordered time capsules and invisible HTML/DOCX watermark verified",
    );
    let html = fs::read_to_string(out.join("案例报告.html")).unwrap();
    assert_eq!(html.matches("data:image/png;base64,").count(), node_count);
    assert!(!html.contains("截图预留"));
    assert!(html.contains("待补证"));
    drop(store);
    let reopened = Store::open(root.clone()).unwrap();
    let w = reopened.workspace().unwrap();
    assert_eq!(w.nodes.len(), node_count);
    assert!(w.nodes.iter().all(|n| n.screenshots.len() == 1));
    assert_eq!(
        report_draft::load(&reopened, &case.id).unwrap().steps.len(),
        10
    );
    checks.push("Restart retained independent case, report structure and all figures");
    let integrity: String = reopened
        .db
        .lock()
        .unwrap()
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    checks.push("SQLite integrity check passed");
    let backup_parent = out.join("客户端案例备份");
    fs::create_dir_all(&backup_parent).unwrap();
    let backup = maintenance::backup(&reopened, &backup_parent).unwrap();
    let backup_path = PathBuf::from(backup["path"].as_str().unwrap());
    let restore_parent =
        std::env::temp_dir().join(format!("gaga-public-restore-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&restore_parent).unwrap();
    let restored = maintenance::restore(&backup_path, &restore_parent).unwrap();
    assert_eq!(restored["credentialsIncluded"], false);
    assert_eq!(restored["backgroundTasksDisabled"], true);
    let restored_store = Store::open(PathBuf::from(restored["path"].as_str().unwrap())).unwrap();
    let restored_workspace = restored_store.workspace().unwrap();
    assert_eq!(restored_workspace.evidence.len(), 7);
    assert_eq!(restored_workspace.nodes.len(), node_count);
    assert!(restored_workspace
        .nodes
        .iter()
        .all(|n| n.screenshots.len() == 1));
    assert_eq!(
        report_draft::load(&restored_store, &case.id)
            .unwrap()
            .steps
            .len(),
        10
    );
    drop(restored_store);
    fs::write(out.join("恢复入口.json"),serde_json::to_vec_pretty(&json!({"backupDirectory":format!("客户端案例备份/{}",backup_path.file_name().unwrap().to_string_lossy()),"synthetic":true,"credentialsIncluded":false,"restoreVerified":true,"backgroundTasksDisabled":true})).unwrap()).unwrap();
    checks.push("Product backup restored all evidence, figures and report in a new workspace");
    drop(reopened);
    fs::write(out.join("流程验收.json"),serde_json::to_vec_pretty(&json!({"version":env!("CARGO_PKG_VERSION"),"synthetic":true,"actualAnalysisAndExport":true,"realClientUiRecording":false,"aiRequests":0,"maliciousSampleExecuted":false,"evidence":7,"nodes":node_count,"figures":node_count,"sections":10,"passed":checks,"errors":[]})).unwrap()).unwrap();
    println!("GAGA_SHOWCASE_ROOT={}", root.display());
}

#[test]
#[ignore = "requires the showcase HTML to have been printed to PDF first"]
fn watermark_rendered_showcase_pdf() {
    let spec =
        PathBuf::from(std::env::var_os("GAGA_SHOWCASE_SPEC").expect("Set GAGA_SHOWCASE_SPEC"));
    let out = spec.parent().unwrap();
    let workspace = PathBuf::from(
        std::env::var_os("GAGA_SHOWCASE_WORKSPACE")
            .expect("Set GAGA_SHOWCASE_WORKSPACE to the printed temporary workspace"),
    );
    let store = Store::open(workspace).unwrap();
    let mark = crate::report_watermark::inspect(&store, &out.join("案例报告.html"))
        .unwrap()
        .watermark
        .unwrap();
    crate::report_watermark::stamp_pdf(
        &out.join("案例报告.pdf"),
        &out.join("案例报告-水印版.pdf"),
        &crate::report_watermark::seal(&store, &mark).unwrap(),
    )
    .unwrap();
    let mut result = serde_json::Map::new();
    for name in ["案例报告.html", "案例报告.docx", "案例报告-水印版.pdf"] {
        let inspected = crate::report_watermark::inspect(&store, &out.join(name)).unwrap();
        assert!(inspected.present);
        assert_eq!(inspected.watermark.as_ref().unwrap().name, mark.name);
        result.insert(name.into(), serde_json::to_value(inspected).unwrap());
    }
    fs::write(
        out.join("水印查询.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "explicit existing synthetic workspace; updates report layout without repeating analysis"]
fn refresh_showcase_exports() {
    let spec =
        PathBuf::from(std::env::var_os("GAGA_SHOWCASE_SPEC").expect("Set GAGA_SHOWCASE_SPEC"));
    let root = PathBuf::from(
        std::env::var_os("GAGA_SHOWCASE_WORKSPACE").expect("Set GAGA_SHOWCASE_WORKSPACE"),
    );
    let store = Store::open(root).unwrap();
    report::export_html(&store, &spec.parent().unwrap().join("案例报告.html")).unwrap();
    report::export_docx(&store, &spec.parent().unwrap().join("案例报告.docx")).unwrap();
}
