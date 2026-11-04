use crate::store::{Store, Workspace};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    fs,
    io::{Cursor, Write},
    path::Path,
};
use zip::{write::SimpleFileOptions, ZipWriter};
fn x(s: &str) -> String {
    // Logs may contain terminal control bytes that XML 1.0 cannot represent.
    s.chars()
        .map(|c| {
            if matches!(c, '\t' | '\n' | '\r')
                || c >= '\u{20}' && c != '\u{fffe}' && c != '\u{ffff}'
            {
                c
            } else {
                '\u{fffd}'
            }
        })
        .collect::<String>()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn paragraph(text: &str, style: &str) -> String {
    format!("<w:p><w:pPr><w:pStyle w:val=\"{style}\"/></w:pPr><w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",x(text).replace('\n',"</w:t><w:br/><w:t xml:space=\"preserve\">"))
}
/// 表格保留可编辑文字，长内容可换页；同一行不拆成两页。
fn table(headers: &[&str], rows: Vec<Vec<String>>, widths: &[u32]) -> String {
    let mut xml = String::from("<w:tbl><w:tblPr><w:tblW w:w=\"9200\" w:type=\"dxa\"/><w:tblLayout w:type=\"fixed\"/><w:tblBorders><w:bottom w:val=\"single\" w:sz=\"4\" w:color=\"E2E2E5\"/><w:insideH w:val=\"single\" w:sz=\"4\" w:color=\"E2E2E5\"/></w:tblBorders><w:tblCellMar><w:top w:w=\"90\" w:type=\"dxa\"/><w:left w:w=\"110\" w:type=\"dxa\"/><w:bottom w:w=\"90\" w:type=\"dxa\"/><w:right w:w=\"110\" w:type=\"dxa\"/></w:tblCellMar></w:tblPr><w:tblGrid>");
    for width in widths {
        xml.push_str(&format!("<w:gridCol w:w=\"{width}\"/>"));
    }
    xml.push_str("</w:tblGrid>");
    for (index, row) in std::iter::once(headers.iter().map(|s| s.to_string()).collect())
        .chain(rows)
        .enumerate()
    {
        xml.push_str(if index == 0 {
            "<w:tr><w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>"
        } else {
            "<w:tr><w:trPr><w:cantSplit/></w:trPr>"
        });
        for (i, value) in row.iter().enumerate() {
            xml.push_str(&format!(
                "<w:tc><w:tcPr><w:tcW w:w=\"{}\" w:type=\"dxa\"/>{}</w:tcPr>{}</w:tc>",
                widths[i],
                if index == 0 {
                    "<w:shd w:fill=\"F3F3F5\"/>"
                } else {
                    ""
                },
                paragraph(value, "Evidence")
            ));
        }
        xml.push_str("</w:tr>");
    }
    xml.push_str("</w:tbl>");
    xml
}
fn insights_docx(data: &crate::report_insights::Insights) -> String {
    let mut out = paragraph("事件数据概览", "Heading1") + &paragraph(data.scope, "Caption");
    out.push_str(&table(
        &["指标", "当前报告", "口径"],
        data.metrics
            .iter()
            .map(|m| vec![m.label.into(), m.value.clone(), m.detail.clone()])
            .collect(),
        &[2300, 2300, 4600],
    ));
    let distribution = data
        .evidence_kinds
        .iter()
        .map(|v| format!("{} {} 份", v.label, v.count))
        .collect::<Vec<_>>()
        .join(" · ");
    out.push_str(&paragraph(
        &format!(
            "材料构成：{}\n章节推进：{} / {} 节已完成，{} 节待补证 / 阻塞。",
            if distribution.is_empty() {
                "未关联原件"
            } else {
                &distribution
            },
            data.completed_sections,
            data.total_sections,
            data.blocked_sections
        ),
        "Normal",
    ));
    out.push_str(&paragraph("阶段与责任", "Heading1"));
    out.push_str(&paragraph(
        "按填写的起止时间计算；阶段可并行，耗时不可直接相加。",
        "Caption",
    ));
    if !data.stages.is_empty() {
        out.push_str(&table(
            &["阶段 / 章节", "负责人 · 章节状态", "起止与耗时"],
            data.stages
                .iter()
                .map(|s| {
                    vec![
                        s.title.clone(),
                        format!("{} · {}\n{} 个举证节点", s.owner, s.status, s.nodes),
                        format!("{} → {}\n{}", s.started_at, s.completed_at, s.duration),
                    ]
                })
                .collect(),
            &[3100, 2200, 3900],
        ));
    }
    out.push_str(&paragraph("事件时间胶囊", "Heading1"));
    out.push_str(&paragraph(
        "按发生时间还原人员行动与举证链，以下章节状态为编排人员填写。",
        "Caption",
    ));
    if data.capsules.is_empty() {
        out.push_str(&paragraph("尚未纳入调查节点。", "Normal"));
    } else {
        out.push_str(&table(
            &["发生时间 / UTC+8", "事件与记录人员", "举证与章节关联"],
            data.capsules
                .iter()
                .map(|c| {
                    vec![
                        format!("{}\n{}\n{}", c.date, c.time, c.gap),
                        format!("{}\n记录 / 执行：{}\n{}", c.title, c.actor, c.summary),
                        format!(
                            "{}\n{}\n{} 张举证图\n{}",
                            c.evidence_name,
                            c.location,
                            c.screenshots,
                            c.sections.join("\n")
                        ),
                    ]
                })
                .collect(),
            &[1700, 4100, 3400],
        ));
    }
    out
}
fn insights_html(data: &crate::report_insights::Insights) -> String {
    let mut out=format!("<div class='report-insights'><div class='insight-overview'><div class='insight-heading'><div><span class='insight-eyebrow'>CASE OVERVIEW</span><h2>事件数据概览</h2></div><span class='insight-tag'>当前报告</span></div><p class='insight-scope'>{}</p><div class='insight-metrics'>",x(data.scope));
    for m in &data.metrics {
        out.push_str(&format!("<div class='insight-metric' data-metric='{}'><span>{}</span><strong>{}</strong><small>{}</small></div>",m.key,x(m.label),x(&m.value),x(&m.detail)));
    }
    out.push_str("</div><div class='insight-distributions'><div class='insight-distribution'><strong>材料构成</strong>");
    let max = data
        .evidence_kinds
        .iter()
        .map(|v| v.count)
        .max()
        .unwrap_or(1)
        .max(1);
    for v in &data.evidence_kinds {
        out.push_str(&format!("<div class='insight-count'><span>{}</span><div class='insight-track'><i style='width:{}%'></i></div><b>{}</b></div>",x(&v.label),v.count*100/max,v.count));
    }
    if data.evidence_kinds.is_empty() {
        out.push_str("<p>尚未关联原件。</p>");
    }
    out.push_str(&format!("</div><div class='insight-distribution'><strong>章节推进</strong><div class='insight-progress-number'>{}<small> / {} 节已完成</small></div><div class='insight-track'><i style='width:{}%'></i></div><p>{} 节待补证 / 阻塞 · 状态来自章节填写</p><div class='insight-ioc-kinds'>",data.completed_sections,data.total_sections,data.completed_sections*100/data.total_sections.max(1),data.blocked_sections));
    for v in &data.indicator_kinds {
        out.push_str(&format!("<span>{} <b>{}</b></span>", x(&v.label), v.count));
    }
    out.push_str("</div></div></div></div><div class='insight-stages'><div class='insight-heading'><div><span class='insight-eyebrow'>PHASE TRACKING</span><h2>阶段与责任</h2></div></div><p class='insight-scope'>耗时使用填写的起止时间；条形按最长已知阶段展示，阶段可以并行，不相加为总耗时。</p>");
    for s in &data.stages {
        out.push_str(&format!("<div class='insight-stage {}'><div><strong>{}</strong><small>{} · {} · {} 个举证节点</small><small>{} → {}</small></div><div class='insight-stage-duration'><span>{}</span><div class='insight-track {}'><i style='width:{}%'></i></div></div></div>",if s.child{"is-child"}else{""},x(&s.title),x(&s.owner),x(&s.status),s.nodes,x(&s.started_at),x(&s.completed_at),x(&s.duration),if s.duration_ms.is_none(){"is-unknown"}else{""},s.width_percent));
    }
    out.push_str(&format!("</div><div class='insight-capsules'><div class='insight-heading'><div><span class='insight-eyebrow'>INCIDENT TIME CAPSULE</span><h2>事件时间胶囊</h2></div><span class='insight-tag'>{} 个节点</span></div><p class='insight-scope'>按节点发生时间排列；每个时间胶囊关联人员、原件、章节和举证图，点击举证可跳转正文。</p>",data.capsules.len()));
    if data.invalid_node_times > 0 {
        out.push_str(&format!(
            "<p class='insight-notice'>{} 个节点时间待复核，置于末尾且不参与跨度计算。</p>",
            data.invalid_node_times
        ));
    }
    out.push_str("<ol class='insight-timeline'>");
    for c in &data.capsules {
        out.push_str(&format!("<li class='insight-capsule'><div class='insight-time'><span>{}</span><strong>{}</strong><small>{}</small></div><div class='insight-capsule-card'><div class='insight-capsule-title'><strong>{}</strong><span>{}</span></div><p>{}</p><div class='insight-section-tags'>",x(&c.date),x(&c.time),x(&c.gap),x(&c.title),x(&c.actor),x(&c.summary)));
        for s in &c.sections {
            out.push_str(&format!("<span>章节：{}</span>", x(s)));
        }
        out.push_str(&format!("</div><div class='insight-proof'><span>{} {}</span><span><a href='#{}'>查看举证 · {} 图</a></span></div></div></li>",x(&c.evidence_name),x(&c.location),c.anchor,c.screenshots));
    }
    out.push_str("</ol></div></div>");
    out
}
fn case_title(w: &Workspace) -> String {
    w.cases
        .iter()
        .find(|c| c.id == w.active_case)
        .map(|c| c.title.clone())
        .unwrap_or_else(|| "调查报告".into())
}
fn entry(
    z: &mut ZipWriter<&mut fs::File>,
    name: &str,
    bytes: &[u8],
    task: &crate::report_jobs::Control,
) -> Result<(), String> {
    z.start_file(
        name,
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
    )
    .map_err(|e| e.to_string())?;
    for chunk in bytes.chunks(256 * 1024) {
        task.check()?;
        z.write_all(chunk).map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn source_text(w: &Workspace, node: &crate::store::TimelineNode) -> String {
    if let Some(e) = w
        .evidence
        .iter()
        .find(|e| Some(&e.id) == node.evidence_id.as_ref())
    {
        let mut s = format!(
            "证据：{}\nSHA-256：{}\n分析引擎：{}",
            e.name, e.sha256, e.report.engine
        );
        if let Some(f) = e
            .report
            .findings
            .iter()
            .find(|f| Some(&f.id) == node.finding_id.as_ref())
        {
            s.push_str(&format!(
                "\n定位：{}\n举证片段（含派生视图时以说明为准）：\n{}\n判断限制：{}",
                f.location, f.excerpt, f.description
            ));
        }
        if let Some(exchange) = e.report.http_exchanges.iter().find(|x| {
            node.finding_id
                .as_ref()
                .is_some_and(|id| x.finding_ids.contains(id))
        }) {
            s.push_str(&format!("\nHTTP 关联：{} · {}\n请求来源：{}\n{}\n请求阅读视图节选：\n{}\n响应来源：{}\n{}\n响应阅读视图节选：\n{}",exchange.id,exchange.assessment,exchange.request.source,exchange.request.representation,crate::analyzers::cut(&exchange.request.raw,4000),exchange.response.as_ref().map(|r|r.source.as_str()).unwrap_or("未提供"),exchange.response.as_ref().map(|r|r.representation.as_str()).unwrap_or("缺少响应，影响未知"),exchange.response.as_ref().map(|r|crate::analyzers::cut(&r.raw,4000)).unwrap_or_default()));
        }
        s
    } else {
        "来源：人工记录；尚未关联原始证据。".into()
    }
}
fn screenshot_bytes(store: &Store, shot: &crate::store::Screenshot) -> Result<Vec<u8>, String> {
    crate::store::verified_image_bytes(
        &store.root.join("screenshots").join(&shot.id),
        shot.size,
        &shot.sha256,
    )
}
/// 只校验本报告实际引用的证据，按 ID 去重；大日志以流式 SHA-256 校验。
/// 数据库保存的摘要不是原件当前仍完整的证明，因此在写输出文件前重新核对。
fn verify_report_sources(
    store: &Store,
    workspace: &Workspace,
    task: &crate::report_jobs::Control,
) -> Result<(), String> {
    let total = workspace
        .evidence
        .iter()
        .try_fold(0u64, |sum, e| sum.checked_add(e.size))
        .ok_or("证据总大小超出范围。")?;
    task.total(total)?;
    task.phase("verifying")?;
    let mut verified = std::collections::HashSet::new();
    for id in workspace
        .nodes
        .iter()
        .filter(|n| n.included)
        .filter_map(|n| n.evidence_id.as_ref())
    {
        if !verified.insert(id) {
            continue;
        }
        let evidence = workspace
            .evidence
            .iter()
            .find(|e| &e.id == id)
            .ok_or("报告引用的证据不存在或不属于当前事件，请重新关联证据")?;
        crate::logbook::verify_archive_progress(&store.root, evidence, |bytes| task.advance(bytes))
            .map_err(|error| {
                if error == crate::report_jobs::CANCELLED {
                    return error;
                }
                format!(
                    "报告引用的证据「{}」校验失败：{error}。请恢复原始归档后重试。",
                    evidence.name
                )
            })?;
    }
    for id in workspace
        .response_actions
        .iter()
        .flat_map(|a| a.evidence_ids.iter())
    {
        if !verified.insert(id) {
            continue;
        }
        let evidence = workspace
            .evidence
            .iter()
            .find(|e| &e.id == id)
            .ok_or("处置动作引用的证据不存在或未被报告捕获，请重新关联证据")?;
        crate::logbook::verify_archive_progress(&store.root, evidence, |bytes| task.advance(bytes))
            .map_err(|error| format!("处置动作引用的证据「{}」校验失败：{error}", evidence.name))?;
    }
    Ok(())
}
fn report_sections<'a>(
    w: &'a Workspace,
    draft: &crate::report_draft::ReportDraft,
) -> Vec<(String, String, Vec<&'a crate::store::TimelineNode>, u8)> {
    let mut sections = vec![];
    if !draft.scope.is_empty() {
        sections.push(("影响范围与调查限制".into(), draft.scope.clone(), vec![], 1));
    }
    let titles = draft.numbered_titles();
    for (i, step) in draft.steps.iter().enumerate() {
        let mut text = crate::report_draft::ReportDraft::step_metadata(step);
        text.push_str("\n\n");
        let content = draft.step_body(&step.id);
        text.push_str(if content.is_empty() {
            "本章节内容待补充。"
        } else {
            content
        });
        let nodes = w
            .nodes
            .iter()
            .filter(|n| n.included && step.node_ids.contains(&n.id))
            .collect();
        sections.push((
            titles[i].clone(),
            text,
            nodes,
            if step.parent_id.is_some() { 2 } else { 1 },
        ));
    }
    if !draft.recommendations.is_empty() {
        sections.push((
            "后续处置与改进建议".into(),
            draft.recommendations.clone(),
            vec![],
            1,
        ));
    }
    let unassigned: Vec<_> = w
        .nodes
        .iter()
        .filter(|n| n.included && !draft.steps.iter().any(|s| s.node_ids.contains(&n.id)))
        .collect();
    if !unassigned.is_empty() {
        sections.push((
            "附录：事件时间线与未分章节证据".into(),
            "以下节点按发生时间排列；尚未指定所属章节。".into(),
            unassigned,
            1,
        ));
    }
    sections
}
// Convenience wrappers are for debug fixtures/tests; production exports use
// the explicit case snapshot and tracked background task below.
#[cfg(any(test, debug_assertions))]
pub fn export_docx(store: &Store, path: &Path) -> Result<(), String> {
    let input = crate::report_input::capture(store, &store.active()?)?;
    export_input(
        store,
        path,
        "docx",
        input,
        &crate::report_jobs::Control::detached(),
    )
}
fn docx(
    store: &Store,
    path: &Path,
    input: crate::report_input::Input,
    task: &crate::report_jobs::Control,
) -> Result<(), String> {
    let crate::report_input::Input {
        workspace: w,
        draft,
        watermark,
    } = input;
    let title = if draft.title.is_empty() {
        case_title(&w)
    } else {
        draft.title.clone()
    };
    let nodes: Vec<_> = w.nodes.iter().filter(|n| n.included).collect();
    if nodes.is_empty() && !draft.has_content() {
        return Err("请填写报告正文或纳入调查节点。".into());
    }
    verify_report_sources(store, &w, task)?;
    task.phase("rendering")?;
    let mut body = paragraph("嘎嘎安全助手 · J4team", "Subtitle")
        + &paragraph(&title, "Title")
        + &paragraph("事件调查报告 / 编写与复核版", "Subtitle");
    body.push_str(&paragraph(if nodes.is_empty() { "本报告为人工编写正文，尚未关联调查节点。相关判断和举证仍需复核补充。" } else { "本报告由已选时间线节点、原始证据引用和截图构成。规则命中需要人工复核，不自动等同于入侵或恶意行为。" },"Normal"));
    if !draft.author.is_empty() {
        body.push_str(&paragraph(&format!("编写：{}", draft.author), "Normal"));
    }
    body.push_str(&table(
        &["事件基本信息", "内容"],
        vec![
            vec!["事件类型".into(), draft.event_type.clone()],
            vec!["危害等级".into(), draft.severity.clone()],
            vec!["发现时间".into(), draft.discovered_at.clone()],
            vec!["发现人".into(), draft.discovered_by.clone()],
            vec!["危害概述".into(), draft.harm.clone()],
        ],
        &[2200, 7000],
    ));
    {
        let (heading, text) = ("事件摘要", &draft.summary);
        if !text.is_empty() {
            body.push_str(&paragraph(heading, "Heading1"));
            body.push_str(&paragraph(text, "Normal"));
        }
    }
    body.push_str("<w:p><w:r><w:br w:type=\"page\"/></w:r></w:p>");
    body.push_str(&insights_docx(&crate::report_insights::summarize(
        &w, &draft,
    )));
    if !w.response_actions.is_empty() {
        body.push_str(&paragraph("处置动作、审批与恢复验证", "Heading1"));
        body.push_str(&paragraph("下表只记录人员填写的审批、执行、回执、回滚和恢复验证，不代表客户端自动执行了高风险操作。", "Caption"));
        body.push_str(&table(
            &["动作 / 目标", "责任与状态", "回执 / 回滚 / 验证"],
            w.response_actions
                .iter()
                .map(|a| {
                    vec![
                        format!("{}\n{}\n{}", a.title, a.action_type, a.target),
                        format!(
                            "申请：{}\n审批：{}\n执行：{}\n状态：{}",
                            a.requested_by,
                            a.approved_by.as_deref().unwrap_or("待审批"),
                            a.executed_by.as_deref().unwrap_or("待执行"),
                            a.status
                        ),
                        format!(
                            "回执：{}\n回滚：{}\n验证：{}",
                            a.receipt.as_deref().unwrap_or("待补"),
                            a.rollback_plan.as_deref().unwrap_or("未填写"),
                            a.verification.as_deref().unwrap_or("待验证")
                        ),
                    ]
                })
                .collect(),
            &[3000, 2600, 3600],
        ));
    }
    let mut media: Vec<(String, Vec<u8>)> = vec![];
    let mut rels = String::new();
    let mut image_id = 0;
    for (heading, text, section_nodes, level) in report_sections(&w, &draft) {
        task.check()?;
        body.push_str(&paragraph(
            &heading,
            if level == 2 { "Heading2" } else { "Heading1" },
        ));
        body.push_str(&paragraph(&text, "Normal"));
        for n in section_nodes {
            task.check()?;
            body.push_str(&paragraph(
                &format!("{}  {}", n.occurred_at, n.title),
                if level == 2 { "Heading3" } else { "Heading2" },
            ));
            body.push_str(&paragraph(
                &format!("记录 / 执行：{}\n录入时间：{}", n.actor, n.recorded_at),
                "Normal",
            ));
            body.push_str(&paragraph(&n.body, "Normal"));
            body.push_str(&paragraph(&source_text(&w, n), "Evidence"));
            if n.screenshots.is_empty() {
                body.push_str(&paragraph(
                    "[截图预留：待补充对应证据截图及图注]",
                    "Caption",
                ));
            }
            for shot in &n.screenshots {
                task.check()?;
                let bytes = screenshot_bytes(store, shot)?;
                let image = crate::store::read_image(&bytes)?;
                let (width, height) = (image.width() as f64, image.height() as f64);
                let scale = (624.0 / width).min(400.0 / height).min(1.0);
                let cx = (width * scale * 9525.0) as u64;
                let cy = (height * scale * 9525.0) as u64;
                let mut png = Cursor::new(Vec::new());
                image
                    .write_to(&mut png, image::ImageFormat::Png)
                    .map_err(|e| e.to_string())?;
                image_id += 1;
                let name = format!("image{image_id}.png");
                let rid = format!("rIdImage{image_id}");
                media.push((name.clone(), png.into_inner()));
                rels.push_str(&format!("<Relationship Id=\"{rid}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"media/{name}\"/>"));
                body.push_str(&format!(r#"<w:p><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{cx}" cy="{cy}"/><wp:docPr id="{image_id}" name="Evidence {image_id}"/><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="{image_id}" name="{name}"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>"#));
                body.push_str(&paragraph(
                    &format!(
                        "图 {image_id}  {}\n来源：{}\n原图 SHA-256：{}",
                        if shot.caption.is_empty() {
                            "未填写图注"
                        } else {
                            &shot.caption
                        },
                        shot.name,
                        shot.sha256
                    ),
                    "Caption",
                ));
            }
        }
    }
    let mut warnings = std::collections::BTreeSet::new();
    for e in &w.evidence {
        for warning in &e.report.warnings {
            warnings.insert(warning.clone());
        }
    }
    if !warnings.is_empty() {
        body.push_str(&paragraph("分析限制", "Heading1"));
    }
    for warning in warnings {
        body.push_str(&paragraph(&warning, "Normal"));
    }
    let document = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"><w:body>{body}<w:sectPr><w:footerReference w:type="default" r:id="rIdFooter"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:footer="567"/></w:sectPr></w:body></w:document>"#
    );
    let styles = r#"<?xml version="1.0" encoding="UTF-8"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Arial" w:eastAsia="Microsoft YaHei"/><w:sz w:val="22"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="140" w:line="320" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:rPr><w:b/><w:sz w:val="42"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:rPr><w:color w:val="666666"/><w:sz w:val="20"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:pPr><w:outlineLvl w:val="0"/><w:keepNext/><w:spacing w:before="260" w:after="160"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Evidence"><w:name w:val="Evidence"/><w:rPr><w:rFonts w:ascii="Consolas"/><w:sz w:val="19"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Caption"><w:name w:val="Caption"/><w:rPr><w:color w:val="666666"/><w:sz w:val="19"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:pPr><w:outlineLvl w:val="1"/><w:keepNext/></w:pPr><w:rPr><w:b/><w:sz w:val="25"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:pPr><w:outlineLvl w:val="2"/><w:keepNext/></w:pPr><w:rPr><w:b/><w:sz w:val="23"/></w:rPr></w:style></w:styles>"#;
    let mut types = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>"#,
    );
    let mut root_rels = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#,
    );
    types=types.replace("</Types>","<Override PartName=\"/word/footer.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml\"/></Types>");
    let custom=watermark.as_ref().map(|token|format!(r#"<?xml version="1.0" encoding="UTF-8"?><Properties xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes" xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"><property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="2" name="GagaReportWatermark"><vt:lpwstr>{}</vt:lpwstr></property></Properties>"#,x(token)));
    if custom.is_some() {
        types=types.replace("</Types>","<Override PartName=\"/docProps/custom.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.custom-properties+xml\"/></Types>");
        root_rels=root_rels.replace("</Relationships>","<Relationship Id=\"rIdWatermark\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties\" Target=\"docProps/custom.xml\"/></Relationships>");
    }
    let document_rels = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer.xml"/>{rels}</Relationships>"#
    );
    task.phase("writing")?;
    crate::file_commit::write_checked(
        path,
        |file| {
            let mut zip = ZipWriter::new(file);
            entry(&mut zip, "[Content_Types].xml", types.as_bytes(), task)?;
            entry(&mut zip, "_rels/.rels", root_rels.as_bytes(), task)?;
            entry(&mut zip, "word/document.xml", document.as_bytes(), task)?;
            entry(&mut zip, "word/styles.xml", styles.as_bytes(), task)?;
            entry(&mut zip,"word/footer.xml",br#"<?xml version="1.0" encoding="UTF-8"?><w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:jc w:val="right"/><w:pBdr><w:top w:val="single" w:sz="4" w:color="DDDDDD"/></w:pBdr></w:pPr><w:r><w:rPr><w:sz w:val="18"/><w:color w:val="777777"/></w:rPr><w:t>J4team  /  </w:t></w:r><w:fldSimple w:instr="PAGE"/></w:p></w:ftr>"#,task)?;
            if let Some(xml) = &custom {
                entry(&mut zip, "docProps/custom.xml", xml.as_bytes(), task)?;
            }
            entry(
                &mut zip,
                "word/_rels/document.xml.rels",
                document_rels.as_bytes(),
                task,
            )?;
            for (name, bytes) in media {
                entry(&mut zip, &format!("word/media/{name}"), &bytes, task)?;
            }
            zip.finish().map_err(|e| e.to_string())?;
            task.check()
        },
        || task.begin_commit(),
    )
}
#[cfg(any(test, debug_assertions))]
pub fn export_html(store: &Store, path: &Path) -> Result<(), String> {
    let input = crate::report_input::capture(store, &store.active()?)?;
    export_input(
        store,
        path,
        "html",
        input,
        &crate::report_jobs::Control::detached(),
    )
}
fn html(
    store: &Store,
    path: &Path,
    input: crate::report_input::Input,
    task: &crate::report_jobs::Control,
) -> Result<(), String> {
    let crate::report_input::Input {
        workspace: w,
        draft,
        watermark,
    } = input;
    verify_report_sources(store, &w, task)?;
    task.phase("rendering")?;
    let title = if draft.title.is_empty() {
        case_title(&w)
    } else {
        draft.title.clone()
    };
    let insights = crate::report_insights::summarize(&w, &draft);
    let mut body=format!("<header class='report-cover'><div class='report-cover-brand'><span>嘎嘎安全助手 · J4team</span><span>INCIDENT REPORT</span></div><div class='report-cover-label'>事件调查报告</div><h1>{}</h1><p class='report-cover-subtitle'>证据 · 时间线 · 处置与复核</p>",x(&title));
    if !w.nodes.iter().any(|n| n.included) {
        body.push_str(
            "<p>本报告为人工编写正文，尚未关联调查节点。相关判断和举证仍需复核补充。</p>",
        );
    }
    if !draft.author.is_empty() {
        body.push_str(&format!("<p>编写：{}</p>", x(&draft.author)));
    }
    body.push_str("<dl class='report-cover-meta'>");
    for (label, value) in [
        ("事件类型", &draft.event_type),
        ("危害等级", &draft.severity),
        ("发现时间", &draft.discovered_at),
        ("发现人", &draft.discovered_by),
    ] {
        body.push_str(&format!(
            "<div><dt>{label}</dt><dd>{}</dd></div>",
            x(if value.is_empty() { "待补充" } else { value })
        ));
    }
    body.push_str(&format!(
        "</dl><div class='report-cover-harm'><strong>危害概述</strong><p class='body'>{}</p></div>",
        x(if draft.harm.is_empty() {
            "待评估"
        } else {
            &draft.harm
        })
    ));
    {
        let (heading, text) = ("事件摘要", &draft.summary);
        if !text.is_empty() {
            body.push_str(&format!(
                "<h2>{heading}</h2><p class='body'>{}</p>",
                x(text)
            ));
        }
    }
    body.push_str("</header>");
    body.push_str(&insights_html(&insights));
    if !w.response_actions.is_empty() {
        body.push_str("<div class='report-phase'><h2>处置动作、审批与恢复验证</h2><p class='body'>下表只记录人员填写的审批、执行、回执、回滚和恢复验证，不代表客户端自动执行了高风险操作。</p><div class='response-report-table'><table><thead><tr><th>动作 / 目标</th><th>责任与状态</th><th>回执 / 回滚 / 验证</th></tr></thead><tbody>");
        for a in &w.response_actions {
            body.push_str(&format!("<tr><td><strong>{}</strong><br>{}<br>{}</td><td>申请：{}<br>审批：{}<br>执行：{}<br><b>{}</b></td><td>回执：{}<br>回滚：{}<br>验证：{}</td></tr>", x(&a.title), x(&a.action_type), x(&a.target), x(&a.requested_by), x(a.approved_by.as_deref().unwrap_or("待审批")), x(a.executed_by.as_deref().unwrap_or("待执行")), x(&a.status), x(a.receipt.as_deref().unwrap_or("待补")), x(a.rollback_plan.as_deref().unwrap_or("未填写")), x(a.verification.as_deref().unwrap_or("待验证"))));
        }
        body.push_str("</tbody></table></div></div>");
    }
    let mut number = 0;
    let mut anchored = std::collections::HashSet::new();
    for (heading, text, section_nodes, level) in report_sections(&w, &draft) {
        task.check()?;
        body.push_str(&format!(
            "<div class='report-phase'><h{tag}>{}</h{tag}><p class='body'>{}</p>",
            x(&heading),
            x(&text),
            tag = level + 1
        ));
        for n in section_nodes {
            task.check()?;
            if anchored.insert(&n.id) {
                if let Some(c) = insights.capsules.iter().find(|c| c.id == n.id) {
                    body.push_str(&format!("<div id='{}'></div>", c.anchor));
                }
            }
            body.push_str(&format!("<section><h{node_tag}>{} {}</h{node_tag}><p>记录 / 执行：{} · 录入：{}</p><p class='body'>{}</p><pre>{}</pre>",x(&n.occurred_at),x(&n.title),x(&n.actor),x(&n.recorded_at),x(&n.body),x(&source_text(&w,n)),node_tag=level+2));
            if n.screenshots.is_empty() {
                body.push_str("<div class='placeholder'>截图预留 · 待补图及图注</div>");
            }
            for shot in &n.screenshots {
                task.check()?;
                number += 1;
                let bytes = screenshot_bytes(store, shot)?;
                body.push_str(&format!("<figure><img src='data:{};base64,{}' alt='{}'><figcaption>图 {}　{}<br>来源：{}<br>原图 SHA-256：{}</figcaption></figure>",shot.mime,STANDARD.encode(bytes),x(&shot.caption),number,x(&shot.caption),x(&shot.name),shot.sha256));
            }
            body.push_str("</section>");
        }
        body.push_str("</div>");
    }
    if !w.nodes.iter().any(|n| n.included) && !draft.has_content() {
        return Err("请填写报告正文或纳入调查节点。".into());
    }
    let warnings: std::collections::BTreeSet<_> = w
        .evidence
        .iter()
        .flat_map(|e| e.report.warnings.iter())
        .collect();
    if !warnings.is_empty() {
        body.push_str("<div class='report-phase report-limitations'><h2>分析限制</h2>");
        for warning in warnings {
            body.push_str(&format!("<p class='body'>{}</p>", x(warning)));
        }
        body.push_str("</div>");
    }
    body.push_str("<footer class='report-end'>嘎嘎安全助手 · J4team / 原件、派生分析与人工复核分别保留</footer>");
    let meta = watermark
        .as_ref()
        .map(|token| format!("<meta name=\"gaga-report-watermark\" content=\"{token}\"> "))
        .unwrap_or_default();
    let html=format!("<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; img-src data:; style-src 'unsafe-inline'\">{meta}<title>{}</title><style>{}{}</style></head><body>{body}</body></html>",x(&title),include_str!("../../src/report-insights.css"),include_str!("report-print.css"));
    task.phase("writing")?;
    crate::file_commit::write_checked(
        path,
        |file| {
            for chunk in html.as_bytes().chunks(256 * 1024) {
                task.check()?;
                file.write_all(chunk).map_err(|e| e.to_string())?;
            }
            Ok(())
        },
        || task.begin_commit(),
    )
}
/// 同一份已捕获输入交给两种渲染器；报告不重新查询活动事件。
pub fn export_input(
    store: &Store,
    path: &Path,
    format: &str,
    input: crate::report_input::Input,
    task: &crate::report_jobs::Control,
) -> Result<(), String> {
    task.check()?;
    validate_output(store, path)?;
    match format {
        "docx" => docx(store, path, input, task),
        "html" => html(store, path, input, task),
        _ => Err("不支持的导出格式。".into()),
    }
}
pub(crate) fn validate_output(store: &Store, path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or("导出路径无效。")?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let name = path.file_name().ok_or("导出文件名无效。")?;
    let target = parent.join(name);
    if fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("导出目标不能是符号链接，请选择普通报告文件。".into());
    }
    let root = store.root.canonicalize().map_err(|e| e.to_string())?;
    if let Ok(relative) = target.strip_prefix(&root) {
        let first = relative
            .components()
            .next()
            .and_then(|c| c.as_os_str().to_str())
            .unwrap_or("");
        if matches!(
            first,
            "evidence"
                | "screenshots"
                | "log-index"
                | "collector-inbox"
                | "http-input"
                | "clipboard-input"
                | "record-input"
                | "alert-input"
                | "example-input"
                | "demo-input"
                | "sandbox-reports"
                | "reverse-artifacts"
                | "migration-backups"
                | "runtime-logs"
                | "workspace.lock"
                | "report-watermark.key"
                | "lan-private"
        ) || first.starts_with("workspace.sqlite3")
        {
            return Err("不能用报告覆盖工作区数据库或内部证据，请另选导出位置。".into());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    #[test]
    fn report_snapshot_is_bound_to_case_and_excludes_unselected_and_unrelated_records() {
        let root =
            std::env::temp_dir().join(format!("gaga-report-snapshot-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let case = store.active().unwrap();
        let e = store
            .analyze_http_pair(
                "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".into(),
                "".into(),
            )
            .unwrap();
        store
            .add_node(
                "A captured node".into(),
                "captured body".into(),
                "2026-10-29T10:00:00+08:00".into(),
                "test".into(),
                Some(e.id.clone()),
                None,
            )
            .unwrap();
        let unused = store
            .analyze_http_pair(
                "GET /unused HTTP/1.1\r\nHost: example.test\r\n\r\n".into(),
                "".into(),
            )
            .unwrap();
        // 非报告引用记录故意损坏；报告不应加载它或无关 AI 历史。
        store
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE evidence SET report='invalid-json' WHERE id=?1",
                [&unused.id],
            )
            .unwrap();
        let input = crate::report_input::capture(&store, &case).unwrap();
        assert_eq!(input.workspace.evidence.len(), 1);
        assert!(input.workspace.ai_reviews.is_empty());
        store
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE nodes SET body='changed after capture' WHERE case_id=?1",
                [&case],
            )
            .unwrap();
        store.create_case("B must not be exported".into()).unwrap();
        export_input(
            &store,
            &root.join("snapshot.html"),
            "html",
            input,
            &crate::report_jobs::Control::detached(),
        )
        .unwrap();
        let html = fs::read_to_string(root.join("snapshot.html")).unwrap();
        assert!(html.contains("captured body"));
        assert!(
            !html.contains("changed after capture") && !html.contains("B must not be exported")
        );
        assert_eq!(store.cases().unwrap().len(), 2);
        for folder in ["migration-backups", "runtime-logs"] {
            fs::create_dir_all(root.join(folder)).unwrap();
            fs::write(root.join(folder).join("retained.dat"), b"internal canary").unwrap();
        }
        for target in [
            root.join("workspace.sqlite3"),
            root.join("report-watermark.key"),
            root.join("evidence").join(&e.id),
            root.join("migration-backups/retained.dat"),
            root.join("runtime-logs/retained.dat"),
        ] {
            let before = fs::read(&target).unwrap();
            let input = crate::report_input::capture(&store, &case).unwrap();
            assert!(export_input(
                &store,
                &target,
                "html",
                input,
                &crate::report_jobs::Control::detached()
            )
            .unwrap_err()
            .contains("不能用报告覆盖"));
            assert_eq!(fs::read(target).unwrap(), before);
        }
        let input = crate::report_input::capture(&store, &case).unwrap();
        let task = crate::report_jobs::Control::detached();
        task.cancel().unwrap();
        fs::write(root.join("cancelled.html"), b"old").unwrap();
        assert_eq!(
            export_input(&store, &root.join("cancelled.html"), "html", input, &task).unwrap_err(),
            crate::report_jobs::CANCELLED
        );
        assert_eq!(fs::read(root.join("cancelled.html")).unwrap(), b"old");
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn audit_071_report_rejects_changed_or_missing_selected_evidence() {
        let root =
            std::env::temp_dir().join(format!("gaga-report-integrity-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let evidence = store
            .analyze_http_pair(
                "GET /.env HTTP/1.1\r\nHost: example.test\r\n\r\n".into(),
                "HTTP/1.1 403 Forbidden\r\n\r\n".into(),
            )
            .unwrap();
        store
            .add_node(
                "请求待复核".into(),
                "保留原始报文".into(),
                "2026-10-28T10:21:00+08:00".into(),
                "测试员".into(),
                Some(evidence.id.clone()),
                None,
            )
            .unwrap();
        let archive = root.join("evidence").join(&evidence.id);
        let original = fs::read(&archive).unwrap();
        for missing in [false, true] {
            if missing {
                fs::remove_file(&archive).unwrap();
            } else {
                crate::store::test_overwrite_archive(&archive, vec![b'x'; original.len()]).unwrap();
            }
            for (name, export) in [
                (
                    "report.docx",
                    export_docx as fn(&Store, &Path) -> Result<(), String>,
                ),
                ("report.html", export_html),
            ] {
                let dest = root.join(name);
                fs::write(&dest, b"previous-valid-report").unwrap();
                let error = export(&store, &dest).expect_err("changed source must block export");
                assert!(error.contains("证据"));
                assert_eq!(fs::read(&dest).unwrap(), b"previous-valid-report");
            }
            crate::store::test_overwrite_archive(&archive, &original).unwrap();
        }
        export_docx(&store, &root.join("report.docx")).unwrap();
        export_html(&store, &root.join("report.html")).unwrap();
        // Unselected material must not prevent a report about unrelated, valid evidence.
        let unrelated = store
            .analyze_http_pair(
                "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".into(),
                "".into(),
            )
            .unwrap();
        fs::remove_file(root.join("evidence").join(unrelated.id)).unwrap();
        export_html(&store, &root.join("report.html")).unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn docx_contains_real_nodes_and_escapes_xml() {
        let root = std::env::temp_dir().join(format!("gaga-docx-{}", uuid::Uuid::new_v4()));
        let s = Store::open(root.clone()).unwrap();
        s.add_node(
            "<test> & 处置".into(),
            "原文保留".into(),
            "2026-10-27T10:22:00+08:00".into(),
            "张三".into(),
            None,
            None,
        )
        .unwrap();
        let mut draft = crate::report_draft::load(&s, &s.active().unwrap()).unwrap();
        draft.steps = crate::report_draft::default_steps();
        draft.event_type = "Web 入侵 <待复核>".into();
        draft.discovered_by = "发现员甲".into();
        draft.discovered_at = "2026-10-27T10:21:00+08:00".into();
        draft.harm = "潜在配置暴露，未确认损失".into();
        draft.steps[1].owner = "处置责任人乙".into();
        draft.steps[1].status = "in_progress".into();
        draft.steps[1]
            .node_ids
            .push(s.workspace().unwrap().nodes[0].id.clone());
        draft.steps[1].body = "已记录指令，待设备回执".into();
        crate::report_draft::save(&s, &s.active().unwrap(), &mut draft).unwrap();
        let dest = root.join("report.docx");
        export_docx(&s, &dest).unwrap();
        let mut z = zip::ZipArchive::new(fs::File::open(dest).unwrap()).unwrap();
        let mut text = String::new();
        z.by_name("word/document.xml")
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert!(text.contains("&lt;test&gt; &amp;"));
        assert!(text.contains("截图预留"));
        assert!(
            text.contains("发现员甲")
                && text.contains("Web 入侵 &lt;待复核&gt;")
                && text.contains("处置责任人乙")
        );
        for title in crate::report_draft::STEP_TITLES {
            assert!(text.contains(title));
        }
        assert!(text.find("2. 事件紧急处置").unwrap() < text.rfind("&lt;test&gt; &amp;").unwrap());
        assert!(text.rfind("&lt;test&gt; &amp;").unwrap() < text.find("3. 事件过程排查").unwrap());
        let html = root.join("report.html");
        export_html(&s, &html).unwrap();
        let html = fs::read_to_string(html).unwrap();
        assert!(
            html.contains("处置责任人乙")
                && html.contains("已记录指令，待设备回执")
                && html.contains("发现员甲")
        );
        assert!(html.find("2. 事件紧急处置").unwrap() < html.rfind("&lt;test&gt; &amp;").unwrap());
        assert!(html.rfind("&lt;test&gt; &amp;").unwrap() < html.find("3. 事件过程排查").unwrap());
        drop(z);
        drop(s);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn screenshot_survives_reopen_and_is_embedded_with_caption() {
        let root = std::env::temp_dir().join(format!("gaga-image-{}", uuid::Uuid::new_v4()));
        let s = Store::open(root.clone()).unwrap();
        s.add_node(
            "截图举证".into(),
            "带控制字节\u{1b}的记录 & <原文>".into(),
            "2026-10-27T10:22:00+08:00".into(),
            "张三".into(),
            None,
            None,
        )
        .unwrap();
        let node = s.workspace().unwrap().nodes[0].id.clone();
        let input = root.join("input.png");
        image::RgbaImage::from_pixel(80, 40, image::Rgba([40, 40, 40, 255]))
            .save(&input)
            .unwrap();
        s.add_screenshot(
            node,
            input.display().to_string(),
            "图注：设备回执 <原图>".into(),
        )
        .unwrap();
        fs::remove_file(input).unwrap();
        drop(s);
        let s = Store::open(root.clone()).unwrap();
        let w = s.workspace().unwrap();
        let shot = &w.nodes[0].screenshots[0];
        assert!(s
            .screenshot_data(shot.id.clone())
            .unwrap()
            .starts_with("data:image/png;base64,"));
        let dest = root.join("report.docx");
        export_docx(&s, &dest).unwrap();
        let mut z = zip::ZipArchive::new(fs::File::open(dest).unwrap()).unwrap();
        let mut xml = String::new();
        z.by_name("word/document.xml")
            .unwrap()
            .read_to_string(&mut xml)
            .unwrap();
        assert!(xml.contains("r:embed=\"rIdImage1\""));
        assert!(xml.contains("图注：设备回执 &lt;原图&gt;"));
        assert!(xml.contains(&shot.sha256));
        assert!(!xml.contains('\u{1b}'));
        assert!(z.by_name("word/media/image1.png").unwrap().size() > 0);
        let mut rels = String::new();
        z.by_name("word/_rels/document.xml.rels")
            .unwrap()
            .read_to_string(&mut rels)
            .unwrap();
        assert!(rels.contains("Target=\"media/image1.png\""));
        export_html(&s, &root.join("report.html")).unwrap();
        let html = fs::read_to_string(root.join("report.html")).unwrap();
        assert!(html.contains("data:image/png;base64,"));
        assert!(html.contains("&lt;原图&gt;"));
        drop(z);
        drop(s);
        fs::remove_dir_all(root).unwrap();
    }
}
