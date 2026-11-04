use crate::analyzers::{cut, detail, extract_indicators, finding, metric, report, AnalysisReport};
use std::path::Path;
pub fn analyze(path: &Path) -> Result<AnalysisReport, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let text = String::from_utf8(bytes).map_err(|_| "告警文本需要 UTF-8 编码。")?;
    if text.trim().is_empty() {
        return Err("请粘贴告警原文或 JSON。".into());
    }
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
        if matches!(
            value["format"].as_str(),
            Some("gaga-monitor/1" | "gaga-collection/1")
        ) {
            let mut out = report("triage", "持续监控 / 采集观测 · 待复核");
            out.engine = "J4team observation-record/0.4.0".into();
            out.summary = value["summary"]
                .as_str()
                .unwrap_or("已归档采集与监控观测，来源和采集范围需要人工复核。")
                .into();
            out.metrics = vec![metric("原文字节", text.len())];
            if value["kind"] == "snapshot" {
                let files = value["body"]["files"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let commands = value["body"]["commands"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let errors = files
                    .iter()
                    .chain(&commands)
                    .filter(|r| r.get("error").is_some_and(|v| !v.is_null()))
                    .count();
                let truncated = files
                    .iter()
                    .chain(&commands)
                    .filter(|r| r["truncated"] == true)
                    .count();
                out.metrics.extend([
                    metric("采集文件项", files.len()),
                    metric("命令项", commands.len()),
                    metric("采集错误项", errors),
                    metric("截断项", truncated),
                ]);
                if errors > 0 || truncated > 0 {
                    out.warnings.push(format!("本次快照有 {errors} 项采集错误、{truncated} 项输出截断；请检查原文中的 error / truncated 字段，不能视为已完成全面排查。"));
                }
            }
            let mut view = value.clone();
            if let Some(object) = view.as_object_mut() {
                object.remove("rawHtmlBase64");
                if let Some(items) = object.get_mut("scripts").and_then(|v| v.as_array_mut()) {
                    for item in items {
                        if let Some(o) = item.as_object_mut() {
                            o.remove("rawBodyBase64");
                        }
                    }
                }
            }
            let mut details = vec![
                detail("记录类型", value["kind"].as_str().unwrap_or("监控观测")),
                detail(
                    "观测摘要与结构化内容",
                    cut(
                        &serde_json::to_string_pretty(&view).unwrap_or_default(),
                        20000,
                    ),
                ),
            ];
            if value["kind"] == "web" {
                details.push(detail(
                    "原始页面与脚本",
                    "完整 HTML / JS 以 Base64 保存在关联原始证据文件中，摘要和变化见上文。",
                ));
            }
            out.details = details;
            out.indicators = extract_indicators(&text);
            out.warnings.push("采集包完整性与任务凭据校验不等于采集主机可信；页面变化、流量或 IOC 命中不自动证明入侵。".into());
            return Ok(out);
        }
        if value["format"] == "gaga-dynamic/1" {
            let mut out = report("triage", "动态行为报告 · 待复核");
            out.engine = "J4team dynamic-record/0.3.0".into();
            out.summary="已归档隔离实验环境的行为观测记录，保留任务、样本摘要及来源。观测结果受采集范围与反分析影响，不自动判定恶意或证明没有其他行为。".into();
            out.metrics = vec![
                metric("报告字节", text.len()),
                metric("报告来源", value["provider"].as_str().unwrap_or("未知")),
            ];
            out.details = vec![
                detail("报告任务", value["jobId"].as_str().unwrap_or("未知")),
                detail(
                    "样本 SHA-256",
                    value["sampleSha256"].as_str().unwrap_or("未提供"),
                ),
                detail("原始行为报告", cut(&text, 16000)),
            ];
            if let Some(items) = value["limitations"].as_array() {
                out.warnings = items
                    .iter()
                    .filter_map(|v| v.as_str())
                    .take(20)
                    .map(String::from)
                    .collect();
            }
            out.warnings.push(
                "本工具归档与呈现沙箱观测；模型、签名和恶意分数仍需依据原始行为人工复核。".into(),
            );
            out.indicators = extract_indicators(&text);
            return Ok(out);
        }
    }
    let mut out = report("triage", "粘贴告警研判");
    out.engine = "J4team alert-context/0.3.0".into();
    out.indicators = extract_indicators(&text);
    out.summary="已归档粘贴的告警，提取可见指标并保留原文。设备标签属于设备给出的结论，尚未通过会话或主机证据独立验证。".into();
    out.metrics = vec![
        metric("文本行数", text.lines().count()),
        metric("候选指标", out.indicators.len()),
        metric("原文字节", text.len()),
    ];
    out.details=vec![detail("输入类型",if serde_json::from_str::<serde_json::Value>(&text).is_ok(){"用户粘贴的 JSON 告警"}else{"用户粘贴的文本告警"}),detail("告警原文",cut(&text,16000)),detail("证据地位","输入来自人工粘贴；告警名称、规则编码与标签可能同源，不能当作多份独立证据。未验证设备来源与完整性。")];
    out.findings.push(finding("low","告警结论需要原始证据复核","仅凭告警描述、编码或标签，无法确认攻击成功、主机被入侵或精确 ATT&CK 技术。请核对原始会话报文与主机记录。","粘贴文本 / 全文".into(),Some(1),&cut(&text,1500),"补充具体 URL、请求 / 响应、时间、源 / 目的资产以及必要的主机证据，区分事实与设备推断。"));
    out.warnings.push("本地处理只提取文本指标与证据边界，不自动把私网 IP、告警标签或重复描述认定为恶意 / 多源佐证。".into());
    out.warnings.push("ATT&CK 映射需依据具体可观测行为；不单凭“敏感路径”套用 T1046 或 T1083。Windows 4611 与 Sysmon 11 也不能独立证明普通文件读取。".into());
    Ok(out)
}
