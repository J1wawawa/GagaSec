use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    io::{BufRead, BufReader, Seek},
    net::IpAddr,
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub level: String,
    pub title: String,
    pub description: String,
    pub location: String,
    pub line: Option<usize>,
    pub excerpt: String,
    pub remediation: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub label: String,
    pub value: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub kind: String,
    pub value: String,
    pub source: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detail {
    pub label: String,
    pub value: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisReport {
    pub kind: String,
    pub engine: String,
    pub title: String,
    pub summary: String,
    pub metrics: Vec<Metric>,
    pub findings: Vec<Finding>,
    pub indicators: Vec<Indicator>,
    pub details: Vec<Detail>,
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webshell: Option<crate::webshell_schema::WebshellAnalysis>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage: Vec<crate::coverage::Check>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_exchanges: Vec<crate::http::HttpExchange>,
}
pub(crate) fn report(kind: &str, title: &str) -> AnalysisReport {
    AnalysisReport {
        kind: kind.into(),
        engine: "J4team local-rules/0.1.0".into(),
        title: title.into(),
        summary: String::new(),
        metrics: vec![],
        findings: vec![],
        indicators: vec![],
        details: vec![],
        warnings: vec![],
        webshell: None,
        coverage: vec![],
        http_exchanges: vec![],
    }
}
pub(crate) fn metric(label: &str, value: impl ToString) -> Metric {
    Metric {
        label: label.into(),
        value: value.to_string(),
    }
}
pub(crate) fn detail(label: &str, value: impl ToString) -> Detail {
    Detail {
        label: label.into(),
        value: value.to_string(),
    }
}
pub(crate) fn cut(s: &str, max: usize) -> String {
    let mut out: String = s.chars().take(max).collect();
    if s.chars().count() > max {
        out.push_str(" …[展示截断]");
    }
    out
}
pub(crate) fn finding(
    level: &str,
    title: &str,
    description: &str,
    location: String,
    line: Option<usize>,
    excerpt: &str,
    remediation: &str,
) -> Finding {
    Finding {
        id: uuid::Uuid::new_v4().to_string(),
        level: level.into(),
        title: title.into(),
        description: description.into(),
        location,
        line,
        excerpt: cut(excerpt, 2000),
        remediation: remediation.into(),
    }
}
fn patterns() -> Vec<(&'static str, &'static str, Regex)> {
    [
        ("high", "路径穿越请求", r"(?i)(\.\./|%2e%2e(?:%2f|/)|%252e%252e)"),
        ("medium", "敏感配置路径请求", r"(?i)(?:/\.env(?:[/?\s]|$)|/\.git/|/etc/passwd|/wp-config\.php)"),
        ("medium", "上传目录脚本请求", r"(?i)/(?:uploads?|files?|attachments?)/[^\s?]*\.(?:php\d?|phtml|jsp|jspx|aspx?)(?:[?\s]|$)"),
        ("medium", "疑似 SQL 注入片段", r"(?i)(?:union(?:\s|%20|\+)+select|sleep\s*(?:\(|%28)|information_schema)"),
        ("medium", "疑似脚本注入片段", r"(?i)(?:<script|%3cscript|javascript:|onerror\s*=)"),
    ].into_iter().map(|(l,t,p)| (l,t,Regex::new(p).unwrap())).collect()
}
#[cfg(test)]
pub fn analyze_log(path: &Path) -> Result<AnalysisReport, String> {
    analyze_log_stream(path, |_| Ok(()))
}
#[cfg(test)]
pub fn analyze_log_stream(
    path: &Path,
    mut emit: impl FnMut(crate::logbook::Event) -> Result<(), String>,
) -> Result<AnalysisReport, String> {
    analyze_log_observed(path, &mut emit, &crate::analysis_progress::Silent)
}
pub fn analyze_log_observed(
    path: &Path,
    mut emit: impl FnMut(crate::logbook::Event) -> Result<(), String>,
    observer: &dyn crate::analysis_progress::Observer,
) -> Result<AnalysisReport, String> {
    let mut out = report("logs", "日志规则分析");
    let common = Regex::new(r#"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[^"]+)?"\s+(?P<status>\d{3})"#).unwrap();
    let syslog = Regex::new(r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+\S+(?:\[\d+\])?:\s*").unwrap();
    let ssh_ip = Regex::new(r"\bfrom\s+(?P<ip>[0-9a-fA-F.:]+)\s+port\s+\d+").unwrap();
    let mut rules = patterns();
    rules.extend([
        (
            "medium",
            "SSH 认证失败",
            Regex::new(r"(?i)\bsshd(?:\[\d+\])?:.*\bFailed (?:password|publickey)\b").unwrap(),
        ),
        (
            "low",
            "SSH 登录成功（需核对授权）",
            Regex::new(r"(?i)\bsshd(?:\[\d+\])?:.*\bAccepted (?:password|publickey)\b").unwrap(),
        ),
        (
            "low",
            "sudo 命令记录（需核对授权）",
            Regex::new(r"(?i)\bsudo(?:\[\d+\])?:.*\bCOMMAND=").unwrap(),
        ),
        (
            "low",
            "定时任务执行记录（需核对授权）",
            Regex::new(r"(?i)\bCRON(?:D)?(?:\[\d+\])?:.*\bCMD\s*\(").unwrap(),
        ),
    ]);
    let matcher =
        RegexSet::new(rules.iter().map(|(_, _, rule)| rule.as_str())).map_err(|e| e.to_string())?;
    let mut rule_totals = vec![0usize; rules.len()];
    let mut rule_shown = vec![0usize; rules.len()];
    let mut total = 0;
    let mut parsed = 0;
    let mut system = 0;
    let mut invalid = 0;
    let mut oversized = 0;
    let mut omitted = 0;
    let mut ips: HashMap<String, usize> = HashMap::new();
    let mut status: BTreeMap<String, usize> = BTreeMap::new();
    let mut untracked_ips = 0;
    let mut reader =
        BufReader::with_capacity(256 * 1024, File::open(path).map_err(|e| e.to_string())?);
    let mut line_bytes = Vec::with_capacity(4096);
    let counts =
        |bytes, lines, parsed, invalid, oversized, hits| crate::analysis_progress::LogCounts {
            bytes,
            lines: lines as u64,
            parsed: parsed as u64,
            invalid: invalid as u64,
            oversized: oversized as u64,
            hits,
        };
    loop {
        if total % 1024 == 0 {
            observer.scanned(
                counts(
                    reader.stream_position().map_err(|e| e.to_string())?,
                    total,
                    parsed,
                    invalid,
                    oversized,
                    rule_totals.iter().sum::<usize>() as u64,
                ),
                &out.findings,
            )?;
        }
        let Some(too_long) = read_log_line(&mut reader, &mut line_bytes, || observer.check())?
        else {
            break;
        };
        total += 1;
        if too_long {
            oversized += 1;
            continue;
        }
        let line = match std::str::from_utf8(&line_bytes) {
            Ok(s) => s,
            Err(_) => {
                invalid += 1;
                continue;
            }
        };
        let mut ip = None;
        let mut code = None;
        if let Some(c) = common.captures(line) {
            parsed += 1;
            ip = Some(c["ip"].to_string());
            code = Some(c["status"].to_string());
        } else if syslog.is_match(line) {
            parsed += 1;
            system += 1;
            ip = ssh_ip.captures(line).map(|c| c["ip"].to_string());
        } else if line.trim_start().starts_with('{') {
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                if v.is_object() {
                    parsed += 1;
                    ip = ["remote_addr", "client_ip", "ip"]
                        .iter()
                        .find_map(|key| v.get(*key).and_then(Value::as_str))
                        .map(str::to_owned);
                    code = v.get("status").and_then(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .or_else(|| v.as_u64().map(|n| n.to_string()))
                    });
                }
            }
        }
        let source_ip = ip.clone().filter(|s| s.parse::<IpAddr>().is_ok());
        if let Some(ip) = ip.filter(|s| s.parse::<IpAddr>().is_ok()) {
            if ips.contains_key(&ip) || ips.len() < 10_000 {
                *ips.entry(ip).or_default() += 1;
            } else {
                untracked_ips += 1;
            }
        }
        if let Some(code) = code.filter(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_digit())) {
            *status.entry(code).or_default() += 1;
        }
        let matches: Vec<_> = matcher.matches(line).iter().collect();
        let had_matches = !matches.is_empty();
        if !matches.is_empty() {
            emit(crate::logbook::event(
                total,
                line,
                source_ip,
                matches.iter().map(|i| (rules[*i].0, rules[*i].1)).collect(),
            ))?;
        }
        for index in matches {
            let (level, title, _) = &rules[index];
            rule_totals[index] += 1;
            if out.findings.len() < 1000 && rule_shown[index] < 100 {
                rule_shown[index] += 1;
                out.findings.push(finding(
                    level,
                    title,
                    "本地规则命中，属于待复核线索；不证明入侵、代码执行或真实落地时间。",
                    format!("第 {total} 行"),
                    Some(total),
                    line,
                    "回查原始请求、响应、文件与运行记录，结合业务上下文确认。",
                ));
            } else {
                omitted += 1;
            }
        }
        if had_matches && !out.findings.is_empty() && out.findings.len() <= 24 {
            observer.scanned(
                counts(
                    reader.stream_position().map_err(|e| e.to_string())?,
                    total,
                    parsed,
                    invalid,
                    oversized,
                    rule_totals.iter().sum::<usize>() as u64,
                ),
                &out.findings,
            )?;
        }
    }
    observer.scanned(
        counts(
            reader.stream_position().map_err(|e| e.to_string())?,
            total,
            parsed,
            invalid,
            oversized,
            rule_totals.iter().sum::<usize>() as u64,
        ),
        &out.findings,
    )?;
    let mut top: Vec<_> = ips.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out.indicators = top
        .iter()
        .take(200)
        .map(|(ip, count)| Indicator {
            kind: "IP".into(),
            value: ip.clone(),
            source: format!("结构化日志 · {count} 次"),
        })
        .collect();
    out.metrics = vec![
        metric("日志行数", total),
        metric("结构化解析", parsed),
        metric("规则命中", out.findings.len()),
        metric("已统计 IP", top.len()),
        metric("系统日志行", system),
        metric("规则命中总数", rule_totals.iter().sum::<usize>()),
    ];
    out.details = status
        .into_iter()
        .map(|(s, n)| detail(&format!("HTTP {s}"), n))
        .collect();
    out.details.extend(
        rules
            .iter()
            .zip(&rule_totals)
            .filter(|(_, count)| **count > 0)
            .map(|((_, title, _), count)| detail(title, count)),
    );
    out.summary = format!("扫描 {total} 行；{parsed} 行识别为 Common/Combined、JSON 或 Linux syslog / auth 日志（系统日志 {system} 行）。规则命中共 {} 项，展示 {} 项原文线索，均需人工复核。",rule_totals.iter().sum::<usize>(),out.findings.len());
    if total > parsed {
        out.warnings.push(format!(
            "{} 行未结构化解析，仍对可解码且不超长的原文执行规则检查。",
            total - parsed
        ));
    }
    if invalid > 0 {
        out.warnings
            .push(format!("{invalid} 行不是有效 UTF-8，未进行规则检查。"));
    }
    if oversized > 0 {
        out.warnings
            .push(format!("{oversized} 行超过 256 KiB，已跳过规则检查。"));
    }
    if omitted > 0 {
        out.warnings.push(format!(
            "另有 {omitted} 项命中未展示；每条规则保留前 100 项、总计最多 1000 项，完整计数见统计。不能按显示数量评估全部风险。"
        ));
    }
    if untracked_ips > 0 {
        out.warnings.push(format!(
            "IP 统计达到 10000 个唯一值上限，{untracked_ips} 条新 IP 记录未计入排名。"
        ));
    }
    out.warnings
        .push("日志时间保留原文；本地规则不做跨时区归一化、会话重建或自动认定爆破成功。SSH 成功、sudo 与定时任务也可能是合法操作。AI 研判需另外选择模型发起。".into());
    Ok(out)
}
// Drain arbitrarily long lines without allocating their full size; keep line numbers exact.
fn read_log_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
    mut check: impl FnMut() -> Result<(), String>,
) -> Result<Option<bool>, String> {
    const MAX_LINE: usize = 256 * 1024;
    line.clear();
    let mut seen = false;
    let mut oversized = false;
    loop {
        check()?; // Also interrupt a single oversized line without allocating it.
        let bytes = reader
            .fill_buf()
            .map_err(|e| format!("日志读取失败：{e}"))?;
        if bytes.is_empty() {
            return Ok(seen.then_some(oversized));
        }
        seen = true;
        let end = bytes.iter().position(|b| *b == b'\n');
        let count = end.map_or(bytes.len(), |p| p + 1);
        let content = end.unwrap_or(bytes.len());
        let remaining = MAX_LINE.saturating_sub(line.len());
        line.extend_from_slice(&bytes[..content.min(remaining)]);
        oversized |= content > remaining;
        reader.consume(count);
        if end.is_some() {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(oversized));
        }
    }
}
#[cfg(test)]
pub use crate::sample_static::analyze_webshell;
pub fn analyze_container(path: &Path) -> Result<AnalysisReport, String> {
    crate::coverage::analyze(path)
}
pub fn extract_indicators(text: &str) -> Vec<Indicator> {
    let mut result = BTreeSet::new();
    let ip = Regex::new(r"(?:\d{1,3}\.){3}\d{1,3}").unwrap();
    for m in ip.find_iter(text) {
        if m.as_str().parse::<IpAddr>().is_ok() {
            result.insert(("IP".to_string(), m.as_str().to_string()));
        }
    }
    let url = Regex::new(r#"(?i)https?://[^\s<>"']+"#).unwrap();
    for m in url.find_iter(text) {
        result.insert((
            "URL".into(),
            m.as_str()
                .trim_end_matches(['.', ',', ';', ')', ']'])
                .to_string(),
        ));
    }
    let hash = Regex::new(r"(?i)\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b").unwrap();
    for m in hash.find_iter(text) {
        result.insert((
            match m.len() {
                32 => "MD5",
                40 => "SHA1",
                _ => "SHA256",
            }
            .into(),
            m.as_str().to_lowercase(),
        ));
    }
    let domain =
        Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b").unwrap();
    for m in domain.find_iter(text) {
        result.insert(("域名候选".into(), m.as_str().to_lowercase()));
    }
    result
        .into_iter()
        .take(2000)
        .map(|(kind, value)| Indicator {
            kind,
            value,
            source: "文本提取 · 未查询外部情报".into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("gaga-test-{}-{name}", uuid::Uuid::new_v4()));
        std::fs::write(&p, body).unwrap();
        p
    }
    #[test]
    fn log_preserves_evidence_and_does_not_claim_execution() {
        let p=fixture("access.log","203.0.113.42 - - [27/Oct/2026:10:21:08 +0800] \"POST /uploads/cache.php HTTP/1.1\" 200 23\nnormal text\n");
        let r = analyze_log(&p).unwrap();
        assert_eq!(r.metrics[0].value, "2");
        assert_eq!(r.metrics[1].value, "1");
        assert_eq!(r.findings[0].line, Some(1));
        assert!(r.findings[0].description.contains("不证明"));
        assert_eq!(r.indicators[0].value, "203.0.113.42");
        std::fs::remove_file(p).unwrap();
    }
    #[test]
    fn webshell_only_static_rule_hits() {
        let p = fixture(
            "sample.php",
            "<?php\n$value = $_POST['text'];\necho base64_decode($value);\n",
        );
        let r = analyze_webshell(&p).unwrap();
        assert_eq!(r.findings.len(), 2);
        assert_eq!(r.findings[0].line, Some(2));
        std::fs::remove_file(p).unwrap();
    }
    #[test]
    fn auth_logs_keep_late_success_and_exact_totals_after_sampling() {
        let mut lines = "Oct 27 10:21:00 lab sshd[12]: Failed password for invalid user admin from 203.0.113.44 port 40222 ssh2\n".repeat(1200);
        lines.push_str("2026-10-27T10:33:00+08:00 lab sshd[18]: Accepted publickey for analyst from 2001:db8::42 port 40223 ssh2\n");
        lines.push_str(
            "Oct 27 10:34:00 lab sudo: analyst : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/id\n",
        );
        let p = fixture("auth.log", &lines);
        let r = analyze_log(&p).unwrap();
        assert_eq!(
            r.metrics
                .iter()
                .find(|m| m.label == "系统日志行")
                .unwrap()
                .value,
            "1202"
        );
        assert_eq!(
            r.metrics
                .iter()
                .find(|m| m.label == "规则命中总数")
                .unwrap()
                .value,
            "1202"
        );
        assert_eq!(r.findings.len(), 102);
        assert!(r
            .findings
            .iter()
            .any(|f| f.line == Some(1201) && f.title.contains("登录成功")));
        assert!(r.indicators.iter().any(|i| i.value == "2001:db8::42"));
        assert!(r.warnings.iter().any(|w| w.contains("1100")));
        std::fs::remove_file(p).unwrap();
    }
    #[test]
    fn oversized_and_invalid_lines_are_bounded_and_following_lines_survive() {
        let p = fixture("bounded.log", "");
        let mut bytes = vec![b'x'; 512 * 1024];
        bytes.extend_from_slice(b"\n\xff\nOct 27 10:21:00 lab sshd[12]: Failed password for root from 203.0.113.44 port 40222 ssh2\n");
        std::fs::write(&p, bytes).unwrap();
        let r = analyze_log(&p).unwrap();
        assert_eq!(r.metrics[0].value, "3");
        assert_eq!(r.findings[0].line, Some(3));
        assert!(r.warnings.iter().any(|w| w.contains("1 行超过")));
        assert!(r.warnings.iter().any(|w| w.contains("1 行不是有效")));
        let mut input = std::io::Cursor::new(vec![b'x'; 2 * 1024 * 1024]);
        let mut line = Vec::new();
        assert_eq!(
            read_log_line(&mut input, &mut line, || Ok(())).unwrap(),
            Some(true)
        );
        assert!(line.len() <= 256 * 1024);
        std::fs::remove_file(p).unwrap();
    }
    #[test]
    fn container_reports_explicit_values_not_missing_fields() {
        let p = fixture(
            "inspect.json",
            &json!({"Name":"demo","HostConfig":{"Privileged":true},"Config":{}}).to_string(),
        );
        let r = analyze_container(&p).unwrap();
        assert_eq!(r.findings.len(), 1);
        assert!(r.findings[0].location.contains("/HostConfig/Privileged"));
        std::fs::remove_file(p).unwrap();
    }
    #[test]
    fn validates_ip_and_preserves_hash() {
        let r = extract_indicators(
            "999.1.1.1 203.0.113.7 https://example.test/path d41d8cd98f00b204e9800998ecf8427e",
        );
        assert!(r.iter().any(|i| i.value == "203.0.113.7"));
        assert!(!r.iter().any(|i| i.value == "999.1.1.1"));
        assert!(r.iter().any(|i| i.kind == "MD5"));
    }
}
