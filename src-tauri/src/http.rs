use crate::analyzers::{
    cut, detail, extract_indicators, finding, metric, report, AnalysisReport, Finding,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::read::{GzDecoder, ZlibDecoder};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};

const BODY_LIMIT: usize = 1024 * 1024;
const PAIR_LIMIT: usize = 2 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpMessage {
    pub start_line: String,
    pub headers: Vec<Header>,
    pub raw: String,
    pub body_preview: String,
    pub body_bytes: usize,
    pub sha256: Option<String>,
    pub source: String,
    pub representation: String,
    pub warnings: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpExchange {
    pub id: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub started_at: String,
    pub request: HttpMessage,
    pub response: Option<HttpMessage>,
    pub assessment: String,
    pub finding_ids: Vec<String>,
}
struct Message {
    view: HttpMessage,
    body: String,
}
fn header<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}
fn text(bytes: &[u8], warnings: &mut Vec<String>) -> String {
    if std::str::from_utf8(bytes).is_err() {
        warnings
            .push("正文含非 UTF-8 字节，分析视图使用替代字符；二进制或其他字符集可能漏检。".into());
    }
    String::from_utf8_lossy(bytes).into_owned()
}
fn bounded<R: Read>(input: R) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    input
        .take((BODY_LIMIT + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|_| "压缩正文损坏或不完整。")?;
    if out.len() > BODY_LIMIT {
        return Err("解压正文超过 1 MiB，停止解压；该正文未执行规则检查。".into());
    }
    Ok(out)
}
fn dechunk(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    loop {
        let end = bytes[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("Chunked 分块大小行不完整。")?
            + pos;
        let size = std::str::from_utf8(&bytes[pos..end])
            .map_err(|_| "Chunked 大小不是 ASCII。")?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if size.is_empty() || size.len() > 16 || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Chunked 分块大小无效。".into());
        }
        let n = usize::from_str_radix(size, 16).map_err(|_| "Chunked 分块大小溢出。")?;
        pos = end + 2;
        if n == 0 {
            if bytes.get(pos..pos + 2) == Some(b"\r\n") {
                if pos + 2 != bytes.len() {
                    return Err("Chunked 结束后仍有额外字节，无法确定报文边界。".into());
                }
                return Ok(out);
            }
            if let Some(i) = bytes[pos..].windows(4).position(|w| w == b"\r\n\r\n") {
                if pos + i + 4 == bytes.len() {
                    return Ok(out);
                }
            }
            return Err("Chunked 尾部不完整或存在额外报文。".into());
        }
        let next = pos.checked_add(n).ok_or("Chunked 分块大小溢出。")?;
        if next > bytes.len() || bytes.get(next..next + 2) != Some(b"\r\n") {
            return Err("Chunked 数据不足或缺少 CRLF。".into());
        }
        if out.len().saturating_add(n) > BODY_LIMIT {
            return Err("Chunked 正文超过 1 MiB，停止解析。".into());
        }
        out.extend_from_slice(&bytes[pos..next]);
        pos = next + 2;
    }
}
fn raw_message(raw: &str, source: &str, response: bool) -> Result<Message, String> {
    if raw.len() > PAIR_LIMIT {
        return Err("单侧原始报文超过 2 MiB。".into());
    }
    let mut warnings = vec![];
    // Copying a header-only request often drops the final empty line. Preserve
    // the submitted bytes and describe the missing boundary instead of rejecting
    // every otherwise valid start line / header. Never invent a response body.
    let parsing = raw.trim_start_matches(['\u{feff}', '\r', '\n']);
    if parsing != raw {
        warnings
            .push("解析阅读视图时忽略了起始 BOM / 空行；原始文本及其 SHA-256 保持不变。".into());
    }
    let (head, body) = parsing
        .split_once("\r\n\r\n")
        .or_else(|| parsing.split_once("\n\n"))
        .unwrap_or_else(|| {
            warnings.push("未提供消息头后的空行；仅检查已提供的起始行和消息头，正文是否缺失或截断未知。原始输入已保留。".into());
            (parsing.trim_end_matches(['\r', '\n']), "")
        });
    if head.len() > 65536 {
        return Err("消息头超过 64 KiB。".into());
    }
    let mut lines = head.lines();
    let original_start = lines.next().unwrap_or("");
    let start = original_start
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if start != original_start.trim_end_matches('\r') {
        warnings.push("起始行空白已在阅读视图中归一化；这不代表线上报文符合协议，原始输入及其 SHA-256 保持不变。".into());
    }
    let valid = if response {
        Regex::new(r"^HTTP/(?:1\.[01]|2(?:\.0)?|3) [1-5][0-9]{2}(?: .*)?$")
            .unwrap()
            .is_match(&start)
    } else {
        Regex::new(r"^[A-Z!#$%&'*+.^_`|~-]+ \S+ HTTP/(?:1\.[01]|2(?:\.0)?|3)$")
            .unwrap()
            .is_match(&start)
    };
    if !valid {
        return Err(if response {
            "响应起始行应类似 HTTP/1.1 200 OK。"
        } else {
            "请求起始行应类似 GET /path HTTP/1.1。"
        }
        .into());
    }
    let mut headers: Vec<Header> = vec![];
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.starts_with([' ', '\t']) {
            warnings.push("消息头包含折叠行，已展开；边界与网关解析差异需要人工核对。".into());
            if let Some(h) = headers.last_mut() {
                h.value.push(' ');
                h.value.push_str(line.trim());
                continue;
            }
            return Err("头字段折叠行缺少前置字段。".into());
        }
        let (name, value) = line
            .split_once(':')
            .ok_or("消息头缺少冒号。若这一行是正文，请在消息头与正文之间补一个空行。")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err(
                "消息头字段名无效。若这一行是正文，请在消息头与正文之间补一个空行。".into(),
            );
        }
        headers.push(Header {
            name: name.into(),
            value: value.trim().into(),
        });
    }
    let body_bytes = body.as_bytes();
    let mut decoded = body_bytes.to_vec();
    let te = header(&headers, "transfer-encoding")
        .unwrap_or("")
        .to_ascii_lowercase();
    let lengths: Vec<_> = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
        .map(|h| h.value.as_str())
        .collect();
    if !te.is_empty() && !lengths.is_empty() {
        warnings.push(
            "同时存在 Transfer-Encoding 与 Content-Length，帧边界存在歧义；不能据此确认请求走私。"
                .into(),
        );
    }
    if lengths.len() > 1 {
        warnings.push("重复 Content-Length，需核对不同组件的解析差异。".into());
    }
    if te == "chunked" {
        match dechunk(body_bytes) {
            Ok(v) => decoded = v,
            Err(e) => {
                warnings.push(e);
                decoded.clear();
            }
        }
    } else if !te.is_empty() && te != "identity" {
        warnings.push(format!("未支持的 Transfer-Encoding：{te}；正文未扫描。"));
        decoded.clear();
    } else if let Some(value) = lengths.first() {
        match value.parse::<usize>(){Ok(n) if n!=body_bytes.len()=>warnings.push(format!("Content-Length 声明 {n} 字节，导入正文 {} 字节；可能为截断、复制换行变化或省略正文。",body_bytes.len())),Err(_)=>warnings.push("Content-Length 不是有效长度。".into()),_=>{}}
    }
    let ce = header(&headers, "content-encoding")
        .unwrap_or("")
        .to_ascii_lowercase();
    if !decoded.is_empty() {
        let result = match ce.as_str() {
            "gzip" => bounded(GzDecoder::new(decoded.as_slice())),
            "deflate" => bounded(ZlibDecoder::new(decoded.as_slice())),
            "" | "identity" => Ok(decoded),
            _ => Err(format!("未支持的 Content-Encoding：{ce}；正文未扫描。")),
        };
        decoded = match result {
            Ok(v) => v,
            Err(e) => {
                warnings.push(e);
                vec![]
            }
        };
    }
    if decoded.len() > BODY_LIMIT {
        decoded.truncate(BODY_LIMIT);
        warnings.push("正文只检查前 1 MiB，超出部分未扫描。".into());
    }
    let body = text(&decoded, &mut warnings);
    if raw.starts_with("HTTP/2")
        || raw.starts_with("HTTP/3")
        || start.ends_with("HTTP/2")
        || start.ends_with("HTTP/3")
    {
        warnings.push("这是工具导出的文本表示；不解析 HTTP/2 二进制帧、HPACK 或 HTTP/3。".into());
    }
    let view = HttpMessage {
        start_line: start,
        headers,
        raw: cut(raw, 16000),
        body_preview: cut(&body, 24000),
        body_bytes: body_bytes.len(),
        sha256: Some(format!("{:x}", Sha256::digest(raw.as_bytes()))),
        source: source.into(),
        representation: "导入的原始文本；SHA-256 针对该侧 UTF-8 文本字节，不证明网络采集来源。"
            .into(),
        warnings,
    };
    Ok(Message { view, body })
}
fn har_message(value: &Value, source: &str, response: bool) -> Result<Message, String> {
    let mut warnings = vec![];
    let mut headers = Vec::new();
    let mut header_size = 0;
    if let Some(a) = value.get("headers").and_then(Value::as_array) {
        if a.len() > 512 {
            return Err("HAR 单侧头字段超过 512 项。".into());
        }
        for h in a {
            let name = h
                .get("name")
                .and_then(Value::as_str)
                .ok_or("HAR 头字段缺少 name。")?;
            let val = h
                .get("value")
                .and_then(Value::as_str)
                .ok_or("HAR 头字段缺少 value。")?;
            header_size += name.len() + val.len();
            if header_size > 65536 {
                return Err("HAR 单侧消息头超过 64 KiB。".into());
            }
            headers.push(Header {
                name: name.into(),
                value: val.into(),
            });
        }
    }
    let version = value
        .get("httpVersion")
        .and_then(Value::as_str)
        .unwrap_or("HTTP/?");
    if version.len() > 32 || version.contains(['\r', '\n']) {
        return Err("HAR httpVersion 无效。".into());
    }
    if value
        .get("statusText")
        .and_then(Value::as_str)
        .is_some_and(|s| s.len() > 512 || s.contains(['\r', '\n']))
    {
        return Err("HAR statusText 无效。".into());
    }
    let start = if response {
        format!(
            "{} {} {}",
            version,
            value
                .get("status")
                .and_then(Value::as_u64)
                .ok_or("HAR 响应缺少状态码。")?,
            value
                .get("statusText")
                .and_then(Value::as_str)
                .unwrap_or("")
        )
    } else {
        let method = value
            .get("method")
            .and_then(Value::as_str)
            .ok_or("HAR 请求缺少 method。")?;
        let url = value
            .get("url")
            .and_then(Value::as_str)
            .ok_or("HAR 请求缺少 url。")?;
        if method.is_empty()
            || url.is_empty()
            || !method
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&' *+-.^_`|~".contains(&b))
            || method.contains(' ')
            || url.contains(['\r', '\n'])
            || method.len() > 32
            || url.len() > 65536
        {
            return Err("HAR 方法或 URL 过长。".into());
        }
        format!("{method} {url} {version}")
    };
    let body_path = if response {
        "/content/text"
    } else {
        "/postData/text"
    };
    let original = value.pointer(body_path).and_then(Value::as_str);
    let generated;
    let body = if let Some(s) = original {
        s
    } else if !response {
        generated = value
            .pointer("/postData/params")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .take(1000)
                    .map(|p| {
                        format!(
                            "{}={}",
                            p.get("name").and_then(Value::as_str).unwrap_or("?"),
                            p.get("value")
                                .and_then(Value::as_str)
                                .unwrap_or("[文件或未导出值]")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("&")
            })
            .unwrap_or_default();
        if !generated.is_empty() {
            warnings.push("请求体由 HAR postData.params 重建，不代表线上编码及字节顺序。".into());
        }
        &generated
    } else {
        ""
    };
    if response && original.is_none() {
        warnings.push("HAR 未导出响应正文；不能当作已检查了完整响应。".into());
    }
    let encoding = value
        .pointer("/content/encoding")
        .and_then(Value::as_str)
        .unwrap_or("");
    let decoded = if response && encoding == "base64" {
        let max = BODY_LIMIT.div_ceil(3) * 4;
        let part = &body.as_bytes()[..body.len().min(max)];
        if body.len() > max {
            warnings.push("Base64 正文只解码前约 1 MiB。".into());
        }
        match STANDARD.decode(part) {
            Ok(mut v) => {
                v.truncate(BODY_LIMIT);
                v
            }
            Err(_) => {
                warnings.push("HAR Base64 正文无效，正文未扫描。".into());
                vec![]
            }
        }
    } else if !encoding.is_empty() {
        warnings.push(format!(
            "HAR content.encoding={encoding} 未支持，正文未扫描。"
        ));
        vec![]
    } else {
        if body.len() > BODY_LIMIT {
            warnings.push("HAR 正文只检查前 1 MiB，超出部分未扫描。".into());
        }
        body.as_bytes()[..body.len().min(BODY_LIMIT)].to_vec()
    };
    let analyzed = text(&decoded, &mut warnings);
    let raw = format!(
        "{}\n{}\n\n{}",
        start,
        headers
            .iter()
            .map(|h| format!("{}: {}", h.name, h.value))
            .collect::<Vec<_>>()
            .join("\n"),
        cut(&analyzed, 12000)
    );
    Ok(Message{view:HttpMessage{start_line:start,headers,raw:cut(&raw,16000),body_preview:cut(&analyzed,24000),body_bytes:decoded.len(),sha256:None,source:source.into(),representation:"从 HAR 字段重建的阅读视图；不是线上原始字节。HAR 原文件另行归档并计算摘要。HAR text 按已解码内容处理，不重复按 Content-Encoding 解压。".into(),warnings},body:analyzed})
}
fn normalized(s: &str) -> String {
    let a = percent_encoding::percent_decode_str(s).decode_utf8_lossy();
    percent_encoding::percent_decode_str(&a)
        .decode_utf8_lossy()
        .replace('+', " ")
}
fn around(s: &str, pattern: &Regex) -> String {
    if let Some(m) = pattern.find(s) {
        let before = s[..m.start()]
            .chars()
            .rev()
            .take(100)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        let after = s[m.end()..].chars().take(180).collect::<String>();
        format!("{before}{}{after}", m.as_str())
    } else {
        cut(s, 360)
    }
}
fn proof(req: &Message, res: Option<&Message>, request_part: &str, response_part: &str) -> String {
    format!(
        "请求来源：{}\n{}\n{}\n\n响应来源：{}\n{}\n{}",
        req.view.source,
        cut(&req.view.start_line, 300),
        cut(request_part, 500),
        res.map(|r| r.view.source.as_str()).unwrap_or("未提供"),
        res.map(|r| cut(&r.view.start_line, 300))
            .unwrap_or_else(|| "[缺少响应]".into()),
        cut(response_part, 700)
    )
}
fn analyze_exchange(
    out: &mut AnalysisReport,
    index: usize,
    req: Message,
    res: Option<Message>,
    url: String,
    method: String,
    started_at: String,
) {
    let status = res
        .as_ref()
        .and_then(|r| r.view.start_line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok());
    let source = format!("交互 #{}", index + 1);
    let mut ids = vec![];
    let mut request_hits = 0;
    let mut response_hits = 0;
    let mut linked = false;
    let target = normalized(&url);
    let body = normalized(&req.body);
    let scan = format!("{target}\n{body}");
    let rules = [
        ("路径穿越请求", r"(?i)(?:\.\./|\.\.\\|/etc/passwd)"),
        (
            "敏感配置路径请求",
            r"(?i)(?:/\.env(?:[/?\s]|$)|/\.git/|/wp-config\.php)",
        ),
        (
            "疑似 SQL 注入请求",
            r"(?i)(?:union\s+select|\bor\s+1\s*=\s*1|sleep\s*\(|information_schema)",
        ),
        (
            "疑似命令执行请求",
            r"(?i)(?:(?:;|\|\||\||&&)\s*(?:whoami|id\b|cat\s|powershell\b)|(?:cmd|command|exec)=(?:whoami|id\b))",
        ),
        (
            "疑似脚本注入请求",
            r"(?i)(?:<script\b|onerror\s*=|javascript:)",
        ),
        (
            "上传目录脚本请求",
            r"(?i)/(?:uploads?|files?)/[^?\s]*\.(?:php\d?|phtml|jsp|aspx?)(?:[?\s]|$)",
        ),
        (
            "上传内容含脚本文件名",
            r#"(?i)filename\s*=\s*"?[^"\r\n;]*\.(?:php\d?|phtml|jsp|jspx|aspx?)"#,
        ),
    ];
    let mut categories = vec![];
    for (title, pattern) in rules {
        let p = Regex::new(pattern).unwrap();
        if p.is_match(&scan) {
            request_hits += 1;
            categories.push(title);
            let in_url = p.is_match(&target);
            let location = if in_url {
                format!("{} · 请求目标 · {} / 起始行", source, req.view.source)
            } else {
                format!(
                    "{} · 请求正文 · {} / 解码视图（原文见报文）",
                    source, req.view.source
                )
            };
            let excerpt = proof(
                &req,
                res.as_ref(),
                &format!("规则检查文本（至多两次百分号解码）：{}", around(&scan, &p)),
                "响应状态码本身不证明漏洞触发；需回查响应正文及主机证据。",
            );
            push(out,&mut ids,finding("medium",title,"请求内容存在待复核特征；编码解码后的匹配是派生线索，不能据此断言恶意或利用成功。",location,None,&excerpt,"结合响应返回内容、实际文件、进程及业务记录复核；保留原始报文。"));
        }
    }
    let framing = req
        .view
        .warnings
        .iter()
        .any(|s| s.contains("帧边界") || s.contains("重复 Content-Length"));
    if framing {
        push(out,&mut ids,finding("medium","HTTP 帧边界需复核","重复长度或 TE/CL 同时存在，可能有解析差异；本工具不回放请求，也不证明请求走私成立。",format!("{source} · {} / 消息头",req.view.source),None,&proof(&req,res.as_ref(),&req.view.headers.iter().filter(|h|h.name.eq_ignore_ascii_case("content-length")||h.name.eq_ignore_ascii_case("transfer-encoding")).map(|h|format!("{}: {}",h.name,h.value)).collect::<Vec<_>>().join("\n"),"需结合代理链及每层解析记录核对。"),"核对请求链各层日志及报文边界。"));
    }
    if let Some(r) = &res {
        let response_rules = [
            (
                "响应含敏感配置字段",
                r"(?im)^(?:DB_PASSWORD|AWS_SECRET_ACCESS_KEY|APP_KEY)\s*=\s*[^\r\n]+",
                "high",
            ),
            ("响应含类 passwd 记录", r"(?m)^root:[^:\r\n]*:0:0:", "high"),
            (
                "响应含数据库错误特征",
                r"(?i)(?:SQLSTATE\[|you have an error in your sql syntax|ORA-[0-9]{5})",
                "medium",
            ),
            (
                "响应含目录索引特征",
                r"(?i)<(?:title|h1)>\s*Index of\b",
                "medium",
            ),
            (
                "响应含异常堆栈特征",
                r"(?i)(?:Traceback \(most recent call last\)|java\.lang\.[a-z]+Exception|System\.[a-z]+Exception:)",
                "medium",
            ),
            (
                "响应含命令输出格式",
                r"uid=[0-9]+\([^\r\n)]*\)\s+gid=[0-9]+",
                "medium",
            ),
        ];
        let reflected_pattern = Regex::new(r"(?i)(?:\.env|\.\./|union|cmd=|<script)").unwrap();
        for (title, pattern, level) in response_rules {
            let p = Regex::new(pattern).unwrap();
            if p.is_match(&r.body) {
                response_hits += 1;
                let related = match title {
                    "响应含敏感配置字段" | "响应含类 passwd 记录" => categories
                        .iter()
                        .any(|c| *c == "路径穿越请求" || *c == "敏感配置路径请求"),
                    "响应含数据库错误特征" => categories.contains(&"疑似 SQL 注入请求"),
                    "响应含命令输出格式" => categories.contains(&"疑似命令执行请求"),
                    _ => false,
                };
                linked |= related;
                let excerpt = proof(
                    &req,
                    Some(r),
                    &around(&scan, &reflected_pattern),
                    &format!("响应解码正文片段：{}", around(&r.body, &p)),
                );
                push(
                    out,
                    &mut ids,
                    finding(
                        level,
                        title,
                        if related {
                            "请求线索与响应格式存在关联，但可能来自错误页、测试数据、缓存或代理；仍需验证影响及主机事实。"
                        } else {
                            "响应包含待核查的暴露或错误格式。仅为内容匹配，不能独立证明攻击成功。"
                        },
                        format!("{} · 响应正文 · {}", source, r.view.source),
                        None,
                        &excerpt,
                        "回查完整响应、来源可信度及后端日志；区分真实数据与示例、错误页或缓存。",
                    ),
                );
            }
        }
        let reflection = Regex::new(r"(?i)<script[^>]*>[^<]{0,120}</script>").unwrap();
        if let Some(payload) = reflection
            .find(&scan)
            .filter(|m| r.body.contains(m.as_str()))
        {
            response_hits += 1;
            linked = true;
            push(out,&mut ids,finding("medium","响应回显可疑请求片段","请求中的脚本片段出现在响应正文；尚未验证浏览器执行、输出上下文及 CSP，不等同于 XSS 成功。",format!("{source} · 请求 / 响应正文 · {} ↔ {}",req.view.source,r.view.source),None,&proof(&req,Some(r),payload.as_str(),&cut(&r.body,500)),"核对输出编码、Content-Type、上下文和 CSP，人工复核。"));
        }
    }
    let assessment = if request_hits > 0 && linked {
        "请求与响应存在关联线索，待复核"
    } else if request_hits > 0 && res.is_none() {
        "请求可疑，缺少响应，影响未知"
    } else if request_hits > 0 {
        "请求可疑，响应不足以确认影响"
    } else if response_hits > 0 {
        "响应存在暴露线索，待复核"
    } else {
        "本规则未命中，仍需复核"
    };
    out.http_exchanges.push(HttpExchange {
        id: format!("http-{}", index + 1),
        method,
        url,
        status,
        started_at,
        request: req.view,
        response: res.map(|r| r.view),
        assessment: assessment.into(),
        finding_ids: ids,
    });
}
fn push(out: &mut AnalysisReport, ids: &mut Vec<String>, f: Finding) {
    if out.findings.len() < 1000 {
        ids.push(f.id.clone());
        out.findings.push(f);
    } else if !out.warnings.iter().any(|s| s.contains("1000 项")) {
        out.warnings
            .push("HTTP 发现最多保存 1000 项，后续命中未展示。".into());
    }
}
fn pair(
    out: &mut AnalysisReport,
    request: &str,
    response: Option<&str>,
    source: &str,
    index: usize,
) -> Result<(), String> {
    let req = raw_message(request, &format!("{source}/request"), false)
        .map_err(|e| format!("请求包：{e}"))?;
    let res = response
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            raw_message(s, &format!("{source}/response"), true).map_err(|e| format!("响应包：{e}"))
        })
        .transpose()?;
    let parts: Vec<_> = req.view.start_line.split_whitespace().collect();
    let method = parts[0].to_owned();
    let url = parts[1].to_owned();
    analyze_exchange(out, index, req, res, url, method, String::new());
    Ok(())
}
pub fn analyze(path: &Path) -> Result<AnalysisReport, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let mut out = report("http", "HTTP 请求 / 响应联合分析");
    out.engine = "J4team http-rules/0.2.0".into();
    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
        if v.get("format").and_then(Value::as_str) == Some("gaga-http-pair/1") {
            let req = v
                .get("request")
                .and_then(Value::as_str)
                .ok_or("报文对缺少 request 字符串。")?;
            let response = match v.get("response") {
                Some(Value::String(s)) => Some(s.as_str()),
                None | Some(Value::Null) => None,
                _ => return Err("response 必须为字符串或 null。".into()),
            };
            pair(&mut out, req, response, "", 0)?;
        } else if let Some(entries) = v.pointer("/log/entries").and_then(Value::as_array) {
            if entries.is_empty() || entries.len() > 200 {
                return Err("本版 HAR 需要包含 1–200 条交互；超出时请先拆分。".into());
            }
            for (i, e) in entries.iter().enumerate() {
                let source = format!("/log/entries/{i}");
                let request = e
                    .get("request")
                    .ok_or_else(|| format!("{source} 缺少 request。"))?;
                let req = har_message(request, &format!("{source}/request"), false)?;
                let res = match e.get("response") {
                    Some(r)
                        if r.get("status")
                            .and_then(Value::as_u64)
                            .is_some_and(|n| (100..=599).contains(&n)) =>
                    {
                        Some(har_message(r, &format!("{source}/response"), true)?)
                    }
                    Some(r) if r.get("status").and_then(Value::as_u64) == Some(0) => None,
                    None | Some(Value::Null) => None,
                    _ => return Err(format!("{source}/response/status 无效。")),
                };
                analyze_exchange(
                    &mut out,
                    i,
                    req,
                    res,
                    request["url"].as_str().unwrap().to_owned(),
                    request["method"].as_str().unwrap().to_owned(),
                    e.get("startedDateTime")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .into(),
                );
            }
        } else {
            return Err("JSON 需为 HAR（log.entries）或 gaga-http-pair/1 报文对。".into());
        }
    } else {
        let raw = std::str::from_utf8(&bytes)
            .map_err(|_| "原始报文文件需要 UTF-8 文本；二进制响应可使用 HAR Base64 正文。")?;
        if let Some((req, res)) = raw
            .split_once("\r\n===RESPONSE===\r\n")
            .or_else(|| raw.split_once("\n===RESPONSE===\n"))
        {
            pair(&mut out, req, Some(res), "原始文本", 0)?;
        } else {
            pair(&mut out, raw, None, "原始文本", 0)?;
        }
    }
    let complete = out
        .http_exchanges
        .iter()
        .filter(|e| e.response.is_some())
        .count();
    for ex in &out.http_exchanges {
        if ex.response.is_none() {
            out.warnings
                .push(format!("{} 缺少有效响应，不能判断服务器结果。", ex.id));
        }
        for m in std::iter::once(&ex.request).chain(ex.response.iter()) {
            for w in &m.warnings {
                out.warnings
                    .push(format!("{} · {}：{}", ex.id, m.source, w));
            }
        }
    }
    out.metrics = vec![
        metric("HTTP 交互", out.http_exchanges.len()),
        metric("成对报文", complete),
        metric("规则线索", out.findings.len()),
        metric("缺少响应", out.http_exchanges.len() - complete),
    ];
    out.summary=format!("分析 {} 条 HTTP 交互，其中 {complete} 条具备请求及响应，发现 {} 项待复核线索。HTTP 状态码及特征匹配均不直接证明攻击成功。",out.http_exchanges.len(),out.findings.len());
    let ioc_text = out
        .http_exchanges
        .iter()
        .map(|e| e.url.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    out.indicators = extract_indicators(&ioc_text);
    out.details.push(detail("处理范围","请求目标与正文最多两次百分号解码后检查；正文最多 1 MiB；展示正文最多 24000 字、报文最多 16000 字。派生解码视图与原始归档分开。未扫描部分均在限制中说明。"));
    out.warnings.push("本地静态分析，不发送或回放 HTTP 请求。手工粘贴两侧报文仅表示人工关联，不证明它们来自同一网络会话。HAR 以同一 entry 关联，重建视图不等于线上原始字节。".into());
    out.warnings.push("HTTP 200、数据库报错、回显或类命令输出均不独立证明利用成功；需结合真实业务、后端日志及主机证据。无规则命中不代表安全。本版不解析 PCAP、TLS 密文、HTTP/2 帧、WebSocket 或 Brotli。".into());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn run(v: Value) -> AnalysisReport {
        let p = std::env::temp_dir().join(format!("gaga-http-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        let r = analyze(&p).unwrap();
        std::fs::remove_file(p).unwrap();
        r
    }
    fn request() -> &'static str {
        "GET /.env HTTP/1.1\r\nHost: example.test\r\n\r\n"
    }
    #[test]
    fn status_200_is_not_exploitation() {
        let r = run(
            json!({"format":"gaga-http-pair/1","request":request(),"response":"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Login</html>"}),
        );
        assert_eq!(
            r.http_exchanges[0].assessment,
            "请求可疑，响应不足以确认影响"
        );
        assert_eq!(r.findings.len(), 1);
        assert!(r.findings[0].excerpt.contains("响应来源"));
    }
    #[test]
    fn related_response_retains_both_sides_and_locations() {
        let r = run(
            json!({"format":"gaga-http-pair/1","request":request(),"response":"HTTP/1.1 200 OK\r\n\r\nDB_PASSWORD=example-not-a-secret"}),
        );
        let e = &r.http_exchanges[0];
        assert!(e.assessment.contains("关联线索"));
        let f = r
            .findings
            .iter()
            .find(|f| f.title.contains("敏感配置字段"))
            .unwrap();
        assert!(f.location.contains("/response"));
        assert!(f.excerpt.contains("GET /.env"));
        assert!(f.excerpt.contains("DB_PASSWORD"));
        assert!(f.description.contains("仍需验证"));
    }
    #[test]
    fn missing_response_is_unknown() {
        let r = run(json!({"format":"gaga-http-pair/1","request":request()}));
        assert!(r.http_exchanges[0].assessment.contains("缺少响应"));
        assert!(r.http_exchanges[0].response.is_none());
    }
    #[test]
    fn har_base64_uses_entry_association() {
        let r = run(
            json!({"log":{"entries":[{"startedDateTime":"2026-10-27T10:21:00+08:00","request":{"method":"GET","url":"https://example.test/","headers":[]},"response":{"status":200,"headers":[],"content":{"encoding":"base64","text":STANDARD.encode(b"root:x:0:0:root:/root:/bin/sh")}}},{"request":{"method":"GET","url":"https://example.test/pending","headers":[]},"response":{"status":0,"headers":[]}}]}}),
        );
        assert_eq!(r.http_exchanges.len(), 2);
        assert!(r.http_exchanges[0]
            .response
            .as_ref()
            .unwrap()
            .body_preview
            .contains("root:x:0:0"));
        assert!(r.http_exchanges[1].response.is_none());
        assert!(r.findings[0].location.contains("/log/entries/0/response"));
    }
    #[test]
    fn chunked_is_decoded_and_bad_lengths_visible() {
        let m=raw_message("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n","/response",true).unwrap();
        assert_eq!(m.body, "hello");
        assert!(m.view.warnings.iter().any(|w| w.contains("帧边界")));
        assert!(dechunk(b"fffffff\r\nx").is_err());
    }
    #[test]
    fn malformed_request_is_rejected_and_double_encoding_matches() {
        assert!(raw_message("garbage", "/request", false).is_err());
        let r = run(
            json!({"format":"gaga-http-pair/1","request":"GET /%252e%252e%252fetc/passwd HTTP/1.1\nHost: example.test\n\n"}),
        );
        assert!(r.findings.iter().any(|f| f.title == "路径穿越请求"));
    }
    #[test]
    fn copied_headers_without_final_blank_line_remain_usable_and_byte_exact() {
        let request = "GET /.env HTTP/1.1\nHost: example.test";
        let response = "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 128";
        let r = run(json!({"format":"gaga-http-pair/1","request":request,"response":response}));
        let ex = &r.http_exchanges[0];
        assert_eq!(ex.request.raw, request);
        assert_eq!(ex.response.as_ref().unwrap().raw, response);
        assert_eq!(ex.status, Some(200));
        assert!(ex.request.warnings.iter().any(|w| w.contains("空行")));
        assert!(ex
            .response
            .as_ref()
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.contains("空行")));
        assert!(ex.response.as_ref().unwrap().body_preview.is_empty());
        assert!(r.findings.iter().any(|f| f.title == "敏感配置路径请求"));
        assert!(!ex.assessment.contains("关联线索"));
        assert_eq!(
            ex.request.sha256.as_deref(),
            Some(format!("{:x}", Sha256::digest(request.as_bytes())).as_str())
        );
    }
    #[test]
    fn copied_bom_blank_prefix_and_trailing_start_line_spaces_preserve_source() {
        let raw = "\u{feff}\r\nGET /.env HTTP/1.1  \nHost: example.test\n\n";
        let m = raw_message(raw, "/request", false).unwrap();
        assert_eq!(m.view.raw, raw);
        assert_eq!(m.view.start_line, "GET /.env HTTP/1.1");
        assert!(m.view.warnings.iter().any(|w| w.contains("阅读视图")));
    }
    #[test]
    fn invalid_response_identifies_side_and_never_creates_successful_exchange() {
        let mut out = report("http", "test");
        let error = pair(&mut out, request(), Some("not a response"), "", 0).unwrap_err();
        assert!(error.contains("响应包"), "{error}");
        assert!(out.http_exchanges.is_empty());
        let error = pair(
            &mut out,
            "GET / HTTP/1.1\nHost: example.test\n{\"missing\":\"separator\"}",
            None,
            "",
            0,
        )
        .unwrap_err();
        assert!(error.contains("请求包"), "{error}");
    }
    #[test]
    fn malformed_unicode_base64_is_a_visible_gap_not_a_panic() {
        let value = serde_json::json!({"status":200,"headers":[],"content":{"encoding":"base64","text":"非".repeat(500000)}});
        let m = har_message(&value, "/response", true).unwrap();
        assert!(m.body.is_empty());
        assert!(m.view.warnings.iter().any(|w| w.contains("无效")));
    }
    #[test]
    fn decompression_is_bounded() {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&vec![b'a'; BODY_LIMIT + 1]).unwrap();
        let b = e.finish().unwrap();
        assert!(bounded(GzDecoder::new(b.as_slice()))
            .unwrap_err()
            .contains("超过 1 MiB"));
    }
}
