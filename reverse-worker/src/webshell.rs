//! Bounded static constant folding. Samples are data: no PHP/JS/JVM runtime,
//! shell, network, reflection, eval or user-defined function is ever invoked.
//! This lexer deliberately does not claim control-flow or taint-analysis proof.
use crate::{
    analyzers::{cut, detail, finding, metric, report, AnalysisReport},
    webshell_schema::{Check, Layer, Trace, WebshellAnalysis},
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    time::{Duration, Instant},
};
const MAX_INPUT: usize = 1024 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_TOTAL: usize = 4 * 1024 * 1024;
const MAX_LAYERS: usize = 48;
const MAX_DEPTH: usize = 8;
const MAX_TOKENS: usize = 120_000;
const PREVIEW: usize = 6000;
const OPS: &[&str] = &[
    "base64_decode",
    "atob",
    "gzinflate",
    "gzuncompress",
    "gzdecode",
    "str_rot13",
    "strrev",
    "hex2bin",
    "urldecode",
    "rawurldecode",
    "chr",
];
fn format(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
        "Java class（仅文件头识别）"
    } else if bytes.starts_with(&[0xac, 0xed, 0, 5]) {
        "Java serialization（未反序列化）"
    } else if std::str::from_utf8(bytes).is_ok() {
        "UTF-8 文本"
    } else {
        "二进制 / 未确认"
    }
}
fn preview(bytes: &[u8]) -> String {
    if std::str::from_utf8(bytes).is_ok() {
        cut(&String::from_utf8_lossy(bytes), PREVIEW)
    } else {
        bytes
            .iter()
            .take(256)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn layer_citation(layer: &Layer) -> String {
    // A finding may be copied into a standalone report node, so its provenance
    // must not depend on the layer workbench still being open.
    format!(
        " 层 {} SHA-256 {}；来源表达式位于 {} 第 {} 行，字节 [{}..{})。",
        layer.id,
        layer.sha256,
        layer.source_layer_id,
        layer.source_line,
        layer.source_start,
        layer.source_end
    )
}
#[derive(Clone, Debug)]
enum Kind {
    String(Option<Vec<u8>>),
    Ident(String),
    Var(String),
    Number(u64),
    Symbol(u8),
}
#[derive(Clone, Debug)]
struct Token {
    kind: Kind,
    start: usize,
    end: usize,
}
fn lex(bytes: &[u8], clock: Instant) -> (Vec<Token>, bool) {
    let mut tokens = vec![];
    let mut i = 0;
    while i < bytes.len() && tokens.len() < MAX_TOKENS {
        if i % 4096 == 0 && clock.elapsed() > Duration::from_secs(3) {
            return (tokens, true);
        }
        let start = i;
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"//") || c == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            i += 2;
            while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        let kind = if c == b'\'' || c == b'"' {
            i += 1;
            let mut value = vec![];
            let mut known = true;
            while i < bytes.len() && bytes[i] != c {
                let b = bytes[i];
                i += 1;
                if b == b'\\' {
                    if i >= bytes.len() {
                        known = false;
                        break;
                    }
                    let escaped = bytes[i];
                    i += 1;
                    if c == b'\'' {
                        if escaped != b'\\' && escaped != b'\'' {
                            value.push(b'\\');
                        }
                        value.push(escaped);
                    } else if escaped == b'x'
                        && i + 1 < bytes.len()
                        && bytes[i..i + 2].iter().all(u8::is_ascii_hexdigit)
                    {
                        value.push(
                            u8::from_str_radix(std::str::from_utf8(&bytes[i..i + 2]).unwrap(), 16)
                                .unwrap(),
                        );
                        i += 2;
                    } else if escaped.is_ascii_digit() && escaped < b'8' {
                        let mut number = (escaped - b'0') as u16;
                        for _ in 0..2 {
                            if i < bytes.len() && (b'0'..=b'7').contains(&bytes[i]) {
                                number = number * 8 + (bytes[i] - b'0') as u16;
                                i += 1;
                            } else {
                                break;
                            }
                        }
                        value.push((number & 255) as u8);
                    } else {
                        match escaped {
                            b'n' => value.push(b'\n'),
                            b'r' => value.push(b'\r'),
                            b't' => value.push(b'\t'),
                            b'\\' | b'"' | b'$' => value.push(escaped),
                            _ => {
                                known = false;
                                value.push(escaped);
                            }
                        }
                    }
                } else {
                    if c == b'"' && b == b'$' {
                        known = false;
                    }
                    value.push(b);
                }
            }
            if i == bytes.len() {
                known = false;
            } else {
                i += 1;
            }
            Kind::String(known.then_some(value))
        } else if c == b'$' || c.is_ascii_alphabetic() || c == b'_' {
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let name = String::from_utf8_lossy(&bytes[start..i]).into_owned();
            if c == b'$' {
                // PHP variables are case sensitive; folding their case can
                // invent a constant flow between distinct variables.
                Kind::Var(name)
            } else {
                Kind::Ident(name.to_ascii_lowercase())
            }
        } else if c.is_ascii_digit() {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            match std::str::from_utf8(&bytes[start..i])
                .ok()
                .and_then(|s| s.parse().ok())
            {
                Some(n) => Kind::Number(n),
                None => Kind::Symbol(b'?'),
            }
        } else {
            i += 1;
            Kind::Symbol(c)
        };
        tokens.push(Token {
            kind,
            start,
            end: i,
        });
    }
    (tokens, i < bytes.len())
}
#[derive(Clone)]
struct Constant {
    bytes: Vec<u8>,
    parent: String,
}
struct Context {
    result: WebshellAnalysis,
    // Full derived bytes stay only inside the isolated worker; IPC holds previews.
    data: Vec<Vec<u8>>,
    total: usize,
    clock: Instant,
    seen: HashSet<(String, String, usize, usize)>,
    attempts: usize,
}
impl Context {
    fn limit(&mut self, message: &str) {
        if !self.result.limits.iter().any(|s| s == message) {
            self.result.limits.push(message.into());
        }
    }
    fn add(
        &mut self,
        parent: &str,
        source: &str,
        operation: &str,
        span: std::ops::Range<usize>,
        input: &[u8],
        output: Vec<u8>,
    ) -> Option<Constant> {
        let start = span.start;
        let end = span.end;
        let parent_index = self.result.layers.iter().position(|l| l.id == parent)?;
        let source_index = self.result.layers.iter().position(|l| l.id == source)?;
        let depth = self.result.layers[parent_index].depth + 1;
        if depth > MAX_DEPTH {
            self.limit("静态变换深度达到 8 层；其余内容未展开。");
            return None;
        }
        if self.result.layers.len() >= MAX_LAYERS || self.total + output.len() > MAX_TOTAL {
            self.limit("达到工件数量或累计 4 MiB 上限；其余内容未展开。");
            return None;
        }
        if output.len() > MAX_OUTPUT || output.len() > input.len().max(1024) * 100 {
            self.limit("解码输出超过 1 MiB 或膨胀比上限；该层未采用。");
            return None;
        }
        let key = (source.into(), operation.into(), start, end);
        if !self.seen.insert(key) {
            let layer = self.result.layers.iter().find(|l| {
                l.source_layer_id == source
                    && l.operation == operation
                    && l.source_start == start
                    && l.source_end == end
            })?;
            return Some(Constant {
                bytes: output,
                parent: layer.id.clone(),
            });
        }
        if output == input {
            return None;
        }
        let id = format!("L{:03}", self.result.layers.len());
        let rendered = String::from_utf8_lossy(&output);
        let layer = Layer {
            id: id.clone(),
            parent_id: Some(parent.into()),
            operation: operation.into(),
            format: format(&output).into(),
            depth,
            source_layer_id: source.into(),
            source_start: start,
            source_end: end,
            source_line: self.data[source_index][..start.min(self.data[source_index].len())]
                .iter()
                .filter(|b| **b == b'\n')
                .count()
                + 1,
            source_excerpt: cut(
                &String::from_utf8_lossy(&self.data[source_index][start..end]),
                1200,
            ),
            input_sha256: hash(input),
            sha256: hash(&output),
            bytes: output.len(),
            preview: preview(&output),
            truncated: if std::str::from_utf8(&output).is_ok() {
                rendered.chars().count() > PREVIEW
            } else {
                output.len() > 256
            },
            finding_ids: vec![],
        };
        self.total += output.len();
        self.result.layers.push(layer);
        self.data.push(output.clone());
        Some(Constant {
            bytes: output,
            parent: id,
        })
    }
    fn transform(&mut self, name: &str, input: &[u8]) -> Option<Vec<u8>> {
        self.attempts += 1;
        if self.attempts > 4096 || self.clock.elapsed() > Duration::from_secs(3) {
            self.limit("达到静态求值次数或 3 秒处理预算；未覆盖部分需要继续复核。");
            return None;
        }
        let result = match name {
            "base64_decode" | "atob" => {
                let data: Vec<u8> = input
                    .iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect();
                STANDARD
                    .decode(&data)
                    .or_else(|_| STANDARD_NO_PAD.decode(&data))
                    .or_else(|_| URL_SAFE.decode(&data))
                    .or_else(|_| URL_SAFE_NO_PAD.decode(&data))
                    .ok()?
            }
            "hex2bin" => {
                if !input.len().is_multiple_of(2) {
                    return None;
                }
                input
                    .chunks(2)
                    .map(|c| {
                        std::str::from_utf8(c)
                            .ok()
                            .and_then(|s| u8::from_str_radix(s, 16).ok())
                    })
                    .collect::<Option<Vec<_>>>()?
            }
            "strrev" => input.iter().rev().copied().collect(),
            "str_rot13" => input
                .iter()
                .map(|b| match b {
                    b'a'..=b'z' => b'a' + (b - b'a' + 13) % 26,
                    b'A'..=b'Z' => b'A' + (b - b'A' + 13) % 26,
                    _ => *b,
                })
                .collect(),
            "urldecode" | "rawurldecode" => {
                let mut result = vec![];
                let mut i = 0;
                while i < input.len() {
                    if input[i] == b'%' {
                        if i + 2 >= input.len() {
                            return None;
                        }
                        result.push(
                            u8::from_str_radix(std::str::from_utf8(&input[i + 1..i + 3]).ok()?, 16)
                                .ok()?,
                        );
                        i += 3;
                    } else {
                        result.push(if name == "urldecode" && input[i] == b'+' {
                            b' '
                        } else {
                            input[i]
                        });
                        i += 1;
                    }
                }
                result
            }
            "gzinflate" | "gzuncompress" | "gzdecode" => {
                let reader: Box<dyn Read> = match name {
                    "gzinflate" => Box::new(DeflateDecoder::new(input)),
                    "gzuncompress" => Box::new(ZlibDecoder::new(input)),
                    _ => Box::new(GzDecoder::new(input)),
                };
                let mut output = vec![];
                if reader
                    .take((MAX_OUTPUT + 1) as u64)
                    .read_to_end(&mut output)
                    .is_err()
                {
                    self.limit("压缩数据无效或截断；未将残缺输出当作完整层。");
                    return None;
                }
                output
            }
            _ => return None,
        };
        if result.len() > MAX_OUTPUT || result.len() > input.len().max(1024) * 100 {
            self.limit("解码输出超过 1 MiB 或膨胀比上限；该层未采用。");
            return None;
        }
        Some(result)
    }
}
struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
    vars: &'a HashMap<String, Constant>,
    layer: &'a str,
    context: &'a mut Context,
}
impl Parser<'_> {
    fn symbol(&self, c: u8) -> bool {
        self.tokens
            .get(self.at)
            .is_some_and(|t| matches!(t.kind,Kind::Symbol(b) if b==c))
    }
    fn expr(&mut self, depth: usize) -> Option<Constant> {
        if depth > 32 {
            return None;
        }
        let mut value = self.atom(depth + 1)?;
        while self.symbol(b'.') || self.symbol(b'+') {
            self.at += 1;
            let next = self.atom(depth + 1)?;
            if value.bytes.len() + next.bytes.len() > MAX_OUTPUT {
                return None;
            }
            value.bytes.extend_from_slice(&next.bytes);
        }
        Some(value)
    }
    fn atom(&mut self, depth: usize) -> Option<Constant> {
        if depth > 32 {
            return None;
        }
        let token = self.tokens.get(self.at)?.clone();
        self.at += 1;
        match token.kind {
            Kind::String(Some(bytes)) => Some(Constant {
                bytes,
                parent: self.layer.into(),
            }),
            Kind::Var(ref name) if !self.symbol(b'(') => self.vars.get(name).cloned(),
            Kind::Symbol(b'(') => {
                let value = self.expr(depth + 1)?;
                if !self.symbol(b')') {
                    return None;
                }
                self.at += 1;
                Some(value)
            }
            Kind::Ident(ref name) | Kind::Var(ref name) => {
                let operation = if name.starts_with('$') {
                    String::from_utf8(self.vars.get(name)?.bytes.clone())
                        .ok()?
                        .to_ascii_lowercase()
                } else {
                    name.clone()
                };
                if !OPS.contains(&operation.as_str()) || !self.symbol(b'(') {
                    return None;
                }
                self.at += 1;
                if operation == "chr" {
                    let Kind::Number(n) = self.tokens.get(self.at)?.kind else {
                        return None;
                    };
                    self.at += 1;
                    if n > 255 || !self.symbol(b')') {
                        return None;
                    }
                    self.at += 1;
                    return Some(Constant {
                        bytes: vec![n as u8],
                        parent: self.layer.into(),
                    });
                }
                let input = self.expr(depth + 1)?;
                if !self.symbol(b')') {
                    return None;
                }
                let end = self.tokens[self.at].end;
                self.at += 1;
                let output = self.context.transform(&operation, &input.bytes)?;
                // The span is in this expression's source layer, while nested
                // transforms link through their own layer. Do not fake offsets
                // in a decoded parent that did not contain this expression.
                self.context.add(
                    &input.parent,
                    self.layer,
                    &operation,
                    token.start..end,
                    &input.bytes,
                    output,
                )
            }
            _ => None,
        }
    }
}
fn sink(name: &str) -> Option<&'static str> {
    match name {
        "eval" | "assert" | "execute" | "executeglobal" => Some("动态代码执行"),
        "system" | "exec" | "shell_exec" | "passthru" | "popen" | "proc_open"
        | "processbuilder" | "process.start" | "runtime.getruntime" => Some("系统命令调用"),
        "defineclass" | "assembly.load" | "loadclass" => Some("动态类或程序集加载"),
        "unserialize" | "readobject" => Some("反序列化入口"),
        "file_put_contents" | "fwrite" | "move_uploaded_file" => Some("文件写入或上传"),
        "call_user_func" | "call_user_func_array" => Some("间接回调调用"),
        _ => None,
    }
}
fn qualified_call(tokens: &[Token], at: usize) -> Option<&'static str> {
    // The lexer splits member access into tokens. Keep the older Java/.NET
    // coverage without treating every ordinary start()/load() as a sink.
    if at < 2 {
        return None;
    }
    match (&tokens[at - 2].kind, &tokens[at - 1].kind, &tokens[at].kind) {
        (Kind::Ident(owner), Kind::Symbol(b'.'), Kind::Ident(member)) => {
            match (owner.as_str(), member.as_str()) {
                ("process", "start") => Some("process.start"),
                ("runtime", "getruntime") => Some("runtime.getruntime"),
                ("assembly", "load") => Some("assembly.load"),
                _ => None,
            }
        }
        _ => None,
    }
}
fn source(name: &str) -> bool {
    matches!(
        name,
        "$_GET"
            | "$_POST"
            | "$_REQUEST"
            | "$_COOKIE"
            | "$_FILES"
            | "$_SERVER"
            | "getparameter"
            | "request"
            | "inputstream"
    )
}
// Parse only the class constant pool with checked byte ranges; never load a
// class or deserialize an object. UTF8 entries use a lossy display of modified
// UTF8 and are explicitly clues, not source code or verification of bytecode.
fn class_strings(bytes: &[u8]) -> Result<(u16, Vec<(usize, String)>), String> {
    fn u16_at(b: &[u8], i: usize) -> Option<u16> {
        Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?))
    }
    let major = u16_at(bytes, 6).ok_or("文件头截断")?;
    let count = u16_at(bytes, 8).ok_or("常量池数量缺失")? as usize;
    if count == 0 || count > 10_000 {
        return Err("常量池数量无效或超限".into());
    }
    let mut at = 10usize;
    let mut index = 1;
    let mut strings = vec![];
    while index < count {
        let tag = *bytes.get(at).ok_or("常量池截断")?;
        at += 1;
        let size = match tag {
            1 => {
                let len = u16_at(bytes, at).ok_or("UTF8 长度截断")? as usize;
                at += 2;
                let b = bytes.get(at..at + len).ok_or("UTF8 内容截断")?;
                if strings.len() < 500 {
                    strings.push((at, cut(&String::from_utf8_lossy(b), 1000)));
                }
                len
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => 4,
            5 | 6 => {
                index += 1;
                if index >= count {
                    return Err("双槽常量超出常量池".into());
                }
                8
            }
            7 | 8 | 16 | 19 | 20 => 2,
            15 => 3,
            _ => return Err(format!("不支持的常量标签 {tag}")),
        };
        at = at
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or("常量池数据截断")?;
        index += 1;
    }
    Ok((major, strings))
}
pub fn analyze(bytes: &[u8]) -> AnalysisReport {
    let mut out = report("webshell", "WebShell 分层静态分析");
    let scoped = &bytes[..bytes.len().min(MAX_INPUT)];
    let text = String::from_utf8_lossy(scoped);
    let language = if text.contains("<?") {
        "PHP"
    } else if text.contains("<%@") || text.contains("javax.") || text.contains("jakarta.") {
        "JSP / Java"
    } else if text.contains("<%") || text.contains("System.") {
        "ASP / .NET"
    } else {
        "脚本 / 未确认"
    };
    let root = Layer {
        id: "L000".into(),
        parent_id: None,
        operation: "原始文件".into(),
        format: format(bytes).into(),
        depth: 0,
        source_layer_id: "L000".into(),
        source_start: 0,
        source_end: scoped.len(),
        source_line: 1,
        source_excerpt: String::new(),
        input_sha256: hash(bytes),
        sha256: hash(bytes),
        bytes: bytes.len(),
        preview: preview(bytes),
        truncated: if std::str::from_utf8(bytes).is_ok() {
            String::from_utf8_lossy(bytes).chars().count() > PREVIEW
        } else {
            bytes.len() > 256
        },
        finding_ids: vec![],
    };
    let mut context = Context {
        result: WebshellAnalysis {
            version: "gaga-webshell/1".into(),
            language: language.into(),
            rules_version: "j4-webshell/0.9.0".into(),
            input_sha256: hash(bytes),
            layers: vec![root],
            traces: vec![],
            checks: vec![],
            limits: vec![],
        },
        data: vec![scoped.to_vec()],
        total: scoped.len(),
        clock: Instant::now(),
        seen: HashSet::new(),
        attempts: 0,
    };
    if bytes.len() > MAX_INPUT {
        context.limit("深度分析只覆盖原文件前 1 MiB；其余字节完整归档但未检查。");
    }
    if std::str::from_utf8(bytes).is_err() {
        context.limit("含非 UTF-8 字节；展示使用替代字符，来源位置仍为原始字节偏移。");
    }
    let mut layer_index = 0;
    while layer_index < context.data.len() {
        if context.clock.elapsed() > Duration::from_secs(3) {
            context.limit("达到 3 秒处理预算；剩余层未分析。");
            break;
        }
        let data = context.data[layer_index].clone();
        let layer = context.result.layers[layer_index].id.clone();
        if data.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
            match class_strings(&data) {
                Ok((major, strings)) => {
                    let references: Vec<_> = strings
                        .iter()
                        .filter(|(_, s)| {
                            [
                                "servlet",
                                "Filter",
                                "ServletRequest",
                                "defineClass",
                                "getRuntime",
                                "ProcessBuilder",
                                "getParameter",
                                "java/lang/Runtime",
                                "ClassLoader",
                            ]
                            .iter()
                            .any(|name| s.contains(name))
                        })
                        .take(40)
                        .collect();
                    for (offset, value) in &references {
                        if out.findings.len() >= 400 {
                            break;
                        }
                        let mut f=finding("medium","Java 类常量池线索","已在隔离环境读取常量池；类名或方法名存在不证明类被加载、内存马驻留或调用发生。",format!("{layer} 常量池 · 字节 {offset}"),None,value,"关联来源脚本的加载调用、容器/应用日志、类加载与内存取证证据。");
                        f.description
                            .push_str(&layer_citation(&context.result.layers[layer_index]));
                        context.result.layers[layer_index]
                            .finding_ids
                            .push(f.id.clone());
                        out.findings.push(f);
                    }
                    if out.details.len() < 20 {
                        out.details.push(detail(
                            &format!("{layer} Java 类常量池"),
                            format!(
                                "major={major}；仅读取常量池，不是反编译或有效字节码认证。\n{}",
                                strings
                                    .iter()
                                    .take(80)
                                    .map(|(o, s)| format!("字节 {o}: {}", cut(s, 200)))
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            ),
                        ));
                    }
                }
                Err(error) => context.limit(&format!("{layer} Java 类常量池未解析：{error}")),
            }
            layer_index += 1;
            continue;
        }
        if data.starts_with(&[0xac, 0xed, 0, 5]) {
            context.limit(&format!(
                "{layer} 为 Java 序列化头；仅识别格式，不执行反序列化，内容需另行分析。"
            ));
            layer_index += 1;
            continue;
        }
        if std::str::from_utf8(&data).is_err() {
            layer_index += 1;
            continue;
        }
        let (tokens, truncated) = lex(&data, context.clock);
        if truncated {
            context.limit("词法分析达到 token 或时间上限；剩余部分未分析。");
        }
        let mut vars: HashMap<String, Constant> = HashMap::new();
        let mut dependencies: HashMap<String, Vec<String>> = HashMap::new();
        let mut statement_sources = vec![];
        let mut statement_sinks = vec![];
        let mut statement_line = 1;
        let mut lines = vec![0];
        for (i, b) in data.iter().enumerate() {
            if *b == b'\n' {
                lines.push(i + 1);
            }
        }
        let line_for = |pos: usize| lines.partition_point(|p| *p <= pos);
        for (i, token) in tokens.iter().enumerate() {
            if i % 128 == 0 && context.clock.elapsed() > Duration::from_secs(3) {
                context.limit("达到 3 秒处理预算；其余语句未分析。");
                break;
            }
            let line = line_for(token.start);
            if statement_sources.is_empty() && statement_sinks.is_empty() {
                statement_line = line;
            }
            if matches!(token.kind, Kind::Symbol(b';' | b'}')) {
                if !statement_sources.is_empty()
                    && !statement_sinks.is_empty()
                    && context.result.traces.len() < 100
                {
                    context.result.traces.push(Trace {layer_id:layer.clone(),line:statement_line,sources:statement_sources.clone(),sinks:statement_sinks.clone(),basis:"同一语句或先前赋值的词法依赖线索；分支、作用域与可达性未验证，不是完整污点分析。".into()});
                }
                statement_sources.clear();
                statement_sinks.clear();
                statement_line = line;
                continue;
            }
            let name = match &token.kind {
                Kind::Ident(s) | Kind::Var(s) => s.as_str(),
                _ => "",
            };
            if source(name) && !statement_sources.contains(&name.to_string()) {
                statement_sources.push(name.into());
            }
            if let Some(origins) = dependencies.get(name) {
                for s in origins {
                    if !statement_sources.contains(s) {
                        statement_sources.push(s.clone());
                    }
                }
            }
            let is_call = tokens
                .get(i + 1)
                .is_some_and(|t| matches!(t.kind, Kind::Symbol(b'(')));
            let alias = vars
                .get(name)
                .and_then(|v| String::from_utf8(v.bytes.clone()).ok())
                .filter(|v| v.len() < 80)
                .map(|v| v.to_ascii_lowercase());
            let call_name = if name.starts_with('$') {
                alias.as_deref().unwrap_or(name)
            } else {
                name
            };
            let call_name = qualified_call(&tokens, i).unwrap_or(call_name);
            let title = if is_call {
                sink(call_name).or_else(|| OPS.contains(&call_name).then_some("编码或压缩解码"))
            } else {
                source(name).then_some("外部请求输入")
            };
            if let Some(title) = title {
                if out.findings.len() < 400 {
                    let begin = lines[line.saturating_sub(1)];
                    let end = data[begin..]
                        .iter()
                        .position(|b| *b == b'\n')
                        .map(|n| begin + n)
                        .unwrap_or(data.len());
                    let location = if layer_index == 0 {
                        format!("原文第 {line} 行 · 字节 {}..{}", token.start, token.end)
                    } else {
                        format!(
                            "{layer} 解码层第 {line} 行 · 字节 {}..{}",
                            token.start, token.end
                        )
                    };
                    let mut f=finding(if sink(call_name).is_some(){"high"}else{"medium"},title,"词法静态线索，已跳过注释；字符串和不可达分支仍需复核。调用及来源接近不证明利用成功。",location,Some(line),&String::from_utf8_lossy(&data[begin..end]),"核对输入约束、认证、分支和实际运行证据；使用关联层的摘要及来源位置举证。");
                    f.description
                        .push_str(&layer_citation(&context.result.layers[layer_index]));
                    context.result.layers[layer_index]
                        .finding_ids
                        .push(f.id.clone());
                    out.findings.push(f);
                } else {
                    context.limit("发现展示达到 400 项上限；不代表其余代码安全。");
                }
                if is_call
                    && sink(call_name).is_some()
                    && !statement_sinks.contains(&call_name.to_string())
                {
                    statement_sinks.push(call_name.into());
                }
            }
            if matches!(token.kind, Kind::Var(_))
                && tokens
                    .get(i + 1)
                    .is_some_and(|t| matches!(t.kind, Kind::Symbol(b'=')))
                && !tokens
                    .get(i + 2)
                    .is_some_and(|t| matches!(t.kind, Kind::Symbol(b'=')))
            {
                let window_end = (i + 2050).min(tokens.len());
                let end = tokens[i + 2..window_end]
                    .iter()
                    .position(|t| matches!(t.kind, Kind::Symbol(b';')))
                    .map(|n| i + 2 + n)
                    .unwrap_or(window_end);
                let origins: Vec<String> = tokens[i + 2..end]
                    .iter()
                    .filter_map(|t| match &t.kind {
                        Kind::Var(s) | Kind::Ident(s) if source(s) => Some(s.clone()),
                        _ => None,
                    })
                    .chain(
                        tokens[i + 2..end]
                            .iter()
                            .filter_map(|t| match &t.kind {
                                Kind::Var(s) => dependencies.get(s),
                                _ => None,
                            })
                            .flatten()
                            .cloned(),
                    )
                    .take(64)
                    .collect();
                if dependencies.len() < 64 || dependencies.contains_key(name) {
                    dependencies.insert(name.into(), origins);
                }
                let mut parser = Parser {
                    tokens: &tokens,
                    at: i + 2,
                    vars: &vars,
                    layer: &layer,
                    context: &mut context,
                };
                let value = parser.expr(0).filter(|_| parser.at == end);
                // Reassignment invalidates known constants instead of using stale values.
                vars.remove(name);
                if let Some(value) = value {
                    if vars.len() < 64 && value.bytes.len() <= 65536 {
                        vars.insert(name.into(), value);
                    }
                }
            } else if is_call && OPS.contains(&call_name) {
                let mut parser = Parser {
                    tokens: &tokens,
                    at: i,
                    vars: &vars,
                    layer: &layer,
                    context: &mut context,
                };
                let _ = parser.expr(0);
            }
        }
        layer_index += 1;
    }
    context.result.checks = vec![
        Check {
            title: "敏感调用与外部输入".into(),
            status: "checked".into(),
            detail: format!(
                "规则 {}，{} 项待复核线索；跳过行注释与块注释。",
                context.result.rules_version,
                out.findings.len()
            ),
        },
        Check {
            title: "常量与分层解码".into(),
            status: if context.result.limits.is_empty() {
                "checked"
            } else {
                "partial"
            }
            .into(),
            detail: format!(
                "{} 个派生工件；支持常量字符串、拼接、chr、固定变量别名及 {}。",
                context.result.layers.len() - 1,
                OPS.join(" / ")
            ),
        },
        Check {
            title: "输入至敏感调用的词法线索".into(),
            status: "partial".into(),
            detail: "有界语句和赋值关联；不具备完整 AST、跨函数/文件/作用域或控制流证明。".into(),
        },
        Check {
            title: "Java 类常量池".into(),
            status: if context.result.layers.iter().any(|l|l.format.starts_with("Java class")){"partial"}else{"not_checked"}.into(),
            detail: "有类文件时只读取常量池，最多 500 条 UTF8 / 每条 1000 字，详情展示前 80 条；未反编译、未验证完整字节码、未加载类。没有类文件不证明不存在内存马。".into(),
        },
        Check {
            title: "动态解密、内存驻留与执行".into(),
            status: "not_checked".into(),
            detail: "没有执行样本；外部密钥、运行时输入、自定义算法、内存马运行状态未知。".into(),
        },
    ];
    out.metrics = vec![
        metric(
            "代码行数",
            bytes.iter().filter(|b| **b == b'\n').count()
                + usize::from(!bytes.is_empty() && !bytes.ends_with(b"\n")),
        ),
        metric("规则命中", out.findings.len()),
        metric("解码工件", context.result.layers.len() - 1),
        metric("调用线索", context.result.traces.len()),
    ];
    out.summary="在禁网容器中进行有界常量求值和分层静态检查。每层保留 Hash、父层表达式范围与待复核线索；没有执行样本，未命中不代表安全。".into();
    let mut numbered = String::new();
    let mut shown = 0;
    for (i, line) in text.lines().take(80).enumerate() {
        let next = format!("原文第 {} 行：{}\n", i + 1, line);
        if numbered.chars().count() + next.chars().count() > 8000 {
            break;
        }
        numbered.push_str(&next);
        shown = i + 1;
    }
    let scope = if scoped.len() == bytes.len() && text.lines().count() == shown {
        format!("完整原文，共 {shown} 行")
    } else {
        format!("仅前 {shown} 行片段，后续内容未知")
    };
    out.details.push(detail(
        "脚本上下文",
        format!("{scope}；最多 80 行 / 8000 字\n{numbered}"),
    ));
    out.details.push(detail(
        "分层静态检查",
        context
            .result
            .layers
            .iter()
            .map(|l| {
                format!(
                    "{} {} · {} bytes · SHA-256 {}\n{}",
                    l.id,
                    l.operation,
                    l.bytes,
                    l.sha256,
                    cut(&l.preview, 1200)
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n"),
    ));
    out.warnings = context.result.limits.clone();
    out.warnings.push("静态结果为待复核线索。词法赋值可能跨越分支或作用域，不能证明可达、可利用或攻击成功；不调用任何样本内函数。".into());
    out.webshell = Some(context.result);
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn java_and_dotnet_member_calls_keep_coverage_without_generic_method_hits() {
        let r =
            analyze(b"Runtime.getRuntime(); Process.Start(request); Assembly.Load(inputStream);");
        assert_eq!(
            r.findings
                .iter()
                .filter(|f| f.title == "系统命令调用")
                .count(),
            2
        );
        assert!(r.findings.iter().any(|f| f.title == "动态类或程序集加载"));
        let w = r.webshell.unwrap();
        assert!(w
            .traces
            .iter()
            .any(|t| t.sinks.contains(&"process.start".into())));
        let normal = analyze(b"// Runtime.getRuntime();\nvar text = \"Assembly.Load(data)\"; timer.Start(); config.Load(); getRuntime();");
        assert!(normal.findings.is_empty());
    }
    #[test]
    fn constants_aliases_layers_and_inert_payloads_have_exact_provenance() {
        let payload = b"<?php system($_POST['cmd']);";
        let b64 = STANDARD.encode(payload);
        let src = format!(
            "<?php\n// eval($_POST['ignored']);\n$a='base64_decode'; $s=$a('{b64}'); eval($s);"
        );
        let r = analyze(src.as_bytes());
        let w = r.webshell.unwrap();
        assert!(w
            .layers
            .iter()
            .any(|l| l.preview == String::from_utf8_lossy(payload)
                && l.parent_id.as_deref() == Some("L000")
                && l.input_sha256 == hash(b64.as_bytes())));
        assert!(!r.findings.iter().any(|f| f.excerpt.contains("ignored")));
        assert!(r
            .findings
            .iter()
            .any(|f| f.title == "系统命令调用" && f.location.starts_with("L001")));
        assert!(w
            .traces
            .iter()
            .any(|t| t.sources.contains(&"$_POST".into()) && t.sinks.contains(&"system".into())));
        assert_eq!(w.input_sha256, hash(src.as_bytes()));
    }
    #[test]
    fn nested_compression_and_concatenation_are_data_only() {
        use flate2::{write::DeflateEncoder, Compression};
        use std::io::Write;
        let mut e = DeflateEncoder::new(vec![], Compression::default());
        e.write_all(b"<?php eval($_POST['x']);").unwrap();
        let encoded = STANDARD.encode(e.finish().unwrap());
        let half = encoded.len() / 2;
        let src = format!(
            "<?php eval(gzinflate(base64_decode('{}'.'{}')));",
            &encoded[..half],
            &encoded[half..]
        );
        let r = analyze(src.as_bytes());
        let w = r.webshell.unwrap();
        assert!(w
            .layers
            .iter()
            .any(|l| l.operation == "gzinflate" && l.preview.contains("$_POST")));
        assert!(r.findings.iter().any(|f| f.location.starts_with("L002")));
    }
    #[test]
    fn unknown_calls_interpolation_and_reassignment_are_not_executed_or_guessed() {
        for src in [
            "<?php $A='c3lzdGVt'; base64_decode($a);",
            "<?php $x=base64_decode($_POST['x']);",
            "<?php $x='c3lzdGVt'; $x=$_GET['x']; eval(base64_decode($x));",
            "<?php eval(base64_decode(\"$dynamic\"));",
            "<?php eval(attacker_function('c3lzdGVt'));",
            "<?php base64_decode('%%%');",
        ] {
            let w = analyze(src.as_bytes()).webshell.unwrap();
            assert_eq!(w.layers.len(), 1, "{src}");
        }
    }
    #[test]
    fn expansion_and_depth_are_bounded_and_reported() {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;
        let mut e = ZlibEncoder::new(vec![], Compression::best());
        e.write_all(&vec![b'a'; MAX_OUTPUT + 1]).unwrap();
        let src = format!(
            "<?php gzuncompress(base64_decode('{}'));",
            STANDARD.encode(e.finish().unwrap())
        );
        let w = analyze(src.as_bytes()).webshell.unwrap();
        assert!(w.limits.iter().any(|s| s.contains("上限")));
        let mut payload = "<?php system($_POST['x']);".to_string();
        for _ in 0..12 {
            payload = format!("<?php eval(base64_decode('{}'));", STANDARD.encode(payload));
        }
        let w = analyze(payload.as_bytes()).webshell.unwrap();
        assert!(w.layers.len() <= MAX_LAYERS);
        assert!(w.layers.iter().all(|l| l.depth <= MAX_DEPTH));
        assert!(w.limits.iter().any(|s| s.contains("8 层")));
    }
    #[test]
    fn java_class_constants_are_read_without_loading_and_bad_pools_are_rejected() {
        let name = b"java/lang/Runtime";
        let mut data = vec![
            0xca,
            0xfe,
            0xba,
            0xbe,
            0,
            0,
            0,
            52,
            0,
            2,
            1,
            0,
            name.len() as u8,
        ];
        data.extend_from_slice(name);
        let src = format!("<?php base64_decode('{}');", STANDARD.encode(&data));
        let r = analyze(src.as_bytes());
        let w = r.webshell.unwrap();
        assert!(w.layers[1].format.starts_with("Java class"));
        assert!(r.findings.iter().any(|f| f.title == "Java 类常量池线索"
            && f.line.is_none()
            && f.description.contains(&w.layers[1].sha256)
            && f.description.contains("来源表达式位于 L000")));
        for n in 0..data.len() {
            assert!(class_strings(&data[..n]).is_err());
        }
        data[10] = 99;
        assert!(class_strings(&data).is_err());
        let r = analyze(&[0xac, 0xed, 0, 5]);
        assert!(r
            .webshell
            .unwrap()
            .limits
            .iter()
            .any(|s| s.contains("不执行反序列化")));
    }
    #[test]
    fn byte_spans_remain_exact_for_unicode_and_decoded_layers() {
        let src = "<?php /* 中文注释 */\n$x=hex2bin('73797374656d');";
        let w = analyze(src.as_bytes()).webshell.unwrap();
        let l = &w.layers[1];
        assert_eq!(
            &src.as_bytes()[l.source_start..l.source_end],
            b"hex2bin('73797374656d')"
        );
        assert_eq!(l.source_line, 2);
        assert_eq!(l.preview, "system");
    }
}
