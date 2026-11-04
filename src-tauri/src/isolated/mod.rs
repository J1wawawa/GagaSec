//! Untrusted sample parsers and Pi run in network-disabled containers. No host fallback.
mod records;
mod rpc;
mod runtime;
use crate::{analyzers::AnalysisReport, sandbox, store::Store};
use chrono::Utc;
pub use records::{cancel, jobs, Job};
use records::{event, save, Artifact};
use runtime::Container;
pub use runtime::{build, environment, Environment};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
pub const VERSION: &str = "0.9.0";
pub const IMAGE: &str = "gaga-analysis:0.9.0";
const MEMORY: i64 = 805306368;
static STATIC: Mutex<()> = Mutex::new(());
static RUN: Mutex<()> = Mutex::new(());
static BUILD: Mutex<()> = Mutex::new(());
static ACTIVE: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();

/// 只管理本任务的取消标志；panic 展开时也不阻塞后续任务。
struct ActiveTask(String);
impl Drop for ActiveTask {
    fn drop(&mut self) {
        if let Some(map) = ACTIVE.get() {
            if let Ok(mut map) = map.lock() {
                map.remove(&self.0);
            }
        }
    }
}
/// 工件先写入并同步，再提交数据库引用；新文件拒绝覆盖已有工件。
fn write_artifact(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}
fn sample_bytes(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut bytes = vec![];
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("样本超过隔离任务上限".into());
    }
    Ok(bytes)
}
#[derive(Debug)]
enum ToolFailure {
    Recoverable(String),
    Fatal {
        message: String,
        cleanup_uncertain: bool,
    },
}
impl From<String> for ToolFailure {
    fn from(message: String) -> Self {
        Self::Fatal {
            message,
            cleanup_uncertain: false,
        }
    }
}
impl From<&str> for ToolFailure {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}
impl std::fmt::Display for ToolFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Recoverable(s) | Self::Fatal { message: s, .. } => f.write_str(s),
        }
    }
}
fn worker(
    store: &Store,
    env: &Environment,
    path: &Path,
    kind: &str,
    operation: &str,
    params: &Value,
) -> Result<Value, ToolFailure> {
    worker_observed(
        store,
        env,
        path,
        kind,
        operation,
        params,
        &crate::analysis_progress::Silent,
    )
}
fn worker_observed(
    store: &Store,
    env: &Environment,
    path: &Path,
    kind: &str,
    operation: &str,
    params: &Value,
    observer: &dyn crate::analysis_progress::Observer,
) -> Result<Value, ToolFailure> {
    observer.check()?;
    let _worker = STATIC
        .try_lock()
        .map_err(|_| ToolFailure::Recoverable("已有样本工具运行，请稍后重试".into()))?;
    if !["metadata", "read_source", "search_strings", "disassemble"].contains(&operation) {
        return Err("工具不在允许清单中".into());
    }
    let bytes = sample_bytes(path, 128 * 1024 * 1024)?;
    let expected = format!("{:x}", Sha256::digest(&bytes));
    let mut c =
        Container::create(store, env, false, kind, operation, params).map_err(|message| {
            ToolFailure::Fatal {
                message,
                cleanup_uncertain: true,
            }
        })?;
    let args = vec![
        "--context".into(),
        c.check.context.clone(),
        "start".into(),
        "-a".into(),
        "-i".into(),
        c.name.clone(),
    ];
    let out = sandbox::command_checked(
        Path::new(&c.check.cli_path),
        &args,
        Some(bytes),
        45,
        4 * 1024 * 1024,
        || observer.check(),
    );
    // 即使 start 超时也尝试删除；清理失败优先报错，不能伪装成可恢复工具错误。
    c.clean().map_err(|message| ToolFailure::Fatal {
        message,
        cleanup_uncertain: true,
    })?;
    let out = out?;
    if !out.ok {
        let message = format!(
            "隔离工具未完成：{}",
            crate::analyzers::cut(&out.stderr, 2000)
        );
        let rejected = serde_json::from_str::<Value>(out.stderr.trim()).ok();
        // 显式、正常退出的受控拒绝可恢复；panic / OOM / 信号退出及无效 stderr 必须中止。
        if out.code == Some(1)
            && rejected
                .as_ref()
                .is_some_and(|v| v["recoverable"] == true && v["error"].is_string())
        {
            return Err(ToolFailure::Recoverable(message));
        }
        return Err(message.into());
    }
    let value: Value =
        serde_json::from_slice(&out.stdout).map_err(|_| "隔离工具返回格式错误或超过输出限制")?;
    if value["protocol"] != "gaga-static/2" {
        return Err("静态工具协议不兼容，请重新构建分析镜像".into());
    }
    if value["sha256"] != expected {
        return Err("隔离工具样本 Hash 不匹配".into());
    }
    Ok(value)
}
pub fn analyze_observed(
    store: &Store,
    path: &Path,
    kind: &str,
    expected_hash: &str,
    observer: &dyn crate::analysis_progress::Observer,
) -> Result<AnalysisReport, String> {
    observer.check()?;
    if format!(
        "{:x}",
        Sha256::digest(sample_bytes(path, 128 * 1024 * 1024)?)
    ) != expected_hash
    {
        return Err("原始归档 Hash 不匹配，拒绝分析".into());
    }
    // Unit fixtures exercise the shared parser; shipping binaries have no host parser compiled in.
    #[cfg(test)]
    {
        let _ = store;
        if kind == "webshell" {
            crate::sample_static::analyze_webshell(path)
        } else {
            crate::sample_static::analyze_binary(path)
        }
    }
    #[cfg(not(test))]
    {
        observer.phase("environment", 0)?;
        let env = environment(store);
        observer.check()?;
        if !env.docker.daemon_ready {
            return Err(format!(
                "隔离分析不可用：{}；不会回退到本机解析。",
                env.docker.message
            ));
        }
        observer.phase("isolated", 0)?;
        let v = worker_observed(store, &env, path, kind, "metadata", &json!({}), observer)
            .map_err(|e| e.to_string())?;
        if v["sha256"] != expected_hash {
            return Err("样本在读取过程中发生变化，拒绝报告".into());
        }
        let mut r: AnalysisReport =
            serde_json::from_value(v["report"].clone()).map_err(|_| "隔离报告结构错误")?;
        if r.kind != kind || r.findings.len() > 1000 || r.details.len() > 30 {
            return Err("隔离报告超出约定范围".into());
        }
        if kind == "webshell" {
            let analysis = r
                .webshell
                .as_ref()
                .ok_or("缺少新版分层结构，请重新构建分析镜像")?;
            if analysis.version != "gaga-webshell/1"
                || analysis.input_sha256 != expected_hash
                || analysis.layers.is_empty()
                || analysis.layers.len() > 48
                || analysis.traces.len() > 100
                || analysis.checks.len() > 8
                || analysis.limits.len() > 64
            {
                return Err("分层报告身份或数量超出约定".into());
            }
            for (i, layer) in analysis.layers.iter().enumerate() {
                if layer.id != format!("L{i:03}")
                    || layer.preview.chars().count() > 6500
                    || layer
                        .finding_ids
                        .iter()
                        .any(|id| !r.findings.iter().any(|f| &f.id == id))
                {
                    return Err("分层内容或发现引用无效".into());
                }
                let source = analysis
                    .layers
                    .iter()
                    .take(i + 1)
                    .find(|s| s.id == layer.source_layer_id)
                    .ok_or("分层来源不存在")?;
                if layer.source_start > layer.source_end || layer.source_end > source.bytes {
                    return Err("分层来源范围无效".into());
                }
                if i == 0 {
                    if layer.sha256 != expected_hash
                        || layer.parent_id.is_some()
                        || layer.depth != 0
                    {
                        return Err("分层原文摘要不匹配".into());
                    }
                } else {
                    let parent = analysis
                        .layers
                        .iter()
                        .take(i)
                        .find(|p| Some(&p.id) == layer.parent_id.as_ref())
                        .ok_or("分层父节点无效")?;
                    if layer.depth != parent.depth + 1
                        || layer.depth > 8
                        || layer.bytes > 1024 * 1024
                    {
                        return Err("分层深度或大小无效".into());
                    }
                }
            }
        }
        r.engine = "J4team isolated-static/0.9.0".into();
        r.details.push(crate::analyzers::detail("隔离执行",format!("镜像：{}\n策略：禁网 / 只读根 / 非 root / 无宿主机挂载\n工具容器已删除；未执行样本。",env.image_id.unwrap_or_default())));
        Ok(r)
    }
}
fn tool_result(
    store: &Store,
    env: &Environment,
    job: &mut Job,
    name: &str,
    params: &Value,
) -> Result<Value, ToolFailure> {
    let op = match name {
        "read_metadata" => "metadata",
        "read_source" => "read_source",
        "search_strings" => "search_strings",
        "disassemble" => "disassemble",
        _ => return Err("未授权的工具调用".into()),
    };
    let e = store.evidence_for_case(&job.case_id, &job.evidence_id)?;
    let path = store.root.join("evidence").join(&e.id);
    let hash = format!(
        "{:x}",
        Sha256::digest(sample_bytes(&path, 128 * 1024 * 1024)?)
    );
    if hash != e.sha256 {
        return Err("原始归档 Hash 不匹配，已停止逆向任务".into());
    }
    validate_tool(name, params).map_err(ToolFailure::Recoverable)?;
    let mut value = worker(store, env, &path, &e.kind, op, params)?;
    if value["sha256"] != job.sample_sha256 {
        return Err("样本在读取过程中发生变化，已拒绝工具结果".into());
    }
    if let Some(report) = value.get_mut("report") {
        if let Some(a) = report["findings"].as_array_mut() {
            a.truncate(30)
        }
        if let Some(layers) = report["webshell"]["layers"].as_array_mut() {
            layers.truncate(8);
            for layer in layers {
                if let Some(preview) = layer["preview"].as_str() {
                    layer["preview"] = json!(crate::analyzers::cut(preview, 1500));
                    layer["truncated"] = json!(true);
                }
            }
        }
        if let Some(a) = report["details"].as_array_mut() {
            for d in a {
                if let Some(text) = d["value"].as_str() {
                    d["value"] = json!(crate::analyzers::cut(text, 6000));
                }
            }
        }
        value["scope"]=json!("模型工具视图最多 30 项发现，每条附加信息最多 6000 字，分层最多 8 项 / 每层 1500 字；完整静态报告保留在原样本证据中。");
    }
    let id = uuid::Uuid::new_v4().to_string();
    let raw = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
    let dir = store.root.join("reverse-artifacts").join(&job.id);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    write_artifact(&dir.join(&id), &raw)?;
    job.artifacts.push(Artifact {
        id: id.clone(),
        tool: name.into(),
        params: params.clone(),
        sha256: format!("{:x}", Sha256::digest(&raw)),
        preview: crate::analyzers::cut(&String::from_utf8_lossy(&raw), 14000),
    });
    value["artifactId"] = json!(id);
    Ok(value)
}
pub fn run(
    store: &Store,
    app: Option<&tauri::AppHandle>,
    evidence_id: String,
    question: String,
) -> Result<Job, String> {
    crate::privacy::ensure_ai_allowed(store)?;
    let _running = RUN
        .try_lock()
        .map_err(|_| "已有逆向任务运行，请等待或取消")?;
    if question.trim().is_empty() || question.chars().count() > 4000 {
        return Err("请填写 1–4000 字的逆向调查问题".into());
    }
    let case = store.active()?;
    let e = store.evidence_for_case(&case, &evidence_id)?;
    if !["webshell", "binary"].contains(&e.kind.as_str()) {
        return Err("只支持当前事件中的脚本或可执行样本".into());
    }
    let env = environment(store);
    if !env.docker.daemon_ready {
        return Err(env.docker.message);
    }
    let image = env.image_id.clone().ok_or("请先构建隔离分析镜像")?;
    let cfg = crate::ai::config(store)?;
    if !cfg.has_key {
        return Err("请先配置官方模型 Key".into());
    }
    let mut job = Job {
        id: uuid::Uuid::new_v4().to_string(),
        case_id: case,
        evidence_id: e.id.clone(),
        sample_sha256: e.sha256.clone(),
        created_at: Utc::now().to_rfc3339(),
        revision: 0,
        provider: cfg.provider.clone(),
        model: cfg.model.clone(),
        endpoint: cfg.endpoint.clone(),
        config_revision: cfg.revision.clone(),
        sample_name: e.name.clone(),
        request_sha256: vec![],
        state: "running".into(),
        image_id: image,
        events: vec![],
        artifacts: vec![],
        model_requests: 0,
        tool_calls: 0,
        question,
        content: String::new(),
        error: None,
        report_evidence_id: None,
        cleanup_confirmed: false,
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    ACTIVE
        .get_or_init(Default::default)
        .lock()
        .map_err(|e| e.to_string())?
        .insert(job.id.clone(), cancelled.clone());
    let _active_task = ActiveTask(job.id.clone());
    let result = (|| -> Result<(), String> {
        event(
            store,
            app,
            &mut job,
            "检查隔离容器；样本不执行，模型 Key 不进入容器",
        )?;
        let mut c = Container::create(store, &env, true, "", "", &json!({}))?;
        let mut session = rpc::Session::start(&c.check, &c.name)?;
        let clock = Instant::now();
        let mut completed = false;
        let deadline = clock + Duration::from_secs(300);
        let mut tools_cleanup_confirmed = true;
        let mut control_messages = 0;
        let execution = (|| -> Result<(), String> {
            session.send(&json!({"endpoint":cfg.endpoint,"model":cfg.model,"name":e.name,"sha256":e.sha256,"kind":e.kind,"question":job.question}), deadline, &cancelled)?;
            loop {
                if cancelled.load(Ordering::SeqCst) {
                    return Err("已取消；不再调用模型或工具".into());
                }
                if clock.elapsed() > Duration::from_secs(300) {
                    return Err("任务达到 300 秒上限".into());
                }
                let line = match session.receive()? {
                    rpc::Message::Line(line) => line,
                    rpc::Message::Pending => continue,
                    rpc::Message::Eof => break,
                };
                control_messages += 1;
                if control_messages > 80 {
                    return Err("控制消息超过任务预算".into());
                }
                let value: Value =
                    serde_json::from_str(&line).map_err(|_| "Pi 控制消息格式错误")?;
                match value["kind"].as_str() {
                    Some("ready") => {
                        if value["protocol"] != "gaga-pi/2" {
                            return Err("Pi 协议版本不兼容，请重新构建分析镜像".into());
                        }
                        event(
                            store,
                            app,
                            &mut job,
                            "Pi SDK 已启动，仅启用四个受控只读工具，无网络与真实 Key",
                        )?;
                    }
                    Some("tool") => {
                        if job.tool_calls >= 16 {
                            return Err("工具调用达到 16 次预算上限".into());
                        }
                        job.tool_calls += 1;
                        let name = value["tool"].as_str().ok_or("缺少工具名")?;
                        event(store, app, &mut job, &format!("隔离工具：{name}"))?;
                        let result = tool_result(store, &env, &mut job, name, &value["params"]);
                        let response = match result {
                            Ok(result) => json!({"id":value["id"],"result":result}),
                            Err(ToolFailure::Recoverable(error)) => {
                                event(store, app, &mut job, &format!("工具未完成：{error}"))?;
                                json!({"id":value["id"],"error":error})
                            }
                            Err(ToolFailure::Fatal {
                                message,
                                cleanup_uncertain,
                            }) => {
                                // 完整性与隔离错误必须中止，不能让模型用旧工件生成完成结论。
                                tools_cleanup_confirmed &= !cleanup_uncertain;
                                return Err(message);
                            }
                        };
                        session.send(&response, deadline, &cancelled)?;
                        save(store, app, &mut job)?;
                    }
                    Some("model") => {
                        if job.model_requests >= 8 {
                            return Err("模型调用达到 8 次预算上限".into());
                        }
                        job.model_requests += 1;
                        event(
                            store,
                            app,
                            &mut job,
                            "客户端通过系统凭据代理官方模型请求；Key 不传给 Pi",
                        )?;
                        let payload = crate::ai::agent_payload(&cfg, value["body"].clone())?;
                        let dir = store.root.join("reverse-artifacts").join(&job.id);
                        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                        let raw = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
                        write_artifact(
                            &dir.join(format!("model-request-{}.json", job.model_requests)),
                            &raw,
                        )?;
                        job.request_sha256
                            .push(format!("{:x}", Sha256::digest(&raw)));
                        save(store, app, &mut job)?;
                        let result = tauri::async_runtime::block_on(crate::ai::agent_transport(
                            store,
                            &cfg,
                            payload,
                            300u64.saturating_sub(clock.elapsed().as_secs()),
                            cancelled.clone(),
                        ))?;
                        session.send(
                            &json!({"id":value["id"],"result":result}),
                            deadline,
                            &cancelled,
                        )?;
                    }
                    Some("done") => {
                        let text = value["text"].as_str().ok_or("Pi 未返回文本")?;
                        if text.trim().is_empty() || text.chars().count() > 20000 {
                            return Err("Pi 最终文本为空或超过节点归档限制".into());
                        }
                        job.content=format!("样本 SHA-256：{}\n任务 ID：{}\n以下为 AI 静态分析草稿，未执行样本，待人工复核。\n\n{}",job.sample_sha256,job.id,text);
                        if job.artifacts.is_empty() {
                            return Err("模型未调用可举证工具，未生成完成结论".into());
                        }
                        completed = true;
                        break;
                    }
                    Some("error") => {
                        return Err(value["error"].as_str().unwrap_or("Pi 任务失败").into())
                    }
                    _ => return Err("未授权的 Pi 控制消息".into()),
                }
            }
            if !completed {
                return Err("Pi 在生成结论前退出".into());
            }
            Ok(())
        })();
        // 无论执行成功、取消或校验失败，都先停止 RPC，再确认所有工具容器的清理状态。
        let cleanup = c.clean();
        let error_bytes = session.close();
        job.cleanup_confirmed = cleanup.is_ok() && tools_cleanup_confirmed;
        cleanup?;
        if let Err(error) = execution {
            return Err(if error_bytes.is_empty() {
                error
            } else {
                format!(
                    "{error} · {}",
                    crate::analyzers::cut(&String::from_utf8_lossy(&error_bytes), 1600)
                )
            });
        }
        if cancelled.load(Ordering::SeqCst) {
            return Err("已取消".into());
        }
        job.state = "completed".into();
        let evidence=store.archive_record(&job.case_id,"AI隔离逆向",&json!({"format":"gaga-ai-reverse/1","sampleEvidence":job.evidence_id,"sampleSha256":job.sample_sha256,"imageId":job.image_id,"analysis":job.content,"toolArtifacts":job.artifacts,"modelRequests":job.model_requests,"provider":job.provider,"model":job.model,"endpoint":job.endpoint,"configRevision":job.config_revision,"requestSha256":job.request_sha256,"limitations":["静态工具与 Pi 均在隔离容器运行，样本未执行。","x86/x64 入口附近线性反汇编不等于反编译、脱壳或完整控制流。","模型判断待人工复核；未覆盖、反分析和加密代码可能导致遗漏。"]}))?;
        job.report_evidence_id = Some(evidence.id);
        Ok(())
    })();
    if let Err(error) = result {
        job.state = if cancelled.load(Ordering::SeqCst) {
            "cancelled"
        } else {
            "failed"
        }
        .into();
        job.error = Some(error);
    }
    event(store, app, &mut job, "任务结束；保留工具工件与待复核结论")?;
    Ok(job)
}
pub fn cleanup(store: &Store) -> Result<Environment, String> {
    let _worker = STATIC.try_lock().map_err(|_| "样本工具运行期间不可清理")?;
    if !ACTIVE
        .get_or_init(Default::default)
        .lock()
        .map_err(|e| e.to_string())?
        .is_empty()
    {
        return Err("逆向任务运行期间不可清理".into());
    }
    let env = environment(store);
    for name in &env.leftovers {
        let out = sandbox::docker(&env.docker, &["rm", "-f", name], None, 15, 8192)?;
        if !out.ok {
            return Err(out.stderr);
        }
    }
    Ok(environment(store))
}

fn validate_tool(name: &str, params: &Value) -> Result<(), String> {
    let keys: &[&str] = match name {
        "read_metadata" => &[],
        "read_source" => &["startLine", "count"],
        "search_strings" => &["query"],
        "disassemble" => &["entryOffset", "count"],
        _ => return Err("未授权工具".into()),
    };
    let object = params.as_object().ok_or("工具参数必须为对象")?;
    if object.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err("工具含未授权参数".into());
    }
    let valid = match name {
        "read_metadata" => true,
        "read_source" => {
            params["startLine"]
                .as_u64()
                .is_some_and(|n| (1..=1_000_000).contains(&n))
                && params["count"]
                    .as_u64()
                    .is_some_and(|n| (1..=120).contains(&n))
        }
        "search_strings" => params["query"].as_str().is_some_and(|s| s.len() <= 128),
        "disassemble" => {
            params["entryOffset"].as_u64().is_some_and(|n| n <= 16384)
                && params["count"]
                    .as_u64()
                    .is_some_and(|n| (1..=160).contains(&n))
        }
        _ => false,
    };
    if !valid {
        return Err("工具参数超出允许范围".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::DockerCheck;
    use runtime::validate;
    #[test]
    fn rejects_expanded_isolation_and_unknown_fields() {
        let good = json!({"HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges=true"],"Tmpfs":{"/tmp":"rw,noexec,nosuid,nodev,size=192m"},"Memory":MEMORY,"PidsLimit":64,"NanoCpus":1000000000,"IpcMode":"none"},"Config":{"User":"65534:65534"},"Mounts":[]});
        assert!(validate(&good).is_ok());
        for (key, value) in [
            ("NetworkMode", json!("host")),
            ("ReadonlyRootfs", json!(false)),
            ("Privileged", json!(true)),
            ("Memory", json!(0)),
            ("PidsLimit", json!(-1)),
            ("CapDrop", json!([])),
            ("SecurityOpt", json!(["seccomp=unconfined"])),
            ("IpcMode", json!("host")),
            ("Binds", json!(["/:/host"])),
            ("CapAdd", json!(["SYS_ADMIN"])),
            ("Devices", json!([{"PathOnHost":"/dev/kvm"}])),
            ("DeviceRequests", json!([{"Capabilities":[["gpu"]]}])),
            ("VolumesFrom", json!(["other"])),
            ("UTSMode", json!("host")),
            ("PidMode", json!("container:other")),
            ("UsernsMode", json!("host")),
        ] {
            let mut v = good.clone();
            v["HostConfig"][key] = value;
            assert!(validate(&v).is_err(), "{key}")
        }
        let mut v = good.clone();
        v["Mounts"] = json!([{"Type":"bind","Destination":"/sample"}]);
        assert!(validate(&v).is_err());
        let mut v = good;
        v["Config"]["User"] = json!("0");
        assert!(validate(&v).is_err());
    }
    #[test]
    fn tools_reject_shell_paths_and_invalid_ranges() {
        assert!(validate_tool("bash", &json!({"command":"id"})).is_err());
        assert!(validate_tool("read_metadata", &json!({"path":"/etc/passwd"})).is_err());
        assert!(validate_tool("read_source", &json!({"startLine":0,"count":1})).is_err());
        assert!(validate_tool("disassemble", &json!({"entryOffset":0,"count":161})).is_err());
        assert!(validate_tool("read_source", &json!({"startLine":1,"count":120})).is_ok());
    }
    #[test]
    fn missing_image_has_no_host_fallback() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let store = Store::open(root.clone()).unwrap();
        let check = DockerCheck {
            cli_found: false,
            daemon_ready: false,
            cli_path: "".into(),
            context: "".into(),
            server_os: "".into(),
            architecture: "".into(),
            version: "".into(),
            runner_image: None,
            leftovers: vec![],
            leftover_volumes: vec![],
            message: "unavailable".into(),
        };
        let env = Environment {
            docker: check,
            image_id: None,
            policy: String::new(),
            leftovers: vec![],
        };
        let path = root.join("inert.php");
        fs::write(&path, b"<?php echo 'benign';").unwrap();
        assert!(
            Container::create(&store, &env, false, "webshell", "metadata", &json!({}))
                .err()
                .unwrap()
                .to_string()
                .contains("不会使用宿主机解析")
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, unix))]
mod fault_tests {
    use super::*;
    use crate::sandbox::DockerCheck;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn integrity_protocol_and_cleanup_errors_are_fatal_and_partial_create_is_cleaned() {
        for mode in [
            "bad-hash",
            "bad-protocol",
            "bad-json",
            "cleanup-fails",
            "create-fails",
            "unsupported",
        ] {
            let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
            let store = Store::open(root.clone()).unwrap();
            let inspect = json!([{"Config":{"User":"65534:65534","Labels":{"team.j4.gaga.reverse":runtime::owner(&store)}},
                "Mounts":[],"HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],
                "SecurityOpt":["no-new-privileges=true"],"Tmpfs":{"/tmp":"rw,noexec,nosuid,nodev,size=192m"},"Memory":MEMORY,
                "PidsLimit":64,"NanoCpus":1000000000,"IpcMode":"none"}}]);
            fs::write(root.join("inspect.json"), inspect.to_string()).unwrap();
            fs::write(root.join("mode"), mode).unwrap();
            let cli = root.join("fake-docker");
            fs::write(&cli,r#"#!/usr/bin/env python3
import sys,json,pathlib,hashlib
root=pathlib.Path(__file__).parent
mode=(root/'mode').read_text(); op=sys.argv[3]
if op=='create':
 (root/'created').touch()
 if mode=='create-fails': print('injected create failure',file=sys.stderr);sys.exit(1)
 print('fixture-id')
elif op=='inspect': print((root/'inspect.json').read_text())
elif op=='rm':
 (root/'cleanup-attempted').touch()
 if mode=='cleanup-fails': print('injected cleanup failure',file=sys.stderr);sys.exit(1)
 (root/'removed').touch()
elif op=='start':
 data=sys.stdin.buffer.read()
 if mode=='unsupported': print(json.dumps({'error':'unsupported fixture architecture','recoverable':True}),file=sys.stderr);sys.exit(1)
 if mode=='bad-json': print('broken JSON')
 else: print(json.dumps({'protocol':'wrong' if mode=='bad-protocol' else 'gaga-static/2','sha256':'wrong' if mode=='bad-hash' else hashlib.sha256(data).hexdigest()}))
else: sys.exit(2)
"#).unwrap();
            fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
            let check = DockerCheck {
                cli_found: true,
                daemon_ready: true,
                cli_path: cli.display().to_string(),
                context: "fixture".into(),
                server_os: "linux".into(),
                architecture: "test".into(),
                version: "test".into(),
                runner_image: None,
                leftovers: vec![],
                leftover_volumes: vec![],
                message: String::new(),
            };
            let env = Environment {
                docker: check,
                image_id: Some("fixture".into()),
                policy: String::new(),
                leftovers: vec![],
            };
            let path = root.join("inert.php");
            fs::write(&path, b"<?php echo 'benign fixture';").unwrap();
            let error =
                worker(&store, &env, &path, "webshell", "metadata", &json!({})).unwrap_err();
            if mode == "unsupported" {
                assert!(matches!(error, ToolFailure::Recoverable(_)));
            } else {
                assert!(
                    matches!(error, ToolFailure::Fatal { .. }),
                    "{mode}: {error}"
                );
                if mode == "cleanup-fails" {
                    assert!(matches!(
                        error,
                        ToolFailure::Fatal {
                            cleanup_uncertain: true,
                            ..
                        }
                    ));
                }
            }
            assert!(root.join("cleanup-attempted").exists(), "{mode}");
            if mode != "cleanup-fails" {
                assert!(root.join("removed").exists(), "{mode}");
            }
            drop(store);
            fs::remove_dir_all(root).unwrap();
        }
    }
}
