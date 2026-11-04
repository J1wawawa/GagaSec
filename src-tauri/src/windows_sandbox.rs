use crate::{
    sandbox::{self, SandboxJob},
    store::Store,
};
use reqwest::{Client, Url};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub endpoint: String,
    pub machine: String,
    pub has_key: bool,
}
fn endpoint(base: &str) -> Result<String, String> {
    let u = Url::parse(base.trim())
        .map_err(|_| "请填写 CAPE API 完整基础地址，例如 http://127.0.0.1:8000/apiv2。")?;
    let local = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if u.host_str().is_none()
        || !(u.scheme() == "https" || u.scheme() == "http" && local)
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err("远端沙箱需要 HTTPS，本机可用 HTTP；地址不得包含凭据或查询参数。".into());
    }
    Ok(u.as_str().trim_end_matches('/').into())
}
pub fn config(store: &Store) -> Result<Config, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let data: Option<String> = db
        .query_row(
            "SELECT value FROM settings WHERE key='windows_sandbox'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    data.map(|v| serde_json::from_str(&v).map_err(|e| e.to_string()))
        .unwrap_or_else(|| Ok(Config::default()))
}
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn credential(base: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(
        "team.j4.gaga-assistant.sandbox",
        &format!("endpoint-{:x}", Sha256::digest(base.as_bytes())),
    )
    .map_err(|_| "无法访问系统凭据服务。".into())
}
pub fn save_config(
    store: &Store,
    base: String,
    machine: String,
    key: String,
) -> Result<Config, String> {
    let endpoint = endpoint(&base)?;
    if machine.len() > 120 || key.len() > 4096 || machine.contains(['\r', '\n']) {
        return Err("配置字段超出限制。".into());
    }
    let old = config(store)?;
    let mut has_key = old.endpoint == endpoint && old.has_key;
    if !key.is_empty() {
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            credential(&endpoint)?
                .set_password(key.trim())
                .map_err(|_| "沙箱 Token 保存到系统凭据失败。")?;
            has_key = true;
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            return Err("该平台尚未接入凭据服务。".into());
        }
    }
    let result = Config {
        endpoint,
        machine: machine.trim().into(),
        has_key,
    };
    let db = store.db.lock().map_err(|e| e.to_string())?;
    db.execute(
        "INSERT OR REPLACE INTO settings VALUES('windows_sandbox',?1)",
        [serde_json::to_string(&result).map_err(|e| e.to_string())?],
    )
    .map_err(|e| e.to_string())?;
    Ok(result)
}
fn client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())
}
fn authenticated(
    cfg: &Config,
    request: reqwest::RequestBuilder,
) -> Result<reqwest::RequestBuilder, String> {
    if !cfg.has_key {
        return Ok(request);
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let key = credential(&cfg.endpoint)?
            .get_password()
            .map_err(|_| "无法读取沙箱 Token，请重新保存。")?;
        Ok(request.header("Authorization", format!("Token {key}")))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err("该平台尚未接入凭据服务。".into())
    }
}
async fn response(request: reqwest::RequestBuilder, limit: usize) -> Result<Value, String> {
    let mut res = request
        .send()
        .await
        .map_err(|_| "无法连接沙箱服务或请求超时。")?;
    if !res.status().is_success() {
        return Err(format!(
            "沙箱 API 返回 HTTP {}，请核对地址与鉴权。",
            res.status().as_u16()
        ));
    }
    let mut data = Vec::new();
    while let Some(bytes) = res.chunk().await.map_err(|_| "沙箱响应读取失败。")? {
        if data.len() + bytes.len() > limit {
            return Err("沙箱响应超过本版读取上限。".into());
        }
        data.extend_from_slice(&bytes);
    }
    let value: Value = serde_json::from_slice(&data)
        .map_err(|_| "沙箱返回了非 JSON 响应；本版适配 CAPE API v2。")?;
    if value["error"] == true {
        return Err("CAPE API 报告错误；请在沙箱端核对任务、机器与权限。".into());
    }
    Ok(value)
}
pub async fn check(store: &Store) -> Result<Value, String> {
    let cfg = config(store)?;
    endpoint(&cfg.endpoint)?;
    response(
        authenticated(
            &cfg,
            client()?.get(format!("{}/machines/list/", cfg.endpoint)),
        )?,
        1024 * 1024,
    )
    .await
}
pub async fn submit(
    store: &Store,
    app: Option<&tauri::AppHandle>,
    evidence_id: String,
    seconds: u64,
    lab_ack: bool,
) -> Result<SandboxJob, String> {
    if !lab_ack {
        return Err("请确认 CAPE 使用专用、可还原快照的 Windows 虚拟机，且其网络已隔离。".into());
    }
    if !(15..=300).contains(&seconds) {
        return Err("Windows 观察时间需为 15–300 秒。".into());
    }
    let cfg = config(store)?;
    endpoint(&cfg.endpoint)?;
    let (e, bytes) = sandbox::sample(store, &evidence_id)?;
    if !bytes.starts_with(b"MZ") {
        return Err("Windows 入口本版仅支持 PE EXE / DLL 样本。".into());
    }
    let mut job = sandbox::new_job(&e, "cape-windows");
    job.endpoint = cfg.endpoint.clone();
    sandbox::event(
        store,
        app,
        &mut job,
        "已核对归档摘要；将样本上传到所配置 CAPE 服务，不在宿主机执行",
    )?;
    let result = async {
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(e.name.clone())
            .mime_str("application/octet-stream")
            .map_err(|e| e.to_string())?;
        let mut form = reqwest::multipart::Form::new()
            .part("file", part)
            .text("platform", "windows")
            .text("timeout", seconds.to_string())
            .text("enforce_timeout", "1")
            .text("memory", "0");
        if !cfg.machine.is_empty() {
            form = form.text("machine", cfg.machine.clone());
        }
        let value = response(
            authenticated(
                &cfg,
                client()?
                    .post(format!("{}/tasks/create/file/", cfg.endpoint))
                    .multipart(form),
            )?,
            1024 * 1024,
        )
        .await?;
        let id = value["data"]["task_ids"][0]
            .as_u64()
            .or_else(|| value["task_ids"][0].as_u64())
            .ok_or("未获得 CAPE task_ids；请核对 API v2 版本。")?;
        job.task_id = Some(id);
        job.state = "submitted".into();
        Ok::<(), String>(())
    }
    .await;
    if let Err(error) = result {
        job.state = "failed".into();
        job.error = Some(error);
    }
    sandbox::event(
        store,
        app,
        &mut job,
        "提交阶段结束；虚拟机启动、隔离网络、快照还原与采集由 CAPE 管理，尚未由客户端验证",
    )?;
    Ok(job)
}
pub async fn refresh(
    store: &Store,
    app: Option<&tauri::AppHandle>,
    id: String,
) -> Result<SandboxJob, String> {
    let mut job = sandbox::jobs(store)?
        .into_iter()
        .find(|j| j.id == id && j.provider == "cape-windows")
        .ok_or("任务不属于当前事件。")?;
    if job.report_evidence_id.is_some() {
        return Ok(job);
    }
    let cfg = config(store)?;
    if cfg.endpoint != job.endpoint {
        return Err("沙箱地址已变更；请恢复该任务的原地址后再查询，避免任务 ID 串用。".into());
    }
    let task = job.task_id.ok_or("此任务没有有效的 CAPE task ID。")?;
    let data = response(
        authenticated(
            &cfg,
            client()?.get(format!("{}/tasks/view/{task}/", cfg.endpoint)),
        )?,
        1024 * 1024,
    )
    .await?;
    let state = data["data"]["status"]
        .as_str()
        .or_else(|| data["data"]["task"]["status"].as_str())
        .or_else(|| data["task"]["status"].as_str())
        .ok_or("未获得 CAPE 任务状态。")?;
    job.state = state.into();
    sandbox::event(store, app, &mut job, &format!("CAPE 返回任务状态：{state}"))?;
    if state == "reported" {
        let raw = response(
            authenticated(
                &cfg,
                client()?.get(format!("{}/tasks/get/report/{task}/json/", cfg.endpoint)),
            )?,
            30 * 1024 * 1024,
        )
        .await?;
        let report = raw
            .get("data")
            .filter(|d| d.get("behavior").is_some() || d.get("info").is_some())
            .unwrap_or(&raw);
        let processes=report.pointer("/behavior/processes").and_then(Value::as_array).map(|p|p.iter().take(100).map(|p|json!({"processId":p["process_id"],"parentId":p["parent_id"],"name":p["process_name"],"firstSeen":p["first_seen"]})).collect::<Vec<_>>()).unwrap_or_default();
        let summary = json!({"processes":processes,"network":report["network"],"fileRegistrySummary":report["behavior"]["summary"],"signatures":report["signatures"]});
        job.trace_preview = crate::analyzers::cut(
            &serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?,
            30000,
        );
        let wrapped = json!({"format":"gaga-dynamic/1","provider":"cape-windows","jobId":job.id,"taskId":task,"sampleSha256":crate::sandbox::sample(store,&job.evidence_id)?.0.sha256,"behaviorSummary":summary,"sandboxReport":raw,"limitations":["报告来源为所配置的 CAPE 服务；客户端未独立验证 Windows VM 隔离、快照还原及采集完整性。","未列出行为不等于没有行为，样本可能识别沙箱或未触发执行路径。","签名、恶意分数与 ATT&CK 映射属于沙箱输出，需结合原始行为复核。"]});
        job.report_evidence_id = Some(sandbox::import_report(store, &job, &wrapped)?);
        job.state = "completed".into();
        sandbox::event(
            store,
            app,
            &mut job,
            "已归档 CAPE 报告及摘要；Windows VM 还原状态由沙箱端确认",
        )?;
    }
    Ok(job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn endpoint_requires_secure_remote_and_keeps_credentials_out_of_url() {
        assert!(endpoint("http://example.test/apiv2").is_err());
        assert!(endpoint("https://u:secret@example.test/apiv2").is_err());
        assert!(endpoint("https://example.test/apiv2?token=x").is_err());
        assert!(endpoint("http://127.0.0.1:8000/apiv2").is_ok());
    }
    #[test]
    fn cape_upload_status_report_and_case_boundary_use_actual_http() {
        let root = std::env::temp_dir().join(format!("gaga-cape-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let p = root.join("inert-test.exe");
        std::fs::write(&p, b"MZ-inert-transport-fixture-NOT-AN-EXECUTABLE").unwrap();
        let e = store
            .analyze_file(p.display().to_string(), "binary".into())
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}/apiv2", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let replies = [
                (
                    "POST /apiv2/tasks/create/file/",
                    json!({"error":false,"data":{"task_ids":[17]}}),
                ),
                (
                    "GET /apiv2/tasks/view/17/",
                    json!({"error":false,"data":{"status":"reported"}}),
                ),
                (
                    "GET /apiv2/tasks/get/report/17/json/",
                    json!({"info":{"id":17},"behavior":{"processes":[{"process_id":400,"parent_id":200,"process_name":"test.exe","first_seen":"2026-10-27"}],"summary":{"file_written":["C:\\test.txt"],"regkey_written":["HKCU\\test"]}},"network":{"domains":[{"domain":"example.test"}]},"signatures":[]}),
                ),
            ];
            for (prefix, reply) in replies {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut data = Vec::new();
                let mut chunk = [0; 4096];
                loop {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&chunk[..n]);
                    if let Some(i) = data.windows(4).position(|s| s == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&data[..i]);
                        assert!(header.starts_with(prefix));
                        let size = header
                            .lines()
                            .find_map(|s| {
                                s.to_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if data.len() >= i + 4 + size {
                            if prefix.starts_with("POST") {
                                let body = String::from_utf8_lossy(&data[i + 4..]);
                                assert!(body.contains("MZ-inert-transport-fixture"));
                                assert!(body.contains("name=\"platform\"\r\n\r\nwindows"));
                                assert!(body.contains("name=\"machine\"\r\n\r\nwin-test"));
                            }
                            break;
                        }
                    }
                }
                let body = reply.to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        save_config(&store, address, "win-test".into(), String::new()).unwrap();
        assert!(
            tauri::async_runtime::block_on(submit(&store, None, e.id.clone(), 30, false)).is_err()
        );
        let submitted =
            tauri::async_runtime::block_on(submit(&store, None, e.id, 30, true)).unwrap();
        assert_eq!(submitted.task_id, Some(17));
        assert_eq!(submitted.state, "submitted");
        let result =
            tauri::async_runtime::block_on(refresh(&store, None, submitted.id.clone())).unwrap();
        server.join().unwrap();
        assert_eq!(result.state, "completed");
        assert!(!result.cleanup_confirmed);
        assert!(
            result.trace_preview.contains("test.exe")
                && result.trace_preview.contains("file_written")
        );
        assert!(result.report_evidence_id.is_some());
        drop(store);
        let store = Store::open(root.clone()).unwrap();
        assert_eq!(sandbox::jobs(&store).unwrap().len(), 1);
        assert_eq!(store.workspace().unwrap().evidence.len(), 2);
        store.create_case("另一事件".into()).unwrap();
        assert!(sandbox::jobs(&store).unwrap().is_empty());
        assert!(tauri::async_runtime::block_on(refresh(&store, None, submitted.id)).is_err());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
