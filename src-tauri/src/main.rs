#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod ai;
mod analysis_jobs;
mod analysis_progress;
mod analyzers;
#[cfg(test)]
mod audit_tests;
mod cases;
mod collector;
mod collector_crypto;
mod connection;
mod coverage;
mod dashboard;
mod diagnostics;
mod enrichment;
#[cfg(debug_assertions)]
mod evaluation;
#[cfg(debug_assertions)]
mod field_verification;
mod file_commit;
mod http;
mod intelligence;
mod investigation;
mod isolated;
mod lan;
mod logbook;
mod maintenance;
mod monitor_browser;
mod monitoring;
mod platform;
mod privacy;
mod record_entry;
mod report;
mod report_draft;
mod report_input;
mod report_insights;
mod report_jobs;
mod report_watermark;
mod response_actions;
mod runtime_log;
#[cfg(test)]
#[path = "../../reverse-worker/src/sample_static.rs"]
mod sample_static;
mod sandbox;
mod security;
#[cfg(test)]
mod showcase_report_tests;
mod startup;
#[cfg(test)]
mod storage_tests;
mod store;
mod triage;
#[cfg(test)]
#[path = "../../reverse-worker/src/webshell.rs"]
mod webshell;
#[path = "../../reverse-worker/src/webshell_schema.rs"]
mod webshell_schema;
mod windows_sandbox;
#[cfg(test)]
#[path = "../../reverse-worker/src/tools.rs"]
mod worker_tools;
use std::{path::Path, sync::Arc};
use store::{Evidence, Store, Workspace};
use tauri::{Manager, State};

#[tauri::command]
async fn get_workspace(store: State<'_, Arc<Store>>) -> Result<Workspace, String> {
    let store = store.inner().clone();
    let w = tauri::async_runtime::spawn_blocking(move || store.workspace())
        .await
        .map_err(|e| e.to_string())??;
    #[cfg(debug_assertions)]
    eprintln!(
        "GAGA_DESKTOP_READY: cases={}, evidence={}",
        w.cases.len(),
        w.evidence.len()
    );
    Ok(w)
}
#[tauri::command]
fn get_timeline_page(
    case_id: String,
    offset: u64,
    limit: u64,
    query: String,
    store: State<'_, Arc<Store>>,
) -> Result<serde_json::Value, String> {
    store.timeline_page(&case_id, offset, limit, &query)
}
#[tauri::command]
fn get_evidence_page(
    case_id: String,
    offset: u64,
    limit: u64,
    query: String,
    store: State<'_, Arc<Store>>,
) -> Result<serde_json::Value, String> {
    store.evidence_page(&case_id, offset, limit, &query)
}
#[tauri::command]
fn create_case(title: String, store: State<'_, Arc<Store>>) -> Result<Workspace, String> {
    store.create_case(title)?;
    store.workspace()
}
#[tauri::command]
fn switch_case(id: String, store: State<'_, Arc<Store>>) -> Result<Workspace, String> {
    store.switch_case(id)?;
    store.workspace()
}
#[tauri::command]
async fn analyze_file(
    app: tauri::AppHandle,
    path: String,
    kind: String,
    store: State<'_, Arc<Store>>,
) -> Result<Evidence, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        investigation::local_analyze(&store, Some(&app), || store.analyze_file(path, kind))
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn analyze_http_pair(
    app: tauri::AppHandle,
    request: String,
    response: String,
    store: State<'_, Arc<Store>>,
) -> Result<Evidence, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        investigation::local_analyze(&store, Some(&app), || {
            store.analyze_http_pair(request, response)
        })
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn read_http_text(path: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Read;
        let mut bytes = Vec::new();
        crate::store::open_regular_read(std::path::Path::new(&path))
            .map_err(|e| e.to_string())?
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("单侧报文超过 2 MiB。".into());
        }
        String::from_utf8(bytes).map_err(|_| "需要 UTF-8 文本；可用 HAR 导入二进制正文。".into())
    })
    .await
    .map_err(|e| e.to_string())?
}
fn example(store: &Store, kind: &str) -> Result<Evidence, String> {
    let (name, text) = match kind {
        "http" => (
            "示例-demo-http.har",
            include_str!("../../fixtures/demo-http.har"),
        ),
        "logs" => (
            "示例-demo-access.log",
            include_str!("../../fixtures/demo-access.log"),
        ),
        "webshell" => (
            "示例-demo-source.php",
            include_str!("../../fixtures/demo-source.php"),
        ),
        "containers" => (
            "示例-demo-inspect.json",
            include_str!("../../fixtures/demo-inspect.json"),
        ),
        _ => return Err("该模块没有内置示例。".into()),
    };
    let dir = store.root.join("example-input");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(name);
    std::fs::write(&path, text).map_err(|e| e.to_string())?;
    let result = store.analyze_file(path.display().to_string(), kind.into());
    let _ = std::fs::remove_file(path);
    result
}
#[tauri::command]
async fn analyze_example(
    app: tauri::AppHandle,
    kind: String,
    store: State<'_, Arc<Store>>,
    mode: State<'_, SmokeMode>,
) -> Result<Evidence, String> {
    if !cfg!(debug_assertions) || !mode.0 {
        return Err("正式工作区不提供测试材料注入。".into());
    }
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        investigation::local_analyze(&store, Some(&app), || example(&store, &kind))
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
fn add_node(
    title: String,
    body: String,
    occurred_at: String,
    actor: String,
    evidence_id: Option<String>,
    finding_id: Option<String>,
    store: State<'_, Arc<Store>>,
) -> Result<Workspace, String> {
    store.add_node(title, body, occurred_at, actor, evidence_id, finding_id)?;
    store.workspace()
}
#[tauri::command]
fn toggle_node(
    id: String,
    included: bool,
    store: State<'_, Arc<Store>>,
) -> Result<Workspace, String> {
    store.toggle_node(id, included)?;
    store.workspace()
}
#[tauri::command]
fn get_response_actions(
    case_id: String,
    store: State<'_, Arc<Store>>,
) -> Result<Vec<response_actions::ResponseAction>, String> {
    response_actions::list(&store, &case_id)
}
#[tauri::command]
fn create_response_action(
    action: response_actions::ResponseAction,
    store: State<'_, Arc<Store>>,
) -> Result<response_actions::ResponseAction, String> {
    response_actions::create(&store, action)
}
#[tauri::command]
fn update_response_action_status(
    action_id: String,
    status: String,
    actor: Option<String>,
    detail: Option<String>,
    store: State<'_, Arc<Store>>,
) -> Result<response_actions::ResponseAction, String> {
    response_actions::update_status(&store, &action_id, &status, actor, detail)
}
#[tauri::command]
fn record_response_receipt(
    action_id: String,
    receipt: String,
    store: State<'_, Arc<Store>>,
) -> Result<response_actions::ResponseAction, String> {
    response_actions::receipt(&store, &action_id, receipt)
}
#[tauri::command]
fn save_response_rollback_plan(
    action_id: String,
    plan: String,
    store: State<'_, Arc<Store>>,
) -> Result<response_actions::ResponseAction, String> {
    response_actions::rollback_plan(&store, &action_id, plan)
}
#[tauri::command]
fn update_node(
    id: String,
    title: String,
    body: String,
    occurred_at: String,
    actor: String,
    store: State<'_, Arc<Store>>,
) -> Result<Workspace, String> {
    store.update_node(id, title, body, occurred_at, actor)?;
    store.workspace()
}
#[tauri::command]
fn add_screenshot(
    node_id: String,
    path: String,
    caption: String,
    store: State<'_, Arc<Store>>,
) -> Result<Workspace, String> {
    store.add_screenshot(node_id, path, caption)?;
    store.workspace()
}
#[tauri::command]
fn screenshot_data(id: String, store: State<'_, Arc<Store>>) -> Result<String, String> {
    store.screenshot_data(id)
}
#[tauri::command]
async fn paste_screenshot(
    node_id: String,
    data_url: String,
    caption: String,
    store: State<'_, Arc<Store>>,
) -> Result<Workspace, String> {
    let s = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        use base64::Engine;
        if data_url.len() > 12 * 1024 * 1024 {
            return Err("粘贴截图超过 8 MiB。".into());
        }
        let (mime, data) = data_url.split_once(',').ok_or("图片数据无效")?;
        if !matches!(
            mime,
            "data:image/png;base64" | "data:image/jpeg;base64" | "data:image/webp;base64"
        ) {
            return Err("仅支持 PNG / JPEG / WebP 截图。".into());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|_| "截图编码无效")?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err("粘贴截图超过 8 MiB。".into());
        }
        let dir = s.root.join("clipboard-input");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("粘贴截图-{}.png", uuid::Uuid::new_v4()));
        std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
        let result = s.add_screenshot(node_id, path.display().to_string(), caption);
        let _ = std::fs::remove_file(&path);
        result?;
        s.workspace()
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
fn extract_indicators(text: String) -> Result<Vec<analyzers::Indicator>, String> {
    if text.len() > 2 * 1024 * 1024 {
        return Err("文本超过 2 MiB。".into());
    }
    Ok(analyzers::extract_indicators(&text))
}
#[tauri::command]
async fn export_report(
    app: tauri::AppHandle,
    path: String,
    format: String,
    case_id: Option<String>,
    store: State<'_, Arc<Store>>,
    registry: State<'_, report_jobs::Registry>,
) -> Result<(), String> {
    let case_id = case_id.map(Ok).unwrap_or_else(|| store.active())?;
    let control = registry.begin(case_id.clone(), format.clone(), path.clone(), Some(app))?;
    control.notify();
    let task = control.clone();
    let store = store.inner().clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let input = report_input::capture(&store, &case_id)?;
        report::export_input(&store, Path::new(&path), &format, input, &task)
    })
    .await
    .unwrap_or_else(|_| Err("报告工作线程异常结束，请检查输出后重试。".into()));
    control.finish(result.clone());
    result
}
#[tauri::command]
fn print_report(window: tauri::WebviewWindow) -> Result<(), String> {
    window.print().map_err(|e| e.to_string())
}
#[tauri::command]
fn get_ai_config(store: State<'_, Arc<Store>>) -> Result<ai::AiConfig, String> {
    ai::config(&store)
}
#[tauri::command]
fn get_ai_profiles(store: State<'_, Arc<Store>>) -> Result<Vec<ai::AiConfig>, String> {
    ai::profiles(&store)
}
#[tauri::command]
fn get_ai_connection_tests(
    store: State<'_, Arc<Store>>,
) -> Result<Vec<ai::ConnectionTest>, String> {
    ai::connection_tests(&store)
}
#[tauri::command]
async fn test_ai_connection(
    revision: String,
    store: State<'_, Arc<Store>>,
) -> Result<ai::ConnectionTest, String> {
    ai::test_connection(&store, &revision).await
}
#[tauri::command]
async fn save_ai_config(
    base_url: String,
    model: String,
    api_key: String,
    remove_key: bool,
    store: State<'_, Arc<Store>>,
) -> Result<ai::AiConfig, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        ai::save_config(&store, base_url, model, api_key, remove_key)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
fn preview_ai_material(
    evidence_id: String,
    store: State<'_, Arc<Store>>,
) -> Result<ai::AiSendPreview, String> {
    ai::send_preview(&store, &evidence_id)
}
#[tauri::command]
async fn review_with_ai(
    app: tauri::AppHandle,
    evidence_id: String,
    material: String,
    question: String,
    store: State<'_, Arc<Store>>,
) -> Result<ai::AiReview, String> {
    let store = store.inner().clone();
    ai::review_traced(&store, Some(&app), evidence_id, material, question).await
}
#[tauri::command]
async fn analyze_alert_text(
    app: tauri::AppHandle,
    text: String,
    store: State<'_, Arc<Store>>,
) -> Result<Evidence, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        investigation::local_analyze(&store, Some(&app), || store.analyze_alert_text(text))
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn followup_review(
    app: tauri::AppHandle,
    review_id: String,
    question: String,
    store: State<'_, Arc<Store>>,
) -> Result<ai::Followup, String> {
    let store = store.inner().clone();
    ai::followup(&store, Some(&app), review_id, question).await
}
#[tauri::command]
fn save_review_feedback(
    review_id: String,
    disposition: String,
    feedback: String,
    notes: String,
    actor: String,
    store: State<'_, Arc<Store>>,
) -> Result<Workspace, String> {
    investigation::save_feedback(&store, review_id, disposition, feedback, notes, actor)?;
    store.workspace()
}
struct SmokeMode(bool);
type UiCoverage = Arc<std::sync::Mutex<std::collections::BTreeMap<String, u64>>>;
#[tauri::command]
async fn reverse_environment(
    store: State<'_, Arc<Store>>,
) -> Result<isolated::Environment, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || Ok(isolated::environment(&store)))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn build_reverse_environment(
    store: State<'_, Arc<Store>>,
) -> Result<isolated::Environment, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || isolated::build(&store))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn cleanup_reverse_environment(
    store: State<'_, Arc<Store>>,
) -> Result<isolated::Environment, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || isolated::cleanup(&store))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
fn get_reverse_jobs(store: State<'_, Arc<Store>>) -> Result<Vec<isolated::Job>, String> {
    isolated::jobs(&store)
}
#[tauri::command]
async fn start_reverse(
    app: tauri::AppHandle,
    store: State<'_, Arc<Store>>,
    evidence_id: String,
    question: String,
) -> Result<isolated::Job, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        isolated::run(&store, Some(&app), evidence_id, question)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
fn cancel_reverse(store: State<'_, Arc<Store>>, id: String) -> Result<(), String> {
    isolated::cancel(&store, &id)
}
#[tauri::command]
async fn check_docker(store: State<'_, Arc<Store>>) -> Result<sandbox::DockerCheck, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || sandbox::preflight(&store))
        .await
        .map_err(|e| e.to_string())
}
#[tauri::command]
async fn build_sandbox_runner(
    mirror: String,
    store: State<'_, Arc<Store>>,
) -> Result<sandbox::DockerCheck, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || sandbox::build_runner(&store, &mirror))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn cleanup_sandbox_containers(
    store: State<'_, Arc<Store>>,
) -> Result<sandbox::DockerCheck, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || sandbox::cleanup(&store))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
fn get_sandbox_jobs(store: State<'_, Arc<Store>>) -> Result<Vec<sandbox::SandboxJob>, String> {
    sandbox::jobs(&store)
}
#[tauri::command]
async fn run_linux_sample(
    app: tauri::AppHandle,
    evidence_id: String,
    seconds: u64,
    lab_ack: bool,
    store: State<'_, Arc<Store>>,
) -> Result<sandbox::SandboxJob, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        sandbox::run_docker(&store, Some(&app), evidence_id, seconds, lab_ack)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
fn get_windows_sandbox_config(
    store: State<'_, Arc<Store>>,
) -> Result<windows_sandbox::Config, String> {
    windows_sandbox::config(&store)
}
#[tauri::command]
fn save_windows_sandbox_config(
    endpoint: String,
    machine: String,
    token: String,
    store: State<'_, Arc<Store>>,
) -> Result<windows_sandbox::Config, String> {
    windows_sandbox::save_config(&store, endpoint, machine, token)
}
#[tauri::command]
async fn check_windows_sandbox(store: State<'_, Arc<Store>>) -> Result<serde_json::Value, String> {
    let store = store.inner().clone();
    windows_sandbox::check(&store).await
}
#[tauri::command]
async fn submit_windows_sample(
    app: tauri::AppHandle,
    evidence_id: String,
    seconds: u64,
    lab_ack: bool,
    store: State<'_, Arc<Store>>,
) -> Result<sandbox::SandboxJob, String> {
    let store = store.inner().clone();
    windows_sandbox::submit(&store, Some(&app), evidence_id, seconds, lab_ack).await
}
#[tauri::command]
async fn refresh_windows_task(
    app: tauri::AppHandle,
    id: String,
    store: State<'_, Arc<Store>>,
) -> Result<sandbox::SandboxJob, String> {
    let store = store.inner().clone();
    windows_sandbox::refresh(&store, Some(&app), id).await
}
#[tauri::command]
fn audit_collector_credentials(
    store: State<'_, Arc<Store>>,
    mode: State<'_, SmokeMode>,
) -> Result<serde_json::Value, String> {
    if !cfg!(debug_assertions) || !mode.0 {
        return Err("仅隔离的开发验证可用".into());
    }
    #[cfg(all(debug_assertions, not(test)))]
    return collector::audit_isolated_credentials(&store);
    #[cfg(any(not(debug_assertions), test))]
    {
        let _ = store;
        Err("非原生验证模式".into())
    }
}
#[tauri::command]
fn record_ui_verification(
    mut result: serde_json::Value,
    coverage: State<'_, UiCoverage>,
    store: State<'_, Arc<Store>>,
    mode: State<'_, SmokeMode>,
) -> Result<(), String> {
    if !cfg!(debug_assertions) || !mode.0 {
        return Err("仅隔离的开发界面验证可使用此命令。".into());
    }
    // 验收记录以实际运行的二进制版本为准，避免脚本旧标签冒充当前版本。
    result["version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
    result["commandInvocations"] =
        serde_json::to_value(&*coverage.lock().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("验证记录过大。".into());
    }
    collector::cleanup_smoke_credentials(&store);
    ai::cleanup_smoke_credentials(&store);
    std::fs::write(store.root.join("native-ui-verification.json"), bytes)
        .map_err(|e| e.to_string())?;
    eprintln!("GAGA_NATIVE_UI_VERIFIED: {}", result);
    Ok(())
}
#[tauri::command]
fn ui_checkpoint(
    label: String,
    store: State<'_, Arc<Store>>,
    mode: State<'_, SmokeMode>,
) -> Result<(), String> {
    if !cfg!(debug_assertions) || !mode.0 || label.len() > 400 {
        return Err("仅隔离验收可用".into());
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(store.root.join("ui-checkpoints.log"))
        .map_err(|e| e.to_string())?;
    writeln!(f, "{label}").map_err(|e| e.to_string())
}
#[tauri::command]
fn resize_ui_verification(
    window: tauri::WebviewWindow,
    width: u32,
    height: u32,
    mode: State<'_, SmokeMode>,
) -> Result<(), String> {
    if !cfg!(debug_assertions)
        || !mode.0
        || !(960..=1600).contains(&width)
        || !(660..=1000).contains(&height)
    {
        return Err("仅隔离界面验收可调整测试窗口。".into());
    }
    window
        .set_size(tauri::LogicalSize::new(width, height))
        .map_err(|e| e.to_string())
}
fn main() {
    runtime_log::panic_hook();
    #[cfg(debug_assertions)]
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("--verify-ebpf" | "--verify-official")
    ) {
        let mode = std::env::args().nth(1).unwrap();
        let root = std::env::args().nth(2).expect("需要新的隔离测试目录");
        let source = std::env::args().nth(3).expect("需要模板或配置源目录");
        if mode == "--verify-ebpf" {
            field_verification::run_ebpf(Path::new(&root), Path::new(&source))
        } else {
            field_verification::run_official(Path::new(&root), Path::new(&source))
        }
        .expect("实机验收失败");
        return;
    }
    #[cfg(debug_assertions)]
    if std::env::args().nth(1).as_deref() == Some("--evaluate-rules") {
        let root = std::env::args().nth(2).expect("需要新的独立评测目录");
        let report = evaluation::run(Path::new(&root)).expect("本地规则评测失败");
        println!("{report}");
        return;
    }
    #[cfg(debug_assertions)]
    if std::env::args().nth(1).as_deref() == Some("--verify-field") {
        let root = std::env::args().nth(2).expect("需要新的隔离测试目录");
        let fixtures = std::env::args().nth(3).expect("需要测试材料目录");
        let templates = std::env::args().nth(4).expect("需要 Agent 模板目录");
        field_verification::run(
            Path::new(&root),
            Path::new(&fixtures),
            Path::new(&templates),
        )
        .expect("容器采集 / 大日志实测失败");
        return;
    }
    #[cfg(debug_assertions)]
    if std::env::args().nth(1).as_deref() == Some("--verify-docker") {
        let root = std::path::PathBuf::from(std::env::args().nth(2).expect("需要新的测试目录"));
        assert!(!root.exists(), "需要新的隔离测试目录");
        let store = Store::open(root.clone()).expect("测试空间");
        let check = sandbox::preflight(&store);
        assert!(check.daemon_ready, "{}", check.message);
        sandbox::build_runner(&store, "https://mirrors.aliyun.com/alpine").expect("构建监控镜像");
        let path = root.join("无害诊断.sh");
        std::fs::write(&path,"#!/bin/sh\nprintf 'gaga harmless diagnostic\\n'\nprintf 'gaga-marker' > /tmp/gaga-created.txt\n/bin/sh -c 'cat /tmp/gaga-created.txt'\nwget -T 1 -q -O /dev/null http://192.0.2.1/ || true\nsleep 1\n").unwrap();
        let e = store
            .analyze_file(path.display().to_string(), "binary".into())
            .expect("归档诊断样本");
        // This mode only runs the fixed harmless diagnostic above, never user samples.
        let job = sandbox::run_docker(&store, None, e.id, 10, true).expect("容器诊断");
        std::fs::write(
            root.join("docker-verification.json"),
            serde_json::to_vec_pretty(&job).unwrap(),
        )
        .unwrap();
        assert_eq!(job.state, "completed", "{:?}", job.error);
        assert!(job.cleanup_confirmed);
        assert!(
            job.trace_preview.contains("execve(")
                && job.trace_preview.contains("gaga-created.txt")
                && job.trace_preview.contains("connect(")
        );
        println!("Docker 无害诊断通过：{}", job.id);
        return;
    }
    #[cfg(debug_assertions)]
    if let Some(arg) = std::env::args().nth(1) {
        if arg == "--verify-local" {
            let root = std::env::args().nth(2).expect("需要验证目录");
            verify_local(std::path::PathBuf::from(root)).expect("本地功能验证失败");
            return;
        }
    }
    let ui_field =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--field-ui");
    let ui_http = cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--http-ui");
    let ui_navigation =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--navigation-ui");
    let ui_official =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--official-ui");
    let ui_audit =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--deep-audit-ui");
    let ui_reverse =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--reverse-ui");
    let ui_scenarios =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--scenario-ui");
    let ui_report =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--report-ui");
    let ui_report_structure = cfg!(debug_assertions)
        && std::env::args().nth(1).as_deref() == Some("--report-structure-ui");
    let ui_usability =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--usability-ui");
    let ui_lan = cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--lan-ui");
    let ui_startup =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--startup-ui");
    let ui_webshell =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--webshell-ui");
    let ui_intel =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--intel-ui");
    let ui_monitor =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--monitor-ui");
    let ui_comfort =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--comfort-ui");
    let ui_analysis =
        cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--analysis-ui");
    let ui_logs = cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--logs-ui");
    let ui_smoke = ui_monitor
        || ui_comfort
        || ui_intel
        || ui_webshell
        || ui_analysis
        || ui_logs
        || ui_startup
        || ui_lan
        || ui_usability
        || ui_report_structure
        || ui_report
        || ui_audit
        || ui_reverse
        || ui_field
        || ui_http
        || ui_navigation
        || ui_official
        || ui_scenarios
        || (cfg!(debug_assertions) && std::env::args().nth(1).as_deref() == Some("--ui-smoke"));
    let workspace_override = if cfg!(debug_assertions)
        && matches!(
            std::env::args().nth(1).as_deref(),
            Some(
                "--workspace"
                    | "--ui-smoke"
                    | "--field-ui"
                    | "--http-ui"
                    | "--navigation-ui"
                    | "--official-ui"
                    | "--scenario-ui"
                    | "--reverse-ui"
                    | "--deep-audit-ui"
                    | "--report-ui"
                    | "--report-structure-ui"
                    | "--usability-ui"
                    | "--lan-ui"
                    | "--startup-ui"
                    | "--logs-ui"
                    | "--analysis-ui"
                    | "--webshell-ui"
                    | "--intel-ui"
                    | "--comfort-ui"
                    | "--monitor-ui"
            )
        ) {
        std::env::args().nth(2).map(std::path::PathBuf::from)
    } else {
        None
    };
    let smoke_started = std::sync::atomic::AtomicBool::new(false);
    let ui_coverage: UiCoverage =
        Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    tauri::Builder::default()
        .plugin(security::navigation_policy())
        .manage(report_jobs::Registry::default())
        .manage(Arc::new(analysis_jobs::Registry::default()))
        .manage(ui_coverage.clone())
        .manage(SmokeMode(ui_smoke))
        .manage(lan::UiCompanion::default())
        .manage(startup::Progress::new())
        .manage(startup::AuditRoot(if ui_startup {
            workspace_override.clone()
        } else {
            None
        }))
        .on_page_load(move |webview, payload| {
            if ui_smoke
                && matches!(payload.event(), tauri::webview::PageLoadEvent::Finished)
                && !smoke_started.swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                if ui_monitor {
                    let _ = webview.eval(include_str!("../tests/monitor-ui.js"));
                } else if ui_comfort {
                    let _ = webview.eval(include_str!("../tests/comfort-ui.js"));
                } else if ui_intel {
                    let _ = webview.eval(include_str!("../tests/intel-ui.js"));
                } else if ui_webshell {
                    let _ = webview.eval(include_str!("../tests/webshell-ui.js"));
                } else if ui_analysis {
                    let _ = webview.eval(include_str!("../tests/analysis-ui.js"));
                } else if ui_logs {
                    let _ = webview.eval(include_str!("../tests/logs-ui.js"));
                } else if ui_startup {
                    let _ = webview.eval(include_str!("../tests/startup-ui.js"));
                    let handle = webview.app_handle().clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_secs(3));
                        if let Some(window) = handle.get_webview_window("main") {
                            let _ = window.eval("window.__TAURI_INTERNALS__.invoke('startup_audit',{result:{diagnostic:true,visibility:document.visibilityState,location:location.href,html:document.body.innerHTML.slice(0,5000)}})");
                        }
                    });
                } else if ui_lan {
                    let _ = webview.eval(include_str!("../tests/lan-ui.js"));
                } else if ui_usability {
                    let _ = webview.eval(include_str!("../tests/usability-ui.js"));
                } else if ui_report_structure {
                    let _ = webview.eval(include_str!("../tests/report-structure-ui.js"));
                } else if ui_report {
                    let _ = webview.eval(include_str!("../tests/report-ui.js"));
                } else if ui_audit {
                    let _ = webview.eval(include_str!("../tests/deep-audit-ui.js"));
                } else if ui_reverse {
                    let _ = webview.eval(include_str!("../tests/reverse-ui.js"));
                } else if ui_scenarios {
                    let _ = webview.eval(include_str!("../tests/scenario-ui.js"));
                } else if ui_official {
                    let _ = webview.eval(include_str!("../tests/official-ui.js"));
                } else if ui_navigation {
                    let _ = webview.eval(include_str!("../tests/navigation-ui.js"));
                } else if ui_http {
                    let _ = webview.eval(include_str!("../tests/http-ui-smoke.js"));
                } else if ui_field {
                    let _ = webview.eval(include_str!("../tests/field-ui.js"));
                } else {
                    let _ = webview.eval(include_str!("../tests/platform-ui-smoke.js"));
                    let _ = webview.eval(include_str!("../tests/audit-ui-smoke.js"));
                    let _ = webview.eval(include_str!("../tests/acceptance-ui.js"));
                    let _ = webview.eval(include_str!("../tests/ui-smoke.js"));
                }
            }
        })
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            // Logs use the platform log directory, not the evidence database.
            // Synthetic GUI acceptance stays inside its disposable workspace.
            let log_root = if ui_smoke { workspace_override.as_ref().map(|p| p.join("runtime-logs")) }
                else { app.path().app_log_dir().ok().map(|p| p.join("runtime")) };
            if let Some(root) = log_root { runtime_log::init(root); }
            if ui_smoke {
                if let Some(window) = app.get_webview_window("main") {
                    window.set_title("自动验收（独立临时数据）— 嘎嘎安全助手")?;
                }
            }
            let menu = tauri::menu::MenuBuilder::new(app)
                .items(&[
                    &tauri::menu::SubmenuBuilder::new(app, "嘎嘎安全助手")
                        .about(None)
                        .separator()
                        .quit()
                        .build()?,
                    &tauri::menu::SubmenuBuilder::new(app, "编辑")
                        .undo()
                        .redo()
                        .separator()
                        .cut()
                        .copy()
                        .paste()
                        .select_all()
                        .build()?,
                    &tauri::menu::SubmenuBuilder::new(app, "窗口")
                        .minimize()
                        .maximize()
                        .close_window()
                        .build()?,
                ])
                .build()?;
            app.set_menu(menu)?;
            let handle = app.handle().clone();
            let allow_mock =
                ui_smoke && !ui_field && !ui_official && !ui_scenarios && !ui_reverse && !ui_audit;
            // Do not block window creation on database migration or a large disk.
            // IPC and the UI stay gated until all shared state is registered.
            if let Err(error) = std::thread::Builder::new()
                .name("gaga-startup".into())
                .spawn(move || {
                    startup::initialize(handle, workspace_override, allow_mock, !ui_smoke);
                })
            {
                app.state::<startup::Progress>()
                    .fail(format!("STARTUP-THREAD：无法创建初始化线程：{error}"));
            }
            Ok(())
        })
        .invoke_handler({
            let handler: fn(tauri::ipc::Invoke<tauri::Wry>) -> bool = tauri::generate_handler![
                startup::get_startup_state,
                startup::close_startup,
                startup::startup_audit,
                runtime_log::get_runtime_logs,
                runtime_log::record_client_error,
                runtime_log::export_runtime_logs,
                ui_checkpoint,
                resize_ui_verification,
                cases::get_case_list,
                cases::update_case,
                report_draft::get_report_draft,
                report_draft::save_report_draft,
                report_insights::get_report_insights,
                report_watermark::inspect_report_watermark,
                report_watermark::stamp_report_pdf,
                record_entry::save_record_entry,
                update_node,
                paste_screenshot,
                audit_collector_credentials,
                logbook::query_log_timeline,
                logbook::get_log_event,
                logbook::rebuild_log_timeline,
                logbook::log_ai_material,
                logbook::record_log_event,
                coverage::refresh_container_coverage,
                dashboard::get_dashboard,
                monitoring::get_monitor_snapshots_page,
                dashboard::create_demo_event,
                platform::platform_state,
                platform::platform_action,
                enrichment::get_intel_config,
                enrichment::save_intel_provider,
                enrichment::set_intel_lock,
                enrichment::get_intel_jobs,
                enrichment::get_intel_job,
                enrichment::start_intel_query,
                enrichment::cancel_intel_job,
                enrichment::archive_intel_result,
                record_ui_verification,
                maintenance::workspace_maintenance,
                lan::lan_action,
                lan::lan_state,
                lan::lan_ui_companion,
                maintenance::activate_workspace,
                diagnostics::export_diagnostics,
                get_workspace,
                get_timeline_page,
                get_evidence_page,
                create_case,
                switch_case,
                analyze_file,
                analyze_example,
                analyze_http_pair,
                read_http_text,
                add_node,
                toggle_node,
                get_response_actions,
                create_response_action,
                update_response_action_status,
                record_response_receipt,
                save_response_rollback_plan,
                add_screenshot,
                screenshot_data,
                extract_indicators,
                export_report,
                analysis_jobs::start_local_analysis,
                analysis_jobs::get_local_analysis_jobs,
                analysis_jobs::cancel_local_analysis,
                report_jobs::start_report_export,
                report_jobs::get_report_exports,
                report_jobs::cancel_report_export,
                print_report,
                get_ai_config,
                privacy::get_ai_privacy,
                privacy::set_ai_privacy,
                get_ai_profiles,
                get_ai_connection_tests,
                test_ai_connection,
                save_ai_config,
                preview_ai_material,
                review_with_ai,
                analyze_alert_text,
                followup_review,
                save_review_feedback,
                reverse_environment,
                build_reverse_environment,
                cleanup_reverse_environment,
                get_reverse_jobs,
                start_reverse,
                cancel_reverse,
                check_docker,
                build_sandbox_runner,
                cleanup_sandbox_containers,
                get_sandbox_jobs,
                run_linux_sample,
                get_windows_sandbox_config,
                save_windows_sandbox_config,
                check_windows_sandbox,
                submit_windows_sample,
                refresh_windows_task
            ];
            move |invocation: tauri::ipc::Invoke<tauri::Wry>| {
                // Future secondary/remote windows must not inherit this command surface.
                if invocation.message.webview_ref().label() != "main" {
                    invocation.resolver.reject("IPC-WINDOW：此窗口无权调用本地接口。");
                    return true;
                }
                let command = invocation.message.command();
                if !matches!(
                    command,
                    "get_startup_state"
                        | "close_startup"
                        | "startup_audit"
                        | "get_report_exports"
                        | "resize_ui_verification"
                        | "get_runtime_logs"
                        | "record_client_error"
                        | "export_runtime_logs"
                ) && !invocation
                    .message
                    .webview()
                    .app_handle()
                    .state::<startup::Progress>()
                    .ready()
                {
                    invocation
                        .resolver
                        .reject("STARTUP-PENDING：本地工作区尚未就绪，请查看启动状态。");
                    return true;
                }
                if cfg!(debug_assertions) && ui_smoke {
                    let mut name = invocation.message.command().to_string();
                    if name == "platform_action" {
                        if let tauri::ipc::InvokeBody::Json(body) = invocation.message.payload() {
                            if let Some(action) =
                                body.get("action").and_then(serde_json::Value::as_str)
                            {
                                name.push('.');
                                name.extend(action.chars().take(80));
                            }
                        }
                    }
                    if let Ok(mut counts) = ui_coverage.lock() {
                        *counts.entry(name).or_default() += 1;
                    }
                }
                handler(invocation)
            }
        })
        .run(tauri::generate_context!())
        .expect("无法启动嘎嘎安全助手");
}
#[cfg(debug_assertions)]
fn verify_local(root: std::path::PathBuf) -> Result<(), String> {
    let store = Store::open(root.clone())?;
    for kind in ["logs", "webshell", "containers", "http"] {
        let e = example(&store, kind)?;
        let f = e.report.findings.first().ok_or("示例未产生命中")?;
        store.add_node(
            format!("[示例] {}", f.title),
            format!("演示数据。{}", f.description),
            "2026-10-27T10:21:00+08:00".into(),
            "示例分析员".into(),
            Some(e.id.clone()),
            Some(f.id.clone()),
        )?;
    }
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let binary = store.analyze_file(me.display().to_string(), "binary".into())?;
    if binary.report.metrics.first().map(|m| m.value.as_str()) != Some("Mach-O")
        && cfg!(target_os = "macos")
    {
        return Err("未识别本程序 Mach-O".into());
    }
    let node = store
        .workspace()?
        .nodes
        .first()
        .ok_or("缺少示例节点")?
        .id
        .clone();
    let image_path = root.join("example-screenshot.png");
    image::RgbaImage::from_pixel(240, 100, image::Rgba([225, 225, 225, 255]))
        .save(&image_path)
        .map_err(|e| e.to_string())?;
    store.add_screenshot(
        node,
        image_path.display().to_string(),
        "[演示图片] 截图归档与导出验证图，不是调查证据。".into(),
    )?;
    std::fs::remove_file(image_path).map_err(|e| e.to_string())?;
    report::export_docx(&store, &root.join("sample-report.docx"))?;
    report::export_html(&store, &root.join("sample-report.html"))?;
    let workspace = store.workspace()?;
    std::fs::write(
        root.join("workspace-verification.json"),
        serde_json::to_vec_pretty(&workspace).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    drop(store);
    let reopened = Store::open(root)?;
    let w = reopened.workspace()?;
    if w.evidence.len() < 5 || w.nodes.len() < 4 {
        return Err("重开后数据不完整".into());
    }
    println!(
        "GAGA_LOCAL_VERIFIED: {} evidence, {} nodes; DOCX + HTML exported; database reopened",
        w.evidence.len(),
        w.nodes.len()
    );
    Ok(())
}
