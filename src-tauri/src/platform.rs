use crate::{
    collector, intelligence, monitoring,
    store::{open_regular_read, Store},
};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};
use tauri::{Manager, State};

#[tauri::command]
pub async fn platform_state(
    store: State<'_, Arc<Store>>,
    receiver: State<'_, Arc<collector::Receiver>>,
) -> Result<Value, String> {
    let store = store.inner().clone();
    let running = receiver.running();
    tauri::async_runtime::spawn_blocking(move || {
        let case=store.active()?;
        Ok(json!({"assets":monitoring::assets(&store,Some(&case))?,"observations":monitoring::observations(&store,&case)?,"indicators":intelligence::query(&store,"")?,"rules":intelligence::rules(&store,&case)?,"sampleCases":intelligence::sample_cases(&store)?,"tasks":collector::tasks(&store,&case)?,"flows":collector::flow_windows(&store,&case)?,"identity":collector::identity(&store)?,"receiver":collector::receiver_config(&store)?,"receiverRunning":running,"aiSettings":monitoring::ai_settings(&store)?,"aiLocked":crate::privacy::get(&store)?.ai_locked,"aiQueue":monitoring::queue_stats(&store,&case)?}))
    }).await.map_err(|e|e.to_string())?
}
fn field(v: &Value, key: &str) -> Result<String, String> {
    v[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("缺少字段 {key}"))
}
fn number(v: &Value, key: &str) -> Result<u64, String> {
    v[key].as_u64().ok_or_else(|| format!("缺少数值 {key}"))
}
fn boolean(v: &Value, key: &str) -> Result<bool, String> {
    v[key].as_bool().ok_or_else(|| format!("缺少开关 {key}"))
}
#[tauri::command]
pub async fn platform_action(
    app: tauri::AppHandle,
    action: String,
    args: Value,
    store: State<'_, Arc<Store>>,
    receiver: State<'_, Arc<collector::Receiver>>,
) -> Result<Value, String> {
    let store = store.inner().clone();
    let receiver = receiver.inner().clone();
    if action == "assetCheck" {
        return serde_json::to_value(
            monitoring::check_asset(&store, Some(&app), &field(&args, "id")?, true).await?,
        )
        .map_err(|e| e.to_string());
    }
    tauri::async_runtime::spawn_blocking(move || match action.as_str() {
        "intelSearch" => Ok(json!(intelligence::query(
            &store,
            &field(&args, "search")?
        )?)),
        "intelOrigins" => Ok(json!(intelligence::origins(&store, &field(&args, "id")?)?)),
        "intelImport" => Ok(json!(intelligence::import(&store, &field(&args, "text")?)?)),
        "intelImportFile" => {
            let text = read_bounded(&field(&args, "path")?, 4 * 1024 * 1024)?;
            Ok(json!(intelligence::import(
                &store,
                &String::from_utf8(text).map_err(|_| "需要 UTF-8 情报文件")?
            )?))
        }
        "intelAnnotate" => {
            intelligence::annotate(
                &store,
                field(&args, "id")?,
                field(&args, "verdict")?,
                field(&args, "labels")?,
                field(&args, "notes")?,
            )?;
            Ok(Value::Null)
        }
        "intelExport" => {
            let ids: Vec<String> =
                serde_json::from_value(args["ids"].clone()).map_err(|_| "请选择 IOC")?;
            let text = intelligence::export(&store, &field(&args, "format")?, &ids)?;
            let path = std::path::PathBuf::from(field(&args, "path")?);
            crate::report::validate_output(&store, &path)?;
            crate::file_commit::write_bytes(&path, text.as_bytes())?;
            Ok(Value::Null)
        }
        "ruleAdd" => {
            intelligence::add_rule(
                &store,
                field(&args, "list")?,
                field(&args, "kind")?,
                field(&args, "value")?,
                field(&args, "scope")?,
                args["expiresAt"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
                field(&args, "notes")?,
            )?;
            Ok(Value::Null)
        }
        "rulePromote" => {
            intelligence::promote_rule(&store, &field(&args, "id")?)?;
            Ok(Value::Null)
        }
        "ruleToggle" => {
            let scope: String = store
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .query_row(
                    "SELECT scope FROM indicator_rules WHERE id=?1",
                    [field(&args, "id")?],
                    |r| r.get(0),
                )
                .map_err(|_| "名单不存在")?;
            if scope != "global" && scope != store.active()? {
                return Err("名单不属于当前事件".into());
            }
            store
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .execute(
                    "UPDATE indicator_rules SET enabled=?1 WHERE id=?2",
                    rusqlite::params![boolean(&args, "enabled")?, field(&args, "id")?],
                )
                .map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        "sampleAdd" => {
            intelligence::add_case(
                &store,
                field(&args, "title")?,
                field(&args, "family")?,
                field(&args, "hashes")?,
                field(&args, "verdict")?,
                field(&args, "notes")?,
                args["evidenceId"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
            )?;
            Ok(Value::Null)
        }
        "assetImport" => Ok(json!(if args["followRedirects"].is_boolean()
            || args["autoScreenshot"].is_boolean()
        {
            monitoring::import_configured(
                &store,
                &field(&args, "text")?,
                number(&args, "intervalSecs")?,
                boolean(&args, "followRedirects")?,
                boolean(&args, "autoScreenshot")?,
            )?
        } else {
            monitoring::import_assets(
                &store,
                &field(&args, "text")?,
                number(&args, "intervalSecs")?,
            )?
        })),
        "assetConfigure" => {
            monitoring::configure_asset(
                &store,
                &field(&args, "id")?,
                boolean(&args, "followRedirects")?,
                boolean(&args, "autoScreenshot")?,
            )?;
            Ok(Value::Null)
        }
        "browserEnvironment" => Ok(crate::monitor_browser::environment(&store)),
        "browserPrepare" => {
            crate::monitor_browser::build(&store, args["mirror"].as_str().unwrap_or("official"))
        }
        "assetToggle" => {
            monitoring::toggle_asset(&store, &field(&args, "id")?, boolean(&args, "enabled")?)?;
            Ok(Value::Null)
        }
        "assetSnapshots" => {
            let id = field(&args, "id")?;
            if !monitoring::assets(&store, Some(&store.active()?))?
                .iter()
                .any(|a| a.id == id)
            {
                return Err("资产不属于当前事件".into());
            }
            Ok(json!(monitoring::snapshots(&store, &id)?))
        }
        "assetBaseline" => {
            monitoring::accept_baseline(
                &store,
                &field(&args, "id")?,
                &field(&args, "snapshotId")?,
            )?;
            Ok(Value::Null)
        }
        "monitorAiSave" => {
            monitoring::save_ai_settings(
                &store,
                serde_json::from_value(args).map_err(|e| e.to_string())?,
            )?;
            Ok(Value::Null)
        }
        "agentGenerate" => {
            let input: collector::TaskInput =
                serde_json::from_value(args["input"].clone()).map_err(|e| e.to_string())?;
            let path = PathBuf::from(field(&args, "path")?);
            let templates = app
                .path()
                .resource_dir()
                .map_err(|e| e.to_string())?
                .join("resources/agents");
            Ok(json!(collector::generate_for_case(
                &store,
                &field(&args, "caseId")?,
                input,
                &path,
                &templates
            )?))
        }
        "agentRevoke" => {
            collector::revoke(&store, &field(&args, "id")?)?;
            Ok(Value::Null)
        }
        "agentImport" => {
            let bytes = read_bounded(&field(&args, "path")?, 32 * 1024 * 1024)?;
            Ok(json!(collector::ingest(&store, Some(&app), &bytes, None)?))
        }
        "receiverSave" => Ok(json!(collector::configure_receiver(
            &store,
            field(&args, "bind")?,
            field(&args, "callbackUrl")?,
            receiver.running()
        )?)),
        "receiverStart" => Ok(json!(collector::start_receiver(store, app, receiver)?)),
        "receiverStop" => {
            receiver.stop();
            Ok(Value::Null)
        }
        "environment" => environment(&store, &app),
        _ => Err("未知的平台操作".into()),
    })
    .await
    .map_err(|e| e.to_string())?
}
fn read_bounded(path: &str, limit: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let f = open_regular_read(std::path::Path::new(path))?;
    let mut bytes = Vec::new();
    f.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("文件超过导入上限".into());
    }
    Ok(bytes)
}
fn environment(store: &Store, app: &tauri::AppHandle) -> Result<Value, String> {
    let probe = store
        .root
        .join(format!("write-probe-{}", uuid::Uuid::new_v4()));
    let writable = std::fs::write(&probe, b"probe").is_ok();
    let _ = std::fs::remove_file(&probe);
    let templates = app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?
        .join("resources/agents");
    Ok(
        json!({"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,"version":env!("CARGO_PKG_VERSION"),"cpuThreads":std::thread::available_parallelism().map(|n|n.get()).unwrap_or(1),"dataDir":store.root,"writable":writable,"availableBytes":fs2::available_space(&store.root).ok(),"templates":(["gaga-agent-linux-amd64","gaga-agent-linux-arm64","gaga-agent-windows-amd64.exe"].map(|name|json!({"name":name,"available":templates.join(name).is_file()}))),"ebpf":"运行在 Linux 目标主机；内核与 CAP_BPF / CAP_SYS_ADMIN、CAP_NET_RAW 在目标侧检查。macOS / Windows 客户端只负责生成任务、接收与分析。","scheduler":"客户端运行期间每 5 秒调度，最多 4 个并发巡检；退出后停止。","database":"SQLite 本地证据、情报、资产与任务库；解密证据在本机明文保存。"}),
    )
}
