# IPC 注册目录 · 0.10.1

由 `scripts/generate-api-docs.py` 生成。更改接口后重新生成；CI 检查漂移。Rust 类型为源码类型，JSON 字段按 camelCase；`Option<T>` 可传 `null`。`State`、窗口和 AppHandle 由框架注入，不是调用参数。

生命周期、权限、错误和调用示例见 [接口契约](IPC-API.md)。本表不承诺第三方插件或所有 `Value` 数据结构的独立版本兼容。

共 100 个已注册命令。验收命令在正式工作区拒绝。

| 命令 | JSON 参数（Rust 类型） | 成功值 | 定义 |
| --- | --- | --- | --- |
| `get_startup_state` | `无` | `Result<Snapshot, String>` | [src-tauri/src/startup.rs](../src-tauri/src/startup.rs#L205) |
| `close_startup` | `无` | `()` | [src-tauri/src/startup.rs](../src-tauri/src/startup.rs#L210) |
| `startup_audit` | `result: Option<serde_json::Value>` | `Result<serde_json::Value, String>` | [src-tauri/src/startup.rs](../src-tauri/src/startup.rs#L218) |
| `get_runtime_logs` | `无` | `Result<Snapshot, String>` | [src-tauri/src/runtime_log.rs](../src-tauri/src/runtime_log.rs#L338) |
| `record_client_error` | `component: String ; message: String` | `Result<(), String>` | [src-tauri/src/runtime_log.rs](../src-tauri/src/runtime_log.rs#L350) |
| `export_runtime_logs` | `path: String` | `Result<(), String>` | [src-tauri/src/runtime_log.rs](../src-tauri/src/runtime_log.rs#L358) |
| `ui_checkpoint` | `label: String` | `Result<(), String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L630) |
| `resize_ui_verification` | `width: u32 ; height: u32` | `Result<(), String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L647) |
| `get_case_list` | `query: String ; status: String ; offset: u32` | `Result<Value, String>` | [src-tauri/src/cases.rs](../src-tauri/src/cases.rs#L6) |
| `update_case` | `id: String ; title: String ; status: String` | `Result<Workspace, String>` | [src-tauri/src/cases.rs](../src-tauri/src/cases.rs#L32) |
| `get_report_draft` | `caseId: String` | `Result<ReportDraft, String>` | [src-tauri/src/report_draft.rs](../src-tauri/src/report_draft.rs#L204) |
| `save_report_draft` | `caseId: String ; draft: ReportDraft` | `Result<ReportDraft, String>` | [src-tauri/src/report_draft.rs](../src-tauri/src/report_draft.rs#L212) |
| `get_report_insights` | `caseId: String ; draft: Option<ReportDraft>` | `Result<Insights, String>` | [src-tauri/src/report_insights.rs](../src-tauri/src/report_insights.rs#L405) |
| `inspect_report_watermark` | `path: String` | `Result<Inspection, String>` | [src-tauri/src/report_watermark.rs](../src-tauri/src/report_watermark.rs#L360) |
| `stamp_report_pdf` | `source: String ; destination: String ; name: String` | `Result<Inspection, String>` | [src-tauri/src/report_watermark.rs](../src-tauri/src/report_watermark.rs#L374) |
| `save_record_entry` | `input: Entry` | `Result<String, String>` | [src-tauri/src/record_entry.rs](../src-tauri/src/record_entry.rs#L228) |
| `update_node` | `id: String ; title: String ; body: String ; occurredAt: String ; actor: String` | `Result<Workspace, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L265) |
| `paste_screenshot` | `nodeId: String ; dataUrl: String ; caption: String` | `Result<Workspace, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L291) |
| `audit_collector_credentials` | `无` | `Result<serde_json::Value, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L588) |
| `query_log_timeline` | `filter: Filter` | `Result<Value, String>` | [src-tauri/src/logbook.rs](../src-tauri/src/logbook.rs#L405) |
| `get_log_event` | `evidenceId: String ; line: u64` | `Result<Event, String>` | [src-tauri/src/logbook.rs](../src-tauri/src/logbook.rs#L486) |
| `rebuild_log_timeline` | `evidenceId: String ; options: Options` | `Result<Value, String>` | [src-tauri/src/logbook.rs](../src-tauri/src/logbook.rs#L415) |
| `log_ai_material` | `evidenceId: String` | `Result<crate::ai::AiSendPreview, String>` | [src-tauri/src/logbook.rs](../src-tauri/src/logbook.rs#L508) |
| `record_log_event` | `evidenceId: String ; line: u64 ; actor: String` | `Result<Workspace, String>` | [src-tauri/src/logbook.rs](../src-tauri/src/logbook.rs#L518) |
| `refresh_container_coverage` | `evidenceId: String` | `Result<Workspace, String>` | [src-tauri/src/coverage.rs](../src-tauri/src/coverage.rs#L265) |
| `get_dashboard` | `caseId: String ; scope: String ; days: u32` | `Result<Value, String>` | [src-tauri/src/dashboard.rs](../src-tauri/src/dashboard.rs#L198) |
| `get_monitor_snapshots_page` | `assetId: String ; offset: u64 ; limit: u64` | `Result<Value, String>` | [src-tauri/src/monitoring.rs](../src-tauri/src/monitoring.rs#L362) |
| `create_demo_event` | `无` | `Result<Workspace, String>` | [src-tauri/src/dashboard.rs](../src-tauri/src/dashboard.rs#L320) |
| `platform_state` | `无` | `Result<Value, String>` | [src-tauri/src/platform.rs](../src-tauri/src/platform.rs#L9) |
| `platform_action` | `action: String ; args: Value` | `Result<Value, String>` | [src-tauri/src/platform.rs](../src-tauri/src/platform.rs#L33) |
| `get_intel_config` | `无` | `Result<Config, String>` | [src-tauri/src/enrichment.rs](../src-tauri/src/enrichment.rs#L169) |
| `save_intel_provider` | `id: String ; enabled: bool ; authorized: bool ; apiKey: String ; removeKey: bool` | `Result<Config, String>` | [src-tauri/src/enrichment.rs](../src-tauri/src/enrichment.rs#L173) |
| `set_intel_lock` | `locked: bool` | `Result<Config, String>` | [src-tauri/src/enrichment.rs](../src-tauri/src/enrichment.rs#L251) |
| `get_intel_jobs` | `caseId: String` | `Result<Vec<Job>, String>` | [src-tauri/src/enrichment.rs](../src-tauri/src/enrichment.rs#L315) |
| `get_intel_job` | `caseId: String ; id: String` | `Result<Job, String>` | [src-tauri/src/enrichment.rs](../src-tauri/src/enrichment.rs#L320) |
| `start_intel_query` | `query: Query` | `Result<Vec<Job>, String>` | [src-tauri/src/enrichment.rs](../src-tauri/src/enrichment.rs#L470) |
| `cancel_intel_job` | `id: String` | `Result<(), String>` | [src-tauri/src/enrichment.rs](../src-tauri/src/enrichment.rs#L333) |
| `archive_intel_result` | `id: String` | `Result<Evidence, String>` | [src-tauri/src/enrichment.rs](../src-tauri/src/enrichment.rs#L1039) |
| `record_ui_verification` | `result: serde_json::Value` | `Result<(), String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L604) |
| `workspace_maintenance` | `operation: String ; path: Option<String> ; parent: Option<String>` | `Result<Value, String>` | [src-tauri/src/maintenance.rs](../src-tauri/src/maintenance.rs#L441) |
| `lan_action` | `action: String ; peerId: Option<String> ; text: Option<String> ; path: Option<String> ; dataUrl: Option<String> ; messageId: Option<String> ; groupId: Option<String> ; groupName: Option<String> ; groupType: Option<String> ; memberIds: Option<Vec<String>> ; notificationKind: Option<String> ; notificationTitle: Option<String> ; notificationBody: Option<String> ; caseId: Option<String> ; actionId: Option<String> ; beforeSeq: Option<i64>` | `Result<Value, String>` | [src-tauri/src/lan/mod.rs](../src-tauri/src/lan/mod.rs#L895) |
| `lan_state` | `peerId: Option<String> ; beforeSeq: Option<i64> ; groupId: Option<String>` | `Result<Value, String>` | [src-tauri/src/lan/mod.rs](../src-tauri/src/lan/mod.rs#L947) |
| `lan_ui_companion` | `action: String` | `Result<Value, String>` | [src-tauri/src/lan/mod.rs](../src-tauri/src/lan/mod.rs#L965) |
| `activate_workspace` | `path: String` | `Result<(), String>` | [src-tauri/src/maintenance.rs](../src-tauri/src/maintenance.rs#L508) |
| `export_diagnostics` | `path: String` | `Result<(), String>` | [src-tauri/src/diagnostics.rs](../src-tauri/src/diagnostics.rs#L52) |
| `get_workspace` | `无` | `Result<Workspace, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L66) |
| `get_timeline_page` | `caseId: String ; offset: u64 ; limit: u64 ; query: String` | `Result<serde_json::Value, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L80) |
| `get_evidence_page` | `caseId: String ; offset: u64 ; limit: u64 ; query: String` | `Result<serde_json::Value, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L90) |
| `create_case` | `title: String` | `Result<Workspace, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L100) |
| `switch_case` | `id: String` | `Result<Workspace, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L105) |
| `analyze_file` | `path: String ; kind: String` | `Result<Evidence, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L110) |
| `analyze_example` | `kind: String` | `Result<Evidence, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L186) |
| `analyze_http_pair` | `request: String ; response: String` | `Result<Evidence, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L124) |
| `read_http_text` | `path: String` | `Result<String, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L140) |
| `add_node` | `title: String ; body: String ; occurredAt: String ; actor: String ; evidenceId: Option<String> ; findingId: Option<String>` | `Result<Workspace, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L203) |
| `toggle_node` | `id: String ; included: bool` | `Result<Workspace, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L216) |
| `get_response_actions` | `caseId: String` | `Result<Vec<response_actions::ResponseAction>, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L225) |
| `create_response_action` | `action: response_actions::ResponseAction` | `Result<response_actions::ResponseAction, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L232) |
| `update_response_action_status` | `actionId: String ; status: String ; actor: Option<String> ; detail: Option<String>` | `Result<response_actions::ResponseAction, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L239) |
| `record_response_receipt` | `actionId: String ; receipt: String` | `Result<response_actions::ResponseAction, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L249) |
| `save_response_rollback_plan` | `actionId: String ; plan: String` | `Result<response_actions::ResponseAction, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L257) |
| `add_screenshot` | `nodeId: String ; path: String ; caption: String` | `Result<Workspace, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L277) |
| `screenshot_data` | `id: String` | `Result<String, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L287) |
| `extract_indicators` | `text: String` | `Result<Vec<analyzers::Indicator>, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L329) |
| `export_report` | `path: String ; format: String ; caseId: Option<String>` | `Result<(), String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L336) |
| `start_local_analysis` | `caseId: String ; path: String ; kind: String` | `Result<Job, String>` | [src-tauri/src/analysis_jobs.rs](../src-tauri/src/analysis_jobs.rs#L370) |
| `get_local_analysis_jobs` | `caseId: Option<String>` | `Result<Vec<Job>, String>` | [src-tauri/src/analysis_jobs.rs](../src-tauri/src/analysis_jobs.rs#L327) |
| `cancel_local_analysis` | `id: String ; caseId: String` | `Result<(), String>` | [src-tauri/src/analysis_jobs.rs](../src-tauri/src/analysis_jobs.rs#L355) |
| `start_report_export` | `caseId: String ; path: String ; format: String` | `Result<Progress, String>` | [src-tauri/src/report_jobs.rs](../src-tauri/src/report_jobs.rs#L215) |
| `get_report_exports` | `无` | `Result<Vec<Progress>, String>` | [src-tauri/src/report_jobs.rs](../src-tauri/src/report_jobs.rs#L205) |
| `cancel_report_export` | `id: String` | `Result<(), String>` | [src-tauri/src/report_jobs.rs](../src-tauri/src/report_jobs.rs#L210) |
| `print_report` | `无` | `Result<(), String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L359) |
| `get_ai_config` | `无` | `Result<ai::AiConfig, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L363) |
| `get_ai_privacy` | `无` | `Result<Settings, String>` | [src-tauri/src/privacy.rs](../src-tauri/src/privacy.rs#L70) |
| `set_ai_privacy` | `settings: Settings` | `Result<Settings, String>` | [src-tauri/src/privacy.rs](../src-tauri/src/privacy.rs#L75) |
| `get_ai_profiles` | `无` | `Result<Vec<ai::AiConfig>, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L367) |
| `get_ai_connection_tests` | `无` | `Result<Vec<ai::ConnectionTest>, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L371) |
| `test_ai_connection` | `revision: String` | `Result<ai::ConnectionTest, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L377) |
| `save_ai_config` | `baseUrl: String ; model: String ; apiKey: String ; removeKey: bool` | `Result<ai::AiConfig, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L384) |
| `preview_ai_material` | `evidenceId: String` | `Result<ai::AiSendPreview, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L399) |
| `review_with_ai` | `evidenceId: String ; material: String ; question: String` | `Result<ai::AiReview, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L406) |
| `analyze_alert_text` | `text: String` | `Result<Evidence, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L417) |
| `followup_review` | `reviewId: String ; question: String` | `Result<ai::Followup, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L430) |
| `save_review_feedback` | `reviewId: String ; disposition: String ; feedback: String ; notes: String ; actor: String` | `Result<Workspace, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L440) |
| `reverse_environment` | `无` | `Result<isolated::Environment, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L454) |
| `build_reverse_environment` | `无` | `Result<isolated::Environment, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L463) |
| `cleanup_reverse_environment` | `无` | `Result<isolated::Environment, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L472) |
| `get_reverse_jobs` | `无` | `Result<Vec<isolated::Job>, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L481) |
| `start_reverse` | `evidenceId: String ; question: String` | `Result<isolated::Job, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L485) |
| `cancel_reverse` | `id: String` | `Result<(), String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L499) |
| `check_docker` | `无` | `Result<sandbox::DockerCheck, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L503) |
| `build_sandbox_runner` | `mirror: String` | `Result<sandbox::DockerCheck, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L510) |
| `cleanup_sandbox_containers` | `无` | `Result<sandbox::DockerCheck, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L520) |
| `get_sandbox_jobs` | `无` | `Result<Vec<sandbox::SandboxJob>, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L529) |
| `run_linux_sample` | `evidenceId: String ; seconds: u64 ; labAck: bool` | `Result<sandbox::SandboxJob, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L533) |
| `get_windows_sandbox_config` | `无` | `Result<windows_sandbox::Config, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L548) |
| `save_windows_sandbox_config` | `endpoint: String ; machine: String ; token: String` | `Result<windows_sandbox::Config, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L554) |
| `check_windows_sandbox` | `无` | `Result<serde_json::Value, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L563) |
| `submit_windows_sample` | `evidenceId: String ; seconds: u64 ; labAck: bool` | `Result<sandbox::SandboxJob, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L568) |
| `refresh_windows_task` | `id: String` | `Result<sandbox::SandboxJob, String>` | [src-tauri/src/main.rs](../src-tauri/src/main.rs#L579) |

## platform_action 操作目录

参数为 `{ action, args }`，args 的字段由各操作校验。返回值按操作不同；未知操作拒绝。完整字段见上表 platform_action 定义；新增操作需同步契约与功能验收。

`agentGenerate`, `agentImport`, `agentRevoke`, `assetBaseline`, `assetCheck`, `assetConfigure`, `assetImport`, `assetSnapshots`, `assetToggle`, `browserEnvironment`, `browserPrepare`, `environment`, `intelAnnotate`, `intelExport`, `intelImport`, `intelImportFile`, `intelOrigins`, `intelSearch`, `monitorAiSave`, `receiverSave`, `receiverStart`, `receiverStop`, `ruleAdd`, `rulePromote`, `ruleToggle`, `sampleAdd`
