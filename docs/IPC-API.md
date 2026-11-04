# 桌面 IPC 接口契约 · 0.9.0

本程序是个人 PC 桌面终端。下面是随版本交付的 React 界面与 Rust 之间的 Tauri IPC，不是供公网调用的 HTTP API，也不承诺第三方插件的跨版本兼容。完整的 84 个注册命令、参数、返回源码类型及定位见 [自动生成目录](IPC-API.generated.md)。

## 生命周期与调用边界

只有 `main` 窗口可以调用业务 IPC。导航策略只接受打包页面的精确 origin，调试构建另允许固定 Vite 开发地址；CSP 和 Tauri capabilities 另作限制。自定义命令仍需在 Rust 校验路径、输入大小、事件归属和任务授权，不能将前端校验当作安全边界。没有为每条命令实现独立的页面 URL 二次校验。

启动使用 `get_startup_state` 查询真实阶段。数据库就绪前，业务命令返回 `STARTUP-PENDING`；启动状态、关闭启动展示、运行日志和报告任务状态等少量命令可以先调用。数据库损坏不自动创建空库覆盖原件。

界面统一从 `src/bridge.ts` 导入 `invoke`。失败以 Promise rejection 返回字符串，原页面显示具体信息；bridge 记录失败命令名和错误文本，不记录参数或成功结果。错误文本经过常见凭据遮盖，但仍按敏感资料处理。日志自己的读取/写入失败避免递归调用。

```ts
import { invoke } from '../src/bridge';
const evidence = await invoke('analyze_http_pair', {
  request: requestText,
  response: responseText,
});
```

所有调用例子中的文本、路径、ID 均来自使用者明确选择。JSON 参数名为 camelCase；`State`、窗口和 AppHandle 由框架注入。具体序列化字段以 `src/types.ts` 与对应 Rust 的 serde 定义为准；目录中的 Rust 类型不是 JSON Schema。

## 事件与报告

事件材料必须属于对应事件。需要显式事件的命令传 `caseId`，异步任务在启动时捕获事件，不因界面后来切换事件而改归档。`get_workspace` 是当前事件的界面快照，不是跨事件授权能力。

`save_report_draft` 保存自由编排正文和章节引用，版本冲突不能覆盖重试。类型见 `report_draft.rs`。`save_record_entry` 将节点、截图和章节关联在同一事务提交，支持幂等请求；不可将其他事件的节点 ID 混入。

```ts
const task = await invoke<{ id: string }>('start_report_export', {
  caseId,
  path: chosenDocxPath,
  format: 'docx', // 或 html
});
const jobs = await invoke('get_report_exports');
await invoke('cancel_report_export', { id: task.id });
```

返回 task 只表示已接收任务。通过 `report-export-updated` 事件或 `get_report_exports` 查询最终状态：`running` / `cancelling` / `completed` / `cancelled` / `failed`。进度包含任务 ID、事件、格式、阶段、实际校验字节、版本与 error。只有 `completed` 表示写入成功；进入 `committing` 后取消被拒绝，提交前取消保留旧文件。任务列表只在当前进程保存，最终状态另写运行日志。

输出先校验引用原件 SHA-256，再编排正文和图片，写到同目录临时文件后提交；拒绝覆盖内部证据、截图、数据库和已知私有目录。输出失败时查看任务具体错误与日志 contextId，不重复覆盖源材料来“修复”。

## 全局名单与巡检历史

`platform_action` 的 `ruleAdd` 必须显式传入 `scope: 'global'` 或当前事件 ID；前端默认全局，空值拒绝。`rulePromote` 接收 `{ id }`，只将当前事件的指定规则设为全局，保留 ID、依据、有效期和启用状态；其他事件的规则拒绝修改。命中不执行封禁或自动放行，黑白冲突同时保留。

`get_monitor_snapshots_page` 接收 `{ assetId, offset, limit }`，返回 `{ rows, total, offset, limit }`，limit 夹取到 1–100。资产必须属于当前事件，拒绝凭其他事件资产 ID 读取快照。界面每页十份，按需查看一份。快照 `coverageGaps` 是向后兼容的字符串数组，旧记录缺省为空；静态发现跳转线索时持续记录覆盖缺口，即使正文摘要与基线相同，也不能表示最终页面已被检查。`rawHtmlBase64` 仍保存实际收到的字节，不自动执行或跟随脚本。

## 本地文件分析任务

`start_local_analysis` 接收 `{ caseId, path, kind }`，kind为logs/webshell/binary。返回任务表示已接受；后端检查事件，固定事件归属，同时最多一个本地文件任务。界面在文件对话框打开前捕获caseId。

```ts
const task = await invoke('start_local_analysis', { caseId, path: chosenFile, kind: 'logs' });
const jobs = await invoke('get_local_analysis_jobs', { caseId: null }); // 当前工作区各事件最近任务；指定caseId可筛选
await invoke('cancel_local_analysis', { id: task.id, caseId });
```

`local-analysis-progress`推送Job，字段定义见`analysis_jobs.rs`和`src/local-analysis-state.ts`：任务/事件/输入名称、state、phase、revision、时间与耗时、总字节/归档字节、日志计数、最多24项previews、阶段进入记录、evidenceId及error。计数与预览每200ms至多持久化和推送一次，阶段/终态立即保存；初始响应和轮询按revision合并。推送仅属于本机UI，不是网络服务。

终态为completed/cancelled/failed/interrupted；非终态为running/cancelling。只有completed且存在evidenceId才可打开完整结果。committing后拒绝取消；隔离工具取消后需等待容器清理。环境检查在已有命令超时范围内结束，不承诺立即停止。取消/失败不修改原始输入，也不形成完整证据；索引删除失败另记运行日志。

每事件保留最近30项历史，查询最多80项。重启时有已提交证据的恢复completed，其余标记interrupted，不自动重试。普通强杀仍可能留下受限权限的临时归档或工具容器；任务记录不是不可篡改的证据链。

本轮普通AI研判仍用完整响应，Pi辅助逆向仍用独立任务；没有把AI逐字流式输出或持续日志tail作为已实现功能。

## WebShell 分层结果

不新增业务命令。`start_local_analysis` 的 webshell 结果仍从证据读取，`AnalysisReport.webshell` 为可选 `gaga-webshell/1` 结构；旧证据缺少它时保留原结果，界面提示重新导入。需要 `gaga-analysis:0.9.0` 镜像，不回退宿主机解析。后台先核对工具协议、原文件 Hash、层数、深度、父层、来源范围与发现引用，再保存证据。

`layers` 含 `id`、`parentId`、`sourceLayerId`、`operation`、`depth`、`format`、`inputSha256`、`sha256`、`bytes`、`preview`、`truncated`、`sourceStart`、`sourceEnd`、`sourceLine`、`sourceExcerpt`、`findingIds`。`parentId` 是变换输入的派生父层；半开字节区间 `[sourceStart,sourceEnd)` 属于 `sourceLayerId`，不是派生输出的反向映射。例如原文的 `gzinflate(base64_decode('…'))`，压缩变换的父层为 Base64 输出，但表达式仍位于原文 L000。原层摘要针对完整原件，深度分析只覆盖前 1 MiB。

`traces` 是有界词法关系，不是完整污点/可达性证明；`checks` 与 `limits` 区分已检查、部分检查与未检查。派生内容仅保留有界预览和摘要，不提供完整派生文件接口。按层 AI 仍先展示可编辑发送材料；样本内容作为不可信资料，不能成为工具指令。字段与预算详见 [分层设计](WEBSHELL-LAYERS-0.9.0.md) 及共享 `reverse-worker/src/webshell_schema.rs`。

## PDF 与电子水印

`print_report` 仅打开系统打印流程；无法获知使用者是否取消、最终保存路径或打印机结果。PDF 生成目前仍由系统打印“保存为 PDF”完成，没有后台直接 PDF 生成接口。

```ts
const checked = await invoke('inspect_report_watermark', { path: pdfPath });
const stamped = await invoke('stamp_report_pdf', {
  source: pdfPath,
  destination: chosenCopyPath,
  name: customWatermarkName,
});
```

PDF 查询/写入上限 64 MiB，必须能解析到 Catalog 和至少一页；数字签名 PDF 不加标记，避免破坏签名。增量写入仅生成副本，保留原字节前缀。`Inspection` 包含 `present`、`watermark`、`notice`、`verification`、`pdfPages`；页数不代替排版及截图人工检查。仅原工作区密钥能解读自身水印；通用备份不含该密钥。水印不是不可删除标记或第三方数字签名。

## 运行日志

`get_runtime_logs` 不依赖 Store，返回最近 200 条及 `path` / `writeError` / `suppressed` / `maxBytes`。`record_client_error` 接收 `component`、`message`，分别限制长度；绝不主动传入报文、样本或模型材料。`export_runtime_logs` 接收新文件路径，只导出无消息正文的错误索引并拒绝覆盖。完整字段、保存和覆盖范围见 [运行日志](LOGGING.md)。

## 局域网协作

`lan_state` 接收可空 `peerId`、`beforeSeq`，返回启用状态、地址、联系人、附近设备、消息和 notice。在线表示最近认证心跳可达，不表示有人正在看消息。`lan_action` 接收 action 及可选 `peerId` / `text` / `path` / `dataUrl` / `messageId`，仅按操作取对应参数。

`lan_state` 还支持可空 `groupId`，返回群组、群消息和本地通知。`lan_action` 的 `group_create` 只接受已配对成员，`group_text` 通过现有 TLS 单播逐个送达，`notify` 可关联事件和处置动作。群成员变更不会自动发生，通知和群消息不会上传到公共中继。

| action | 主要输入 | 行为 |
| --- | --- | --- |
| start / stop | text 为本机别名 / 无 | 开启或关闭发现与监听；重启默认关闭 |
| invite / pair | 无 / path 为地址、text 为邀请 | 生成一次性短期邀请 / 配对 |
| unpair | peerId | 使旧联系人凭据失效，保留历史 |
| text / file | peerId 与 text / path 或 dataUrl | 发送消息 / 通知附件可领取 |
| receive / decline | messageId | 明确接收或拒绝附件 |
| recover_history | peerId、可选 beforeSeq | 从在线的已配对伙伴按页恢复历史；只追加、按消息 ID 去重，不覆盖本机记录。返回 `recovered`、`received`、`hasMore` 和下一页 `nextBeforeSeq`。 |
| recover_attachment | messageId | 对历史恢复出的 `recovered_metadata` 附件，经过用户确认后从伙伴取回正文并校验 SHA-256；不会自动下载或执行。 |
| retry | messageId | 重试或查询对端持久保存状态 |
| save / image | messageId 与另存 path / messageId | 另存明文副本 / 读取已验证图片 |

文件上限 32 MiB；图片另受 8 MiB、尺寸及 GIF 帧/累计像素限制。附件先校验再保存，不自动执行。历史恢复要求伙伴已配对且在线，单次操作有页数和通信帧上限，界面可用“继续恢复”接着取更早记录；恢复后的附件正文仍需逐条确认。协议使用双向 TLS 和联系人凭据，但不构成公网中继服务；网络隔离或系统权限仍会影响可达性。

## 处置动作、审批与恢复

`get_response_actions`、`create_response_action`、`update_response_action_status`、`record_response_receipt` 和 `save_response_rollback_plan` 维护事件独立的处置对象。状态机拒绝跳步和跨事件证据引用；客户端不会自动执行封禁、删除或恢复命令。报告导出会带上动作状态、责任人、回执、回滚方案和恢复验证。

## 大型列表与 AI 发送预览

`get_timeline_page` 和 `get_evidence_page` 使用有界 `LIMIT/OFFSET` 返回 `rows/total`；`get_monitor_snapshots_page` 对巡检历史采用相同协议。截图元数据和正文分离，前端进入视口后才读取图片。`preview_ai_material` / `log_ai_material` 返回材料来源、脱敏项目、服务、模型、端点主机和输入/输出预算；API Key 永远不在返回值中。

## 模型、采集及维护

模型只允许 DeepSeek / Qwen / GLM / Kimi 官方端点及列出的模型。外发锁、凭据读取前后检查和预算由后端执行；调用方不得直接读取系统 Key。模型调用、Pi 工具结果和 CAPE 样本上传的外发范围见 [隐私说明](../PRIVACY.md)。

Agent、资产、IOC 等通过 `platform_action` 分发，操作名见自动目录，args 字段由 `platform.rs` 与对应模块校验。未知操作拒绝；新增 action 必须补契约、实际归档与错误测试，不能假定任意 `Value` 可以无验证落库。Agent HTTPS 接收是可选本地接收服务，认证格式与加密包流程见 Agent 源码和既有 C4 文档。

0.7.9 的 `agentGenerate` 要求 `{ caseId, input, path }`，caseId 在打开保存窗口之前捕获，path 为 ZIP 文件名。后端确认事件存在及输出路径安全后才访问采集身份，整个任务只用该事件。旧的省略 caseId 的自动化需更新；注册命令名未改变，但 action 的 JSON 契约有此增量。

```ts
await invoke('platform_action', {
  action: 'agentGenerate',
  args: { caseId: capturedCaseId, input: capturedTaskInput, path: chosenZipPath },
});
```

包完整写入临时文件后登记任务，登记失败不替换旧包；最终文件提交失败会删除本次登记，清理失败明确提示停用任务并检查工作区。文件系统和 SQLite 不是一个跨资源事务：强杀或断电落在登记与最终提交之间时，仍可能有未交付任务记录，不能声称任意崩溃下完全原子。

备份、激活工作区和诊断属于显式维护操作。完整备份含客户材料，不能冒充脱敏诊断。`analyze_example`、UI 验收及本地合成入口只允许调试构建的显式临时验收模式，正式工作区拒绝。

## 维护接口文档

修改注册命令后运行 `python3 scripts/generate-api-docs.py`，再运行 `npm run check:api`。CI 检查声明/注册与目录漂移，不验证每一个动态 JSON 形状。更改持久格式需提供旧记录兼容及回归；更改网络协议需单独验收真实连接。

## 官方情报查询（0.10.0）

`get_intel_config` 返回 `{locked,providers:[{id,enabled,hasKey,authorized,revision}]}`，不返回 Key。`save_intel_provider` 参数为 `{id,enabled,authorized,apiKey,removeKey}`；仅支持 threatbook/rdap/abuseipdb/virustotal，固定官方接口，无自定义 URL。`set_intel_lock({locked})` 保存工作区情报外发锁，与 AI 外发锁独立；锁定取消未结束任务，不能撤回已发送数据。

`start_intel_query({query})` 的 query 为 `{caseId,evidenceId:null|id,provider,operation,kind,indicators:string[],currentOnly,fresh,consent}`，每批 1–20 条，全工作区最多 40 条排队/运行。caseId 必须当前事件，evidenceId 必须属于该事件。操作：微步 inbound/outbound/ip_context/domain_context/hash；RDAP registration（域名）；AbuseIPDB reports（IP、30天）；VT hash。拒绝未知组合；不提供提交或样本下载操作。返回创建任务摘要，不包含结果正文；查询在后台继续。

`get_intel_jobs({caseId})` 只返回当前事件最新 200 条摘要，result=null；`get_intel_job({caseId,id})` 单独取得有界结果；`cancel_intel_job({id})` 只在当前事件取消 queued/running。各任务含固定 caseId、sourceEvidenceId、provider、operation、kind、indicator、configRevision、currentOnly、createdAt、state、outcome、message、fetchedAt、sourceUrl、sourceJobId（缓存）、resultSha256、resultEvidenceId。state 与 outcome 分开，completed+pending 不是厂商分析完成。

`archive_intel_result({id})` 校验当前事件和完成结果摘要，返回已有 Evidence；重复调用复用已登记证据。归档对象为 gaga-enrichment/1，保存查询/参数/时间/来源/脱敏结果/限制。SHA-256 为脱敏规范化 JSON，不是 HTTP 原始字节。接口不创建节点，UI 使用现有举证窗口补负责人/截图/章节。后台响应仅能覆盖 queued/running，不能复活取消。重启中断不自动重试。

安全错误采用 TI-* 固定描述，不回显 Key、请求头或指标；后台网络/权限失败写运行日志。事件切换报 TI-CASE，配置损坏/锁定阻止外发；Key 等待超时在网络发送前返回。详见 [功能与限制](THREAT-INTELLIGENCE-0.10.0.md)、[架构](C4-intelligence-0.10.0.md)。
