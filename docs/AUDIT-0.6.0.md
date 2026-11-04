# 嘎嘎安全助手 0.6.0 深度审计与修复记录

J4team · 2026-10-27 · macOS arm64 开发预览版

审计结论：当前应用采用 React + Tauri / Rust + 本地 SQLite，已具备实际证据归档、规则分析、AI 协议、Agent 加密回收、事件和报告链路。本次发现并修复了多项会造成错误时间认知、跨事件展示、规则漏匹配和举证不一致的问题，同时补齐事件管理、截图粘贴及日志索引。它仍是开发预览版；本报告不宣称不存在其他缺陷，也不将协议测试代替 Windows / eBPF 实机验收。

本次审查读取主命令入口、所有 Rust 业务模块、React 主要页面、Go Agent、建表语句、CSP / capability、打包与测试入口。使用源码检查、Rust 回归、真实 Tauri WebView 操作、localhost 协议服务、OS 钥匙串隔离凭据、实际 Docker / Agent 和实体大日志进行验证。原有测试材料和 0.5.0 交付物保留。

## 1. 已修复的缺陷及补齐能力

以下严重性按本地单用户调查工具的证据正确性、资料归属及可用性评估，不是互联网服务 CVSS，也不代表已存在多租户越权。

| ID / 类型 | 触发与影响 | 修复 | 主要证据与位置 |
| --- | --- | --- | --- |
| A01 · 高 · 时间线覆盖 | 重复日志超过每规则 100 项时，抽样 findings 无法承担完整命中行时间线；关键后续行为可能不可定位 | 独立按事件的 SQLite 日志索引，保存每个规则命中行，100 条 keyset 分页、IP / 类型筛选、按确定时间排序 | `logbook.rs::index/query`；1,205 条命中仍有全部索引，第 2 页从第 101 行开始；真实 1 GiB 索引另验收 |
| A02 · 高 · 时间准确性 | 从发现记录节点时默认使用录入时刻，可能把原文 10:33 登录写成 17:03 发生；无年份 syslog 也不能直接猜时间 | 明确 raw_time / normalized at / time_basis；正式日志节点使用原文时间，未知则阻止自动入正式时间线；参考年份 / 偏移可补充重建 | `logbook.rs::normalize/record_log_event`，`main.tsx::draftNode`；跨文件排序、未知时间、原生 source-time 检查 |
| A03 · 高 · 检测结论 | inspect 字段缺失或只检查少量配置，却容易被解释成“未发现入侵” | 13 类检查分为 risk / clear / unknown / not_covered；列出来源 JSON 路径和原因，另列 5 类未覆盖领域 | `coverage.rs`；只含 Privileged 的对象结果为 1 风险、12 未知、5 未覆盖 |
| A04 · 中 · 输入鲁棒性 | CapAdd / SecurityOpt 含非字符串、Mounts 缺 Source 时可被误算 clear；CAP_SYS_ADMIN 前缀可能漏判 | 错误类型保留未知；已知危险项仍报风险；识别 CAP_ 前缀和 /proc、/sys 子路径 | `coverage.rs::array_risk`，`audit_tests.rs::malformed_inspect_fields_never_establish_clear_and_cap_prefix_is_recognized` |
| A05 · 中 · 事件隔离 | malware_cases 原查询缺 case_id 条件，A 案例笔记会显示在 B | 查询明确限定当前事件；名单展示与实际匹配都按全局 + 目标事件读取 | `intelligence.rs::sample_cases/rules`，`platform.rs::platform_state`；Rust 与原生 A/B 切换检查 |
| A06 · 中 · 截图隔离 | screenshot_data 原来只凭截图 ID 读取文件，不校验所属节点事件 | 查询 join nodes.case_id；跨事件读取 / 附图后端拒绝；切换事件清除旧选中和弹窗 | `store.rs::screenshot_data/add_screenshot`，`main.tsx`；原生跨事件读图、粘贴、日志查询拒绝 |
| A07 · 高 · 举证完整性 | 归档截图被替换后，读取 / 导出仍可能携带旧 SHA-256，图与摘要不一致 | 共享有界图像读取，重新核对大小和 SHA-256；失配拒绝显示 / DOCX / HTML 导出；图片仍有解码尺寸 / 内存限制 | `store.rs::verified_image_bytes`，`report.rs::screenshot_bytes`；篡改后读图及两类导出均拒绝 |
| A08 · 高 · 凭据可用性 | 采集私钥的 Keychain account 绑定目录 Hash，移动工作区后可能不能解密历史包 | 持久 workspace UUID 命名空间；旧路径凭据成功读取后迁移；错误时不覆盖旧钥匙 | `collector.rs::secret_account/secret_read`；实际隔离 OS 钥匙串迁移与目录移动后公钥一致 |
| A09 · 高 · 名单漏匹配 | 匹配函数共用了最近 1,000 条展示查询；添加新规则后，旧 deny 规则可能失效 | SQL 先限定 global / 目标事件，匹配不按展示条数截断 | `intelligence.rs::rules/matches`；插入 1,005 条较新规则后，旧 deny 仍命中 |
| A10 · 高 · 分析过程真实性 | AI 阶段曾写“已核对 SHA-256”，实际只验证证据归属，没有重读归档 | AI 发送前在 blocking pool 重算实际文件大小 / Hash；失败不发送模型请求，阶段落为 failed / skipped | `ai.rs::review_record`，`logbook.rs::verify_archive_at`；篡改输入在模型请求前被拒绝、无成功 AI 记录 |
| A11 · 中 · 性能 | 同步 workspace 查询和全工作区 AI 材料读取扩大主线程等待及反序列化成本 | get_workspace 使用 spawn_blocking；AI 材料直接读取当前证据；GiB 扫描不持主库 Mutex，索引单独事务 | `main.rs::get_workspace`，`ai.rs::material`，`logbook.rs`；构建、真实大日志与原生交互回归 |
| A12 · 中 · 异步界面 | 快速筛选 / 事件切换时旧请求返回可能覆盖新列表，旧事件弹窗仍可能保留 | 列表和日志请求增加 epoch；切换事件清除相关草稿，日志时间参数从索引元数据恢复 | `Cases.tsx`，`Investigation.tsx`，`main.tsx`；源码检查、原生事件切换与布局回归 |
| A13 · 能力缺口 · 截图粘贴 | 只有“预留截图”与选文件，无法完成用户要求的直接复制举证 | 节点新增粘贴入口；自动聚焦目标，处理 DOM ClipboardEvent，预览、必填图注、本地 Hash 归档与报告嵌图 | `main.rs::paste_screenshot`，`main.tsx`；实际 WebView 派发含 PNG 的 paste 事件、图注输入焦点与导出检查 |
| A14 · 中 · 工作区并发 | 两个客户端共用同一库，初始化会重置监控运行状态，后台调度器可互相干扰 | Store 持有工作区文件独占锁；第二次打开明确失败，关闭后可正常重开 | `store.rs::open`；两个 Store 打开同路径与释放后重开测试 |
| A15 · 中 · 桌面可用性 | 外层没有溢出仍不代表可用；重复标题 / 指标把日志事件列表挤出可视区 | 保留 4 个关键日志指标、完整指标移至文件信息；时间线和原文分区滚动、紧凑工具区；最小窗口保证分页和事件区可见 | `src/style.css`、`main.tsx`；实际数据浏览器预览，1320×860 / 1100×760 / 960×660，浅深色验证可视区域 |

同时修复 JSON 行前置空白的解析入口；为时间线游标增加类型 / 长度边界；旧容器覆盖刷新和日志重建前校验原归档。没有直接重写用户已保存的历史节点发生时间。

A12 的异步竞态防护主要依据代码检查与请求代次机制；未构造每一种乱序返回组合。原生剪贴板验收通过的是 WebView 的真实 DOM paste 事件和后端归档链；没有自动操纵用户的系统剪贴板或截取原生系统画面。

## 2. 验证结果与复现入口

验收 JSON 与本次源代码一同交付，完整结果见 `gaga-verification-0.6.0.json`。大日志为实际生成且完整落盘的合成日志；PHP 特征在不会执行的注释中，无害脚本仅在专用测试容器运行。

- Rust：57 项通过，0 失败。覆盖 HTTP 解码 / 越界、归档、DOCX、数据隔离、AI 协议与阶段、预算、名单、Go/Rust 加密互操作、沙箱约束，以及本次新增审计用例。
- 原生桌面：92 项流程检查 + 11 项传输 / 持久化检查通过，localhost 实际收到 3 次预期请求；没有调用外部模型。新增检查包括来源时间、剪贴板 PNG、必填图注、事件 A/B、隔离凭据迁移 / 移动。
- Go Agent：`go test ./...`、`go vet ./...` 通过；这不包含真实内核 eBPF 挂载。
- 浏览器布局：60 组平台页布局 + 44 项平台 / 设置检查；29 项实际仪表盘检查；新增 55 项实际调查数据布局检查，包含事件列表、容器四态、日志 / 举证分栏和最小窗口分页可视性。浏览器预览不作为原生后端验收。
- 实际 Docker / Agent：只读采集、密文回收、原客户端解密、不同私钥拒绝、篡改 / 重放拒绝、临时容器清理；固定无害动态诊断记录 execve、文件写入与 connect 尝试。
- 大日志初次复测：134,402,827 字节 / 499,714 行约 8.5 秒；1,074,288,981 字节 / 4,648,965 行约 43.9 秒。包含复制、Hash、扫描与新时间索引，是本机未优化 debug 测量，不能当作其他机器的性能承诺。最终复测原始耗时以验收 JSON 为准。
- TypeScript / Vite、Tauri app 打包、Prettier、rustfmt 通过。npm 生产依赖审计返回 0 条已知漏洞，不涵盖 Rust / Go 或未来漏洞。

复现命令（源码根目录）：

```sh
npm ci
npm run build:agents
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
npm run format:check
cargo fmt --check --manifest-path src-tauri/Cargo.toml
cd agent
go test ./...
go vet ./...
```

原生开发验收：

```sh
npm run tauri -- build --debug --bundles app
node tests/native-platform.mjs /absolute/path/to/debug-executable
node tests/field-exercise.mjs /absolute/path/to/debug-executable /absolute/new-test-directory
node tests/native-field-ui.mjs /absolute/path/to/debug-executable /absolute/completed-field-workspace
```

`field-exercise.mjs` 需要脚本指定的已有本地测试镜像和 observer；生成实体大日志需要磁盘空间。测试固定服务、Key 和测试私钥仅用于隔离验收，不用于客户环境。

Clippy 未完成：本机 toolchain 未安装组件，尝试下载时 static.rust-lang.org 连接超时并回滚。本报告没有将 Clippy 标为通过。Rust / Go 全量漏洞数据库扫描和第三方渗透测试也不在已完成验收内。

## 3. 仍存在的架构限制与优先级

| 优先级 | 当前限制 | 影响及下一步 |
| --- | --- | --- |
| 高 | 证据库、Prompt、解密快照明文；无完整证据签名链和认证身份 | 本机文件 / 数据库同时可写时 Hash 不能证明不可篡改；需设计加密、签名、审计、角色和密钥灾备 |
| 高 | 无统一版本化 schema migration、整库备份 / 恢复与归档校验入口 | 多次迭代仍依赖建表兼容；升级、回滚、保留期和删除需要专项实现与恢复测试 |
| 高 | Windows 原生客户端 / Credential Manager、真实 CAPE VM、真实 eBPF 挂载未验收 | 共用源码、交叉编译及 localhost 协议不等于实机完成；需分别建立环境矩阵 |
| 高 | 容器、WebShell、日志规则是有限检测集合 | 未命中、未知、未覆盖不能解释为无入侵；复杂混淆、文件落地、进程 / 账号 / 多主机链路仍需证据补充 |
| 中 | 时间线覆盖规则命中行，AI 材料为每文件有界代表样本 | 不能承诺还原所有真实攻击阶段；跨年 / 时钟漂移、NAT、不同目标主机的关联仍需人工核验 |
| 中 | `workspace()` 仍加载当前事件全部报告 JSON 与节点 | 大量大报告 / 长期监控可能逐渐变慢；下一阶段应拆 summary / detail、查询分页和列表虚拟化 |
| 中 | 日志索引 / 主库 / 文件不是统一事务，无统一垃圾回收和可恢复取消 | 崩溃可留下孤立派生记录；当前读取 join 隐藏无主索引，需完善恢复 / 配额 / 取消与清理 |
| 中 | 调度和接收仅在客户端运行时在线；名单较多时匹配仍需优化 | 未来使用持久服务 / 独立 Agent 心跳、规则缓存与索引；任务有效不表示主机在线 |
| 中 | 静态页面监控限量抓取 HTML / JS，不运行完整浏览器 | 动态注入、登录后内容、深层路由、响应选择性劫持可能漏检；需独立浏览器采集适配 |
| 中 | Docker 共享内核、strace 受反调试及日志截断影响 | 不能提供恶意程序隔离或完整行为保证；专用可丢弃 VM 与外部沙箱仍必要 |
| 中 | 微步 / WHOIS / RDAP、RAG、反编译、漏洞库、后台 PDF 尚未实现 | UI 和文档须保持未接入状态；不展示伪造调用链、耗时或推理完成结果 |
| 中 | macOS 开发包未签名 / 公证；依赖供应链扫描未全覆盖 | 发布前补 Developer ID / 公证、Windows 签名、依赖漏洞源与升级政策 |

工作区独占锁针对当前版本的本地 Store。旧版客户端尚不遵守新锁，不能在同一工作区混开新旧版本。旧目录绑定凭据应先在原路径迁移后再移动；复制数据库到另一台机器不会自动携带系统私钥。界面中的“结束事件”是可继续复核的业务状态，不是只读封存。

## 4. 架构交付

`C4-architecture-0.6.0.md` 提供实际 C4 Level 1–4、事件隔离矩阵、存储一致性、日志 / AI / Agent 动态视图与架构决策。它明确区分本机逻辑组件、独立 Go Agent、外部模型 / Docker / CAPE 以及尚未实现的能力。
