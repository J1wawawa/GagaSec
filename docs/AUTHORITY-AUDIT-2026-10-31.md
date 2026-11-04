# 权威要求对照与下一轮优化

日期：2026-10-31。本文把公开规范中的可核对要求映射到嘎嘎安全助手当前源码，不把规范阅读、接口回环或合成案例写成生产能力验收。

## 研究结论

| 来源 | 对产品的关键要求 | 当前实现 | 需要继续补齐 |
| --- | --- | --- | --- |
| [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | 事件响应要与风险管理结合，持续记录检测、分析、响应和恢复决定 | 事件、节点、报告章节、负责人、状态、时间和证据已分开保存 | 增加通用处置动作/审批/执行/回执/回滚对象，避免“建议”被误读为“已生效” |
| [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final) | 取证过程要保留来源、采集方式、完整性和分析记录，报告可复核 | 原件 SHA-256、来源定位、派生分析、截图和导出校验已存在 | 增加采集器版本、时区/时钟偏移、权限结果、缺失项和保留/销毁策略的统一字段 |
| [CISA 事件响应与漏洞响应 Playbooks](https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks) | 识别、协调、遏制/修复、恢复并追踪缓解结果 | 本地调查、报告和监控流程已覆盖部分环节 | 将处置回执和恢复验证作为事件节点的一等对象，并在报告中强制显示失败/未完成 |
| [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/) | 防提示注入、敏感信息泄露、不当输出处理、过度代理、无界消耗和错误结论 | AI system prompt 明确证据是不可信数据；请求锁、材料上限、响应上限、结构化引用和人工复核已实现 | 增加“模型输出不得直接执行”的统一策略字段；让每次外发显示脱敏摘要、目标服务、预算和人工采纳记录 |
| [Tauri Security](https://v2.tauri.app/security/) | 使用 CSP、最小权限、能力范围和导航边界 | CSP、窗口能力、外部导航阻断和 Rust 参数校验已有测试 | 将这些约束纳入发布前自动门禁；本轮新增 `check:security` |
| [Sigma Rule Basics](https://sigmahq.io/docs/basics/rules.html) | 规则应有标题、ID、状态、作者、日期、引用、误报、级别等可追踪元数据 | 当前解析结果能保留规则命中和限制 | 离线规则包导入需增加版本、作者、许可、误报说明、测试样例和回滚指针 |
| [SLSA v1.0](https://slsa.dev/spec/v1.0/levels) | 发布产物应能追溯构建来源并验证构建过程 | 源码哈希、锁文件和本地构建命令已有；CI 权限已限制为只读 | 正式仓库配置固定 Action 提交、构建摘要/签名和可验证 provenance；当前 macOS 包仍 ad-hoc、未公证 |
| [Velociraptor Offline Collections](https://docs.velociraptor.app/docs/deployment/offline_collections/building/) | 离线采集需要明确采集器、目标、版本、范围和回包结果 | Agent 任务有绑定凭据、目标、有效期、摘要和加密回包 | 在客户端展示逐项成功/缺失/失败和权限结果，避免固定清单被误解为完整取证 |

## 本轮已落地

新增 `npm run check:security`，无网络、无凭据读取、无客户端启动，检查以下发布边界：

- CSP 不允许通配脚本/连接源，禁用对象和 frame，开发地址只能是本机回环。
- Tauri capability 绑定主窗口，拒绝 shell/http/宽泛文件权限；Cargo 不得悄悄引入未经审阅的 shell/http 插件。
- CI 保持 `contents: read`，必须执行前端和 reverse-worker 依赖审计。
- AI 目录只能有四个 HTTPS 官方服务，且每个服务有模型清单。

CI 同时补上 reverse-worker Clippy、两个 npm audit；这些检查只说明依赖和源码门禁执行，不代表 OSV 公告、容器基础镜像或签名发行链已经清零。

## 下一轮优先级

1. **证据与处置模型**：增加 `action / approval / execution / receipt / rollback / verification` 记录，所有报告阶段显示负责人、开始/结束时间、状态、证据和失败原因。
2. **采集可复核性**：统一记录 Agent/工具版本、目标主机声明、权限、时区、时钟偏移、成功/缺失/失败、输出摘要和保留期限。
3. **AI 外发可见性**：发送前展示本次材料范围、脱敏结果、服务和模型、预算与联网状态；输出始终是待复核建议，禁止转成自动封禁或自动执行。
4. **大数据体验**：对证据、节点、巡检快照和报告截图使用后端分页/虚拟列表；当前前端大模块和聚合数组仍可能在极大事件上造成主线程压力。
5. **发行可信度**：启用 GitHub 私密漏洞入口、固定 Action SHA、SBOM、构建 provenance、Developer ID/公证和可验证更新后，再评估稳定版标签。

## 不能由本轮研究推出的结论

权威文档不能证明复杂 WebShell/木马的检测率，也不能替代 Windows/CAPE、双物理设备 P2P、真实目标主机 eBPF、四家官方模型账号或专用 VM 的实机验收。普通 Docker 仍共享内核；原始数据库和证据仍是本机明文；PDF 主要依赖系统打印。

