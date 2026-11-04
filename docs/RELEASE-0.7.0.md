# 0.7.0 发布与验收

面向防御团队、运行在个人 PC 上的一站式安全终端。发布形态为开发预览版；源码公开、非商用免费、商用需 J4team 授权，不使用 AGPL / OSI 标识。

## 可复现检查

```sh
npm ci
npm run format:check
npm run test:ui-state
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path src-tauri/Cargo.toml
npm run desktop:build:mac-dev
# 构建后的 debug 可执行文件：
gaga-security-assistant --evaluate-rules /tmp/new-gaga-evaluation
```

固定评测含 10 个公开合成 HTTP 案例，检查预期/禁止线索、原文举证、缺失响应与畸形输入拒绝。它不是 AI 准确率、真实攻击检出率或复杂木马能力评测。AI 评测继续使用独立官方案例脚本，保留模型版本、材料、引用、耗时和实际调用记录；未配置的服务不标为通过。

## 发布条件与环境

macOS 使用实际 WebView 检查主流程、主题、小窗口、截图、报告、备份恢复和重启；校验 SQLite、导出 DOCX XML/图片关系与原始 SHA。Docker 检查真实 Worker/Pi 工具协议、取消与清理；模型合成响应不能替代官方请求。采集端需要跨客户端、篡改、重放及撤销拒绝回归。在线回传必须跑实际固定证书 TLS 连接。

当前仅交付 macOS arm64 ad-hoc 开发包，未 Apple 公证。Windows 客户端/Agent 与真实 CAPE 虚拟机需要对应环境验收；CI 文件存在不表示远端已运行。AWS-LC 的 Windows 构建需要 CMake / NASM，CI 已配置 NASM。eBPF 的一次性 Linux 回环实测不能代替客户宿主机全流量验证。

发布源码前检查不含真实 Key、任务凭据、客户材料和工作区数据库。fixtures/agent-interop/test-only-private.pem 是明确公开的固定测试私钥，生产身份从不使用它。客户端包保留密码学组件许可；维护者应在仓库启用私密漏洞报告，完善实际安全联系方式，并安排首次用户试用录屏。

## 本机结果

实际结果见 [ACCEPTANCE-0.7.0.md](ACCEPTANCE-0.7.0.md)。本轮实际验证 DeepSeek 研判/追问及 Pi 工具闭环、四个完整合成案例的五步报告、固定证书 HTTPS 回传、十资产两轮巡检、128 MiB / 1 GiB 实体日志、Agent 采集回收及隔离 Linux eBPF 回环。附带验证 JSON 和可编辑的合成案例报告，不附带客户工作区或系统凭据。

## 需要继续的外部验收

Qwen/GLM/Kimi 的账号和 Key、Windows GUI/CAPE VM、实际目标主机内核、多事件长期容量、系统打印交互、外部首次用户观察。没有将缺少这些条件的项目记为通过；验证结果与原始日志随交付提供。
