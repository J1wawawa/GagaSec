# 社区维护与发布流程

2026-10-29。当前是开发预览版：面向防御团队、运行在个人 PC 上的一站式安全终端。使用与分发遵守 [LICENSE.txt](../LICENSE.txt)：源码公开、非商用免费、商用需 J4team 授权。该许可不是 AGPL 或 OSI 开源许可，项目宣传、仓库标签和贡献说明保持一致。

## 从干净源码启动

先安装 Node.js 22.12+、Rust stable、Go 1.27.3+ 及 Tauri 平台依赖。Windows 还需要 C++ 工具链、SDK、WebView2、CMake 和 NASM。然后：

```sh
npm ci
npm run desktop
```

开发启动与打包都会先生成 Go Agent 模板。没有 Docker 或模型 Key 也可以先做 HTTP、日志、IOC 和报告；只有样本静态工具需要 Docker 镜像。不要把前端浏览器预览当作完整客户端。使用步骤见 [QUICKSTART.md](QUICKSTART.md)，联网说明见 [PRIVACY.md](../PRIVACY.md)。

## 发布前的可重复检查

```sh
npm run check:source
npm run test:source-check
npm run check:security
npm run format:check
npm run test:ui-state
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path src-tauri/Cargo.toml
npm audit --audit-level=high
npm --prefix reverse-worker audit --audit-level=high
```

Go、隔离工具和原生验收见 [CONTRIBUTING.md](../CONTRIBUTING.md)。当前 CI 配置运行源码检查和对应测试，远端 CI 是否成功必须看真实记录；配置文件本身不是执行证明。正式仓库需保护发布分支、启用私密漏洞报告并公布实际维护与商用授权联系渠道，当前文档不虚构联系地址。

## 源码检查的范围

scripts/check-source.mjs 在 Git 仓库根目录检查 tracked 文件，即使文件被 .gitignore 忽略但意外 force-add 也会检查；源码目录/ZIP 解压环境没有 Git 时扫描源码，排除依赖、构建缓存与生成模板。它检查常见模型 Key 格式、PEM 私钥、本地环境配置、工作区数据库内容/文件名、任务配置和超大源码文件，失败只输出相对文件名与原因，不输出匹配内容，不读取系统凭据。

唯一允许的私钥是 fixtures/agent-interop/test-only-private.pem 的固定公开测试向量，必须匹配审阅过的 SHA-256，不能用同名文件替换成其他私钥来绕过。生产身份从不使用该固定测试向量。变更向量时需要单独审阅并更新允许摘要。

该检查不是完整秘密检测或压缩包 DLP，不解压依赖归档，不识别全部厂商凭据。维护者仍需审阅新增二进制、归档、截图、案例和数据文件。不要把可运行的恶意样本作为演示附件，也不要上传客户材料和真实任务 ZIP。

## 交付证据

每个版本同时提供源码、能力/未测范围、测试记录和 SHA256SUMS；macOS 开发包在完整打包后 ad-hoc 签名并解压校验，仍不是 Apple 公证。Windows 实机、CAPE、模型官方接口和目标内核按真实状态列出，不能以交叉构建、固定响应或 mock 替代。

当前只有 Mac 验收环境，本阶段先交付 macOS 开发预览版；Windows / CAPE 的环境缺失不阻塞本地核心流程，但发布材料必须继续注明未验收。正式跨平台发布需另补对应实机证据。

可对外演示的材料应来自合成案例，明确标注。诊断白名单只用于支持；完整备份含明文材料。不要发布“零 Bug”“全场景准确率”或未验证客户/投资数据。

## 接下来适合社区共建的功能

0.7.3 已加入报告导出的原件校验进度与取消。按实际需求继续推进：工作台证据列表分页、备份与日志导入的进度和取消、离线规则包版本/来源管理、逐项预览的分享包。事件管理已有 50 条分页，工作台聚合仍需优化。分享包的匿名化必须能人工审阅，不能承诺一键完全脱敏。多用户协作、任意插件、自动处置和在线情报涉及新的权限/数据边界，应在独立设计与验收后再开放。
