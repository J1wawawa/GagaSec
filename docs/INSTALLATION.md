# 安装与发行 · 0.10.1

当前交付 macOS Apple Silicon（arm64）开发预览版。Mac 和 Windows 共用源码，Windows 安装包、凭据和 CAPE 仍待对应环境验收，不能将 Mac 结果视为 Windows 已通过。

## Mac 安装

1. 校验交付文件 SHA-256，与同版本 SHA256SUMS 对照。
2. 打开 `gaga-0.10.1-arm64.dmg`，将“嘎嘎安全助手.app”拖到 Applications，再从 Applications 打开；不要长期直接运行安装盘中的副本。
3. 进入本机环境检查，按需要配置 Docker、分析镜像或四家官方模型。日志/HTTP 规则、IOC、举证和报告不要求模型 Key。

安装不附带常驻管理员服务，不自动安装 Docker、虚拟机或浏览器扩展。使用系统 WebView，应用本身不捆绑 Chromium。样本分析镜像与运行数据按功能另行准备，不包含在应用体积中。

本版完整应用使用 ad-hoc 签名，**未获得 Developer ID 签名和 Apple 公证**。这不提供发行者身份验证或完整 Gatekeeper 流转体验；不能宣传成已公证的正式发行。正式面向公众的可信安装仍应由 J4team 配置 Developer ID 并完成 Apple 公证，不以关闭系统保护替代。

应用使用 release 优化、符号裁剪及有限归档压缩特性；具体交付字节与 Hash 以同版本验收清单为准。工作区、日志、Docker 镜像和后续材料占用不包含在应用体积内。

0.9.0 静态引擎镜像为 `gaga-analysis:0.9.0`。已有旧版镜像时，进入“样本分析 → 隔离环境”重新构建；旧证据保留原结果，新版分层结构需重新导入生成。安装包不附带该镜像，不会在升级时自动执行样本。

## 升级与数据

关闭旧客户端，保留原工作区与密钥，按数据维护说明备份，再替换 Applications 中的应用。安装包不带测试工作区、模型 Key 或使用者数据；不会因升级自动清空数据库。通用事件备份不含聊天配对/附件密钥和电子水印密钥，不能当成所有数据的完整迁移。

原事件库及证据仍是明文。卸载应用不等于清除工作区；保留、归档和销毁客户资料由使用者显式处理。日志真实路径可在设置查看，保存策略见 [LOGGING.md](LOGGING.md)。

## 从源码构建

平台工具链和检查见 [CONTRIBUTING.md](../CONTRIBUTING.md)。Mac 可运行 `npm run desktop:build:mac`：Tauri release 构建 → 完整 bundle ad-hoc 签名校验 → 临时 staging → 带 Applications 链接的压缩 DMG → 安装盘校验。打包拒绝覆盖已有同名 DMG；不脚本控制 Finder，不请求 Automation 权限。

脚本用于本机可复现预览发行。正式 Developer ID 与公证流水线尚未配置；压缩包、DMG 和解压后的签名分别核对。调试验收标志不在 release 中启用，不应为生产包开放任意工作区注入入口。
