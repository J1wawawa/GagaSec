# 嘎嘎安全助手源码迁移

本目录是 J4team 工具仓库中的客户端源码存放位置。当前版本：0.10.1。

已迁移 React/Tauri/Rust/Go Agent/reverse-worker、测试、fixtures、配置、脚本、许可证和全部项目文档。未迁移 `node_modules`、`dist`、`target`、生成的 Tauri schema、编译后的 Agent、运行日志、工作区数据库和凭据。依赖可按 `CONTRIBUTING.md` 与 `docs/INSTALLATION.md` 从锁文件恢复。

文件级 SHA-256 和排除项见 `MIGRATION-MANIFEST-0.10.1.json`；2026-10-31 的 UI/稳定性增量及验证记录见 `docs/AUDIT-UI-STABILITY-2026-10-31.md`。清单已在本轮源码变更后重新计算，仍不包含可重建依赖、编译产物或本地数据。
