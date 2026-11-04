# 依赖公告审阅 · 0.9.0

2026-10-30 本轮真实复扫 568 条去重包/工具链记录，5 个包匹配；前端和 reverse-worker 的 npm audit 均为 0 条。此次修正扫描器遗漏独立 worker 锁文件的问题，同时扫描 `src-tauri/Cargo.lock` 与 `reverse-worker/Cargo.lock`，按包名/版本去重。下述 PDF/ZIP 升级在 0.7.8 完成，仍沿用，不冒充本轮新修复。

本轮按锁文件和 Agent 实际使用的 Go 模块查询 OSV，另对前端及 reverse-worker 运行 npm audit。只向审计服务发送依赖名称与版本，不读取客户工作区或模型 Key。公告匹配不是可利用性证明，也不等于完成供应链审计。

## 本轮依赖变更

静态 worker 新增直接依赖 base64 0.22 和 flate2 1，锁文件锁定具体版本；使用有界读取解压与输出放大比限制。它们已经在宿主机依赖树出现，本轮双锁去重后总数仍为 568，不能由总数未变推断 worker 没有增加依赖。离线 vendor 已重建，Docker 以 locked/offline 构建。第三方依赖源码及其随附许可在 vendor 中，不将依赖扫描视为完整法律许可审计。

## 既有已处理

- **lopdf 0.38.0 → 0.42.0**：PDF 解析的异常深度嵌套可触发栈溢出/进程退出，直接影响客户端报告查询及加水印；属于可达入口。不能用 catch_unwind 作为栈溢出修复。0.7.8 已采用上游修复版，加入约 10380 层嵌套合成 PDF 拒绝回归，本版继续验证源文件与旧目标保留。
- **zip 2.6.1 → 锁文件 9.1.3**：移除旧版本公告匹配，仅启用 deflate-flate2-zlib-rs，保留 Agent 包与 DOCX 回归；不因升级引入全部压缩格式。上游许可文本随源码和客户端资源保存。

## 最终扫描与剩余匹配

本轮最终结果为 568 条去重记录、5 个包匹配。此前 0.7.8 升级前为 574 条/7 个包，只用作历史对比，不是本轮重测的升级前状态。npm 0 条不代表所有 Rust/Go 依赖无公告。当前 OSV 结果仍包含：

| 包 | 公告 | 当前审阅 |
| --- | --- | --- |
| block-buffer 0.10.4 | GHSA-qwgh-2vcv-g2f7 | 经 digest / SHA / HMAC 等使用。公告描述内联游标在回调 panic 后继续复用的 UB；当前锁定源码游标为独立 pos 字段，并未发现应用提供攻击者控制压缩回调或 catch 后复用 hasher 的路径。仍保留数据库匹配，未以此宣称风险消除；需跟随上游完整处理，不能跨不兼容版本硬覆盖整个依赖树。 |
| glib 0.18.5 | GHSA-wrw7-89jp-8q8g / RUSTSEC-2024-0429 | VariantStrIter 的不健全实现；锁文件为 Linux GTK 路径，`cargo tree --target aarch64-apple-darwin -i glib@0.18.5` 无反向树。Mac 交付未链接此路径，Linux GUI 支持前必须升级对应框架链并复验。 |
| fxhash 0.2.1 | RUSTSEC-2025-0057 | 无人维护公告，Tauri 等间接路径；跟踪上游替换。 |
| proc-macro-error 1.0.4 | RUSTSEC-2024-0370 | 无人维护公告，构建宏依赖；不等于已发现远程执行。 |
| ttf-parser 0.25.1 | RUSTSEC-2026-0192 | 无人维护公告，由新 lopdf 依赖；维护风险未消除，不以 PDF 修复版覆盖该事实。 |

没有对全部间接依赖做独立源代码审计，也未复现 block-buffer 在本应用中的可利用链。剩余公告应持续复扫并保留评估，不把本轮写成“安全漏洞清零”。

## 可复现检查

```sh
python3 scripts/audit-dependencies.py /tmp/gaga-dependency-audit
npm audit --json
npm --prefix reverse-worker audit --json
cargo tree --locked --manifest-path src-tauri/Cargo.toml -i block-buffer@0.10.4
cargo tree --locked --manifest-path src-tauri/Cargo.toml --target aarch64-apple-darwin -i glib@0.18.5
```

扫描依赖 OSV 当时数据库和工具链版本，后续结果可能变化。本轮扫描原始 JSON、两份 npm 结果、源码指纹和验收记录随 0.9.0 包归档；并非继承旧版扫描。升级前记录见 0.7.8 交付。许可目录只归档相关依赖文本，尚未生成覆盖全部依赖的法律许可清单或独立完整 SBOM。
