# 依赖公告审阅 · 0.7.8

本轮按锁文件和 Agent 实际使用的 Go 模块查询 OSV，另对前端及 reverse-worker 运行 npm audit。只向审计服务发送依赖名称与版本，不读取客户工作区或模型 Key。公告匹配不是可利用性证明，也不等于完成供应链审计。

## 已处理

- **lopdf 0.38.0 → 0.42.0**：PDF 解析的异常深度嵌套可触发栈溢出/进程退出，直接影响客户端报告查询及加水印；属于可达入口。不能用 catch_unwind 作为栈溢出修复。本轮采用上游修复版，加入约 10380 层嵌套合成 PDF 拒绝回归，验证源文件与旧目标保留。
- **zip 2.6.1 → 锁文件 9.1.3**：移除旧版本公告匹配，仅启用 deflate-flate2-zlib-rs，保留 Agent 包与 DOCX 回归；不因升级引入全部压缩格式。上游许可文本随源码和客户端资源保存。

## 最终扫描与剩余匹配

升级前 574 条包/工具链记录、7 个包匹配；升级后 568 条记录、5 个包匹配。前端和 reverse-worker 的 npm audit 均为 0 条，但这不代表所有 Rust/Go 依赖无公告。最终 OSV 结果仍包含：

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

扫描依赖 OSV 当时数据库和工具链版本，后续结果可能变化。原始 JSON、升级前后结果、锁文件指纹与测试证据随本轮验收归档。许可目录只归档相关依赖文本，尚未生成覆盖全部依赖的法律许可清单或独立完整 SBOM。
