# 页面巡检、模块切换与报告复核

2026-10-31，0.10.1 源码工作区。此次审计实际发现了问题，不能沿用上一轮“两个开关同时开 / 同时关通过”就推断任意组合都正确。

## 已修复

| 问题                                            | 影响与修正                                                                                                                                                         | 回归入口                                                  |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- |
| Playwright 路由没有拦到 Chromium 后续 HTTP 跳转 | 原先关闭跟随仍访问了 302 目标，也可能绕过跨主机检查。改为每次只抓一跳，顶层 Location 经验证后显式导航，子资源同样逐跳检查，不将未经校验的 Location 交给 Chromium。 | `tests/browser-capture.mjs`，检查服务器真实收到的请求     |
| 浏览器内部错误页可能被当成页面截图              | 中止导航后可能出现 `chrome-error://chromewebdata/`。只允许已加载的 HTTP/HTTPS 页面作为截图；关闭 JS 跳转时返回无内容导航，保留入口文档。                           | 302 禁止跟随、JS 禁止跳转、断开连接三个实际 Chromium 场景 |
| 镜像标签不变时会复用旧脚本                      | 源码文件及长度共同计算 SHA-256，后端核对兼容标签，旧镜像提示重新准备；启动继续使用不可变镜像 ID。                                                                  | Rust 镜像兼容测试和原生环境检查                           |
| 立即巡检后清空可见历史                          | 新结果完成后重新读取后端分页，保留历史选项和真实总数；仅历史读取失败时保留新结果并提示。                                                                           | 原生巡检连续 4 次，检查每次可见下拉项数量                 |
| 同一组件跨模块切换沿用旧列表                    | 页面与事件改变时立即刷新；清空旧事件表单，阻止先前页面或事件的异步返回覆盖当前数据。                                                                               | 原生功能验收中黑白名单 → 资产切换                         |
| 专用分析标签切换时短暂收到其他种类的证据        | React effect 复位标签之前，日志组件可能对容器证据发起查询，留下“请选择日志证据”错误。渲染时先核对证据类型，再挂载对应分析组件。                                    | 原生功能验收增加运行日志检查，拒绝隐藏的 CLIENT_ERROR     |

IPv6 字面量在解析前去除 URL 的方括号，避免误交给 DNS；IPv6 回环跳转也加入真实浏览器阻断检查。40 秒浏览器总时限返回结构化超时信息，后端仍按确切随机容器名清理，不执行全局 prune。

## 验证方式

全部原生验收写入独立临时 SQLite，未向使用者事件加入验收材料，未读取模型 Key、未调用云模型、未执行恶意样本。HTTP、日志、配置分析通过实际客户端接口；WebShell / PE 使用无害材料进行禁网静态分析。

```sh
npm run build
npm run test:ui-state
npm run format:check
npm run check:api
npm run check:security
npm run check:source
npm run test:source-check
cargo test --locked --manifest-path src-tauri/Cargo.toml
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
npm run build:monitor-browser
npm run test:browser-capture -- /absolute/browser-results.json
node tests/native-comfort.mjs /absolute/debug/binary /absolute/public-screenshot.png
node tests/native-report-structure.mjs /absolute/debug/binary /absolute/report-output
node tests/native-monitor.mjs /absolute/debug/binary /absolute/monitor-output
```

`build:monitor-browser` 自动写入源码兼容标签；可通过 `-- --mirror aliyun` 选择镜像源。此次本机升级复用已安装 Chromium 的既有本地镜像层、替换同一份源码并写入新摘要；完整联网安装步骤没有重新通过验收，受镜像源和 Docker 网络影响。清洁安装由原构建脚本提供。

GitHub Actions 新增独立 `page-capture` 作业，构建真实浏览器镜像并运行七种网络场景；这是已配置的防回归门槛，本轮未远程执行 GitHub Actions。

## 实际结果

- [Mac 原生主要功能](verification/followup-audit-2026-10-31/native-comfort.json)：148 项通过，60 组窗口/主题布局检查、20 张原生截图。实际走通 HTTP 请求/响应、日志、容器配置、WebShell 与 PE 静态分析、全局名单、资产监控及含图报告导出。额外检查运行日志，没有模块切换造成的 CLIENT_ERROR。
- [报告专项](verification/followup-audit-2026-10-31/report-structure.json)：首次 32 项、重启 5 项、文件检查 11 项通过。包含独占编辑区、章节目录焦点、多阶段/子事件、负责人、节点复用、电子水印与实际 HTML/DOCX 图片；检查 ZIP/XML、SQLite 完整性与外键。
- [巡检专项](verification/followup-audit-2026-10-31/monitor-summary.json)：首次 21 项、重启 2 项、文件检查 3 项通过。四种开关组合、截图失败留证、持续增长的历史下拉、真实 PNG、DOM/Hash、自动节点、重启和含图导出。
- [真实 Chromium 网络场景](verification/followup-audit-2026-10-31/browser-network.json)：7 项通过，核对服务器实际收到的请求，覆盖 HTTP/JS 跳转、关闭跟随、IPv4/IPv6 私网跳转、断开连接及跳转循环。
- 修复后再次通过同一容器入口访问百度公开主页，取得“百度一下，你就知道”，最终地址 `https://www.baidu.com/`、无导航错误、101,219 字节 PNG。[原始元数据](verification/followup-audit-2026-10-31/baidu-browser.json)与[截图](verification/followup-audit-2026-10-31/baidu-browser.png)。此项是公开网站浏览器验证；客户端完整链路仍使用可重复的本地页面。
- Rust：170 通过、0 失败、4 显式忽略；25 项前端状态断言，Clippy、生产构建、格式、接口文档、源码卫生及安全配置检查通过。客户端、逆向 Worker、截图 Worker 的 npm audit 本次均返回 0 项已知漏洞。

[检查汇总](verification/followup-audit-2026-10-31/checks.json)。本轮没有把早期失败当成通过：旧原生检查曾暴露资产列表不刷新，修正后完整重新运行，以上只引用最终通过记录。

## 边界

本轮是 Mac 本机验证。Windows 桌面、Windows/CAPE 动态分析、四家官方模型的真实 Key 调用和操作系统打印对话框没有新增实测。自动截图仅记录无登录态的 1440×900 视口，HTTP 原文和浏览器是两次独立请求。公网到私网跳转受限，但 DNS 重绑定和浏览器漏洞仍需专用网络/虚拟机作为进一步边界；不能宣称浏览器容器绝对安全。

无法以一次审计保证永无缺陷。此次把已经复现的问题固化为真实网络、原生界面及文件检查，并在自动检查中持续复验。完整材料随本轮验收结果保存。
