# 参与开发

功能、规则、案例文章和报告模板均可参与。社区分类、处理流程与投稿格式见 [社区共建](docs/community/README.md)；线上入口由维护者确认后公布。

嘎嘎安全助手 / J4team。使用与分发遵循 LICENSE.txt：个人及非商用免费，商用需单独授权；本项目不是 AGPL 或 OSI 开源许可。提交前请阅读 [当前 C4](docs/C4-architecture-0.9.0.md) 与 [IPC 契约](docs/IPC-API.md)，明确真实执行范围。

## 本地构建

Node.js 22.12+、Rust stable（含 rustfmt / clippy）、Go 1.27.3+，以及 Tauri 2 平台依赖。Windows 需要 C++ Build Tools / SDK / WebView2，AWS-LC 还需要 CMake / NASM；macOS 需要 Command Line Tools。当前附带的是 macOS arm64 开发构建，不代表 Windows 已实机验收。

```sh
npm ci
npm run desktop
```

Tauri 的构建钩子会构建目标端 Agent 与前端。单独运行前端只是 UI 预览，不能替代 IPC、凭据、文件和 Docker 的原生测试。Mac release 优化预览包运行 `npm run desktop:build:mac`，生成完整 ad-hoc 签名应用与 DMG；正式发行签名及公证另行配置，见 [安装说明](docs/INSTALLATION.md)。

## 检查

```sh
npm run build
npm run check:source
npm run test:source-check
npm run check:security
npm run check:api
npm run format:check
npm run test:ui-state
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo fmt --manifest-path reverse-worker/Cargo.toml -- --check
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path src-tauri/Cargo.toml
cd agent
go vet ./...
go test -race ./...
```

涉及样本解析、工具参数、协议或 Pi 时，还必须用真实容器验证。单元测试为了速度会直接调用共享静态解析器；发布程序只编译容器入口，二者的执行边界不同。

```sh
docker build --pull=false -t gaga-analysis:0.7.0 reverse-worker
python3 scripts/test-isolated.py /tmp/gaga-isolated-checks
```

该脚本只使用合成 PHP / ELF 与合成模型 SSE，不需要真实 API Key，不执行恶意样本。默认产物目录必须是专用测试目录。原生 WebView 脚本在 src-tauri/tests/，仅调试模式可启用，不能据此宣称真实模型或 Windows VM 已通过。

## 公告和采集流程复现

依赖公告扫描使用 Python 3.11+ 与网络；仅提交锁定包名称和版本给 OSV，不读取客户材料或系统凭据。数据库匹配需结合调用点与目标平台审阅，不能将有剩余公告的结果称为“全部清零”。

```sh
python3 scripts/audit-dependencies.py /tmp/gaga-dependency-audit
npm audit
npm --prefix reverse-worker audit
```

Docker 采集实测使用仓库自有的固定无害镜像：

```sh
docker build --pull=false -f tests/field-fixture.Dockerfile -t gaga-field-fixture:0.7.0 .
node tests/field-exercise.mjs /absolute/path/to/debug-executable /tmp/gaga-field-fixtures
```

原生报告/恢复与安全入口验收：

```sh
node tests/native-deep-audit.mjs ABS_DEBUG_EXECUTABLE ABS_METADATA_WORKSPACE ABS_INERT_FIXTURES ABS_RESULT_DIR
python3 tests/check-deep-audit.py ABS_TEST_WORKSPACE /tmp/gaga-physical-checks.json
```

带官方 Key 的 Pi 工具链可用 `node tests/native-reverse.mjs ABS_DEBUG_EXECUTABLE ABS_METADATA_WORKSPACE ABS_INERT_FIXTURES ABS_RESULT_DIR` 验证；会实际调用已保存的 DeepSeek，可能产生费用，不执行样本。

元数据工作区只复制 ai_config 的服务商/模型/配置版本信息，不读取 Key；Pi 在官方请求前取消。固定 PHP/ELF 可由 test-isolated.py 生成。CLI 参数以各脚本 usage 为准。大文件和原生工作区放在专用临时目录，避免 macOS Documents 权限影响自动化。动态样本仅运行镜像内固定无害诊断，不使用真实木马。0.7.0 已迁移采集私钥运算至 AWS-LC；在线接收需验收实际 HTTPS 链路。离线包的生成、采集、导入及跨客户端拒绝仍需完整验收。

## 代码约定

- Tauri 命令只做参数适配、调度与错误透传；阻塞文件和 Docker 操作放在 spawn_blocking。数据库锁不得跨 await，也不得跨事件发送。
- 前端 invoke 从 bridge 导入，不序列化接口参数写日志。后台终态接入 runtime_log，使用受限元数据与任务 UUID；不记录报文、样本或模型正文。日志及真实工作区不得提交。新增 IPC 运行 scripts/generate-api-docs.py 并补契约。
- 每个异步任务启动时捕获 case_id。后台完成、迟到保存、取消与报告关联使用原始事件，不能重新读取“当前事件”来决定归档位置。
- 文件选择器和钥匙串等待也属于异步边界：在打开前捕获事件，Agent 等后端显式接收并校验 caseId。身份/密钥使用 file_commit::write_new 排他发布，普通报告使用受保护路径与替换提交，不能用 exists 后 fs::write 代替。
- 原始证据、派生分析、AI 推测和人工处置分别保存。原文时间不能替换成导入时间；缺少字段、规则未命中和未观察到行为都不能表示安全。
- 宿主机不执行样本、不调用不受控 shell、不回退到宿主机解析 PE / ELF / WebShell。新增工具同时修改宿主验证、Worker 验证、Pi schema 和容器回归。
- 完整性、隔离、协议或清理失败必须终止任务。只有参数范围、格式不支持等有界工具拒绝可返回模型继续研判。
- 模型 Key 只进入系统凭据服务及官方 HTTPS 认证头。不要把 Key、采集私钥、客户材料、工作区数据库或任务 Token 提交到仓库。
- 所有新增模型调用必须经过 AI 外发锁，在读取系统凭据前和授权等待后复核；自动外发必须绑定事件和新的插入边界，不继承历史积压授权。新引用应来自本次实际发送材料，遵守独立数量与字符预算。
- 注释说明为什么要有边界、如何恢复和哪里未覆盖；不为简单赋值逐行加注释。
- 持久化字段使用 serde(default) 兼容旧记录；SQL 变更可重复执行；修改前保留关闭状态的工作区备份。报告恢复日志位于本机 WebView 存储，按工作区与事件隔离。

## 提交问题与变更

提供版本、平台、脱敏复现步骤、预期/实际行为及错误文字。漏洞报告不要附真实恶意样本、客户证据或凭据。涉及权限、网络、隔离配置与供应链的改动应说明信任边界及故障测试；UI 修改请验证白天/夜晚主题、960×660 最低窗口、键盘焦点和事件切换。

CI 配置包含两个桌面平台构建及 Linux 容器测试。新增配置不等于远端 CI 已实际运行通过；本机验收记录见 docs/ACCEPTANCE-0.7.0.md。
