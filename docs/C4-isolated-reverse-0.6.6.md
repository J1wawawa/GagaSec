# C4：0.6.6 隔离分析增量架构

完整平台背景见 [0.6.0 C4](C4-architecture-0.6.0.md)。本文对应 `isolated.rs`、`ai.rs::agent_transport`、`Reverse.tsx` 与 `reverse-worker/` 的实际代码，不包含尚未实现的反编译器或本地 VM 编排。

## C1：系统上下文

```mermaid
flowchart LR
  analyst[蓝队分析员] --> desktop[嘎嘎安全助手桌面客户端]
  desktop --> docker[用户本机 Docker Linux 引擎]
  desktop --> providers[四家官方模型 API]
  desktop --> vault[macOS Keychain / Windows 凭据服务]
  desktop --> report[事件报告 HTML / DOCX / 打印 PDF]
```

## C2：容器与信任边界

```mermaid
flowchart TB
  subgraph host[可信客户端进程与本地数据]
    ui[React / Tauri UI]
    jobs[Rust 任务与隔离控制器]
    broker[官方模型请求代理]
    db[(SQLite：事件 / 任务 / 报告)]
    files[(原始证据 / 工具工件 / 模型请求)]
    vault[系统凭据服务]
    ui --> jobs
    jobs --> db
    jobs --> files
    jobs --> broker
    broker --> vault
  end
  subgraph engine[Docker Linux 引擎：共享内核]
    agent[禁网 Pi Agent Core 容器]
    worker[每次调用新建禁网静态工具容器]
    sample[只读样本文件：tmpfs 中]
    worker --> sample
  end
  jobs <-->|Docker attach：JSON 行| agent
  jobs <-->|stdin 原始字节 / stdout JSON| worker
  broker -->|HTTPS；禁重定向| api[DeepSeek / Qwen / GLM / Kimi]
```

两个容器无网络、无 Key、无宿主目录或 Docker socket 挂载。Pi 不能直接连接静态工作器或官方 API；每次工具名、参数、样本归属与预算均经 Rust 控制器处理。

## C3：组件与数据路径

| 组件 | 责任 |
|---|---|
| `Reverse.tsx` | 独立环境页签、当前事件样本选择、任务状态、工件预览、取消、时间线入口 |
| `store.rs` | 原始字节快照与 Hash；生产样本解析路由到隔离工作器；结果按原事件归档 |
| `isolated.rs` | 镜像构建、配置 inspect、临时容器生命周期、JSON 行 RPC、预算与任务恢复 |
| `ai.rs::agent_transport` | 保存配置 revision 校验、官方目录校验、系统凭据、受限 HTTPS 模型调用 |
| `reverse-worker/agent.mjs` | Pi 核心模型循环，四个自定义工具；不加载 shell、扩展或用户资源 |
| `reverse-worker/src/` | Rust 静态解析、源码行切片、ASCII 字符串和结构定位；样本从 stdin 读取 |
| `reverse-worker/disassemble.mjs` | 在同一工作器容器读取固定样本路径，WASM 解码 x86 / x64 窗口 |
| `report_draft.rs` / `report.rs` | 五步报告正文、节点关联、截图与文档导出 |

```mermaid
sequenceDiagram
  participant U as 桌面 UI
  participant C as Rust 控制器
  participant P as 禁网 Pi
  participant W as 临时静态工作器
  participant A as 官方模型
  U->>C: 当前事件样本 ID + 问题
  C->>C: 事件绑定、镜像与权限检查
  C->>P: 任务元信息，无 Key / 原始文件
  P->>C: 模型请求 JSON
  C->>A: 从系统凭据读取 Key 后 HTTPS
  A-->>C: 有界 SSE
  C-->>P: 仅响应正文
  P->>C: 工具名 + 结构化参数
  C->>W: 校验隔离后 stdin 输入样本字节
  W-->>C: 结果 + 样本 SHA-256
  C->>C: 校验 Hash、删除工作器、保存工件
  C-->>P: 工具结果 + 工件 ID
  P-->>C: 待复核分析草稿
  C->>C: 删除 Pi；按原 caseId 归档
  C-->>U: 任务、过程、工件、报告关联
```

本版本的动态样本运行仍使用既有独立实验环境流程。Pi 静态分析任务不会自动触发该流程，也不因模型请求而启动样本。
