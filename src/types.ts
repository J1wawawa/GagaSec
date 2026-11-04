export type Module =
  | 'dashboard'
  | 'cases'
  | 'triage'
  | 'http'
  | 'logs'
  | 'containers'
  | 'webshell'
  | 'binary'
  | 'sandbox'
  | 'intel'
  | 'assets'
  | 'flows'
  | 'agents'
  | 'knowledge'
  | 'lists'
  | 'samples'
  | 'environment'
  | 'evidence'
  | 'timeline'
  | 'reports'
  | 'lan'
  | 'settings';
export type Theme = 'system' | 'light' | 'dark';
export interface Finding {
  id: string;
  level: string;
  title: string;
  description: string;
  location: string;
  line: number | null;
  excerpt: string;
  remediation: string;
}
export interface AnalysisReport {
  kind: string;
  engine: string;
  title: string;
  summary: string;
  metrics: { label: string; value: string }[];
  findings: Finding[];
  indicators: Indicator[];
  details: { label: string; value: string }[];
  warnings: string[];
  webshell?: {
    version: string;
    language: string;
    rulesVersion: string;
    inputSha256: string;
    layers: {
      id: string;
      parentId: string | null;
      sourceLayerId: string;
      operation: string;
      format: string;
      depth: number;
      sourceStart: number;
      sourceEnd: number;
      sourceLine: number;
      sourceExcerpt: string;
      inputSha256: string;
      sha256: string;
      bytes: number;
      preview: string;
      truncated: boolean;
      findingIds: string[];
    }[];
    traces: {
      layerId: string;
      line: number;
      sources: string[];
      sinks: string[];
      basis: string;
    }[];
    checks: { title: string; status: string; detail: string }[];
    limits: string[];
  };
  httpExchanges?: HttpExchange[];
  coverage?: {
    title: string;
    status: string;
    location: string;
    value: string;
    reason: string;
  }[];
}
export interface Evidence {
  id: string;
  caseId: string;
  name: string;
  kind: string;
  sha256: string;
  size: number;
  createdAt: string;
  report: AnalysisReport;
}
export interface Screenshot {
  id: string;
  nodeId: string;
  name: string;
  sha256: string;
  size: number;
  mime: string;
  caption: string;
}
export interface TimelineNode {
  id: string;
  caseId: string;
  evidenceId: string | null;
  findingId: string | null;
  occurredAt: string;
  recordedAt: string;
  title: string;
  body: string;
  actor: string;
  included: boolean;
  screenshots: Screenshot[];
}
export interface Workspace {
  cases: { id: string; title: string; createdAt: string }[];
  activeCase: string;
  evidence: Evidence[];
  nodes: TimelineNode[];
  aiReviews: AiReview[];
  analysisRuns: AnalysisRun[];
  followups: Followup[];
  reviewFeedback: ReviewFeedback[];
  responseActions: ResponseAction[];
  dataDir: string;
}
export interface AiMaterialItem {
  source: string;
  kind: string;
  included: boolean;
  detail: string;
}
export interface AiSendPreview {
  evidenceId: string;
  material: string;
  scope: AiMaterialItem[];
  redactions: string[];
  provider: string;
  model: string;
  endpointHost: string;
  maxInputChars: number;
  maxOutputTokens: number;
  external: boolean;
  locked: boolean;
  notices: string[];
}
export type ResponseActionStatus =
  | 'draft'
  | 'pending_approval'
  | 'approved'
  | 'executing'
  | 'succeeded'
  | 'failed'
  | 'rolled_back'
  | 'verified'
  | 'cancelled';
export interface ResponseAction {
  id: string;
  caseId: string;
  title: string;
  actionType:
    | 'containment'
    | 'block'
    | 'eradication'
    | 'recovery'
    | 'verification'
    | string;
  target: string;
  description: string;
  requestedBy: string;
  approvedBy: string | null;
  executedBy: string | null;
  status: ResponseActionStatus;
  requestedAt: string;
  approvedAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
  receipt: string | null;
  failureReason: string | null;
  rollbackPlan: string | null;
  rollbackAt: string | null;
  verification: string | null;
  evidenceIds: string[];
  nodeIds: string[];
  createdAt: string;
  updatedAt: string;
}
export interface Indicator {
  kind: string;
  value: string;
  source: string;
}
export const moduleInfo: Record<Module, { title: string; subtitle: string }> = {
  cases: { title: '事件列表', subtitle: '各事件独立保存证据、时间线与报告' },
  dashboard: {
    title: '调查总览',
    subtitle: '本地调查数据、监控任务与待复核状态',
  },
  assets: { title: '资产页面监控', subtitle: '静态页面与同源脚本基线巡检' },
  flows: { title: '重点主机流量', subtitle: 'Linux eBPF 流量观测与分析队列' },
  agents: { title: '采集 Agent', subtitle: '生成专属任务并回收加密数据' },
  knowledge: {
    title: '本地情报库',
    subtitle: '全局 IOC 知识库；来源关联各事件，支持共享导出',
  },
  lists: { title: '黑白名单', subtitle: '管理命中依据与适用范围' },
  samples: { title: '样本案例库', subtitle: 'Hash 与分析案例' },
  environment: { title: '本机环境', subtitle: '本地环境检测' },
  sandbox: {
    title: '动态行为分析',
    subtitle: '在独立实验环境观察样本进程、文件与网络行为，归档执行记录。',
  },
  triage: {
    title: '告警研判',
    subtitle: '粘贴告警原文或 JSON，复核依据、缺失证据与后续调查。',
  },
  http: {
    title: 'HTTP 报文分析',
    subtitle: '关联请求与响应，核对可疑输入、返回内容与影响依据。',
  },
  logs: {
    title: '日志分析',
    subtitle: '导入访问日志，检查可疑请求并回到原文举证。',
  },
  containers: {
    title: '容器排查',
    subtitle: '检查 docker inspect 配置，逐项定位风险字段。',
  },
  webshell: {
    title: 'WebShell 分析',
    subtitle: '静态检查敏感调用、外部输入与解码特征。',
  },
  binary: {
    title: '样本静态分析',
    subtitle: '查看 PE / ELF 基础结构、导入与字符串。',
  },
  intel: {
    title: '情报溯源',
    subtitle: '提取 IP、URL、Hash 与域名候选，整理调查线索。',
  },
  evidence: {
    title: '证据资料',
    subtitle: '查看本事件已归档的原始文件摘要与分析结果。',
  },
  timeline: {
    title: '事件时间线',
    subtitle: '记录调查判断与人员处置，为每个节点附上证据和截图。',
  },
  reports: {
    title: '报告编辑',
    subtitle: '从已选节点、原始依据与截图生成报告。',
  },
  lan: {
    title: '局域网协作',
    subtitle: '设备在线状态、消息、表情、截图和文件',
  },
  settings: {
    title: 'AI 与设置',
    subtitle: '管理主题、启动体验与功能实现状态。',
  },
};

export interface AiConfig {
  provider: string;
  endpoint: string;
  model: string;
  hasKey: boolean;
  revision: string;
  validationError?: string | null;
}
export interface AiConnectionTest {
  id: string;
  provider: string;
  model: string;
  endpoint: string;
  configRevision: string;
  createdAt: string;
  elapsedMs: number;
  success: boolean;
  reply: string;
  error?: string | null;
}
export interface AiReview {
  id: string;
  evidenceId: string;
  endpoint: string;
  model: string;
  createdAt: string;
  material: string;
  question: string;
  content: string;
  finishReason: string;
  requestMessages: ChatMessage[];
  promptVersion: string;
  runId: string;
  elapsedMs: number;
  assessment: Assessment | null;
  schemaError: string | null;
}

export interface HttpMessage {
  startLine: string;
  headers: { name: string; value: string }[];
  raw: string;
  bodyPreview: string;
  bodyBytes: number;
  sha256: string | null;
  source: string;
  representation: string;
  warnings: string[];
}
export interface HttpExchange {
  id: string;
  method: string;
  url: string;
  status: number | null;
  startedAt: string;
  request: HttpMessage;
  response: HttpMessage | null;
  assessment: string;
  findingIds: string[];
}

export interface ChatMessage {
  role: string;
  content: string;
}
export interface AnalysisStage {
  name: string;
  status: string;
  elapsedMs: number | null;
  note: string;
}
export interface AnalysisRun {
  id: string;
  evidenceId: string;
  caseId: string;
  kind: string;
  state: string;
  startedAt: string;
  elapsedMs: number;
  model: string;
  stages: AnalysisStage[];
  reviewId: string | null;
  error: string | null;
}
export interface Assessment {
  verdict: string;
  category: string;
  confidence: number | null;
  attackSuccess: string;
  reasons: { claim: string; refs: string[] }[];
  recommendations: string[];
  evidenceGaps: string[];
  mitre: { id: string; name: string; basis: string; refs: string[] }[];
  notices: string[];
}
export interface Followup {
  id: string;
  reviewId: string;
  question: string;
  content: string;
  model: string;
  endpoint: string;
  createdAt: string;
  finishReason: string;
  runId: string;
  elapsedMs: number;
  requestMessages: ChatMessage[];
}
export interface ReviewFeedback {
  id: string;
  reviewId: string;
  disposition: string;
  feedback: string;
  notes: string;
  actor: string;
  recordedAt: string;
}
