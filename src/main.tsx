import { WebshellWorkbench } from './Webshell';
import { TextEditor } from './TextEditor';
import React, { useEffect, useState, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import { invoke, isTauri } from './bridge';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { open, save } from '@tauri-apps/plugin-dialog';
import {
  Activity,
  Network,
  Radar,
  FolderOpen,
  Route,
  Plus,
  Upload,
  Monitor,
  Check,
  Copy,
  X,
  ImagePlus,
  FileText,
  Download,
  AlertCircle,
  Info,
  Play,
  ChevronDown,
  Search,
  Link2,
  ShieldCheck,
  GripVertical,
  LoaderCircle,
  ArrowUpRight,
  ArrowLeft,
  Database,
  PanelLeft,
} from 'lucide-react';
import type {
  Module,
  Theme,
  Evidence,
  Finding,
  Workspace,
  TimelineNode,
  Screenshot,
  Indicator,
  AiConfig,
  AiConnectionTest,
  AiReview,
  AnalysisRun,
  Followup,
  HttpMessage,
  HttpExchange,
  AiSendPreview,
} from './types';
import { moduleInfo } from './types';
import { useReportExports } from './ReportExports';
import { LocalAnalysisPanel, useLocalAnalysis } from './LocalAnalysis';
import './style.css';
import './analysis-workspace.css';
import aiCatalog from './ai-providers.json';
import { PlatformPanel, type PlatformPage } from './Platform';
import { ThreatIntelSettings, type IntelSeed } from './Intelligence';
import { Dashboard, type DashboardRecord } from './Dashboard';
import { LogTimelinePanel, CoveragePanel } from './Investigation';
import { CasesPanel } from './Cases';
import { ReportEditor } from './Reports';
import { ResponseActionsPanel } from './ResponseActions';
import { LanPanel } from './Lan';
import { StartupScreen, useStartup } from './Startup';
import { AppErrorBoundary } from './AppErrorBoundary';
import { RuntimeLogs } from './RuntimeLogs';
import { installErrorCapture } from './bridge';
import { RecordOptions, type RecordOptionsValue } from './RecordOptions';
import { EvidenceLibrary } from './EvidenceLibrary';
import './usability.css';
import { MaintenancePanel, CapabilityMatrix, FailureDetails } from './Support';
import { AiPrivacyIndicator, PrivacyPanel } from './Privacy';
import release from './release-manifest.json';
import { Modal } from './Modal';
import {
  moduleIcons as icons,
  PrimaryNavigation,
  ToolNavigation,
  ToolLauncher,
} from './Navigation';
import { SandboxPanel, type SandboxJob } from './Sandbox';
import { ReversePanel } from './Reverse';

const native = isTauri();
const preview: Workspace =
  import.meta.env.DEV && !native && window.__GAGA_WORKSPACE_FIXTURE__
    ? window.__GAGA_WORKSPACE_FIXTURE__
    : {
        cases: [{ id: 'preview', title: '本地调查空间', createdAt: '' }],
        activeCase: 'preview',
        evidence: [],
        nodes: [],
        aiReviews: [],
        analysisRuns: [],
        followups: [],
        reviewFeedback: [],
        responseActions: [],
        dataDir: '',
      };
const analysisModules: Module[] = [
  'logs',
  'http',
  'triage',
  'containers',
  'webshell',
  'binary',
];
function readPreference<T extends string>(
  key: string,
  allowed: T[],
  fallback: T,
): T {
  try {
    const value = localStorage.getItem(key) as T;
    return allowed.includes(value) ? value : fallback;
  } catch {
    return fallback;
  }
}
const size = (n: number) =>
  n > 1024 * 1024
    ? `${(n / 1024 / 1024).toFixed(1)} MB`
    : `${(n / 1024).toFixed(1)} KB`;
const date = (s: string) => {
  if (!s) return '—';
  const d = new Date(s);
  return Number.isNaN(d.valueOf())
    ? s
    : new Intl.DateTimeFormat('zh-CN', {
        timeZone: 'Asia/Shanghai',
        dateStyle: 'short',
        timeStyle: 'medium',
        hour12: false,
      }).format(d);
};
const localTime = (at?: string) =>
  new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
    .format(at ? new Date(at) : new Date())
    .replace(' ', 'T');
function ShotImage({
  shot,
  eager = false,
}: {
  shot: Screenshot;
  eager?: boolean;
}) {
  const [src, setSrc] = useState('');
  const [failure, setFailure] = useState('');
  const [attempt, setAttempt] = useState(0);
  const [visible, setVisible] = useState(false);
  const loadRequested = visible || eager;
  const container = useRef<HTMLElement>(null);
  useEffect(() => {
    const node = container.current;
    if (!node || !('IntersectionObserver' in window)) {
      setVisible(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { rootMargin: '480px' },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [shot.id]);
  useEffect(() => {
    // Keep already verified pixels when print preloading ends. Clearing them
    // here would blank offscreen figures as the native print sheet opens.
    if (native && !loadRequested) return;
    let alive = true;
    setSrc('');
    setFailure('');
    if (native)
      invoke<string>('screenshot_data', { id: shot.id })
        .then((value) => {
          if (alive) setSrc(value);
        })
        .catch((error) => {
          if (alive) setFailure(String(error));
        });
    else if (!native) setFailure('请在客户端中读取归档原图。');
    return () => {
      alive = false;
    };
  }, [shot.id, attempt, loadRequested]);
  return (
    <figure className="shot" ref={container}>
      <div className="shot-image">
        {src ? (
          <img
            src={src}
            alt={shot.caption || shot.name}
            loading={eager ? 'eager' : 'lazy'}
            onError={() => {
              setSrc('');
              setFailure('原图无法解码，请检查归档文件。');
            }}
          />
        ) : failure ? (
          <div className="shot-error" role="alert">
            <strong>截图读取失败</strong>
            <span>{failure}</span>
            <button
              className="button small"
              onClick={() => setAttempt((n) => n + 1)}
            >
              重新校验并加载
            </button>
          </div>
        ) : (
          <span>{visible || eager ? '图片读取中' : '滚动至此处加载截图'}</span>
        )}
      </div>
      <figcaption>
        {shot.caption || '未填写图注'}
        <small>
          {shot.name} · SHA-256 {shot.sha256.slice(0, 16)}…
        </small>
      </figcaption>
    </figure>
  );
}
function Empty({
  icon: Icon,
  title,
  text,
  children,
}: {
  icon: typeof Activity;
  title: string;
  text: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-symbol">
        <Icon size={28} strokeWidth={1.2} />
      </div>
      <h2>{title}</h2>
      <p>{text}</p>
      {children}
    </div>
  );
}
function App() {
  const reportExports = useReportExports();
  const [exportChoosing, setExportChoosing] = useState(false);
  const [sampleView, setSampleView] = useState<'static' | 'pi' | 'environment'>(
    'static',
  );
  const [page, setPage] = useState<Module>('dashboard');
  const [workspace, setWorkspace] = useState<Workspace>(preview);
  const [timelineRows, setTimelineRows] = useState<TimelineNode[]>(
    preview.nodes,
  );
  const [timelineTotal, setTimelineTotal] = useState(0);
  const [timelineOffset, setTimelineOffset] = useState(0);
  const [theme, setTheme] = useState<Theme>(() =>
    readPreference('gaga.theme', ['system', 'light', 'dark'], 'system'),
  );
  const [splashEnabled, setSplashEnabled] = useState(
    () => readPreference('gaga.splash', ['yes', 'no'], 'yes') === 'yes',
  );
  const [splash, setSplash] = useState(splashEnabled);
  const [startupReplay, setStartupReplay] = useState(false);
  const [startupReduced, setStartupReduced] = useState(false);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [statusToast, setStatusToast] = useState('');
  const [status, setStatus] = useState(
    native ? '正在打开本地数据库…' : '界面预览 · 本地功能需启动桌面客户端',
  );
  const [selectedId, setSelectedId] = useState('');
  const pendingResultTab = useRef<'ai' | 'findings' | null>(null);
  const pendingFinding = useRef('');
  const [findingId, setFindingId] = useState('');
  const [tab, setTab] = useState<
    | 'findings'
    | 'information'
    | 'indicators'
    | 'ai'
    | 'http'
    | 'log-timeline'
    | 'coverage'
    | 'webshell-layers'
  >('findings');
  const [inputDrafts, setInputDrafts] = useState<
    Record<string, { request: string; response: string; alert: string }>
  >({});
  const inputDraft = inputDrafts[workspace.activeCase];
  const httpRequest = inputDraft?.request || '';
  const httpResponse = inputDraft?.response || '';
  const alertText = inputDraft?.alert || '';
  const [httpError, setHttpError] = useState('');
  function updateInputDraft(
    patch: Partial<{ request: string; response: string; alert: string }>,
  ) {
    const caseId = workspace.activeCase;
    setInputDrafts((previous) => ({
      ...previous,
      [caseId]: {
        ...(previous[caseId] || { request: '', response: '', alert: '' }),
        ...patch,
      },
    }));
    setHttpError('');
  }
  const setHttpRequest = (request: string) => updateInputDraft({ request });
  const setHttpResponse = (response: string) => updateInputDraft({ response });
  const setAlertText = (alert: string) => updateInputDraft({ alert });
  const [httpEditor, setHttpEditor] = useState(true);
  const [alertEditor, setAlertEditor] = useState(true);
  const [httpExchangeId, setHttpExchangeId] = useState('');
  const [httpView, setHttpView] = useState<'raw' | 'body' | 'headers'>('raw');
  const [liveRuns, setLiveRuns] = useState<Record<string, AnalysisRun>>({});
  const [traceNow, setTraceNow] = useState(Date.now());
  const [followupDrafts, setFollowupDrafts] = useState<Record<string, string>>(
    {},
  );
  const [feedbackDrafts, setFeedbackDrafts] = useState<
    Record<
      string,
      { disposition: string; feedback: string; notes: string; actor: string }
    >
  >({});
  const [query, setQuery] = useState('');
  const [fileQuery, setFileQuery] = useState('');
  const [listWidth, setListWidth] = useState(204);
  const [analysisFilesOpen, setAnalysisFilesOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState('model');
  const [intelQuerySeed, setIntelQuerySeed] = useState<IntelSeed>();
  // A query seed is an event-local shortcut. Never carry an IOC or evidence
  // pointer into another incident when the analyst switches cases.
  useEffect(() => {
    setIntelQuerySeed(undefined);
  }, [workspace.activeCase]);
  const [caseModal, setCaseModal] = useState(false);
  const [caseTitle, setCaseTitle] = useState('');
  const [nodeDraft, setNodeDraft] = useState<{
    caseId?: string;
    id?: string;
    originalOccurredAt?: string;
    originalInputTime?: string;
    title: string;
    body: string;
    time: string;
    actor: string;
    evidenceId: string | null;
    findingId: string | null;
    focusScreenshot?: boolean;
  } | null>(null);
  const [recordOptions, setRecordOptions] = useState<RecordOptionsValue | null>(
    null,
  );
  const activeCaseRef = useRef(workspace.activeCase);
  activeCaseRef.current = workspace.activeCase;
  const [reportReload, setReportReload] = useState(0);
  const [reportEntry, setReportEntry] = useState<'home' | 'write' | 'delivery'>(
    'home',
  );
  const [shotDraft, setShotDraft] = useState<{
    nodeId: string;
    path: string;
    caption: string;
    dataUrl?: string;
  } | null>(null);
  const [iocText, setIocText] = useState('');
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [aiConfig, setAiConfig] = useState<AiConfig>({
    provider: '',
    endpoint: '',
    model: '',
    hasKey: false,
    revision: '',
  });
  const [aiProfiles, setAiProfiles] = useState<AiConfig[]>([]);
  const [connectionTests, setConnectionTests] = useState<AiConnectionTest[]>(
    [],
  );
  const [apiProvider, setApiProvider] = useState('deepseek');
  const [apiModel, setApiModel] = useState(aiCatalog.providers[0].models[0].id);
  const selectedProvider =
    aiCatalog.providers.find((p) => p.id === apiProvider) ||
    aiCatalog.providers[0];
  const apiEndpoint = selectedProvider.endpoint;
  const selectedProfile =
    aiProfiles.find((p) => p.provider === apiProvider) ||
    (aiConfig.provider === apiProvider ? aiConfig : undefined);
  const aiDirty =
    apiProvider !== aiConfig.provider || apiModel !== aiConfig.model;

  const [apiKey, setApiKey] = useState('');
  const currentProvider = aiCatalog.providers.find(
    (p) => p.id === aiConfig.provider,
  );
  const [aiDraft, setAiDraft] = useState<{
    evidenceId: string;
    material: string;
    question: string;
    preview?: AiSendPreview;
  } | null>(null);
  const splashStarted = useRef(performance.now());
  const startup = useStartup((data) => {
    setWorkspace(data.workspace);
    setStatus('本地工作区已打开');
    setAiConfig(data.config);
    setAiProfiles(data.profiles);
    setConnectionTests(data.connectionTests);
    const provider = aiCatalog.providers.find(
      (p) => p.id === data.config.provider,
    );
    if (provider) {
      setApiProvider(provider.id);
      setApiModel(data.config.model);
    }
  });
  const startupVisible = startup.snapshot.state !== 'ready' || splash;
  const startupAnimate = (splashEnabled || startupReplay) && !startupReduced;
  useEffect(() => {
    // Keep completion feedback close to the work area without adding another
    // modal. The status bar remains the durable source; this short-lived cue
    // makes a save/export result discoverable after a long form is submitted.
    if (!status || status.startsWith('正在打开')) return;
    setStatusToast(status);
    const timer = window.setTimeout(() => setStatusToast(''), 3200);
    return () => window.clearTimeout(timer);
  }, [status]);
  const activeCase = workspace.cases.find((c) => c.id === workspace.activeCase);
  useEffect(() => {
    if (page !== 'timeline' || workspace.nodes.length <= 300 || !native) {
      setTimelineRows(workspace.nodes);
      setTimelineTotal(workspace.nodes.length);
      setTimelineOffset(0);
      return;
    }
    let alive = true;
    invoke<{ rows: TimelineNode[]; total: number }>('get_timeline_page', {
      caseId: workspace.activeCase,
      offset: timelineOffset,
      limit: 100,
      query: '',
    })
      .then((result) => {
        if (alive) {
          setTimelineRows(result.rows);
          setTimelineTotal(result.total);
        }
      })
      .catch((e) => setError(String(e)));
    return () => {
      alive = false;
    };
  }, [page, native, workspace.activeCase, workspace.nodes, timelineOffset]);
  const moduleFiles = workspace.evidence.filter((e) => e.kind === page);
  const httpInputOpen =
    httpEditor || !workspace.evidence.some((e) => e.kind === 'http');
  const alertInputOpen =
    alertEditor || !workspace.evidence.some((e) => e.kind === 'triage');
  const current =
    workspace.evidence.find(
      (e) =>
        e.id === selectedId &&
        (analysisModules.includes(page) ? e.kind === page : true),
    ) || moduleFiles[0];
  const filtered =
    current?.report.findings.filter((f) =>
      `${f.title} ${f.location} ${f.excerpt}`
        .toLowerCase()
        .includes(query.toLowerCase()),
    ) || [];
  const finding = filtered.find((f) => f.id === findingId) || filtered[0];
  const analysisTasks = useLocalAnalysis(
    startup.snapshot.state === 'ready',
    () => {
      void refresh().catch((e) => setError(String(e)));
    },
  );
  useEffect(() => {
    if (shotDraft)
      document
        .querySelector<HTMLElement>('[aria-label="粘贴截图区域"]')
        ?.focus();
  }, [shotDraft?.nodeId]);
  useEffect(() => {
    const media = matchMedia('(prefers-color-scheme: dark)');
    const apply = () => {
      document.documentElement.dataset.theme =
        theme === 'system' ? (media.matches ? 'dark' : 'light') : theme;
      document.documentElement.dataset.themeMode = theme;
      if (native)
        getCurrentWindow()
          .setTheme(theme === 'system' ? null : theme)
          .catch(() => {});
    };
    apply();
    media.addEventListener('change', apply);
    localStorage.setItem('gaga.theme', theme);
    return () => media.removeEventListener('change', apply);
  }, [theme]);
  useEffect(() => {
    if (!splash || startup.snapshot.state !== 'ready') return;
    const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
    // Only the visual entrance has a minimum duration. Initialization itself
    // advances on actual completion and cannot be skipped by this timer.
    const delay =
      reduced || !startupAnimate
        ? 0
        : Math.max(0, 1100 - (performance.now() - splashStarted.current));
    const timer = setTimeout(() => setSplash(false), delay);
    return () => clearTimeout(timer);
  }, [splash, startup.snapshot.state, startupAnimate, startupReplay]);
  useEffect(() => {
    setQuery('');
    setFindingId(pendingFinding.current);
    pendingFinding.current = '';
    setTab(
      pendingResultTab.current ||
        (page === 'http'
          ? 'http'
          : page === 'triage'
            ? 'ai'
            : page === 'logs'
              ? 'log-timeline'
              : page === 'containers'
                ? 'coverage'
                : page === 'webshell'
                  ? 'webshell-layers'
                  : 'findings'),
    );
    pendingResultTab.current = null;
    setHttpExchangeId('');
  }, [page, selectedId]);
  useEffect(() => {
    if (!nodeDraft) setRecordOptions(null);
  }, [!!nodeDraft]);
  useEffect(() => {
    const selected = workspace.evidence.find((e) => e.id === selectedId);
    if (!selected) setSelectedId('');
    setNodeDraft(null);
    setRecordOptions(null);
    setFileQuery('');
    setShotDraft(null);
    setAiDraft(null);
    setHttpError('');
    setHttpEditor(!selected || selected.kind !== 'http');
    setAlertEditor(!selected || selected.kind !== 'triage');
  }, [workspace.activeCase]);
  useEffect(() => {
    if (!native) return;
    let disposed = false;
    let stop: (() => void) | undefined;
    listen<AnalysisRun>('analysis-progress', (event) => {
      if (!disposed)
        setLiveRuns((previous) => ({
          ...previous,
          [event.payload.id]: event.payload,
        }));
    })
      .then((unlisten) => {
        if (disposed) unlisten();
        else stop = unlisten;
      })
      .catch((e) => setError(String(e)));
    return () => {
      disposed = true;
      stop?.();
    };
  }, []);
  useEffect(() => {
    if (!Object.values(liveRuns).some((r) => r.state === 'running')) return;
    const tick = setInterval(() => {
      if (!document.hidden) setTraceNow(Date.now());
    }, 250);
    const onVisibilityChange = () => {
      if (!document.hidden) setTraceNow(Date.now());
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      clearInterval(tick);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [liveRuns]);
  const dialogOpen = !!(aiDraft || caseModal || nodeDraft || shotDraft);
  useEffect(() => {
    setError('');
  }, [dialogOpen]);
  async function perform<T>(
    label: string,
    fn: () => Promise<T>,
    done?: (value: T) => void,
    onFailure?: (message: string) => void,
  ) {
    if (busy) return;
    setError('');
    setBusy(label);
    try {
      const value = await fn();
      done?.(value);
      setStatus(label + '完成');
      return value;
    } catch (e) {
      setError(String(e));
      setStatus(label + '失败');
      onFailure?.(String(e));
    } finally {
      setBusy('');
    }
  }
  async function refresh() {
    const w = await invoke<Workspace>('get_workspace');
    setWorkspace(w);
    return w;
  }
  function needNative() {
    if (native) return true;
    setError(
      '当前为浏览器界面预览。请打开嘎嘎安全助手桌面客户端，使用文件分析、本地数据库与文档导出。',
    );
    return false;
  }
  async function analyze(kind: Module) {
    if (!needNative()) return;
    const caseId = workspace.activeCase; // Capture before the file dialog yields.
    let path: string | null = null;
    {
      const picked = await open({
        multiple: false,
        directory: false,
        title:
          kind === 'http'
            ? '选择 HAR / HTTP 文本 / 报文对 JSON'
            : '选择待分析文件',
        ...(kind === 'http'
          ? {
              filters: [
                {
                  name: 'HTTP / HAR 文件',
                  extensions: ['har', 'http', 'txt', 'json'],
                },
              ],
            }
          : {}),
      }).catch((e) => {
        setError(String(e));
        return null;
      });
      if (typeof picked !== 'string') return;
      path = picked;
    }
    if (['logs', 'webshell', 'binary'].includes(kind)) {
      await perform('启动分析任务', () =>
        analysisTasks.start(caseId, path!, kind),
      );
      return;
    }
    await perform(
      '本地分析',
      async () => {
        const e = await invoke<Evidence>('analyze_file', { path, kind });
        await refresh();
        return e;
      },
      (e) => {
        setSelectedId(e.id);
        setPage(kind);
        if (kind === 'http') setHttpEditor(false);
      },
    );
  }
  async function loadHttp(side: 'request' | 'response') {
    if (!needNative()) return;
    const path = await open({
      multiple: false,
      title: side === 'request' ? '选择请求报文文本' : '选择响应报文文本',
    }).catch((e) => {
      setError(String(e));
      return null;
    });
    if (typeof path !== 'string') return;
    await perform(
      '加载报文',
      () => invoke<string>('read_http_text', { path }),
      (text) => {
        if (side === 'request') setHttpRequest(text);
        else setHttpResponse(text);
      },
    );
  }
  async function analyzeHttp(event: React.FormEvent) {
    event.preventDefault();
    if (!needNative()) return;
    setHttpError('');
    for (const [label, value] of [
      ['请求包', httpRequest],
      ['响应包', httpResponse],
    ]) {
      if (new TextEncoder().encode(value).length > 2 * 1024 * 1024) {
        setHttpError(
          `${label}：UTF-8 编码超过 2 MiB，请截取相关交互或拆分导入。`,
        );
        return;
      }
    }
    await perform(
      'HTTP 联合分析',
      async () => {
        const e = await invoke<Evidence>('analyze_http_pair', {
          request: httpRequest,
          response: httpResponse,
        });
        await refresh();
        return e;
      },
      (e) => {
        setSelectedId(e.id);
        setPage('http');
        setHttpEditor(false);
      },
      (message) => {
        setError('');
        setHttpError(message);
        setHttpEditor(true);
      },
    );
  }
  function recordHttp(e: Evidence, exchange: HttpExchange) {
    setNodeDraft({
      caseId: e.caseId,
      title: `HTTP 复核：${exchange.method} ${exchange.url.slice(0, 100)}`,
      body: `待人工复核：${exchange.assessment}\n交互：${exchange.id}\n采集时间：${exchange.startedAt || '未提供'}\n\n请求来源：${exchange.request.source}\n${exchange.request.raw.slice(0, 6000)}\n\n响应来源：${exchange.response?.source || '未提供'}\n${exchange.response?.raw.slice(0, 6000) || '[缺少响应，影响未知]'}\n\n这里只保存阅读视图节选，完整材料在归档文件中。HTTP 状态及内容匹配不能独立证明利用成功。`,
      time: localTime(),
      actor: '本地分析员',
      evidenceId: e.id,
      findingId: null,
    });
  }
  async function analyzeAlert(event: React.FormEvent) {
    event.preventDefault();
    if (!needNative()) return;
    await perform(
      '告警归档与本地检查',
      async () => {
        const e = await invoke<Evidence>('analyze_alert_text', {
          text: alertText,
        });
        await refresh();
        return e;
      },
      (e) => {
        setSelectedId(e.id);
        setPage('triage');
        setTab('ai');
        setAlertEditor(false);
      },
    );
  }
  function AlertComposer() {
    return (
      <form
        className="alert-composer"
        data-open={alertInputOpen}
        onSubmit={analyzeAlert}
      >
        <div className="composer-heading">
          录入告警原文<span>文本或 JSON · 保留原始字段</span>
        </div>
        {alertInputOpen && (
          <TextEditor
            label="告警原文"
            size="fill"
            code
            aria-label="告警原文"
            required
            spellCheck={false}
            maxLength={2097152}
            disabled={!!busy}
            value={alertText}
            onChange={(event) => setAlertText(event.target.value)}
            placeholder="粘贴 NDR / WAF / EDR 告警、原始 JSON 或调查材料。保留时间、源与目的资产、规则描述及 proof 字段。"
          />
        )}
        <div className="http-compose-footer" hidden={!alertInputOpen}>
          <p>
            人工粘贴数据不自动视为已认证事实。保留原文与摘要，模型发送前可以删减。
          </p>
          <button
            className="button primary"
            disabled={!!busy || !alertText.trim()}
          >
            <Play size={14} />
            开始分析
          </button>
        </div>
      </form>
    );
  }
  function HttpComposer() {
    return (
      <section className="http-composer" data-open={httpInputOpen}>
        <div className="composer-heading">
          请求与响应<span>请求必填 · 响应可留空</span>
        </div>
        {httpError && (
          <div className="http-input-error" role="alert" aria-live="assertive">
            <AlertCircle size={16} />
            <div>
              <strong>HTTP 联合分析未完成</strong>
              <FailureDetails message={httpError} stage="HTTP 报文解析" />
              <small>请求和响应输入已保留。修改对应报文后可直接重试。</small>
            </div>
          </div>
        )}
        {httpInputOpen && (
          <form onSubmit={analyzeHttp}>
            <div className="http-columns">
              <TextEditor
                label="请求包"
                size="fill"
                code
                actions={
                  <button
                    type="button"
                    className="button small"
                    disabled={!!busy}
                    onClick={() => loadHttp('request')}
                  >
                    加载请求文件
                  </button>
                }
                aria-label="HTTP 请求包"
                required
                spellCheck={false}
                maxLength={2097152}
                disabled={!!busy}
                value={httpRequest}
                onChange={(e) => setHttpRequest(e.target.value)}
                placeholder="在此粘贴 HTTP 请求行、消息头和正文"
              />
              <TextEditor
                label="响应包"
                size="fill"
                code
                actions={
                  <button
                    type="button"
                    className="button small"
                    disabled={!!busy}
                    onClick={() => loadHttp('response')}
                  >
                    加载响应文件
                  </button>
                }
                aria-label="HTTP 响应包"
                spellCheck={false}
                maxLength={2097152}
                disabled={!!busy}
                value={httpResponse}
                onChange={(e) => setHttpResponse(e.target.value)}
                placeholder="在此粘贴对应的 HTTP 响应，可留空"
              />
            </div>
            <div className="http-compose-footer">
              <p>
                每侧最多 2 MiB UTF-8
                文本。支持仅有消息头的报文；有正文时请用空行分隔。
                缺失内容会明确标注；本地分析不回放请求。
              </p>

              <button
                className="button primary"
                disabled={!!busy || !httpRequest.trim()}
              >
                <Network size={14} />
                开始分析
              </button>
            </div>
          </form>
        )}
      </section>
    );
  }
  function HttpPackets(e: Evidence) {
    const exchanges = e.report.httpExchanges || [];
    const selected =
      exchanges.find((x) => x.id === httpExchangeId) || exchanges[0];
    if (!selected)
      return <div className="quiet-empty">没有可显示的 HTTP 交互。</div>;
    const packet = (message: HttpMessage | null, title: string) => (
      <section className="http-side">
        <div className="pane-label">
          {title}
          <span>{message ? `${message.bodyBytes} 正文字节` : '未提供'}</span>
        </div>
        {message ? (
          <>
            <code className="http-start">{message.startLine}</code>
            <pre className="http-packet">
              {httpView === 'body'
                ? message.bodyPreview ||
                  '[未提供正文、正文为空或未成功解码，请查看限制]'
                : httpView === 'headers'
                  ? message.headers
                      .map((h) => `${h.name}: ${h.value}`)
                      .join('\n') || '[无头字段]'
                  : message.raw}
            </pre>
            <p className="small-note">
              来源：{message.source}
              <br />
              {message.representation}
            </p>
            {message.sha256 && (
              <small className="hash">该侧文本 SHA-256：{message.sha256}</small>
            )}
            {message.warnings.length > 0 && (
              <details className="limitations">
                <summary>
                  {message.warnings.length} 项解析限制 <ChevronDown size={13} />
                </summary>
                <ul>
                  {message.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </details>
            )}
          </>
        ) : (
          <div className="http-missing">
            未提供有效响应，不能判断服务器执行结果。
          </div>
        )}
      </section>
    );
    return (
      <div className="http-reader">
        <div className="http-reader-toolbar">
          <label>
            交互
            <select
              aria-label="HTTP 交互"
              value={selected.id}
              onChange={(event) => setHttpExchangeId(event.target.value)}
            >
              {exchanges.map((x, i) => (
                <option key={x.id} value={x.id}>
                  #{i + 1} {x.method} {x.url.slice(0, 90)} ·{' '}
                  {x.status || '无响应'}
                </option>
              ))}
            </select>
          </label>
          <select
            aria-label="HTTP 查看方式"
            value={httpView}
            onChange={(event) =>
              setHttpView(event.target.value as 'raw' | 'body' | 'headers')
            }
          >
            <option value="raw">报文视图</option>
            <option value="headers">消息头</option>
            <option value="body">解码正文</option>
          </select>
        </div>
        <div className="http-assessment">
          <div>
            <strong>{selected.assessment}</strong>
            <small>
              {selected.startedAt
                ? `HAR 记录时间：${date(selected.startedAt)}`
                : '采集时间未提供'}{' '}
              · 状态 {selected.status || '未知'}
            </small>
          </div>
          <button
            className="button small"
            onClick={() => recordHttp(e, selected)}
          >
            <Plus size={13} />
            记录这组报文
          </button>
        </div>
        <div className="http-columns">
          {packet(selected.request, '请求包')}
          {packet(selected.response, '响应包')}
        </div>
        <div className="http-findings">
          <h3>这组交互的线索 · {selected.findingIds.length}</h3>
          {e.report.findings
            .filter((f) => selected.findingIds.includes(f.id))
            .map((f) => (
              <button
                key={f.id}
                className="http-finding"
                onClick={() => {
                  setQuery('');
                  setFindingId(f.id);
                  setTab('findings');
                }}
              >
                <span>{f.title}</span>
                <small>{f.location}</small>
                <ArrowUpRight size={13} />
              </button>
            ))}
          {!selected.findingIds.length && (
            <p className="small-note">
              当前规则未命中，不代表安全。可选择片段进行 AI 复核。
            </p>
          )}
        </div>
      </div>
    );
  }
  async function draftNode(e?: Evidence, f?: Finding) {
    const caseId = e?.caseId || workspace.activeCase;
    if (e?.kind === 'logs' && f?.line && native) {
      try {
        const event = await invoke<{
          at: string | null;
          rawTime: string;
          timeBasis: string;
          excerpt: string;
        }>('get_log_event', { evidenceId: e.id, line: f.line });
        // 日志查询完成前若已换案，不弹出上一事件的举证窗口。
        if (activeCaseRef.current !== caseId) return;
        setNodeDraft({
          caseId,
          title: f.title,
          body: `原文第 ${f.line} 行\n原文时间：${event.rawTime}\n时间依据：${event.timeBasis}\n\n${event.excerpt}\n\n待人工复核。`,
          time: event.at ? localTime(event.at) : '',
          actor: '本地分析员',
          evidenceId: e.id,
          findingId: f.id,
        });
        return;
      } catch (err) {
        setError(String(err));
        return;
      }
    }
    setNodeDraft({
      caseId,
      title: f?.title || '',
      body: f ? `${f.description}\n\n建议核查：${f.remediation}` : '',
      time: localTime(),
      actor: '本地分析员',
      evidenceId: e?.id || null,
      findingId: f?.id || null,
    });
  }
  async function saveNode(event: React.FormEvent) {
    event.preventDefault();
    if (!nodeDraft || !needNative()) return;
    const openReport =
      (event.nativeEvent as SubmitEvent).submitter?.getAttribute(
        'data-destination',
      ) === 'reports';
    const occurredAt =
      nodeDraft.id && nodeDraft.time === nodeDraft.originalInputTime
        ? nodeDraft.originalOccurredAt
        : nodeDraft.time.length === 16
          ? `${nodeDraft.time}:00+08:00`
          : `${nodeDraft.time}+08:00`;
    if (!nodeDraft.id) {
      if (!recordOptions) return;
      if (recordOptions.caseId !== nodeDraft.caseId) {
        setError('举证窗口的事件状态已变化，请关闭后重新记录。');
        return;
      }
      await perform(
        '保存举证',
        async () => {
          await invoke('save_record_entry', {
            input: {
              ...recordOptions,
              title: nodeDraft.title,
              body: nodeDraft.body,
              actor: nodeDraft.actor,
              occurredAt,
              evidenceId: nodeDraft.evidenceId,
              findingId: nodeDraft.findingId,
            },
          });
          return invoke<Workspace>('get_workspace');
        },
        (w) => {
          setWorkspace(w);
          setNodeDraft(null);
          setReportReload((v) => v + 1);
          if (openReport) {
            setReportEntry('write');
            setPage('reports');
          }
        },
      );
      return;
    }
    await perform(
      '保存时间线节点',
      () =>
        invoke<Workspace>(nodeDraft.id ? 'update_node' : 'add_node', {
          ...nodeDraft,
          occurredAt:
            nodeDraft.id && nodeDraft.time === nodeDraft.originalInputTime
              ? nodeDraft.originalOccurredAt
              : nodeDraft.time.length === 16
                ? `${nodeDraft.time}:00+08:00`
                : `${nodeDraft.time}+08:00`,
        }),
      (w) => {
        setWorkspace(w);
        setNodeDraft(null);
        if (page !== 'reports') setPage('timeline');
      },
    );
  }
  function editNode(node: TimelineNode) {
    const millis = new Date(node.occurredAt).getMilliseconds();
    const inputTime =
      localTime(node.occurredAt) +
      (millis ? `.${String(millis).padStart(3, '0')}` : '');
    setNodeDraft({
      id: node.id,
      originalOccurredAt: node.occurredAt,
      originalInputTime: inputTime,
      title: node.title,
      body: node.body,
      actor: node.actor,
      time: inputTime,
      evidenceId: node.evidenceId,
      findingId: node.findingId,
    });
  }
  async function attach(node: TimelineNode) {
    if (!needNative()) return;
    const path = await open({
      multiple: false,
      filters: [{ name: '截图', extensions: ['png', 'jpg', 'jpeg', 'webp'] }],
    }).catch((e) => {
      setError(String(e));
      return null;
    });
    if (typeof path === 'string')
      setShotDraft({ nodeId: node.id, path, caption: '' });
  }
  async function exportReport(format: 'docx' | 'html', caseId: string) {
    if (!needNative()) return;
    setExportChoosing(true);
    try {
      const path = await save({
        title: '导出调查报告',
        defaultPath: `${activeCase?.title || '调查报告'}.${format}`,
        filters: [{ name: format.toUpperCase(), extensions: [format] }],
      }).catch((e) => {
        setError(String(e));
        return null;
      });
      if (!path) return;
      await invoke('start_report_export', { caseId, path, format });
      await reportExports.refresh();
      setStatus('报告已开始后台导出，可在报告页查看进度。');
    } catch (e) {
      setError(String(e));
    } finally {
      setExportChoosing(false);
    }
  }
  async function saveAi(removeKey = false) {
    if (!needNative()) return;
    await perform(
      '保存模型配置',
      () =>
        invoke<AiConfig>('save_ai_config', {
          baseUrl: apiEndpoint,
          model: apiModel,
          apiKey: removeKey ? '' : apiKey,
          removeKey,
        }),
      (c) => {
        setAiConfig(c);
        setApiKey('');
        setApiProvider(c.provider);
        setApiModel(c.model);
        setAiProfiles((p) => [
          ...p.filter((p) => p.provider !== c.provider),
          c,
        ]);
      },
    );
  }
  async function prepareAi(e: Evidence) {
    if (!needNative()) return;
    if (!aiConfig.endpoint) {
      setPage('settings');
      setStatus('请先选择官方模型并保存 API Key');
      return;
    }
    await perform(
      '准备发送材料',
      () =>
        invoke<AiSendPreview>(
          e.kind === 'logs' ? 'log_ai_material' : 'preview_ai_material',
          { evidenceId: e.id },
        ),
      (preview) =>
        setAiDraft({
          evidenceId: e.id,
          material: preview.material,
          preview,
          question:
            '请复核可疑点，逐项引用证据，区分事实与推断，给出后续调查建议。',
        }),
    );
  }
  async function prepareAiMaterial(
    e: Evidence,
    _selectedMaterial: string,
    question: string,
  ) {
    if (!needNative()) return;
    if (!aiConfig.endpoint) {
      setPage('settings');
      setStatus('请先配置官方模型，再发送时间线材料');
      return;
    }
    await perform(
      '准备发送材料',
      () =>
        invoke<AiSendPreview>(
          e.kind === 'logs' ? 'log_ai_material' : 'preview_ai_material',
          { evidenceId: e.id },
        ),
      (preview) =>
        setAiDraft({
          evidenceId: e.id,
          // Always use the backend's bounded/redacted material. Panel text is
          // a navigation hint and is never trusted as an external payload.
          material: preview.material,
          question,
          preview,
        }),
    );
  }

  const duration = (ms: number | null | undefined) =>
    ms == null
      ? '—'
      : ms === 0
        ? '<1 ms'
        : ms < 1000
          ? `${ms} ms`
          : `${(ms / 1000).toFixed(1)} s`;
  function ProcessCard(e: Evidence, runId?: string) {
    const merged = new Map<string, AnalysisRun>();
    for (const r of workspace.analysisRuns || []) merged.set(r.id, r);
    for (const r of Object.values(liveRuns)) merged.set(r.id, r);
    const run = runId
      ? merged.get(runId)
      : Array.from(merged.values())
          .filter(
            (r) => r.evidenceId === e.id && r.caseId === workspace.activeCase,
          )
          .sort((a, b) => b.startedAt.localeCompare(a.startedAt))[0];
    if (!run)
      return (
        <div className="process-empty">
          本地文件任务过程可从底部“分析任务”查看；此材料尚无可显示的 AI
          研判过程。
        </div>
      );
    const live =
      run.state === 'running' && liveRuns[run.id]?.state === 'running';
    const elapsed = live
      ? Math.max(run.elapsedMs, traceNow - new Date(run.startedAt).valueOf())
      : run.elapsedMs;
    return (
      <details className="analysis-process" aria-label="分析过程" open={live}>
        <summary className="process-heading">
          <div>
            <span>
              当前{run.kind === 'followup' ? '追问' : '分析'} ·{' '}
              {run.kind === 'local' ? '本地引擎' : run.model}
            </span>
          </div>
          <strong>
            {run.state === 'completed'
              ? '已完成'
              : run.state === 'failed'
                ? '失败'
                : live
                  ? '分析中'
                  : '执行状态待确认'}{' '}
            · {duration(elapsed)}
          </strong>
        </summary>
        <div className="process-reference">
          分析 ID <code>{run.id}</code>
        </div>
        <div className="process-steps">
          {run.stages.map((step, index) => (
            <div key={index} className={'process-step ' + step.status}>
              <span className="step-symbol">
                {step.status === 'running' ? (
                  <LoaderCircle size={13} className="spinning" />
                ) : step.status === 'completed' ? (
                  <Check size={13} />
                ) : step.status === 'failed' ? (
                  <X size={13} />
                ) : (
                  <span />
                )}
              </span>
              <div>
                <strong>{step.name}</strong>
                <small>{step.note || '等待前序步骤'}</small>
              </div>
              <span>
                {step.status === 'skipped'
                  ? '未执行'
                  : step.status === 'pending'
                    ? '等待'
                    : step.status === 'running'
                      ? '执行中'
                      : duration(step.elapsedMs)}
              </span>
            </div>
          ))}
        </div>
        {run.error && <p className="small-note">{run.error}</p>}
      </details>
    );
  }
  function verdictLabel(verdict: string) {
    return (
      {
        credible: '存在可信线索 · 待人工复核',
        suspicious: '可疑线索 · 待核实',
        benign: '倾向正常 · 待人工复核',
        insufficient: '证据不足',
      }[verdict] || '待人工复核'
    );
  }
  function reviewText(r: AiReview) {
    const a = r.assessment;
    if (!a) return r.content;
    return `${a.category}\n判断：${verdictLabel(a.verdict)}\n攻击成功性：${a.attackSuccess === 'not_confirmed' ? '暂未找到成功证据' : '未确认'}\n\n依据：\n${a.reasons.map((reason, index) => `${index + 1}. ${reason.claim}\n引用：${reason.refs.join('；') || '未提供'}`).join('\n')}\n\n建议：\n${a.recommendations.map((v, index) => `${index + 1}. ${v}`).join('\n')}\n\n证据缺口：\n${a.evidenceGaps.join('\n')}\n\n限制：\n${a.notices.join('\n')}`;
  }
  async function askReview(r: AiReview) {
    const question = followupDrafts[r.id] || '';
    if (!question.trim() || !needNative()) return;
    await perform(
      '对话追问',
      async () => {
        await invoke<Followup>('followup_review', { reviewId: r.id, question });
        await refresh();
      },
      () => setFollowupDrafts((previous) => ({ ...previous, [r.id]: '' })),
    );
  }
  function FeedbackPanel(r: AiReview, e: Evidence) {
    const history = (workspace.reviewFeedback || []).filter(
      (f) => f.reviewId === r.id,
    );
    const saved = history.at(-1);
    const draft = feedbackDrafts[r.id] || {
      disposition: saved?.disposition || 'pending',
      feedback: saved?.feedback || '',
      notes: saved?.notes || '',
      actor: saved?.actor || '本地分析员',
    };
    const update = (patch: Partial<typeof draft>) =>
      setFeedbackDrafts((previous) => ({
        ...previous,
        [r.id]: { ...draft, ...patch },
      }));
    const commit = async (feedback = draft.feedback) => {
      if (!needNative()) return;
      if (
        (feedback === 'false_positive' ||
          draft.disposition === 'false_positive') &&
        !draft.notes.trim()
      ) {
        update({ feedback, disposition: 'false_positive' });
        setError('请填写标记误报的依据，再保存处置。');
        document.getElementById('feedback-' + r.id)?.focus();
        return;
      }
      await perform(
        '保存处置反馈',
        () =>
          invoke<Workspace>('save_review_feedback', {
            reviewId: r.id,
            ...draft,
            feedback,
          }),
        (w) => {
          setWorkspace(w);
          setFeedbackDrafts((previous) => {
            const next = { ...previous };
            delete next[r.id];
            return next;
          });
        },
      );
    };
    return (
      <section className="review-feedback">
        <div className="detail-head">
          <h3>处置备注与反馈</h3>
          <small>{history.length} 条已存记录</small>
        </div>
        <div className="feedback-controls">
          <label>
            处置
            <select
              aria-label={'处置-' + r.id}
              value={draft.disposition}
              onChange={(event) => update({ disposition: event.target.value })}
            >
              <option value="pending">待处置</option>
              <option value="investigate">继续调查</option>
              <option value="ignore">忽略</option>
              <option value="false_positive">误报</option>
            </select>
          </label>
          <label>
            记录人员
            <input
              aria-label={'处置人员-' + r.id}
              maxLength={100}
              value={draft.actor}
              onChange={(event) => update({ actor: event.target.value })}
            />
          </label>
        </div>
        <TextEditor
          label="处置备注"
          id={'feedback-' + r.id}
          aria-label={'处置备注-' + r.id}
          rows={3}
          maxLength={10000}
          value={draft.notes}
          onChange={(event) => update({ notes: event.target.value })}
          placeholder="填写处置依据、补充证据或标记误报的原因。"
        />
        <div className="feedback-actions">
          <div className="toolbar-group">
            <button
              className="button small"
              disabled={!!busy}
              onClick={() => commit('accurate')}
            >
              分析准确
            </button>
            <button
              className="button small"
              disabled={!!busy}
              onClick={() => commit('inaccurate')}
            >
              分析有误
            </button>
            <button
              className="button small"
              disabled={!!busy}
              onClick={() => commit('false_positive')}
            >
              标记误报
            </button>
          </div>
          <button
            className="button primary small"
            disabled={!!busy}
            onClick={() => commit()}
          >
            保存处置
          </button>
        </div>
        <p className="small-note">
          处置只记录人工决定，不会自动封禁。人员为人工填写；反馈不会改写原始 AI
          回答。
        </p>
        {saved && (
          <small className="saved-feedback">
            最近记录：{saved.actor} · {date(saved.recordedAt)} ·{' '}
            {saved.disposition} / {saved.feedback || '未评价'}
          </small>
        )}
        {history.length > 1 && (
          <details className="limitations">
            <summary>
              查看全部处置历史 <ChevronDown size={13} />
            </summary>
            {history.map((f) => (
              <p className="small-note" key={f.id}>
                {date(f.recordedAt)} · {f.actor} · {f.disposition} /{' '}
                {f.feedback}
                <br />
                {f.notes}
              </p>
            ))}
          </details>
        )}
      </section>
    );
  }
  function AiResults(e: Evidence) {
    const reviews = workspace.aiReviews.filter((r) => r.evidenceId === e.id);
    return (
      <div className="ai-results">
        <div className="ai-notice">
          <Info size={14} />
          <p>
            AI 研判以当前提供材料为依据。模型结论、百分比自评与 ATT&CK
            建议均需复核；分析过程展示实际执行步骤和耗时。
          </p>
        </div>
        {!reviews.length ? (
          <div className="ai-start">
            <h3>基于当前证据开始 AI 研判</h3>
            <p>先核对并删减发送材料，再调用你配置的模型。</p>
            <button
              className="button primary"
              disabled={!!busy}
              onClick={() => prepareAi(e)}
            >
              <Play size={14} />
              {aiConfig.endpoint ? '开始 AI 研判' : '配置模型后开始研判'}
            </button>
          </div>
        ) : (
          reviews.map((r) => {
            const a = r.assessment;
            const turns = (workspace.followups || []).filter(
              (f) => f.reviewId === r.id,
            );
            return (
              <article className="ai-review" key={r.id}>
                <div className="detail-head">
                  <div>
                    <h3>{a?.category || 'AI 原始回答 · 待复核'}</h3>
                    <small>
                      {r.model} · {date(r.createdAt)} · {duration(r.elapsedMs)}
                    </small>
                  </div>
                  <button
                    className="button small"
                    onClick={() =>
                      setNodeDraft({
                        caseId: e.caseId,
                        title: 'AI 研判：' + e.name,
                        body: `AI 研判草稿，待人工复核。\n模型：${r.model}\n生成：${r.createdAt}\n分析 ID：${r.runId || '旧版本未记录'}\n复核 ID：${r.id}\n\n${reviewText(r).slice(0, 12000)}\n\n实际发送材料节选：\n${r.material.slice(0, 10000)}\n[完整记录见该复核；阅读视图与原始归档区分保存]`,
                        time: localTime(),
                        actor: '本地分析员',
                        evidenceId: e.id,
                        findingId: null,
                      })
                    }
                  >
                    <Plus size={13} />
                    记录研判结论
                  </button>
                </div>
                {a ? (
                  <>
                    <div className="assessment-heading">
                      <strong>{verdictLabel(a.verdict)}</strong>
                      {a.confidence != null && (
                        <small>模型自评 {a.confidence}% · 未校准</small>
                      )}
                      <span>
                        成功性：
                        {a.attackSuccess === 'not_confirmed'
                          ? '暂未找到成功证据'
                          : '未确认'}
                      </span>
                    </div>
                    <section className="assessment-section">
                      <h3>原因与证据引用</h3>
                      {a.reasons.map((reason, index) => (
                        <div className="reason" key={index}>
                          <p>
                            {index + 1}. {reason.claim}
                          </p>
                          <div className="reason-refs">
                            {reason.refs.length ? (
                              reason.refs.map((ref) => (
                                <button
                                  key={ref}
                                  className="source-link"
                                  onClick={() => {
                                    const f = e.report.findings.find(
                                      (f) => f.id === ref || f.location === ref,
                                    );
                                    if (f) {
                                      setFindingId(f.id);
                                      setTab('findings');
                                    } else
                                      setTab(
                                        e.kind === 'http'
                                          ? 'http'
                                          : 'information',
                                      );
                                  }}
                                >
                                  <Link2 size={12} />
                                  {e.report.findings.find((f) => f.id === ref)
                                    ?.location || ref}
                                </button>
                              ))
                            ) : (
                              <small>未提供可定位引用；需补证</small>
                            )}
                          </div>
                        </div>
                      ))}
                    </section>
                    <section className="assessment-section">
                      <h3>建议</h3>
                      <ol>
                        {a.recommendations.map((v, i) => (
                          <li key={i}>{v}</li>
                        ))}
                      </ol>
                    </section>
                    <section className="assessment-section">
                      <h3>证据缺口</h3>
                      {a.evidenceGaps.length ? (
                        <ul>
                          {a.evidenceGaps.map((v, i) => (
                            <li key={i}>{v}</li>
                          ))}
                        </ul>
                      ) : (
                        <p className="small-note">
                          模型未列出缺口，不代表证据完整。
                        </p>
                      )}
                    </section>
                    {a.mitre.length > 0 && (
                      <section className="assessment-section">
                        <h3>ATT&CK 映射建议 · 未核验技术库</h3>
                        {a.mitre.map((m, i) => (
                          <p className="small-note" key={i}>
                            {m.id} · {m.name}
                            <br />
                            {m.basis}
                            <br />
                            引用：{m.refs.join('；')}
                          </p>
                        ))}
                      </section>
                    )}
                    <details className="limitations" open>
                      <summary>
                        判断限制 <ChevronDown size={13} />
                      </summary>
                      <ul>
                        {a.notices.map((v, i) => (
                          <li key={i}>{v}</li>
                        ))}
                      </ul>
                    </details>
                  </>
                ) : (
                  <>
                    <p className="small-note">
                      {r.schemaError ||
                        '旧版本没有结构化结论，仅保留原始回答。'}
                    </p>
                    <pre>{r.content}</pre>
                  </>
                )}
                {r.finishReason !== 'stop' && (
                  <p className="small-note">
                    完成标记为 {r.finishReason}，回答可能不完整。
                  </p>
                )}
                <details className="limitations">
                  <summary>
                    本次分析过程 <ChevronDown size={13} />
                  </summary>
                  {ProcessCard(e, r.runId)}
                </details>
                <details className="limitations">
                  <summary>
                    查看最终 Prompt <ChevronDown size={13} />
                  </summary>
                  {r.requestMessages?.length ? (
                    <>
                      <p className="small-note">
                        {r.promptVersion} · {r.endpoint} · 不包含 API Key
                      </p>
                      <pre>
                        {JSON.stringify(
                          {
                            model: r.model,
                            stream: false,
                            messages: r.requestMessages,
                          },
                          null,
                          2,
                        )}
                      </pre>
                    </>
                  ) : (
                    <p className="small-note">
                      旧版本未保存完整 Prompt；不使用现版本模板冒充历史输入。
                    </p>
                  )}
                </details>
                <details className="limitations">
                  <summary>
                    AI 分析输入数据与原始回答 <ChevronDown size={13} />
                  </summary>
                  <p className="small-note">调查问题：{r.question}</p>
                  <pre>{r.material}</pre>
                  <h3>模型原始回答</h3>
                  <pre>{r.content}</pre>
                </details>
                <section className="followup">
                  <h3>对话式追问</h3>
                  <p className="small-note">
                    基于本条复核的实际材料及最近三轮对话回答；历史模型回答不算新证据。
                  </p>
                  <div className="suggested-questions">
                    {[
                      '提取这条证据里的所有 IOC',
                      '判断是否误报，并说明依据',
                      '给出排查与取证步骤',
                      '生成检测规则建议并说明验证方法',
                    ].map((question) => (
                      <button
                        className="button small"
                        key={question}
                        onClick={() =>
                          setFollowupDrafts((previous) => ({
                            ...previous,
                            [r.id]: question,
                          }))
                        }
                      >
                        {question}
                      </button>
                    ))}
                  </div>
                  {turns.map((turn) => (
                    <article className="chat-turn" key={turn.id}>
                      <div className="chat-question">你：{turn.question}</div>
                      <small>
                        {turn.model} · {date(turn.createdAt)} ·{' '}
                        {duration(turn.elapsedMs)}
                      </small>
                      <pre>{turn.content}</pre>
                      <details className="limitations">
                        <summary>
                          本轮实际 Prompt <ChevronDown size={13} />
                        </summary>
                        <pre>
                          {JSON.stringify(
                            {
                              model: turn.model,
                              messages: turn.requestMessages,
                              stream: false,
                            },
                            null,
                            2,
                          )}
                        </pre>
                      </details>
                    </article>
                  ))}
                  <form
                    onSubmit={(event) => {
                      event.preventDefault();
                      askReview(r);
                    }}
                  >
                    <TextEditor
                      label="对话追问"
                      aria-label={'追问-' + r.id}
                      required
                      maxLength={2000}
                      rows={3}
                      disabled={!!busy}
                      value={followupDrafts[r.id] || ''}
                      onChange={(event) =>
                        setFollowupDrafts((previous) => ({
                          ...previous,
                          [r.id]: event.target.value,
                        }))
                      }
                      placeholder="向 AI 分析师追问；缺少证据时应说明限制。"
                    />
                    <button
                      className="button primary"
                      disabled={!!busy || !(followupDrafts[r.id] || '').trim()}
                    >
                      {busy === '对话追问' ? (
                        <LoaderCircle size={14} className="spinning" />
                      ) : (
                        <ArrowUpRight size={14} />
                      )}
                      发送
                    </button>
                  </form>
                </section>
                {FeedbackPanel(r, e)}
              </article>
            );
          })
        )}
      </div>
    );
  }
  function sourceOf(n: TimelineNode) {
    const e = workspace.evidence.find((e) => e.id === n.evidenceId);
    return { e, f: e?.report.findings.find((f) => f.id === n.findingId) };
  }
  function switchPage(next: Module) {
    if (next === 'reports') setReportEntry('home');
    setPage(next);
  }
  function Divider() {
    return (
      <div
        className="splitter"
        role="separator"
        aria-label="调整资料列表宽度"
        aria-orientation="vertical"
        tabIndex={0}
        aria-valuemin={160}
        aria-valuemax={300}
        aria-valuenow={listWidth}
        onKeyDown={(e) => {
          if (e.key === 'ArrowLeft') setListWidth((w) => Math.max(160, w - 10));
          if (e.key === 'ArrowRight')
            setListWidth((w) => Math.min(300, w + 10));
        }}
        onPointerDown={(e) => {
          e.currentTarget.setPointerCapture(e.pointerId);
        }}
        onPointerMove={(e) => {
          if (e.currentTarget.hasPointerCapture(e.pointerId)) {
            const left =
              e.currentTarget.parentElement!.getBoundingClientRect().left;
            setListWidth(Math.max(160, Math.min(300, e.clientX - left)));
          }
        }}
        onPointerUp={(e) => e.currentTarget.releasePointerCapture(e.pointerId)}
      >
        <GripVertical size={10} />
      </div>
    );
  }
  function SampleModes() {
    return (
      <div
        className="tabs sample-view-tabs"
        role="tablist"
        aria-label="样本分析方式"
      >
        {(
          [
            ['static', '静态结果'],
            ['pi', 'Pi 辅助逆向'],
            ['environment', '隔离环境'],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            role="tab"
            data-sample-view={id}
            aria-selected={sampleView === id}
            onClick={() => setSampleView(id)}
          >
            {label}
          </button>
        ))}
      </div>
    );
  }
  function Analysis() {
    const meta = moduleInfo[page];
    const editing =
      (page === 'http' && httpInputOpen) ||
      (page === 'triage' && alertInputOpen);
    const descriptions: Record<string, string> = {
      triage:
        '粘贴 NDR / WAF / EDR 告警文本或 JSON，保留原文、指标和证据边界。',
      http: '支持请求与响应文本、HAR 及报文对 JSON；成对关联分析，保留两侧来源与原文。',
      logs: '支持 Nginx / Apache、JSON 行和 Linux syslog / auth 日志。流式扫描，单文件上限 2 GiB；展示按规则抽样，保留完整命中计数和原文行号。',
      containers:
        '导入 docker inspect JSON，检查特权模式、host 网络 / PID、敏感挂载、capability 与用户配置。单文件上限 16 MB。',
      webshell:
        '禁网容器展开常量编码与压缩，核对来源、敏感调用和 Java 类线索。单文件上限 8 MB；分层深度分析覆盖前 1 MiB，不执行样本。',
      binary:
        '禁网容器提取 PE / ELF 头信息、节区、导入与字符串。单文件上限 128 MB；先构建隔离环境，不执行程序。',
    };
    return (
      <>
        <div className="page-head analysis-head">
          <div className="analysis-heading">
            <div>
              <h1>{meta.title}</h1>
              {current && !editing && (
                <p className="analysis-current-file" title={current.name}>
                  {current.name} · {size(current.size)}
                </p>
              )}
            </div>
            {(!current || editing) && (
              <span className="analysis-mode">
                <ShieldCheck size={12} />
                {page === 'webshell' || page === 'binary'
                  ? '隔离静态分析'
                  : '本地分析'}
              </span>
            )}
          </div>
          {(page === 'webshell' || page === 'binary') && SampleModes()}
          <div
            className="toolbar-group analysis-commands"
            role="toolbar"
            aria-label="分析操作"
          >
            {!!moduleFiles.length && !editing && (
              <button
                className="button analysis-files-toggle"
                aria-expanded={analysisFilesOpen}
                aria-controls="analysis-file-library"
                onClick={() => setAnalysisFilesOpen((open) => !open)}
              >
                <PanelLeft size={15} />
                资料 · {moduleFiles.length}
              </button>
            )}
            {((page === 'http' && moduleFiles.length > 0) ||
              (page === 'triage' && moduleFiles.length > 0)) && (
              <button
                className="button"
                data-action="toggle-input"
                disabled={!!busy}
                onClick={() =>
                  page === 'http'
                    ? setHttpEditor(!httpEditor)
                    : setAlertEditor(!alertEditor)
                }
              >
                {editing ? <ArrowLeft size={14} /> : <Plus size={14} />}
                {editing
                  ? '返回分析结果'
                  : page === 'http'
                    ? '新增报文对'
                    : '新增告警'}
              </button>
            )}
            <button
              className={`button ${!moduleFiles.length && !['http', 'triage'].includes(page) ? 'primary' : ''}`}
              disabled={!!busy}
              onClick={() => analyze(page)}
            >
              <Upload size={15} />
              {page === 'http' ? '导入 HAR / 报文文件' : '导入文件分析'}
            </button>
            <details
              className="analysis-help"
              onKeyDown={(event) => {
                if (event.key === 'Escape') event.currentTarget.open = false;
              }}
              onBlur={(event) => {
                if (!event.currentTarget.contains(event.relatedTarget as Node))
                  event.currentTarget.open = false;
              }}
            >
              <summary aria-label="分析说明" title="查看格式、分析范围与限制">
                <Info size={16} />
              </summary>
              <div>
                <strong>{meta.title}</strong>
                <p>{descriptions[page]}</p>
                <p>
                  原始材料与 SHA-256 本地归档，规则命中和 AI 判断均需复核。AI
                  调用前可检查并删减发送材料。
                </p>
              </div>
            </details>
          </div>
        </div>
        {page === 'http' && HttpComposer()}
        {page === 'triage' && AlertComposer()}
        {!moduleFiles.length ? (
          page === 'http' ? (
            <div className="http-empty">
              <p>在上方粘贴或加载请求和响应，或导入 HAR 批量查看交互。</p>
            </div>
          ) : page === 'triage' ? (
            <div className="http-empty">
              <p>
                粘贴原文后开始分析。设备标签与模型推断会与原始材料区分展示。
              </p>
            </div>
          ) : (
            <Empty
              icon={icons[page]}
              title={`导入文件，开始${meta.title}`}
              text={descriptions[page]}
            >
              <div className="empty-actions">
                <button
                  className="button primary"
                  disabled={!!busy}
                  onClick={() => analyze(page)}
                >
                  <Plus size={15} />
                  选择文件
                </button>
              </div>
              <div className="capability-line">
                <span>规则命中定位原文</span>
                <span>可加入事件时间线</span>
                <span>分析结果持久保存</span>
              </div>
            </Empty>
          )
        ) : (
          <div
            className="analysis-layout"
            data-files-open={analysisFilesOpen}
            style={{
              gridTemplateColumns: analysisFilesOpen
                ? `${listWidth}px 7px minmax(0,1fr)`
                : 'minmax(0,1fr)',
            }}
          >
            <aside
              className="file-pane"
              id="analysis-file-library"
              hidden={!analysisFilesOpen}
            >
              <div className="pane-label">
                本事件资料 <span>{moduleFiles.length}</span>
              </div>
              <div className="file-search">
                <input
                  aria-label="查找本模块资料"
                  placeholder="查找文件名或摘要"
                  value={fileQuery}
                  onChange={(e) => setFileQuery(e.target.value)}
                />
              </div>
              {moduleFiles
                .filter((e) =>
                  `${e.name} ${e.sha256}`
                    .toLowerCase()
                    .includes(fileQuery.trim().toLowerCase()),
                )
                .map((e) => (
                  <button
                    className={`file-row ${current?.id === e.id ? 'selected' : ''}`}
                    key={e.id}
                    onClick={() => setSelectedId(e.id)}
                  >
                    <FileText size={16} />
                    <span>
                      <strong>{e.name}</strong>
                      <small>
                        {size(e.size)} · {e.report.findings.length} 项命中
                      </small>
                    </span>
                  </button>
                ))}
            </aside>
            {analysisFilesOpen && Divider()}
            <section className="results-pane">
              {current && (
                <>
                  <div className="result-title">
                    <div
                      className="toolbar-group result-actions"
                      role="toolbar"
                      aria-label="当前证据操作"
                    >
                      <details
                        className="analysis-evidence-details"
                        onKeyDown={(event) => {
                          if (event.key === 'Escape')
                            event.currentTarget.open = false;
                        }}
                        onBlur={(event) => {
                          if (
                            !event.currentTarget.contains(
                              event.relatedTarget as Node,
                            )
                          )
                            event.currentTarget.open = false;
                        }}
                      >
                        <summary>
                          摘要与过程 <ChevronDown size={12} />
                        </summary>
                        <div className="analysis-evidence-popover">
                          <h3>文件与分析摘要</h3>
                          <code>{current.sha256}</code>
                          <div className="metrics">
                            {current.report.metrics.map((m) => (
                              <div key={m.label}>
                                <span>{m.label}</span>
                                <strong>{m.value}</strong>
                              </div>
                            ))}
                          </div>
                          {ProcessCard(current)}
                        </div>
                      </details>
                      <button
                        className="button small primary"
                        disabled={!!busy}
                        onClick={() => prepareAi(current)}
                      >
                        AI 复核
                      </button>
                      <button
                        className="button small"
                        disabled={!!busy}
                        onClick={() => draftNode(current)}
                      >
                        <Plus size={13} />
                        记录调查结论
                      </button>
                    </div>
                  </div>
                  <div className="result-tabs">
                    <div className="tabs">
                      {(
                        [
                          ...(page === 'http'
                            ? [['http', '请求 / 响应'] as const]
                            : []),
                          ...(page === 'logs'
                            ? [['log-timeline', '行为时间线'] as const]
                            : []),
                          ...(page === 'webshell'
                            ? [['webshell-layers', '分层分析'] as const]
                            : []),
                          ...(page === 'containers'
                            ? [['coverage', '检查覆盖'] as const]
                            : []),
                          ['findings', '发现与举证'],
                          ['information', '文件与信息'],
                          ['indicators', '关联指标'],
                          ['ai', 'AI 复核'],
                        ] as const
                      ).map(([t, label]) => (
                        <button
                          key={t}
                          aria-selected={tab === t}
                          onClick={() => setTab(t)}
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="result-content">
                    {tab === 'findings' && (
                      <label className="search-field">
                        <Search size={13} />
                        <input
                          aria-label="筛选发现"
                          value={query}
                          onChange={(e) => setQuery(e.target.value)}
                          placeholder="筛选规则或原文"
                        />
                      </label>
                    )}
                    {tab === 'log-timeline' && current.kind === 'logs' ? (
                      <LogTimelinePanel
                        key={current.id}
                        evidence={current}
                        onAI={(material, question) => {
                          void prepareAiMaterial(current, material, question);
                        }}
                        onRecorded={(w) => {
                          setWorkspace(w);
                          setPage('timeline');
                        }}
                      />
                    ) : tab === 'webshell-layers' &&
                      current.kind === 'webshell' ? (
                      <WebshellWorkbench
                        key={current.id}
                        evidence={current}
                        busy={!!busy}
                        onRecord={(f) => draftNode(current, f)}
                        onFinding={(id) => {
                          setFindingId(id);
                          setTab('findings');
                        }}
                        onAI={(material, question) => {
                          void prepareAiMaterial(current, material, question);
                        }}
                      />
                    ) : tab === 'coverage' && current.kind === 'containers' ? (
                      <CoveragePanel
                        key={current.id}
                        evidence={current}
                        onRefresh={setWorkspace}
                      />
                    ) : tab === 'http' && current.kind === 'http' ? (
                      HttpPackets(current)
                    ) : tab === 'findings' ? (
                      <>
                        {filtered.length ? (
                          <>
                            <div className="finding-table">
                              <div className="table-head">
                                <span>级别</span>
                                <span>规则 / 发现</span>
                                <span>证据位置</span>
                                <span>状态</span>
                              </div>
                              {filtered.map((f) => (
                                <button
                                  className={`finding-row ${finding?.id === f.id ? 'selected' : ''}`}
                                  key={f.id}
                                  onClick={() => setFindingId(f.id)}
                                >
                                  <span className={`severity ${f.level}`}>
                                    {f.level === 'high'
                                      ? '高'
                                      : f.level === 'medium'
                                        ? '中'
                                        : '低'}
                                  </span>
                                  <strong>{f.title}</strong>
                                  <span>{f.location}</span>
                                  <span className="review-label">待复核</span>
                                </button>
                              ))}
                            </div>
                            {finding && (
                              <div className="finding-detail">
                                <div className="detail-head">
                                  <h3>{finding.title}</h3>
                                  <button
                                    className="button small"
                                    disabled={!!busy}
                                    onClick={() => draftNode(current, finding)}
                                  >
                                    <Plus size={13} />
                                    加入事件
                                  </button>
                                </div>
                                <p>{finding.description}</p>
                                <div className="code-head">
                                  <span>
                                    {page === 'http'
                                      ? '举证片段（含解码视图）'
                                      : page === 'webshell' &&
                                          finding.location.startsWith('L')
                                        ? '派生层举证（来源保留）'
                                        : '原文举证'}{' '}
                                    / {finding.location}
                                  </span>
                                  <span>{current.name}</span>
                                </div>
                                <pre>{finding.excerpt}</pre>
                                <div className="recommendation">
                                  <Info size={14} />
                                  <p>{finding.remediation}</p>
                                </div>
                              </div>
                            )}
                          </>
                        ) : (
                          <div className="quiet-empty">
                            {query
                              ? '没有匹配的发现。'
                              : '本规则集未命中。结果不等于已证明文件或系统安全。'}
                          </div>
                        )}
                      </>
                    ) : tab === 'information' ? (
                      <div className="information">
                        <dl>
                          <dt>归档文件</dt>
                          <dd>{current.name}</dd>
                          <dt>SHA-256</dt>
                          <dd className="hash">
                            {current.sha256}
                            <button
                              className="icon-button"
                              aria-label="复制 SHA-256"
                              onClick={() =>
                                navigator.clipboard
                                  .writeText(current.sha256)
                                  .then(() => setStatus('摘要已复制'))
                                  .catch((e) => setError(String(e)))
                              }
                            >
                              <Copy size={13} />
                            </button>
                          </dd>
                          <dt>导入时间</dt>
                          <dd>{date(current.createdAt)}</dd>
                          <dt>文件大小</dt>
                          <dd>{size(current.size)}</dd>
                          <dt>分析引擎</dt>
                          <dd>{current.report.engine}</dd>
                        </dl>
                        <dl>
                          {current.report.metrics.map((m) => (
                            <React.Fragment key={m.label}>
                              <dt>{m.label}</dt>
                              <dd>{m.value}</dd>
                            </React.Fragment>
                          ))}
                        </dl>
                        {current.report.details.map((d) => (
                          <div className="detail-value" key={d.label}>
                            <h3>{d.label}</h3>
                            <pre>{d.value || '未提取到内容'}</pre>
                          </div>
                        ))}
                      </div>
                    ) : tab === 'ai' ? (
                      AiResults(current)
                    ) : (
                      <div className="indicator-table">
                        {current.report.indicators.length ? (
                          current.report.indicators.map((i) => (
                            <div
                              className="indicator-row"
                              key={i.kind + i.value}
                            >
                              <span>{i.kind}</span>
                              <code>{i.value}</code>
                              <small>{i.source}</small>
                              {[
                                'ip',
                                'domain',
                                'md5',
                                'sha1',
                                'sha256',
                              ].includes(i.kind) && (
                                <button
                                  onClick={() => {
                                    setIntelQuerySeed({
                                      caseId: current.caseId,
                                      kind: i.kind,
                                      value: i.value,
                                      evidenceId: current.id,
                                    });
                                    setPage('knowledge');
                                  }}
                                >
                                  查询情报
                                </button>
                              )}
                            </div>
                          ))
                        ) : (
                          <p className="quiet-empty">
                            本次分析未生成结构化指标，可在情报溯源中从文本提取。
                          </p>
                        )}
                      </div>
                    )}
                    {tab !== 'webshell-layers' && (
                      <details className="limitations">
                        <summary>
                          <Info size={13} />
                          分析范围与限制 <ChevronDown size={13} />
                        </summary>
                        <ul>
                          {current.report.warnings.map((w) => (
                            <li key={w}>{w}</li>
                          ))}
                        </ul>
                      </details>
                    )}
                  </div>
                </>
              )}
            </section>
          </div>
        )}
      </>
    );
  }
  function Timeline() {
    return (
      <>
        <div className="page-head">
          <div>
            <div className="eyebrow">调查管理 / 记录与举证</div>
            <h1>事件时间线</h1>
            <p>
              {activeCase?.title} ·
              仅本事件。发生时间与录入时间分开保存，人员指令与设备结果分别记录。
            </p>
          </div>
          <button
            className="button primary"
            disabled={!!busy}
            onClick={() => draftNode()}
          >
            <Plus size={15} />
            新增节点
          </button>
        </div>
        <ResponseActionsPanel
          key={workspace.activeCase}
          workspace={workspace}
          onChange={setWorkspace}
        />
        {!workspace.nodes.length ? (
          <Empty
            icon={Route}
            title="把分析发现和实际处置串起来"
            text="在任意分析结果中选择“加入事件”，或手工记录人员指令。每个节点都可以关联证据、附入截图并填写图注。"
          >
            <button className="button" onClick={() => draftNode()}>
              新增人工记录
            </button>
          </Empty>
        ) : (
          <div className="timeline-list">
            {timelineRows.map((n) => {
              const { e, f } = sourceOf(n);
              return (
                <article className="timeline-node" key={n.id}>
                  <div className="node-time">
                    <time>{date(n.occurredAt)}</time>
                    <small>UTC+8</small>
                  </div>
                  <div className="node-body">
                    <div className="detail-head">
                      <h2>{n.title}</h2>
                      <button
                        className="button small"
                        disabled={!!busy}
                        onClick={() => editNode(n)}
                      >
                        编辑节点
                      </button>
                      <label className="check">
                        <input
                          type="checkbox"
                          checked={n.included}
                          disabled={!!busy}
                          onChange={(event) =>
                            perform(
                              '更新报告选择',
                              () =>
                                invoke<Workspace>('toggle_node', {
                                  id: n.id,
                                  included: event.target.checked,
                                }),
                              setWorkspace,
                            )
                          }
                        />
                        纳入报告
                      </label>
                    </div>
                    <div className="node-meta">
                      {n.actor} · 录入 {date(n.recordedAt)}
                    </div>
                    <p className="body-text">{n.body}</p>
                    <div className="proof-columns">
                      <div>
                        <h3>举证来源</h3>
                        {e ? (
                          <>
                            <button
                              className="source-link"
                              onClick={() => {
                                setSelectedId(e.id);
                                setPage(e.kind as Module);
                              }}
                            >
                              <Link2 size={13} />
                              {e.name}
                              <ArrowUpRight size={12} />
                            </button>
                            <small className="hash">SHA-256 {e.sha256}</small>
                            {f && (
                              <>
                                <div className="code-head">{f.location}</div>
                                <pre>{f.excerpt}</pre>
                              </>
                            )}
                          </>
                        ) : (
                          <div className="placeholder-note">
                            人工记录，尚未关联原始证据。
                          </div>
                        )}
                      </div>
                      <div>
                        <div className="detail-head">
                          <h3>截图举证</h3>
                          <button
                            className="button small"
                            disabled={!!busy}
                            onClick={() => attach(n)}
                          >
                            <ImagePlus size={13} />
                            附图
                          </button>
                          <button
                            className="button small"
                            disabled={!!busy}
                            onClick={() =>
                              setShotDraft({
                                nodeId: n.id,
                                path: '',
                                caption: '',
                              })
                            }
                          >
                            粘贴截图
                          </button>
                        </div>
                        {n.screenshots.length ? (
                          n.screenshots.map((shot) => (
                            <ShotImage key={shot.id} shot={shot} />
                          ))
                        ) : (
                          <button
                            className="screenshot-placeholder"
                            onClick={() =>
                              setShotDraft({
                                nodeId: n.id,
                                path: '',
                                caption: '',
                              })
                            }
                          >
                            <ImagePlus size={20} />
                            <span>预留截图位置</span>
                            <small>点击后可粘贴截图或选择原图，填写图注</small>
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                </article>
              );
            })}
            {timelineTotal > 300 && (
              <div className="timeline-pagination">
                <button
                  className="button small"
                  disabled={timelineOffset === 0}
                  onClick={() =>
                    setTimelineOffset(Math.max(0, timelineOffset - 100))
                  }
                >
                  上一页
                </button>
                <span>
                  {timelineOffset + 1}–
                  {Math.min(
                    timelineOffset + timelineRows.length,
                    timelineTotal,
                  )}{' '}
                  / {timelineTotal}
                </span>
                <button
                  className="button small"
                  disabled={timelineOffset + 100 >= timelineTotal}
                  onClick={() => setTimelineOffset(timelineOffset + 100)}
                >
                  下一页
                </button>
              </div>
            )}
          </div>
        )}
      </>
    );
  }
  function Reports() {
    return (
      <>
        <ReportEditor
          key={`${workspace.activeCase}:${reportReload}:${reportEntry}`}
          entry={reportEntry}
          workspace={workspace}
          busy={!!busy || exportChoosing}
          exports={reportExports}
          onExport={exportReport}
          onPrint={() => {
            if (needNative())
              void perform('打开系统打印', () => invoke('print_report'));
          }}
          onEdit={editNode}
          onSource={(node) => {
            const source = workspace.evidence.find(
              (e) => e.id === node.evidenceId,
            );
            if (!source) return;
            pendingFinding.current = node.findingId || '';
            pendingResultTab.current = node.findingId ? 'findings' : null;
            setSelectedId(source.id);
            setHttpEditor(false);
            setAlertEditor(false);
            setPage(source.kind as Module);
          }}
          onNew={() => draftNode()}
          onPaste={(node) =>
            setShotDraft({ nodeId: node.id, path: '', caption: '' })
          }
          onAttach={attach}
          onToggle={(node, included) => {
            void perform(
              '更新报告选择',
              () => invoke<Workspace>('toggle_node', { id: node.id, included }),
              setWorkspace,
            );
          }}
          renderShot={(shot, eager) => (
            <ShotImage key={shot.id} shot={shot} eager={eager} />
          )}
        />
      </>
    );
  }
  function Settings() {
    return (
      <section className="desktop-settings" data-settings-view={settingsTab}>
        <div className="page-head">
          <div>
            <div className="eyebrow">客户端 / 偏好设置</div>
            <h1>AI 与设置</h1>
            <p>模型连接、外观与客户端偏好，统一在本机管理。</p>
          </div>
        </div>
        <div className="settings-layout">
          <nav className="settings-navigation" aria-label="设置分类">
            {[
              ['model', '模型连接'],
              ['intelligence', '情报服务'],
              ['privacy', '隐私与外发'],
              ['appearance', '外观体验'],
              ['maintenance', '数据与维护'],
              ['logs', '运行日志'],
              ['features', '功能状态'],
              ['about', '关于与许可'],
            ].map(([id, label]) => (
              <button
                key={id}
                aria-current={settingsTab === id ? 'page' : undefined}
                onClick={() => setSettingsTab(id)}
              >
                {label}
              </button>
            ))}
          </nav>
          <section className="settings-section" data-settings="appearance">
            <h2>外观与启动</h2>
            <div className="setting-row">
              <div>
                <strong>主题</strong>
                <p>手动选择会持久保存。</p>
              </div>
              {ThemeControl()}
            </div>
            <div className="setting-row">
              <div>
                <strong>启动动画</strong>
                <p>安全帽鸭子与真实加载阶段 · 支持收起动效和系统减少动态效果</p>
              </div>
              <label className="check">
                <input
                  type="checkbox"
                  checked={splashEnabled}
                  onChange={(e) => {
                    setSplashEnabled(e.target.checked);
                    localStorage.setItem(
                      'gaga.splash',
                      e.target.checked ? 'yes' : 'no',
                    );
                  }}
                />
                启用
              </label>
            </div>
            <button
              className="button"
              onClick={() => {
                splashStarted.current = performance.now();
                setStartupReplay(true);
                setStartupReduced(false);
                setSplash(true);
              }}
            >
              <Play size={14} />
              重播启动动画
            </button>
          </section>
          <section className="settings-section" data-settings="model">
            <div className="model-config-heading">
              <div>
                <h2>官方模型连接</h2>
                <p>四家官方服务 · 密钥按服务分别保存</p>
              </div>
              <span className="catalog-date">
                适配目录 {aiCatalog.verifiedAt}
              </span>
            </div>
            {aiConfig.validationError && (
              <p className="small-note" role="alert">
                {aiConfig.validationError}
              </p>
            )}
            <form
              className="api-form"
              onSubmit={(e) => {
                e.preventDefault();
                saveAi();
              }}
            >
              <div className="provider-model-fields">
                <label>
                  模型服务商
                  <select
                    aria-label="模型服务商"
                    value={apiProvider}
                    onChange={(e) => {
                      const p = aiCatalog.providers.find(
                        (p) => p.id === e.target.value,
                      )!;
                      const saved = aiProfiles.find((c) => c.provider === p.id);
                      setApiProvider(p.id);
                      setApiModel(saved?.model || p.models[0].id);
                      setApiKey('');
                    }}
                  >
                    {aiCatalog.providers.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  分析模型
                  <select
                    aria-label="分析模型"
                    value={apiModel}
                    onChange={(e) => setApiModel(e.target.value)}
                  >
                    {selectedProvider.models.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.name}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="official-endpoint">
                <ShieldCheck size={15} />
                <div>
                  <span>官方 API 地址</span>
                  <code aria-label="模型 API 基础地址">{apiEndpoint}</code>
                </div>
                <span className="endpoint-lock">固定</span>
              </div>
              <p className="provider-note">{selectedProvider.note}</p>
              <label>
                API Key
                <input
                  aria-label="模型 API Key"
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  maxLength={4096}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder={
                    selectedProfile?.hasKey
                      ? '已存入系统凭据；留空复用'
                      : '输入此服务的 API Key'
                  }
                />
              </label>
              <div className="model-actionbar">
                <button className="button primary" disabled={!!busy}>
                  保存并使用
                </button>
                <button
                  className="button"
                  type="button"
                  disabled={!!busy || aiDirty || !!apiKey || !aiConfig.endpoint}
                  onClick={() => {
                    if (!needNative()) return;
                    perform(
                      '测试官方模型连接',
                      () =>
                        invoke<AiConnectionTest>('test_ai_connection', {
                          revision: aiConfig.revision,
                        }),
                      (r) => setConnectionTests((v) => [r, ...v].slice(0, 20)),
                    );
                  }}
                >
                  {busy === '测试官方模型连接' ? (
                    <LoaderCircle size={14} className="spinning" />
                  ) : (
                    <Activity size={14} />
                  )}
                  测试连接
                </button>
                {selectedProfile?.hasKey && (
                  <button
                    className="button text-button"
                    type="button"
                    disabled={!!busy}
                    onClick={() => saveAi(true)}
                  >
                    删除此服务密钥
                  </button>
                )}
                <span>
                  {aiDirty || apiKey
                    ? '有未保存的配置'
                    : aiConfig.endpoint
                      ? '当前配置已保存'
                      : '尚未配置'}
                </span>
              </div>
              <p className="small-note">
                先保存，再测试。测试仅发送固定验证短句，最多 2048 输出 token、45
                秒超时，可能产生少量 API 费用。正式研判前可预览和删减发送材料。
              </p>
            </form>
            <div className="connection-test-panel" aria-live="polite">
              <div className="connection-test-heading">
                <h3>连接验证</h3>
                <span>最近 20 次 · 本地保存</span>
              </div>
              {connectionTests.filter((t) => t.provider === apiProvider)
                .length ? (
                connectionTests
                  .filter((t) => t.provider === apiProvider)
                  .slice(0, 5)
                  .map((t) => (
                    <div
                      className="connection-test-result"
                      key={t.id}
                      data-success={t.success}
                    >
                      {t.success ? (
                        <Check size={16} />
                      ) : (
                        <AlertCircle size={16} />
                      )}
                      <div>
                        <strong>
                          {t.success ? '连接成功' : '连接失败'} · {t.model}
                        </strong>
                        <p>{t.success ? t.reply : t.error}</p>
                        <small>
                          {new Date(t.createdAt).toLocaleString()} ·{' '}
                          {t.elapsedMs} ms
                          {t.configRevision !== aiConfig.revision
                            ? ' · 历史配置'
                            : ''}
                        </small>
                      </div>
                    </div>
                  ))
              ) : (
                <p className="test-empty">
                  尚未测试此服务。测试会实际请求所选官方模型。
                </p>
              )}
            </div>
            <p className="setting-note">
              {page === 'webshell' || page === 'binary'
                ? '隔离静态分析'
                : '本地分析'}
              独立运行。手动复核发送前可预览材料；自动 AI 与 Pi
              工具结果的外发范围见“隐私与外发”，可在那里锁定新的模型请求。
              动态行为页提供 Linux 容器观察和 Windows CAPE 连接器。
            </p>
          </section>
          <section className="settings-section" data-settings="logs">
            {settingsTab === 'logs' && <RuntimeLogs />}
          </section>
          <section className="settings-section" data-settings="intelligence">
            {settingsTab === 'intelligence' && <ThreatIntelSettings />}
          </section>
          <section className="settings-section" data-settings="features">
            <CapabilityMatrix onNavigate={setPage} />
          </section>
          <section className="settings-section" data-settings="privacy">
            <PrivacyPanel />
          </section>
          <section className="settings-section" data-settings="maintenance">
            <MaintenancePanel workspace={workspace} busy={busy} />
          </section>
          <section className="settings-section" data-settings="about">
            <div className="about-brand">
              <img src="/gaga-icon.svg" />
              <div>
                <h2>嘎嘎安全助手</h2>
                <p>
                  {release.version} {release.stage} · J4team
                </p>
                <p>{release.positioning}</p>
              </div>
            </div>
            <p className="setting-note">
              源码公开，非商用免费；商用须获 J4team 授权。
              <br />
              本版证据与数据库在本机明文保存，尚未实现证据库加密或团队身份认证。
            </p>
            {workspace.dataDir && (
              <>
                <h3>本地数据目录</h3>
                <code className="data-path">{workspace.dataDir}</code>
              </>
            )}
          </section>
        </div>
      </section>
    );
  }
  function ThemeControl() {
    return (
      <label className="theme-control">
        <Monitor size={14} />
        <select
          aria-label="主题模式"
          value={theme}
          onChange={(e) => setTheme(e.target.value as Theme)}
        >
          <option value="system">跟随系统</option>
          <option value="light">浅色</option>
          <option value="dark">深色</option>
        </select>
      </label>
    );
  }
  function Intel() {
    return (
      <>
        <div className="page-head">
          <div>
            <div className="eyebrow">分析工具 / 指标整理</div>
            <h1>情报溯源</h1>
            <p>
              先提取和整理指标；可在「威胁情报 → 在线查询」核对官方服务结果。
            </p>
          </div>
          <button
            className="button primary"
            disabled={!!busy || !iocText.trim()}
            onClick={() => {
              if (needNative())
                perform(
                  '提取指标',
                  () =>
                    invoke<Indicator[]>('extract_indicators', {
                      text: iocText,
                    }),
                  setIndicators,
                );
            }}
          >
            <Radar size={15} />
            提取指标
          </button>
        </div>
        <div className="intel-layout">
          <section>
            <div className="pane-label">原始线索文本</div>
            <TextEditor
              label="原始线索文本"
              size="large"
              code
              className="ioc-input"
              aria-label="线索文本"
              value={iocText}
              onChange={(e) => setIocText(e.target.value)}
              placeholder="粘贴 IP、域名、URL、Hash 或日志片段…"
            />
            <p className="small-note">
              提取 IPv4、URL、MD5 / SHA1 / SHA256
              与域名候选。域名候选需人工排除文件名等误匹配。
            </p>
          </section>
          <section>
            <div className="pane-label">
              提取结果 <span>{indicators.length}</span>
            </div>
            {indicators.length ? (
              <div className="indicator-table">
                {indicators.map((i) => (
                  <div className="indicator-row" key={i.kind + i.value}>
                    <span>{i.kind}</span>
                    <code>{i.value}</code>
                    <small>{i.source}</small>
                  </div>
                ))}
              </div>
            ) : (
              <div className="quiet-empty">提取后在此显示指标。</div>
            )}
            <div className="service-status">
              <Info size={15} />
              <p>
                微步、RDAP / WHOIS 尚未接入；持久黑白名单和 IOC
                来源关联请使用「黑白名单」与「本地情报库」。
              </p>
            </div>
          </section>
        </div>
      </>
    );
  }
  const nav = (modules: Module[]) =>
    modules.map((m) => {
      const Icon = icons[m];
      return (
        <button
          className={`nav-item ${page === m ? 'active' : ''}`}
          key={m}
          data-module={m}
          aria-label={moduleInfo[m].title}
          title={moduleInfo[m].title}
          aria-current={page === m ? 'page' : undefined}
          onClick={() => switchPage(m)}
        >
          <Icon size={17} strokeWidth={1.65} />
          <span>{m === 'binary' ? '样本静态分析' : moduleInfo[m].title}</span>
          {m === 'timeline' && workspace.nodes.length > 0 && (
            <small>{workspace.nodes.length}</small>
          )}
        </button>
      );
    });
  return (
    <>
      {startup.dataReady && (
        <div
          className="desktop-app"
          aria-label="嘎嘎安全助手桌面客户端"
          inert={startupVisible}
        >
          <header className="desktop-commandbar">
            <div className="brand">
              <img src="/gaga-icon.svg" alt="安全帽鸭子标志" />
              <strong>嘎嘎安全助手</strong>
              <small>J4team</small>
            </div>
            <PrimaryNavigation page={page} onNavigate={switchPage} />
            <div className="commandbar-actions">
              <ToolLauncher page={page} onNavigate={switchPage} />
              {nav(['lan', 'environment', 'settings'])}
            </div>
          </header>
          <div className="workbench">
            <header className="app-toolbar">
              <div className="case-switcher">
                <FolderOpen size={15} />
                <select
                  aria-label="当前事件"
                  value={workspace.activeCase}
                  disabled={!!busy}
                  onChange={(e) => {
                    if (needNative())
                      perform(
                        '切换事件',
                        () =>
                          invoke<Workspace>('switch_case', {
                            id: e.target.value,
                          }),
                        (w) => {
                          setWorkspace(w);
                          setSelectedId('');
                        },
                      );
                  }}
                >
                  {workspace.cases.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.title}
                    </option>
                  ))}
                </select>
                <button
                  className="icon-button"
                  aria-label="新建事件"
                  disabled={!!busy}
                  onClick={() => setCaseModal(true)}
                >
                  <Plus size={15} />
                </button>
              </div>
              <div className="toolbar-right">
                <AiPrivacyIndicator
                  onOpen={() => {
                    setSettingsTab('privacy');
                    setPage('settings');
                  }}
                />
                {currentProvider && (
                  <select
                    className="quick-model-select"
                    aria-label="当前分析模型"
                    value={aiConfig.model}
                    disabled={!!busy}
                    onChange={(e) => {
                      if (!needNative()) return;
                      const model = e.target.value;
                      perform(
                        '切换分析模型',
                        () =>
                          invoke<AiConfig>('save_ai_config', {
                            baseUrl: aiConfig.endpoint,
                            model,
                            apiKey: '',
                            removeKey: false,
                          }),
                        (c) => {
                          setAiConfig(c);
                          setApiProvider(c.provider);
                          setApiModel(c.model);
                          setApiKey('');
                          setAiProfiles((p) => [
                            ...p.filter((p) => p.provider !== c.provider),
                            c,
                          ]);
                        },
                      );
                    }}
                  >
                    {currentProvider.models.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.name}
                      </option>
                    ))}
                  </select>
                )}
                <button
                  className="model-state"
                  onClick={() => setPage('settings')}
                >
                  <span />
                  {busy.includes('AI') || busy === '对话追问'
                    ? `${currentProvider ? '模型' : aiConfig.model || '模型'} 分析中`
                    : aiConfig.endpoint
                      ? `${currentProvider ? '' : aiConfig.model + ' '}空闲`
                      : 'AI 待配置'}
                </button>
                <span className="toolbar-divider" />
                {ThemeControl()}
              </div>
            </header>
            <ToolNavigation
              page={page}
              onNavigate={switchPage}
              nodeCount={workspace.nodes.length}
            />
            {!native && (
              <div className="preview-banner">
                <Info size={13} />
                浏览器界面预览 · 真实分析与持久保存请使用桌面客户端
              </div>
            )}
            <div
              className={`content-scroll module-${page}`}
              data-workspace={
                analysisModules.includes(page) ? 'analysis' : undefined
              }
              data-editing={
                (page === 'http' && httpInputOpen) ||
                (page === 'triage' && alertInputOpen)
              }
            >
              {error && (
                <div className="error-banner" role="alert">
                  <AlertCircle size={15} />
                  <FailureDetails
                    message={error}
                    stage={moduleInfo[page].title}
                  />
                  <button
                    className="icon-button"
                    aria-label="关闭提示"
                    onClick={() => setError('')}
                  >
                    <X size={14} />
                  </button>
                </div>
              )}
              {page === 'dashboard' ? (
                <Dashboard
                  workspace={workspace}
                  busy={busy}
                  onNavigate={setPage}
                  onRecord={async (record: DashboardRecord) => {
                    if (!needNative()) return;
                    await perform('打开调查记录', async () => {
                      const w =
                        record.caseId === workspace.activeCase
                          ? workspace
                          : await invoke<Workspace>('switch_case', {
                              id: record.caseId,
                            });
                      setWorkspace(w);
                      const target =
                        record.module in moduleInfo
                          ? (record.module as Module)
                          : 'evidence';
                      pendingResultTab.current =
                        record.category === 'review' ? 'ai' : null;
                      setSelectedId(record.evidenceId || '');
                      setHttpEditor(false);
                      setAlertEditor(false);
                      setPage(target);
                    });
                  }}
                />
              ) : (
                  [
                    'assets',
                    'flows',
                    'agents',
                    'knowledge',
                    'lists',
                    'samples',
                    'environment',
                  ] as string[]
                ).includes(page) ? (
                <PlatformPanel
                  querySeed={intelQuerySeed}
                  page={page as PlatformPage}
                  workspace={workspace}
                  busy={busy}
                  perform={perform}
                  refresh={refresh}
                  aiConfig={aiConfig}
                  onSettings={() => {
                    setSettingsTab('intelligence');
                    setPage('settings');
                  }}
                  onIsolation={() => {
                    setPage('binary');
                    setSampleView('environment');
                  }}
                  onEvidence={(id) => {
                    setSelectedId(id);
                    setAlertEditor(false);
                    setPage('triage');
                    setTab('ai');
                  }}
                  renderShot={(shot) => <ShotImage key={shot.id} shot={shot} />}
                  onRecord={(id, title, body, focusScreenshot) =>
                    setNodeDraft({
                      caseId:
                        workspace.evidence.find((e) => e.id === id)?.caseId ||
                        workspace.activeCase,
                      title,
                      body,
                      time: localTime(),
                      actor: '本地分析员',
                      evidenceId: id,
                      findingId: null,
                      focusScreenshot,
                    })
                  }
                />
              ) : page === 'lan' ? (
                <LanPanel />
              ) : page === 'cases' ? (
                <CasesPanel
                  active={workspace.activeCase}
                  onNew={() => setCaseModal(true)}
                  onUpdate={setWorkspace}
                  onOpen={(id) => {
                    void perform(
                      '打开事件',
                      () => invoke<Workspace>('switch_case', { id }),
                      (w) => {
                        setWorkspace(w);
                        setSelectedId('');
                        setPage('dashboard');
                      },
                    );
                  }}
                />
              ) : page === 'binary' || page === 'webshell' ? (
                <div className="sample-workspace">
                  {sampleView !== 'static' && SampleModes()}
                  {sampleView === 'static' ? (
                    Analysis()
                  ) : (
                    <ReversePanel
                      key={workspace.activeCase}
                      view={sampleView}
                      workspace={workspace}
                      preferredId={selectedId}
                      onRefresh={refresh}
                      onEnvironment={() => setSampleView('environment')}
                      onSettings={() => setPage('settings')}
                      onRecord={(job) =>
                        setNodeDraft({
                          caseId: job.caseId,
                          title: 'AI 隔离逆向分析 · 待复核',
                          body: `样本 SHA-256：${job.sampleSha256}\n任务 ID：${job.id}\n镜像：${job.imageId}\n容器清理：${job.cleanupConfirmed ? '已确认' : '待确认'}\n\n${job.content}\n\n工具工件：\n${job.artifacts.map((a) => `${a.tool} · ${a.id} · SHA-256 ${a.sha256}`).join('\n')}\n\n静态分析未执行样本，结论待人工复核。`,
                          time: localTime(),
                          actor: '本地分析员',
                          evidenceId: job.reportEvidenceId,
                          findingId: null,
                        })
                      }
                    />
                  )}
                </div>
              ) : analysisModules.includes(page) ? (
                Analysis()
              ) : page === 'timeline' ? (
                Timeline()
              ) : page === 'reports' ? (
                Reports()
              ) : page === 'settings' ? (
                Settings()
              ) : page === 'intel' ? (
                Intel()
              ) : page === 'sandbox' ? (
                <SandboxPanel
                  workspace={workspace}
                  busy={busy}
                  perform={perform}
                  refresh={refresh}
                  onReview={(e) => {
                    setPage('triage');
                    setSelectedId(e.id);
                    setAlertEditor(false);
                    prepareAi(e);
                  }}
                  onRecord={(job: SandboxJob) =>
                    setNodeDraft({
                      caseId: job.caseId,
                      title: '动态行为观察 · 待人工复核',
                      body: `任务 ID：${job.id}\n环境：${job.provider}\n记录状态：${job.state}\n退出码：${job.exitCode ?? '未提供'}\n临时容器清理：${job.cleanupConfirmed ? '已确认' : '未确认 / 由沙箱端管理'}\n\n执行记录：\n${job.events.map((e) => `${e.time} ${e.text}`).join('\n')}\n\n行为节选：\n${job.tracePreview.slice(0, 8000)}\n\n完整记录见关联行为报告。采集受环境与反分析影响，需复核并补充举证截图。`,
                      time: localTime(),
                      actor: '本地分析员',
                      evidenceId: job.reportEvidenceId,
                      findingId: null,
                    })
                  }
                />
              ) : (
                <>
                  <div className="page-head">
                    <div>
                      <div className="eyebrow">调查管理 / 本地归档</div>
                      <h1>证据资料</h1>
                      <p>
                        {workspace.evidence.length} 份原始文件，保存 SHA-256
                        和对应分析结果。
                      </p>
                    </div>
                  </div>
                  {workspace.evidence.length ? (
                    <EvidenceLibrary
                      key={workspace.activeCase}
                      workspace={workspace}
                      onOpen={(e) => {
                        setSelectedId(e.id);
                        setPage(e.kind as Module);
                        setHttpEditor(false);
                        setAlertEditor(false);
                      }}
                    />
                  ) : (
                    <Empty
                      icon={Database}
                      title="证据库还没有文件"
                      text="从顶部选择分析工具导入文件，原始文件副本、摘要与分析结果会保存到当前事件。"
                    />
                  )}
                </>
              )}
            </div>
            <LocalAnalysisPanel
              model={analysisTasks}
              cases={workspace.cases}
              onOpen={(job) => {
                void perform('打开分析结果', async () => {
                  const w =
                    job.caseId === workspace.activeCase
                      ? await invoke<Workspace>('get_workspace')
                      : await invoke<Workspace>('switch_case', {
                          id: job.caseId,
                        });
                  setWorkspace(w);
                  setSelectedId(job.evidenceId || '');
                  setPage(job.kind as Module);
                  setSampleView('static');
                  analysisTasks.setOpened(false);
                });
              }}
            />
            <footer className="status-bar">
              <span>
                {busy ? (
                  <LoaderCircle size={12} className="spinning" />
                ) : (
                  <span className="status-dot" />
                )}
                {reportExports.active ? (
                  <button
                    className="report-export-status"
                    data-action="show-report-export"
                    onClick={() => {
                      setReportEntry('delivery');
                      setReportReload((v) => v + 1);
                      setPage('reports');
                    }}
                  >
                    报告导出中 · 查看进度
                  </button>
                ) : (
                  busy || status
                )}
              </span>
              <button
                className="local-task-status"
                data-action="show-local-analysis"
                onClick={() => {
                  if (!analysisTasks.opened && analysisTasks.active)
                    analysisTasks.setSelected(analysisTasks.active.id);
                  analysisTasks.setOpened(!analysisTasks.opened);
                }}
              >
                {analysisTasks.active ? (
                  <LoaderCircle size={12} className="spinning" />
                ) : (
                  <Activity size={12} />
                )}
                {analysisTasks.active
                  ? '本地分析中 · 查看进度'
                  : `分析任务${analysisTasks.jobs.length ? ` · ${analysisTasks.jobs.length}` : ''}`}
              </button>
              <span>
                {workspace.evidence.length} 份证据{' '}
                <span className="status-sep">/</span> {workspace.nodes.length}{' '}
                个节点 <span className="status-sep">/</span> J4team
              </span>
            </footer>
            {statusToast && !startupVisible && (
              <div
                className="status-toast"
                data-tone={statusToast.endsWith('失败') ? 'error' : 'success'}
                role="status"
                aria-live="polite"
              >
                <span className="status-toast-mark" aria-hidden="true">
                  {statusToast.endsWith('失败') ? (
                    <AlertCircle size={14} />
                  ) : (
                    <Check size={14} />
                  )}
                </span>
                <span>{statusToast}</span>
              </div>
            )}
          </div>
        </div>
      )}
      {startupVisible && (
        <StartupScreen
          snapshot={startup.snapshot}
          animate={startupAnimate}
          replay={startupReplay}
          retryable={startup.retryable}
          onRetry={startup.retry}
          onClose={() => setSplash(false)}
          onReduce={() => {
            setStartupReduced(true);
            setSplash(false);
          }}
        />
      )}
      {aiDraft && (
        <Modal
          title="发送材料进行 AI 研判"
          busy={!!busy}
          onClose={() => setAiDraft(null)}
        >
          <form
            className="modal wide"
            onSubmit={(e) => {
              e.preventDefault();
              if (!needNative()) return;
              const payload = aiDraft;
              setAiDraft(null);
              setTab('ai');
              perform(
                'AI 研判中',
                async () => {
                  await invoke<AiReview>('review_with_ai', payload);
                  await refresh();
                },
                () => {
                  setAiDraft(null);
                  setTab('ai');
                },
              );
            }}
          >
            <div className="modal-title">
              <h2>发送材料进行 AI 研判</h2>
              <button
                type="button"
                disabled={!!busy}
                className="icon-button"
                aria-label="关闭 AI 发送窗口"
                onClick={() => setAiDraft(null)}
              >
                <X size={16} />
              </button>
            </div>
            {aiDraft.preview && (
              <div className="ai-send-preview">
                <strong>发送前复核</strong>
                <span>
                  {aiDraft.preview.provider} · {aiDraft.preview.model} ·{' '}
                  {aiDraft.preview.endpointHost || '未配置'}
                </span>
                <span>
                  材料 {aiDraft.preview.material.length.toLocaleString()} /{' '}
                  {aiDraft.preview.maxInputChars.toLocaleString()} 字；输出预算{' '}
                  {aiDraft.preview.maxOutputTokens.toLocaleString()} tokens
                </span>
                <span>
                  范围：
                  {aiDraft.preview.scope
                    .filter((s) => s.included)
                    .map((s) => s.detail)
                    .join('；')}
                </span>
                <span>脱敏：{aiDraft.preview.redactions.join('；')}</span>
                {aiDraft.preview.notices.map((n) => (
                  <span key={n}>{n}</span>
                ))}
                {aiDraft.preview.locked && (
                  <span className="danger-text">
                    AI 外发已锁定，解锁后才能发送。
                  </span>
                )}
              </div>
            )}
            {error && (
              <p className="small-note" role="alert">
                {error}
              </p>
            )}
            <TextEditor
              label="调查问题"
              aria-label="AI 调查问题"
              required
              rows={2}
              maxLength={2000}
              value={aiDraft.question}
              onChange={(e) =>
                setAiDraft({ ...aiDraft, question: e.target.value })
              }
            />
            <TextEditor
              label="将发送的材料 · 可删减敏感内容"
              size="document"
              code
              aria-label="AI 发送材料"
              className="ai-material"
              required
              rows={10}
              maxLength={24000}
              value={aiDraft.material}
              onChange={(e) =>
                setAiDraft({ ...aiDraft, material: e.target.value })
              }
            />
            <p className="small-note">
              只发送以上问题和材料，配合内置蓝队复核指令。不会附带原始文件或截图。回答独立保存，需人工举证复核。模型服务可能按用量收费。
            </p>
            <button
              className="button primary"
              disabled={!!busy || !!aiDraft.preview?.locked}
            >
              {busy ? (
                <LoaderCircle size={14} className="spinning" />
              ) : (
                <ArrowUpRight size={14} />
              )}
              发送并研判
            </button>
          </form>
        </Modal>
      )}
      {caseModal && (
        <Modal
          title="新建调查事件"
          busy={!!busy}
          onClose={() => setCaseModal(false)}
        >
          <form
            className="modal"
            onSubmit={(e) => {
              e.preventDefault();
              if (needNative())
                perform(
                  '新建事件',
                  () => invoke<Workspace>('create_case', { title: caseTitle }),
                  (w) => {
                    setWorkspace(w);
                    setCaseModal(false);
                    setCaseTitle('');
                    setSelectedId('');
                  },
                );
            }}
          >
            <div className="modal-title">
              <h2>新建调查事件</h2>
              <button
                type="button"
                className="icon-button"
                disabled={!!busy}
                aria-label="关闭新建事件窗口"
                onClick={() => setCaseModal(false)}
              >
                <X size={16} />
              </button>
            </div>
            {error && (
              <p className="modal-error" role="alert">
                {error}
              </p>
            )}
            <label>
              事件名称
              <input
                autoFocus
                maxLength={120}
                required
                value={caseTitle}
                onChange={(e) => setCaseTitle(e.target.value)}
                placeholder="例如：业务容器异常外联调查"
              />
            </label>
            <p className="small-note">证据、分析结果与时间线按事件分别保存。</p>
            <button className="button primary" disabled={!!busy}>
              创建事件
            </button>
          </form>
        </Modal>
      )}
      {nodeDraft && (
        <Modal
          title={nodeDraft.id ? '编辑调查节点' : '记录到事件时间线'}
          busy={!!busy}
          onClose={() => setNodeDraft(null)}
        >
          <form
            className={`modal wide ${!nodeDraft.id ? 'capture-modal' : ''}`}
            onSubmit={saveNode}
          >
            <div className="modal-title">
              <h2>{nodeDraft.id ? '编辑调查节点' : '记录到事件时间线'}</h2>
              <button
                type="button"
                className="icon-button"
                disabled={!!busy}
                aria-label="关闭时间线节点窗口"
                onClick={() => setNodeDraft(null)}
              >
                <X size={16} />
              </button>
            </div>
            {error && (
              <p className="modal-error" role="alert">
                {error}
              </p>
            )}
            <div className="capture-fields">
              <label>
                节点标题
                <input
                  required
                  maxLength={200}
                  value={nodeDraft.title}
                  onChange={(e) =>
                    setNodeDraft({ ...nodeDraft, title: e.target.value })
                  }
                />
              </label>
              <div className="form-row">
                <label>
                  发生时间 · UTC+8
                  <input
                    type="datetime-local"
                    step="0.001"
                    required
                    value={nodeDraft.time}
                    onChange={(e) =>
                      setNodeDraft({ ...nodeDraft, time: e.target.value })
                    }
                  />
                </label>
                <label>
                  记录 / 执行人员
                  <input
                    required
                    maxLength={100}
                    value={nodeDraft.actor}
                    onChange={(e) =>
                      setNodeDraft({ ...nodeDraft, actor: e.target.value })
                    }
                  />
                </label>
              </div>
              <TextEditor
                label="举证说明 / 处置详情"
                size="large"
                required
                rows={5}
                maxLength={30000}
                value={nodeDraft.body}
                onChange={(e) =>
                  setNodeDraft({ ...nodeDraft, body: e.target.value })
                }
              />
              <p className="small-note">
                {nodeDraft.evidenceId
                  ? '已关联原始证据与分析结果，原文依据会一同进入报告。'
                  : '当前为人工记录，可在右侧一起附入截图。'}{' '}
                记录时间由客户端另存。
              </p>
            </div>
            {!nodeDraft.id && (
              <RecordOptions
                focusScreenshot={nodeDraft.focusScreenshot}
                caseId={nodeDraft.caseId || workspace.activeCase}
                dataDir={workspace.dataDir}
                onChange={setRecordOptions}
              />
            )}
            <div className="capture-footer">
              <button
                className="button primary"
                disabled={!!busy || (!nodeDraft.id && !recordOptions)}
              >
                保存节点
              </button>
              {!nodeDraft.id && (
                <button
                  className="button"
                  type="submit"
                  data-destination="reports"
                  disabled={!!busy || !recordOptions}
                >
                  保存并打开报告
                </button>
              )}
            </div>
          </form>
        </Modal>
      )}
      {shotDraft && (
        <Modal
          title="添加截图举证"
          busy={!!busy}
          onClose={() => setShotDraft(null)}
        >
          <form
            className="modal"
            onSubmit={(e) => {
              e.preventDefault();
              perform(
                '归档截图',
                () =>
                  shotDraft.dataUrl
                    ? invoke<Workspace>('paste_screenshot', {
                        nodeId: shotDraft.nodeId,
                        dataUrl: shotDraft.dataUrl,
                        caption: shotDraft.caption,
                      })
                    : invoke<Workspace>('add_screenshot', shotDraft),
                (w) => {
                  setWorkspace(w);
                  setShotDraft(null);
                },
              );
            }}
          >
            <div className="modal-title">
              <h2>添加截图举证</h2>
              <button
                type="button"
                className="icon-button"
                disabled={!!busy}
                aria-label="关闭截图窗口"
                onClick={() => setShotDraft(null)}
              >
                <X size={16} />
              </button>
            </div>
            {error && (
              <p className="modal-error" role="alert">
                {error}
              </p>
            )}
            <p className="small-note">
              事件：{activeCase?.title} · 节点：
              {workspace.nodes.find((n) => n.id === shotDraft.nodeId)?.title}
            </p>
            <div
              className="screenshot-paste"
              tabIndex={0}
              aria-label="粘贴截图区域"
              onPaste={async (event) => {
                const file = Array.from(event.clipboardData.items)
                  .find((item) =>
                    ['image/png', 'image/jpeg', 'image/webp'].includes(
                      item.type,
                    ),
                  )
                  ?.getAsFile();
                if (!file) return;
                event.preventDefault();
                if (file.size > 8 * 1024 * 1024) {
                  setError('截图不能超过 8 MiB');
                  return;
                }
                setError('');
                const reader = new FileReader();
                const nodeId = shotDraft.nodeId;
                reader.onload = () => {
                  if (typeof reader.result === 'string')
                    setShotDraft((old) =>
                      old?.nodeId === nodeId
                        ? { ...old, path: '', dataUrl: String(reader.result) }
                        : old,
                    );
                };
                reader.onerror = () =>
                  setError('无法读取剪贴板图片，请重新复制或选择图片文件。');
                reader.readAsDataURL(file);
              }}
            >
              {shotDraft.dataUrl ? (
                <img src={shotDraft.dataUrl} alt="待归档的粘贴截图预览" />
              ) : (
                <>
                  <ImagePlus size={24} />
                  <strong>
                    {shotDraft.path
                      ? '已选择图片文件'
                      : '点击此处后按 ⌘V / Ctrl+V 粘贴截图'}
                  </strong>
                  <small>
                    {shotDraft.path || '支持剪贴板图片，也可选择本地原图'}
                  </small>
                </>
              )}
            </div>
            <button
              type="button"
              className="button small"
              onClick={() => {
                const node = workspace.nodes.find(
                  (n) => n.id === shotDraft.nodeId,
                );
                if (node) void attach(node);
              }}
            >
              选择图片文件
            </button>
            <TextEditor
              label="图注 / 证明事项"
              required
              rows={3}
              maxLength={1000}
              value={shotDraft.caption}
              onChange={(e) =>
                setShotDraft({ ...shotDraft, caption: e.target.value })
              }
              placeholder="这张截图证明了什么？"
            />
            <p className="small-note">
              原图复制到本地证据库并保存 SHA-256。支持 PNG / JPEG /
              WebP，每张最多 8 MB。
            </p>
            <button
              className="button primary"
              disabled={!!busy || (!shotDraft.path && !shotDraft.dataUrl)}
            >
              保存原图与图注
            </button>
          </form>
        </Modal>
      )}
    </>
  );
}
installErrorCapture();
createRoot(document.getElementById('root')!).render(
  <AppErrorBoundary>
    <App />
  </AppErrorBoundary>,
);
