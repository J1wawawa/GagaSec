import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { invoke, isTauri } from './bridge';
import { listen } from '@tauri-apps/api/event';
import { open, save } from '@tauri-apps/plugin-dialog';
import {
  RefreshCw,
  Download,
  Upload,
  Plus,
  ShieldCheck,
  Server,
  Activity,
  FileSearch,
  ArrowUpRight,
  Search,
  ImagePlus,
  Settings2,
  X,
} from 'lucide-react';
import type { AiConfig, Screenshot, Workspace } from './types';
import { Modal } from './Modal';
import { TextEditor } from './TextEditor';
import { OnlineIntelligence, type IntelSeed } from './Intelligence';
export type PlatformPage =
  | 'assets'
  | 'flows'
  | 'agents'
  | 'knowledge'
  | 'lists'
  | 'samples'
  | 'environment';
type Ioc = {
  id: string;
  kind: string;
  value: string;
  verdict: string;
  labels: string;
  notes: string;
  observations: number;
  lastSeen: string;
};
type Rule = {
  id: string;
  list: string;
  kind: string;
  value: string;
  scope: string;
  enabled: boolean;
  expiresAt: string | null;
  notes: string;
};
type Asset = {
  id: string;
  name: string;
  url: string;
  intervalSecs: number;
  enabled: boolean;
  followRedirects: boolean;
  autoScreenshot: boolean;
  baselineId: string | null;
  lastStatus: string;
  lastChecked: string | null;
};
type Script = {
  url: string;
  sha256: string | null;
  bytes: number;
  error: string | null;
};
type Snapshot = {
  id: string;
  createdAt: string;
  evidenceId: string;
  status: number | null;
  title: string;
  sha256: string;
  changes: string[];
  hiddenLinks: string[];
  finalUrl: string;
  redirects: unknown[];
  screenshot: Screenshot | null;
  screenshotError: string | null;
  browserFinalUrl: string | null;
  browserNavigations: unknown[];
  domSha256: string | null;
  scripts: Script[];
  error: string | null;
  elapsedMs: number;
};
type SnapshotPage = {
  rows: Snapshot[];
  total: number;
  offset: number;
  limit: number;
};
type Observation = {
  id: string;
  kind: string;
  subject: string;
  summary: string;
  createdAt: string;
  evidenceId: string;
  aiState: string;
  reviewId: string | null;
  error: string | null;
};
type Task = {
  id: string;
  name: string;
  target: string;
  mode: string;
  architecture: string;
  enabled: boolean;
  expiresAt: string;
  batches: number;
  lastSeen: string | null;
  clientFingerprint: string;
};
type Flow = {
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  packets: number;
  bytes: number;
  httpFragment?: string;
};
type Window = {
  id: string;
  taskId: string;
  target: string;
  createdAt: string;
  evidenceId: string;
  observedPackets: number;
  kernelDrops: number | null;
  unparsedPackets: number;
  omittedFlowPackets: number;
  flowCount: number;
  listHitCount: number;
  flows: Flow[];
};
type Sample = {
  id: string;
  title: string;
  family: string;
  hashes: string;
  verdict: string;
  notes: string;
  evidenceId: string | null;
  caseId: string;
  createdAt: string;
};
type AiSettings = {
  enabled: boolean;
  minIntervalSecs: number;
  maxPerHour: number;
  scopeCaseId: string | null;
  enabledAfter: string | null;
  revision: string;
  needsConfirmation: boolean;
};
type PlatformState = {
  assets: Asset[];
  observations: Observation[];
  indicators: Ioc[];
  rules: Rule[];
  tasks: Task[];
  flows: Window[];
  sampleCases: Sample[];
  identity: { fingerprint: string } | null;
  receiver: { bind: string; callbackUrl: string; certificate: string };
  receiverRunning: boolean;
  aiSettings: AiSettings;
  aiLocked: boolean;
  aiQueue: {
    pending: number;
    reviewed: number;
    globalPending: number;
    eligible: number;
    retained: number;
  };
};
interface Props {
  querySeed?: IntelSeed;
  page: PlatformPage;
  workspace: Workspace;
  busy: string;
  perform: <T>(
    label: string,
    fn: () => Promise<T>,
    done?: (v: T) => void,
  ) => Promise<T | undefined>;
  refresh: () => Promise<Workspace>;
  onEvidence: (id: string) => void;
  onRecord: (
    id: string,
    title: string,
    body: string,
    screenshot?: boolean,
  ) => void;
  renderShot: (shot: Screenshot) => ReactNode;
  aiConfig: AiConfig;
  onSettings: () => void;
  onIsolation: () => void;
}
const empty: PlatformState = {
  assets: [],
  observations: [],
  indicators: [],
  rules: [],
  tasks: [],
  flows: [],
  sampleCases: [],
  identity: null,
  receiver: {
    bind: '127.0.0.1:3443',
    callbackUrl: 'https://localhost:3443',
    certificate: '',
  },
  receiverRunning: false,
  aiSettings: {
    enabled: false,
    minIntervalSecs: 60,
    maxPerHour: 60,
    scopeCaseId: null,
    enabledAfter: null,
    revision: '',
    needsConfirmation: false,
  },
  aiLocked: false,
  aiQueue: {
    pending: 0,
    reviewed: 0,
    globalPending: 0,
    eligible: 0,
    retained: 0,
  },
};
const labels: Record<string, string> = {
  unknown: '待复核',
  suspicious: '可疑',
  malicious: '人工标记恶意',
  benign: '人工标记可信',
  pending: '待研判',
  running: '分析中',
  completed: '已研判',
  failed: '研判失败',
  interrupted: '已中断',
};
const stamp = (s: string | null) =>
  s ? new Date(s).toLocaleString('zh-CN', { hour12: false }) : '—';
const kinds = ['ip', 'cidr', 'domain', 'url', 'md5', 'sha1', 'sha256'];
const action = <T,>(action: string, args: unknown = {}) =>
  invoke<T>('platform_action', { action, args });
function Empty({ text }: { text: string }) {
  return (
    <div className="platform-empty">
      <ShieldCheck size={26} />
      <p>{text}</p>
    </div>
  );
}
function Detail({ title, value }: { title: string; value: unknown }) {
  return (
    <details className="platform-detail">
      <summary>{title}</summary>
      <pre>
        {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
      </pre>
    </details>
  );
}
export function PlatformPanel({
  querySeed,
  page,
  workspace,
  busy,
  perform,
  refresh,
  onEvidence,
  onRecord,
  renderShot,
  aiConfig,
  onSettings,
  onIsolation,
}: Props) {
  const native = isTauri();
  const [data, setData] = useState<PlatformState>(empty);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const activeCase = useRef(workspace.activeCase);
  activeCase.current = workspace.activeCase;
  const activePage = useRef(page);
  activePage.current = page;
  const [text, setText] = useState('');
  const [interval, setIntervalSecs] = useState(300);
  const [importOptions, setImportOptions] = useState({
    followRedirects: true,
    autoScreenshot: true,
  });
  const [browserMirror, setBrowserMirror] = useState('official');
  const [assetSettings, setAssetSettings] = useState<Asset | null>(null);
  const [browserEnv, setBrowserEnv] = useState<{
    ready: boolean;
    message: string;
  } | null>(null);
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [snapshotId, setSnapshotId] = useState('');
  const [snapshotOffset, setSnapshotOffset] = useState(0);
  const [snapshotTotal, setSnapshotTotal] = useState(0);
  const [shotSnapshot, setShotSnapshot] = useState('');
  const [assetId, setAssetId] = useState('');
  const [flowId, setFlowId] = useState('');
  const [search, setSearch] = useState('');
  const [found, setFound] = useState<Ioc[] | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [ioc, setIoc] = useState<Ioc | null>(null);
  const [intelSeed, setIntelSeed] = useState<IntelSeed>();
  const [origins, setOrigins] = useState<unknown[]>([]);
  const [exportFormat, setExportFormat] = useState('json');
  const [rule, setRule] = useState({
    list: 'deny',
    kind: 'ip',
    value: '',
    // 名单是跨事件的长期策略；事件级规则仍可通过下拉显式选择。
    scope: 'global',
    expiresAt: '',
    notes: '',
  });
  const [sample, setSample] = useState({
    title: '',
    family: '',
    hashes: '',
    verdict: 'unknown',
    notes: '',
    evidenceId: '',
  });
  const [task, setTask] = useState({
    name: '',
    target: '',
    mode: 'snapshot',
    architecture: 'linux-amd64',
    interface: 'any',
    durationSeconds: 300,
    batchSeconds: 15,
    snaplen: 512,
    includeHttp: false,
    hours: 24,
    online: false,
  });
  const [receiver, setReceiver] = useState(empty.receiver);
  const [ai, setAi] = useState(empty.aiSettings);
  const [env, setEnv] = useState<Record<string, unknown> | null>(null);
  const [docker, setDocker] = useState<Record<string, unknown> | null>(null);
  const [staticEnvironment, setStaticEnvironment] = useState<{
    imageId: string | null;
  } | null>(null);
  const [environmentErrors, setEnvironmentErrors] = useState<string[]>([]);
  const load = useCallback(async () => {
    if (!native) return;
    const d = await invoke<PlatformState>('platform_state');
    if (
      activeCase.current === workspace.activeCase &&
      activePage.current === page
    )
      setData(d);
  }, [native, workspace.activeCase, page]);
  useEffect(() => {
    setFound(null);
    setData(empty);
    setAssetSettings(null);
    setSelected([]);
    setAssetId('');
    setSnapshots([]);
    setIoc(null);
    setIntelSeed(undefined);
    setRule((r) => ({
      ...r,
      scope: r.scope === 'global' ? 'global' : workspace.activeCase,
    }));
    setSnapshotId('');
    setSnapshotOffset(0);
    setSnapshotTotal(0);
    setShotSnapshot('');
    setLoading(true);
    load()
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [load]);
  useEffect(() => {
    setReceiver(data.receiver);
    setAi({
      ...data.aiSettings,
      enabled:
        data.aiSettings.enabled &&
        data.aiSettings.scopeCaseId === workspace.activeCase,
    });
  }, [
    data.receiver.bind,
    data.receiver.callbackUrl,
    data.receiver.certificate,
    data.aiSettings.enabled,
    data.aiSettings.minIntervalSecs,
    data.aiSettings.maxPerHour,
    data.aiSettings.revision,
    workspace.activeCase,
  ]);
  useEffect(() => {
    if (!native) return;
    let stop: (() => void) | undefined;
    let disposed = false;
    listen('platform-updated', () => {
      if (document.hidden) return;
      load()
        .then(refresh)
        .catch((e) => setError(String(e)));
    }).then((f) => {
      if (disposed) f();
      else stop = f;
    });
    const tick = window.setInterval(() => {
      if (!document.hidden) load().catch((e) => setError(String(e)));
    }, 15000);
    const onVisibilityChange = () => {
      if (!document.hidden) load().catch((e) => setError(String(e)));
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      disposed = true;
      stop?.();
      window.clearInterval(tick);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [load, refresh, native]);
  async function run<T>(
    label: string,
    fn: () => Promise<T>,
    done?: (v: T) => void,
  ) {
    if (!native) {
      setError('请在桌面客户端使用本地数据库、巡检与 Agent。');
      return;
    }
    await perform(
      label,
      async () => {
        const value = await fn();
        await load();
        await refresh();
        return value;
      },
      done,
    );
  }
  async function pickImport(type: 'intel' | 'agent') {
    if (!native) {
      setError('请在桌面客户端导入文件。');
      return;
    }
    const paths = await open({
      multiple: type === 'agent',
      title: type === 'agent' ? '导入加密采集批次' : '导入情报文件',
      filters: [
        {
          name: '数据文件',
          extensions:
            type === 'agent' ? ['json'] : ['json', 'csv', 'txt', 'xml'],
        },
      ],
    });
    if (!paths) return;
    await run('导入', async () => {
      for (const path of Array.isArray(paths) ? paths : [paths])
        await action(type === 'agent' ? 'agentImport' : 'intelImportFile', {
          path,
        });
    });
  }
  async function exportIocs() {
    const path = await save({
      defaultPath: `gaga-intelligence.${exportFormat === 'stix' ? 'json' : exportFormat}`,
    });
    if (path)
      await run('分享导出', () =>
        action('intelExport', { ids: selected, path, format: exportFormat }),
      );
  }
  async function showSnapshots(id: string, offset = 0) {
    await run(
      '读取快照',
      () =>
        invoke<SnapshotPage>('get_monitor_snapshots_page', {
          assetId: id,
          offset,
          limit: 10,
        }),
      (s) => {
        setAssetId(id);
        setSnapshots(s.rows);
        setSnapshotId(s.rows[0]?.id || '');
        setSnapshotOffset(s.offset);
        setSnapshotTotal(s.total);
      },
    );
  }
  async function checkAsset(id: string) {
    await run(
      '立即巡检',
      async () => {
        const snapshot = await action<Snapshot>('assetCheck', { id });
        // A successful capture must not replace the entire visible history
        // with one row, or imply capture failure if only the history read fails.
        let history: SnapshotPage | null = null;
        try {
          history = await invoke<SnapshotPage>('get_monitor_snapshots_page', {
            assetId: id,
            offset: 0,
            limit: 10,
          });
        } catch (error) {
          setError(`巡检已完成，但历史记录读取失败：${String(error)}`);
        }
        return { snapshot, history };
      },
      ({ snapshot, history }) => {
        setAssetId(id);
        setSnapshots(history?.rows || [snapshot]);
        setSnapshotId(snapshot.id);
        setSnapshotOffset(0);
        setSnapshotTotal(history?.total || 1);
      },
    );
  }
  async function generate() {
    if (!native) {
      setError('请在桌面客户端生成采集任务。');
      return;
    }
    const caseId = workspace.activeCase;
    const input = { ...task };
    const path = await save({
      defaultPath: 'gaga-collection-task.zip',
      filters: [{ name: 'Agent 任务包', extensions: ['zip'] }],
    });
    if (path)
      await run('生成专属任务包', () =>
        action('agentGenerate', { caseId, input, path }),
      );
  }
  const [viewByPage, setViewByPage] = useState<Record<string, string>>({});
  const tabs: Record<PlatformPage, [string, string][]> = {
    assets: [
      ['asset-main', '目标与快照'],
      ['asset-import', '登记资产'],
    ],
    flows: [
      ['flow-main', '流量窗口'],
      ['queue', '观测队列'],
      ['ai-settings', 'AI 调度'],
      ['flow-scope', '采集范围'],
    ],
    agents: [
      ['agent-main', '任务列表'],
      ['agent-new', '生成任务'],
      ['receiver', 'HTTPS 接收'],
      ['queue', '观测队列'],
      ['ai-settings', 'AI 调度'],
    ],
    knowledge: [
      ['intel-main', '指标与来源'],
      ['intel-online', '在线查询'],
      ['intel-import', '导入指标'],
    ],
    lists: [
      ['rule-main', '规则列表'],
      ['rule-new', '新增规则'],
    ],
    samples: [
      ['sample-main', '案例列表'],
      ['sample-new', '整理案例'],
    ],
    environment: [
      ['env-main', '本机检查'],
      ['env-docker', 'Docker'],
      ['env-info', '运行说明'],
    ],
  };
  const view = viewByPage[page] ?? tabs[page][0][0];
  const showView = (value: string) =>
    setViewByPage((prev) => ({ ...prev, [page]: value }));
  useEffect(() => {
    if (
      page === 'knowledge' &&
      querySeed &&
      querySeed.caseId === workspace.activeCase
    ) {
      setIntelSeed(querySeed);
      setViewByPage((prev) => ({ ...prev, knowledge: 'intel-online' }));
    }
  }, [querySeed, page]);
  const queue = data.aiQueue.pending;
  const reviewed = data.aiQueue.reviewed;
  const heading: Record<PlatformPage, [string, string]> = {
    assets: [
      '资产页面监控',
      '定时检查页面与同源 JS，保留原始快照，发现变化后关联证据。',
    ],
    flows: [
      '重点主机流量',
      '接收 Linux eBPF 观测窗口，结合名单与 AI 队列持续复核。',
    ],
    agents: [
      '采集 Agent',
      '生成绑定本客户端公钥的离线任务包，采集后导回解密分析。',
    ],
    knowledge: [
      '本地情报库',
      '从请求、响应、日志与文件中提取 IOC，保留来源并积累调查知识。',
    ],
    lists: [
      '黑白名单',
      '管理明确的命中依据、适用事件和有效期，发现冲突时保留双方记录。',
    ],
    samples: [
      '样本案例库',
      '整理木马与病毒的 Hash、分析笔记和证据关联，人工复核分类。',
    ],
    environment: ['本机环境', '检查客户端存储、Agent 模板与 Docker 可用性。'],
  };
  const browserSetup = (
    <div className="asset-browser-setup">
      <p>
        {browserEnv?.message ||
          '自动截图使用独立的临时浏览器容器，首次使用需准备环境。'}
      </p>
      <label className="asset-browser-source">
        软件包来源
        <select
          aria-label="截图环境软件源"
          value={browserMirror}
          disabled={!!busy}
          onChange={(e) => setBrowserMirror(e.target.value)}
        >
          <option value="official">Alpine 官方源</option>
          <option value="aliyun">阿里云镜像源</option>
        </select>
      </label>
      <div className="platform-actions">
        <button
          disabled={!!busy}
          onClick={() =>
            run(
              '检测截图环境',
              () =>
                action<{ ready: boolean; message: string }>(
                  'browserEnvironment',
                ),
              setBrowserEnv,
            )
          }
        >
          检测环境
        </button>
        <button
          disabled={!!busy || browserEnv?.ready}
          onClick={() =>
            run(
              '准备浏览器容器',
              () =>
                action<{ ready: boolean; message: string }>('browserPrepare', {
                  mirror: browserMirror,
                }),
              setBrowserEnv,
            )
          }
        >
          {browserEnv?.ready ? '截图环境已就绪' : '准备截图环境'}
        </button>
      </div>
    </div>
  );
  return (
    <section className="platform-page" data-view={view}>
      {assetSettings && (
        <Modal
          title="资产巡检设置"
          busy={!!busy}
          onClose={() => setAssetSettings(null)}
        >
          <section className="modal asset-settings-dialog">
            <header>
              <h2>巡检设置</h2>
              <button
                className="icon-button"
                aria-label="关闭资产巡检设置"
                disabled={!!busy}
                onClick={() => setAssetSettings(null)}
              >
                <X size={17} />
              </button>
            </header>
            <p>{assetSettings.name}</p>
            <code>{assetSettings.url}</code>
            <label className="asset-option">
              <input
                type="checkbox"
                aria-label="跟随页面跳转"
                disabled={!!busy}
                checked={assetSettings.followRedirects || false}
                onChange={(e) =>
                  setAssetSettings({
                    ...assetSettings,
                    followRedirects: e.target.checked,
                  })
                }
              />
              <span>
                <strong>跟随页面跳转</strong>
                <small>
                  HTTP / meta 跳转最多 8
                  跳；开启自动截图时也跟随浏览器脚本跳转，保留最终地址和跳转链。
                </small>
              </span>
            </label>
            <label className="asset-option">
              <input
                type="checkbox"
                aria-label="自动页面截图"
                disabled={!!busy}
                checked={assetSettings.autoScreenshot || false}
                onChange={(e) =>
                  setAssetSettings({
                    ...assetSettings,
                    autoScreenshot: e.target.checked,
                  })
                }
              />
              <span>
                <strong>自动页面截图</strong>
                <small>
                  临时容器打开页面，自动归档截图、采集时间和渲染 DOM
                  摘要到本事件。无登录态，1440×900 视口。
                </small>
              </span>
            </label>
            {assetSettings.autoScreenshot && browserSetup}
            <button
              className="button primary"
              disabled={!!busy}
              onClick={() =>
                run(
                  '保存巡检设置',
                  () =>
                    action('assetConfigure', {
                      id: assetSettings.id,
                      followRedirects: assetSettings.followRedirects || false,
                      autoScreenshot: assetSettings.autoScreenshot || false,
                    }),
                  () => setAssetSettings(null),
                )
              }
            >
              保存设置
            </button>
          </section>
        </Modal>
      )}
      <div className="page-heading">
        <div>
          <h1>{heading[page][0]}</h1>
          <p>{heading[page][1]}</p>
        </div>
        <button disabled={!!busy || loading} onClick={() => run('刷新', load)}>
          <RefreshCw size={14} />
          刷新
        </button>
      </div>
      {error && (
        <div className="error-banner" role="alert">
          <span>{error}</span>
          <button onClick={() => setError('')}>关闭</button>
        </div>
      )}
      <div className="platform-tabs" role="tablist" aria-label="工作区视图">
        {tabs[page].map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={view === id}
            onClick={() => showView(id)}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="platform-content">
        {page === 'knowledge' && view === 'intel-online' && (
          <div data-panel="intel-online">
            <OnlineIntelligence
              key={workspace.activeCase}
              workspace={workspace}
              seed={intelSeed}
              onSettings={onSettings}
              onEvidence={onEvidence}
              onRecord={onRecord}
              refresh={refresh}
            />
          </div>
        )}
        {page === 'assets' && (
          <>
            <div className="platform-stats">
              <div>
                <b>{data.assets.length}</b>
                <span>已登记资产</span>
              </div>
              <div>
                <b>{data.assets.filter((a) => a.enabled).length}</b>
                <span>定时巡检中</span>
              </div>
              <div>
                <b>{data.assets.filter((a) => a.baselineId).length}</b>
                <span>已确认基线</span>
              </div>
              <div>
                <b>{queue}</b>
                <span>待 AI 研判观测</span>
              </div>
            </div>
            <div className="platform-columns" data-panel="asset-import">
              <div className="platform-card">
                <h2>批量登记目标</h2>
                <p className="muted">
                  每行一个 URL，或「资产名称,URL」。新资产默认暂停。
                </p>
                <TextEditor
                  label="目标资产清单"
                  size="large"
                  code
                  aria-label="资产导入内容"
                  rows={5}
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder={
                    '门户,https://portal.example.org/\n业务系统,https://app.example.org/'
                  }
                />
                <div className="asset-import-options">
                  <label className="asset-option">
                    <input
                      type="checkbox"
                      aria-label="新资产跟随跳转"
                      checked={importOptions.followRedirects}
                      onChange={(e) =>
                        setImportOptions({
                          ...importOptions,
                          followRedirects: e.target.checked,
                        })
                      }
                    />
                    <span>跟随页面跳转</span>
                  </label>
                  <label className="asset-option">
                    <input
                      type="checkbox"
                      aria-label="新资产自动截图"
                      checked={importOptions.autoScreenshot}
                      onChange={(e) =>
                        setImportOptions({
                          ...importOptions,
                          autoScreenshot: e.target.checked,
                        })
                      }
                    />
                    <span>自动页面截图</span>
                  </label>
                </div>
                {importOptions.autoScreenshot && browserSetup}
                <div className="platform-inline">
                  <label>
                    巡检间隔（秒）
                    <input
                      aria-label="巡检间隔"
                      type="number"
                      min={60}
                      max={86400}
                      value={interval}
                      onChange={(e) => setIntervalSecs(+e.target.value)}
                    />
                  </label>
                  <button
                    disabled={!!busy || !text.trim()}
                    onClick={() =>
                      run(
                        '登记资产',
                        () =>
                          action('assetImport', {
                            text,
                            intervalSecs: interval,
                            ...importOptions,
                          }),
                        () => {
                          setText('');
                          showView('asset-main');
                        },
                      )
                    }
                  >
                    <Plus size={14} />
                    登记资产
                  </button>
                </div>
              </div>
              <div className="platform-card platform-note">
                <Server size={20} />
                <h2>变化都有原始依据</h2>
                <p>
                  HTML 上限 1 MiB，最多抓取 8 个同源 JS，每个 512 KiB。记录页面
                  / 脚本 SHA-256、外链、静态隐藏链接和采集错误。
                </p>
                <p>
                  可分别开关跟随跳转与自动截图。浏览器在临时容器内渲染，不带登录态；客户端运行期间执行计划，首次观测需人工确认基线。
                </p>
              </div>
            </div>
            <div className="platform-card asset-master" data-panel="asset-main">
              <div className="platform-pane-head">
                <h2>
                  目标资产 <small>{data.assets.length}</small>
                </h2>
                <button
                  className="icon-button"
                  aria-label="登记目标资产"
                  onClick={() => showView('asset-import')}
                >
                  <Plus size={15} />
                </button>
              </div>
              {!data.assets.length ? (
                <Empty text="登记护网目标后开始巡检。" />
              ) : (
                data.assets.map((a) => (
                  <div
                    key={a.id}
                    className={`asset-item ${assetId === a.id ? 'selected' : ''}`}
                  >
                    <button
                      className="asset-select"
                      onClick={() => showSnapshots(a.id)}
                    >
                      <strong>{a.name}</strong>
                      <code>{a.url}</code>
                      <small>
                        {a.enabled ? '定时启用' : '定时暂停'} · {a.lastStatus}
                      </small>
                    </button>
                    <div className="asset-quick-actions">
                      <button
                        aria-label={`巡检设置 ${a.name}`}
                        disabled={!!busy}
                        onClick={() => {
                          setAssetSettings(a);
                          setBrowserEnv(null);
                          // Read-only preflight must not freeze the dialog or
                          // prevent the user from closing it while Docker responds.
                          void action<{ ready: boolean; message: string }>(
                            'browserEnvironment',
                          )
                            .then(setBrowserEnv)
                            .catch((error) =>
                              setBrowserEnv({
                                ready: false,
                                message: String(error),
                              }),
                            );
                        }}
                      >
                        <Settings2 size={14} />
                        设置
                      </button>
                      <button
                        disabled={!!busy}
                        onClick={() => checkAsset(a.id)}
                      >
                        立即巡检
                      </button>
                      <button
                        disabled={!!busy}
                        onClick={() =>
                          run('定时设置', () =>
                            action('assetToggle', {
                              id: a.id,
                              enabled: !a.enabled,
                            }),
                          )
                        }
                      >
                        {a.enabled ? '暂停' : '启用定时'}
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
            <div
              className="platform-card asset-inspector"
              data-panel="asset-detail"
            >
              <div className="platform-pane-head">
                <h2>快照与差异</h2>
                {assetId && (
                  <button
                    disabled={!!busy}
                    onClick={() => showSnapshots(assetId)}
                  >
                    历史快照
                  </button>
                )}
              </div>
              {!!snapshots.length && (
                <div className="asset-snapshot-picker">
                  <label>
                    巡检记录
                    <select
                      aria-label="巡检快照"
                      value={snapshotId}
                      onChange={(event) => setSnapshotId(event.target.value)}
                    >
                      {snapshots.map((s) => (
                        <option key={s.id} value={s.id}>
                          {stamp(s.createdAt)} · HTTP {s.status ?? '—'}
                        </option>
                      ))}
                    </select>
                  </label>
                  {snapshotTotal > 10 && (
                    <div className="platform-actions">
                      <button
                        disabled={!!busy || !snapshotOffset}
                        onClick={() =>
                          showSnapshots(assetId, snapshotOffset - 10)
                        }
                      >
                        较新
                      </button>
                      <span>
                        {snapshotOffset + 1}–
                        {Math.min(snapshotOffset + 10, snapshotTotal)} /{' '}
                        {snapshotTotal}
                      </span>
                      <button
                        disabled={
                          !!busy || snapshotOffset + 10 >= snapshotTotal
                        }
                        onClick={() =>
                          showSnapshots(assetId, snapshotOffset + 10)
                        }
                      >
                        较早
                      </button>
                    </div>
                  )}
                </div>
              )}
              {!snapshots.length ? (
                <Empty text="从左侧选择资产，查看快照、差异和原始依据。" />
              ) : (
                snapshots
                  .filter((s) => s.id === snapshotId)
                  .map((snapshot) => (
                    <article className="platform-row" key={snapshot.id}>
                      <div className="platform-inline">
                        <strong>
                          HTTP {snapshot.status ?? '—'} ·{' '}
                          {snapshot.title || '无标题'}
                        </strong>
                        <span>
                          {stamp(snapshot.createdAt)} · {snapshot.elapsedMs} ms
                        </span>
                      </div>
                      {snapshot.finalUrl && (
                        <p className="asset-final-url">
                          HTTP 最终地址 <code>{snapshot.finalUrl}</code>
                        </p>
                      )}
                      {!!snapshot.redirects?.length && (
                        <Detail
                          title={`HTTP / meta 跳转链 · ${snapshot.redirects.length}`}
                          value={snapshot.redirects.map((r) => {
                            const { rawHtmlBase64: _raw, ...meta } =
                              r as Record<string, unknown>;
                            return meta;
                          })}
                        />
                      )}
                      {snapshot.browserFinalUrl && (
                        <p className="asset-final-url">
                          浏览器最终地址 <code>{snapshot.browserFinalUrl}</code>
                        </p>
                      )}
                      {!!snapshot.browserNavigations?.length && (
                        <Detail
                          title="浏览器跳转记录"
                          value={snapshot.browserNavigations}
                        />
                      )}
                      <code className="platform-hash">
                        SHA-256 {snapshot.sha256 || '未取得'}
                      </code>
                      {snapshot.error && <p>{snapshot.error}</p>}
                      <ul>
                        {snapshot.changes.map((change, i) => (
                          <li key={i}>{change}</li>
                        ))}
                      </ul>
                      <Detail
                        title={`脚本来源与摘要 · ${snapshot.scripts.length}`}
                        value={snapshot.scripts}
                      />
                      <div className="asset-screenshot-evidence">
                        <div>
                          <ImagePlus size={19} />
                          <strong>页面截图举证</strong>
                        </div>
                        {snapshot.screenshot ? (
                          <>
                            <p>
                              已自动采集并归档到本事件，报告可直接引用此截图节点。截图与
                              HTTP 原文分别留存。
                            </p>
                            {renderShot(snapshot.screenshot)}
                          </>
                        ) : (
                          <p>
                            {snapshot.screenshotError
                              ? `自动截图失败：${snapshot.screenshotError}`
                              : '本次未采集自动截图。可在资产设置中开启，下一次巡检生效。'}
                          </p>
                        )}
                        <div className="platform-actions">
                          <button
                            disabled={!!busy}
                            onClick={() =>
                              onRecord(
                                snapshot.evidenceId,
                                `资产页面截图 · ${data.assets.find((a) => a.id === assetId)?.name || snapshot.title}`,
                                `资产 URL：${data.assets.find((a) => a.id === assetId)?.url || '待核实'}\n巡检快照：${snapshot.id}\n静态采集时间：${snapshot.createdAt}\nHTML SHA-256：${snapshot.sha256 || '未取得'}\n\n截图采集时间与说明：待填写。截图为人工补充材料，与静态 HTTP 采集相互独立；请确认页面地址、时间和图注。`,
                                true,
                              )
                            }
                          >
                            <ImagePlus size={14} />
                            补充截图
                          </button>
                          {workspace.nodes.some(
                            (n) =>
                              n.evidenceId === snapshot.evidenceId &&
                              n.screenshots.length,
                          ) && (
                            <button
                              aria-expanded={shotSnapshot === snapshot.id}
                              onClick={() =>
                                setShotSnapshot(
                                  shotSnapshot === snapshot.id
                                    ? ''
                                    : snapshot.id,
                                )
                              }
                            >
                              查看已归档截图
                            </button>
                          )}
                        </div>
                        {shotSnapshot === snapshot.id &&
                          workspace.nodes
                            .filter((n) => n.evidenceId === snapshot.evidenceId)
                            .flatMap((n) => n.screenshots)
                            .map(renderShot)}
                      </div>
                      <div className="platform-actions">
                        <button onClick={() => onEvidence(snapshot.evidenceId)}>
                          查看证据与 AI
                        </button>
                        <button
                          disabled={
                            !!busy ||
                            snapshot.error !== null ||
                            !snapshot.status ||
                            snapshot.status < 200 ||
                            snapshot.status >= 300
                          }
                          onClick={() =>
                            run('确认可信基线', () =>
                              action('assetBaseline', {
                                id: assetId,
                                snapshotId: snapshot.id,
                              }),
                            )
                          }
                        >
                          人工确认此快照为基线
                        </button>
                        <button
                          onClick={() =>
                            onRecord(
                              snapshot.evidenceId,
                              '资产页面变化 · 待复核',
                              snapshot.changes.join('\n'),
                            )
                          }
                        >
                          记录时间线
                        </button>
                      </div>
                    </article>
                  ))
              )}
            </div>
          </>
        )}
        {page === 'knowledge' && (
          <>
            <div className="platform-toolbar" data-panel="intel-toolbar">
              <input
                aria-label="搜索情报"
                placeholder="搜索 IP / 域名 / Hash / 标签"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <button
                disabled={!!busy}
                onClick={() =>
                  run(
                    '检索情报',
                    () => action<Ioc[]>('intelSearch', { search }),
                    setFound,
                  )
                }
              >
                <Search size={14} />
                检索
              </button>
              <button disabled={!!busy} onClick={() => pickImport('intel')}>
                <Upload size={14} />
                导入文件
              </button>
              <select
                aria-label="情报导出格式"
                value={exportFormat}
                onChange={(e) => setExportFormat(e.target.value)}
              >
                <option value="json">JSON</option>
                <option value="csv">CSV</option>
                <option value="stix">STIX 2.1 基础指标</option>
              </select>
              <button
                disabled={!!busy || !selected.length || !native}
                onClick={exportIocs}
              >
                <Download size={14} />
                分享 {selected.length} 项
              </button>
            </div>
            <div className="platform-columns" data-panel="intel-import">
              <div className="platform-card">
                <h2>粘贴 IOC / 情报文件内容</h2>
                <TextEditor
                  label="情报导入内容"
                  size="large"
                  code
                  rows={4}
                  aria-label="情报导入内容"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder="IP、域名、URL、MD5、SHA1、SHA256，支持常见去武器化写法"
                />
                <button
                  disabled={!!busy || !text.trim()}
                  onClick={() =>
                    run(
                      '解析入库',
                      () => action('intelImport', { text }),
                      () => {
                        setText('');
                        setFound(null);
                        showView('intel-main');
                      },
                    )
                  }
                >
                  解析并入库
                </button>
              </div>
              <div className="platform-card platform-note">
                <h2>出现过，才有来源可查</h2>
                <p>
                  HTTP 请求 / 响应、日志和样本分析会自动索引
                  IOC，默认待复核。Hash 本身不是恶意结论。
                </p>
                <p>
                  分享仅包含所选指标、标签与分类；不包含原始报文、私密备注、API
                  Key 或样本字节。导入方需重新复核。
                </p>
              </div>
            </div>
            <div className="platform-card" data-panel="intel-main">
              <h2>
                指标记录 <small>最新 / 检索最多 500 条</small>
              </h2>
              {!(found ?? data.indicators).length ? (
                <Empty text="分析证据或导入 IOC 后，情报会保存在本地。" />
              ) : (
                <div className="platform-table-wrap">
                  <table className="platform-table">
                    <thead>
                      <tr>
                        <th>
                          <input
                            aria-label="选择当前全部 IOC"
                            type="checkbox"
                            checked={
                              (found ?? data.indicators).length > 0 &&
                              (found ?? data.indicators).every((i) =>
                                selected.includes(i.id),
                              )
                            }
                            onChange={(e) =>
                              setSelected(
                                e.target.checked
                                  ? (found ?? data.indicators).map((i) => i.id)
                                  : [],
                              )
                            }
                          />
                        </th>
                        <th>类型 / 指标</th>
                        <th>人工分类</th>
                        <th>来源</th>
                        <th>操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(found ?? data.indicators).map((i) => (
                        <tr key={i.id}>
                          <td>
                            <input
                              aria-label={`选择 ${i.value}`}
                              type="checkbox"
                              checked={selected.includes(i.id)}
                              onChange={(e) =>
                                setSelected((v) =>
                                  e.target.checked
                                    ? [...v, i.id]
                                    : v.filter((id) => id !== i.id),
                                )
                              }
                            />
                          </td>
                          <td>
                            <small>{i.kind}</small>
                            <code>{i.value}</code>
                            <small>{i.labels}</small>
                          </td>
                          <td>{labels[i.verdict] || i.verdict}</td>
                          <td>{i.observations} 处</td>
                          <td>
                            <button
                              disabled={!!busy}
                              onClick={() =>
                                run(
                                  '定位来源',
                                  () =>
                                    action<unknown[]>('intelOrigins', {
                                      id: i.id,
                                    }),
                                  (o) => {
                                    setIoc({ ...i });
                                    setOrigins(o);
                                  },
                                )
                              }
                            >
                              复核与来源
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
            {ioc && (
              <div className="platform-card" data-panel="intel-detail">
                <h2>复核 {ioc.kind}</h2>
                <code>{ioc.value}</code>
                {['ip', 'domain', 'md5', 'sha1', 'sha256'].includes(
                  ioc.kind,
                ) && (
                  <button
                    onClick={() => {
                      const origin = origins.find(
                        (o) =>
                          typeof o === 'object' &&
                          o !== null &&
                          (o as { caseId?: string }).caseId ===
                            workspace.activeCase,
                      ) as { evidenceId?: string } | undefined;
                      setIntelSeed({
                        caseId: workspace.activeCase,
                        kind: ioc.kind,
                        value: ioc.value,
                        evidenceId: origin?.evidenceId,
                      });
                      showView('intel-online');
                    }}
                  >
                    查询此指标的在线情报
                  </button>
                )}
                <div className="platform-form">
                  <label>
                    人工分类
                    <select
                      aria-label="IOC 分类"
                      value={ioc.verdict}
                      onChange={(e) =>
                        setIoc({ ...ioc, verdict: e.target.value })
                      }
                    >
                      {Object.entries(labels)
                        .slice(0, 4)
                        .map(([v, l]) => (
                          <option value={v} key={v}>
                            {l}
                          </option>
                        ))}
                    </select>
                  </label>
                  <label>
                    标签
                    <input
                      value={ioc.labels}
                      onChange={(e) =>
                        setIoc({ ...ioc, labels: e.target.value })
                      }
                    />
                  </label>
                  <TextEditor
                    label="判断依据 / 私密备注"
                    fieldClassName="wide"
                    aria-label="IOC 判断依据"
                    value={ioc.notes}
                    onChange={(e) => setIoc({ ...ioc, notes: e.target.value })}
                  />
                </div>
                <button
                  disabled={!!busy}
                  onClick={() =>
                    run(
                      '保存复核',
                      () => action('intelAnnotate', ioc),
                      () => setFound(null),
                    )
                  }
                >
                  保存复核
                </button>
                <Detail
                  title={`证据来源 · ${origins.length}`}
                  value={origins}
                />
              </div>
            )}
          </>
        )}
        {page === 'knowledge' && !ioc && (
          <div className="platform-card" data-panel="intel-detail">
            <h2>指标检查器</h2>
            <Empty text="选择「复核与来源」，查看关联证据并记录判断依据。" />
          </div>
        )}
        {page === 'lists' && (
          <>
            <div className="platform-card" data-panel="rule-new">
              <h2>新增名单规则</h2>
              <div className="platform-form">
                <label>
                  名单
                  <select
                    value={rule.list}
                    onChange={(e) => setRule({ ...rule, list: e.target.value })}
                  >
                    <option value="deny">黑名单</option>
                    <option value="allow">白名单</option>
                  </select>
                </label>
                <label>
                  指标类型
                  <select
                    value={rule.kind}
                    onChange={(e) => setRule({ ...rule, kind: e.target.value })}
                  >
                    {kinds.map((k) => (
                      <option key={k}>{k}</option>
                    ))}
                  </select>
                </label>
                <label className="wide">
                  指标值
                  <input
                    aria-label="名单指标"
                    value={rule.value}
                    onChange={(e) =>
                      setRule({ ...rule, value: e.target.value })
                    }
                    placeholder="例如 203.0.113.0/24 或 example.org"
                  />
                </label>
                <label>
                  适用范围
                  <select
                    value={rule.scope}
                    onChange={(e) =>
                      setRule({ ...rule, scope: e.target.value })
                    }
                  >
                    <option value="global">全局（所有事件）</option>
                    <option value={workspace.activeCase}>
                      仅当前事件（临时）
                    </option>
                  </select>
                </label>
                <label>
                  有效期（可空）
                  <input
                    type="datetime-local"
                    value={rule.expiresAt}
                    onChange={(e) =>
                      setRule({ ...rule, expiresAt: e.target.value })
                    }
                  />
                </label>
                <TextEditor
                  label="名单依据"
                  fieldClassName="wide"
                  aria-label="名单依据"
                  rows={2}
                  value={rule.notes}
                  onChange={(e) => setRule({ ...rule, notes: e.target.value })}
                />
              </div>
              <button
                disabled={!!busy || !rule.value.trim() || !rule.notes.trim()}
                onClick={() =>
                  run(
                    '添加名单',
                    () =>
                      action('ruleAdd', {
                        ...rule,
                        expiresAt: rule.expiresAt
                          ? new Date(rule.expiresAt).toISOString()
                          : null,
                      }),
                    () => {
                      setRule({ ...rule, value: '', notes: '' });
                      showView('rule-main');
                    },
                  )
                }
              >
                <Plus size={14} />
                添加规则
              </button>
              <p className="muted">
                IP 支持 CIDR；域名 / URL / Hash
                为精确匹配。默认保存为全局规则，切换事件后仍然生效；名单命中只提供研判依据，不会自动封禁、放行或删除证据，黑白冲突会同时呈现。
              </p>
            </div>
            <div className="platform-card" data-panel="rule-main">
              <h2>
                全局黑白名单 <small>全局规则对所有事件持续生效</small>
              </h2>
              {!data.rules.length ? (
                <Empty text="添加规则，为流量与页面巡检提供名单依据。" />
              ) : (
                data.rules
                  .filter(
                    (r) =>
                      r.scope === 'global' || r.scope === workspace.activeCase,
                  )
                  .map((r) => (
                    <article className="platform-row" key={r.id}>
                      <div className="platform-inline">
                        <strong>
                          {r.list === 'allow' ? '白名单' : '黑名单'} · {r.kind}
                        </strong>
                        <span>
                          {r.enabled ? '启用' : '停用'} ·{' '}
                          {r.scope === 'global' ? '全局' : '本事件'} · 失效{' '}
                          {stamp(r.expiresAt)}
                        </span>
                        <button
                          disabled={!!busy}
                          onClick={() =>
                            run('更新规则', () =>
                              action('ruleToggle', {
                                id: r.id,
                                enabled: !r.enabled,
                              }),
                            )
                          }
                        >
                          {r.enabled ? '停用' : '启用'}
                        </button>
                        {r.scope !== 'global' && (
                          <button
                            disabled={!!busy}
                            onClick={() =>
                              run('设为全局规则', () =>
                                action('rulePromote', { id: r.id }),
                              )
                            }
                          >
                            设为全局
                          </button>
                        )}
                      </div>
                      <code>{r.value}</code>
                      <p>{r.notes}</p>
                    </article>
                  ))
              )}
            </div>
          </>
        )}
        {page === 'samples' && (
          <>
            <div className="platform-card" data-panel="sample-new">
              <h2>整理分析案例</h2>
              <div className="platform-form">
                <label>
                  案例名称
                  <input
                    aria-label="案例名称"
                    value={sample.title}
                    onChange={(e) =>
                      setSample({ ...sample, title: e.target.value })
                    }
                  />
                </label>
                <label>
                  家族 / 类型（待核对）
                  <input
                    value={sample.family}
                    onChange={(e) =>
                      setSample({ ...sample, family: e.target.value })
                    }
                  />
                </label>
                <TextEditor
                  label="Hash（可多个）"
                  fieldClassName="wide"
                  code
                  aria-label="案例 Hash"
                  rows={2}
                  value={sample.hashes}
                  onChange={(e) =>
                    setSample({ ...sample, hashes: e.target.value })
                  }
                />
                <label>
                  人工分类
                  <select
                    value={sample.verdict}
                    onChange={(e) =>
                      setSample({ ...sample, verdict: e.target.value })
                    }
                  >
                    {Object.entries(labels)
                      .slice(0, 4)
                      .map(([v, l]) => (
                        <option value={v} key={v}>
                          {l}
                        </option>
                      ))}
                  </select>
                </label>
                <label>
                  关联证据
                  <select
                    value={sample.evidenceId}
                    onChange={(e) =>
                      setSample({ ...sample, evidenceId: e.target.value })
                    }
                  >
                    <option value="">外部案例 / 无关联</option>
                    {workspace.evidence.map((e) => (
                      <option value={e.id} key={e.id}>
                        {e.name}
                      </option>
                    ))}
                  </select>
                </label>
                <TextEditor
                  label="分析笔记与依据"
                  fieldClassName="wide"
                  size="large"
                  aria-label="案例分析笔记"
                  value={sample.notes}
                  onChange={(e) =>
                    setSample({ ...sample, notes: e.target.value })
                  }
                />
              </div>
              <button
                disabled={
                  !!busy || !sample.title.trim() || !sample.hashes.trim()
                }
                onClick={() =>
                  run(
                    '保存案例',
                    () => action('sampleAdd', sample),
                    () => {
                      showView('sample-main');
                      setSample({
                        ...sample,
                        title: '',
                        hashes: '',
                        notes: '',
                      });
                    },
                  )
                }
              >
                保存案例
              </button>
            </div>
            <div className="platform-card" data-panel="sample-main">
              <h2>本地案例</h2>
              {!data.sampleCases.length ? (
                <Empty text="将静态 / 动态分析发现整理为可查证的样本案例。" />
              ) : (
                data.sampleCases.map((s) => (
                  <article className="platform-row" key={s.id}>
                    <div className="platform-inline">
                      <strong>{s.title}</strong>
                      <span>
                        {labels[s.verdict]} · {s.family || '家族未确认'}
                      </span>
                    </div>
                    <Detail title="文件 Hash" value={JSON.parse(s.hashes)} />
                    <p>{s.notes}</p>
                    {s.evidenceId && s.caseId === workspace.activeCase && (
                      <button onClick={() => onEvidence(s.evidenceId!)}>
                        关联分析报告
                      </button>
                    )}
                  </article>
                ))
              )}
            </div>
          </>
        )}
        {(page === 'agents' || page === 'flows') && (
          <>
            <div className="platform-stats">
              <div>
                <b>{data.tasks.filter((t) => t.enabled).length}</b>
                <span>有效采集任务</span>
              </div>
              <div>
                <b>{data.flows.length}</b>
                <span>最近流量窗口</span>
              </div>
              <div>
                <b>{queue}</b>
                <span>待 AI 分析</span>
              </div>
              <div>
                <b>{reviewed}</b>
                <span>已有研判观测</span>
              </div>
            </div>
            {page === 'agents' && (
              <>
                <div className="platform-card" data-panel="agent-new">
                  <h2>生成客户端专属任务包</h2>
                  <div className="platform-form">
                    <label>
                      任务名称
                      <input
                        aria-label="Agent 任务名称"
                        value={task.name}
                        onChange={(e) =>
                          setTask({ ...task, name: e.target.value })
                        }
                      />
                    </label>
                    <label>
                      目标备注
                      <input
                        aria-label="Agent 目标备注"
                        value={task.target}
                        onChange={(e) =>
                          setTask({ ...task, target: e.target.value })
                        }
                        placeholder="仅作识别，不由客户端远程执行"
                      />
                    </label>
                    <label>
                      采集方式
                      <select
                        aria-label="Agent 采集方式"
                        value={task.mode}
                        onChange={(e) =>
                          setTask({
                            ...task,
                            mode: e.target.value,
                            architecture:
                              e.target.value === 'ebpf' &&
                              task.architecture === 'windows-amd64'
                                ? 'linux-amd64'
                                : task.architecture,
                          })
                        }
                      >
                        <option value="snapshot">一次性只读元数据快照</option>
                        <option value="ebpf">Linux eBPF 持续流量窗口</option>
                      </select>
                    </label>
                    <label>
                      目标系统
                      <select
                        aria-label="Agent 目标系统"
                        value={task.architecture}
                        onChange={(e) =>
                          setTask({ ...task, architecture: e.target.value })
                        }
                      >
                        <option value="linux-amd64">Linux x86_64</option>
                        <option value="linux-arm64">Linux ARM64</option>
                        {task.mode !== 'ebpf' && (
                          <option value="windows-amd64">Windows x86_64</option>
                        )}
                      </select>
                    </label>
                    {task.mode === 'ebpf' && (
                      <>
                        <label>
                          网卡
                          <input
                            value={task.interface}
                            onChange={(e) =>
                              setTask({ ...task, interface: e.target.value })
                            }
                          />
                        </label>
                        <label>
                          采集时长（秒）
                          <input
                            type="number"
                            min={5}
                            max={86400}
                            value={task.durationSeconds}
                            onChange={(e) =>
                              setTask({
                                ...task,
                                durationSeconds: +e.target.value,
                              })
                            }
                          />
                        </label>
                        <label>
                          窗口（秒）
                          <input
                            type="number"
                            min={5}
                            max={300}
                            value={task.batchSeconds}
                            onChange={(e) =>
                              setTask({
                                ...task,
                                batchSeconds: +e.target.value,
                              })
                            }
                          />
                        </label>
                        <label>
                          每包解析上限（字节）
                          <input
                            type="number"
                            min={128}
                            max={4096}
                            value={task.snaplen}
                            onChange={(e) =>
                              setTask({ ...task, snaplen: +e.target.value })
                            }
                          />
                        </label>
                        <label className="platform-check wide">
                          <input
                            type="checkbox"
                            checked={task.includeHttp}
                            onChange={(e) =>
                              setTask({
                                ...task,
                                includeHttp: e.target.checked,
                              })
                            }
                          />
                          采集明文 HTTP 首行片段（可能含敏感路径，默认关闭）
                        </label>
                      </>
                    )}
                    <label>
                      任务有效期（小时）
                      <input
                        type="number"
                        min={1}
                        max={168}
                        value={task.hours}
                        onChange={(e) =>
                          setTask({ ...task, hours: +e.target.value })
                        }
                      />
                    </label>
                    <label className="platform-check">
                      <input
                        type="checkbox"
                        checked={task.online}
                        onChange={(e) =>
                          setTask({ ...task, online: e.target.checked })
                        }
                      />
                      HTTPS 自动回传（需先配置接收证书）
                    </label>
                  </div>
                  <div className="platform-actions">
                    <button
                      disabled={!!busy || !task.name.trim()}
                      onClick={generate}
                    >
                      <Download size={14} />
                      生成任务 ZIP
                    </button>
                    <button
                      disabled={!!busy}
                      onClick={() => pickImport('agent')}
                    >
                      <Upload size={14} />
                      导入加密采集包
                    </button>
                  </div>
                  <details className="platform-detail agent-help">
                    <summary>采集范围与密钥说明</summary>
                    <p className="muted">
                      ZIP 内是对应架构
                      Agent、专属配置和运行说明。在授权目标解压后手动运行，先使用
                      -check
                      检查环境。快照采集固定元数据，缺项会记录；不是完整主机取证。
                    </p>
                    <p className="muted">
                      RSA-OAEP +
                      AES-GCM，仅原客户端私钥可解密；私钥保存在系统凭据中，本版尚无私钥备份界面。解密证据本地明文保存，系统凭据丢失后旧包无法恢复。
                    </p>
                  </details>
                  {data.identity && (
                    <code className="platform-hash">
                      本客户端公钥指纹 {data.identity.fingerprint}
                    </code>
                  )}
                </div>
                <div className="platform-card" data-panel="receiver">
                  <h2>
                    HTTPS 接收端{' '}
                    <small>
                      {data.receiverRunning ? '正在监听' : '已停止'}
                    </small>
                  </h2>
                  <div className="platform-form">
                    <label>
                      监听地址
                      <input
                        aria-label="接收监听地址"
                        value={receiver.bind}
                        onChange={(e) =>
                          setReceiver({ ...receiver, bind: e.target.value })
                        }
                        placeholder="127.0.0.1:3443"
                      />
                    </label>
                    <label>
                      目标可达回传根地址
                      <input
                        aria-label="回传根地址"
                        value={receiver.callbackUrl}
                        onChange={(e) =>
                          setReceiver({
                            ...receiver,
                            callbackUrl: e.target.value,
                          })
                        }
                        placeholder="https://client.example.org:3443"
                      />
                    </label>
                  </div>
                  <div className="platform-actions">
                    <button
                      disabled={!!busy || data.receiverRunning}
                      onClick={() =>
                        run('保存接收配置', () =>
                          action('receiverSave', receiver),
                        )
                      }
                    >
                      保存配置与证书
                    </button>
                    <button
                      disabled={!!busy}
                      onClick={() =>
                        run('接收服务', () =>
                          action(
                            data.receiverRunning
                              ? 'receiverStop'
                              : 'receiverStart',
                          ),
                        )
                      }
                    >
                      {data.receiverRunning ? '停止接收' : '启动 HTTPS 接收'}
                    </button>
                  </div>
                  <p className="muted">
                    接收端使用 HTTPS
                    与固定证书，任务凭据、有效期及撤销状态均会校验。密钥运算已迁移至
                    AWS-LC，旧离线包保持兼容；只在目标可达的授权网络中启动。
                  </p>
                </div>
                <div className="platform-card" data-panel="agent-main">
                  <h2>采集任务</h2>
                  {!data.tasks.length ? (
                    <Empty text="生成任务后，在这里查看批次回传和撤销状态。" />
                  ) : (
                    data.tasks.map((t) => (
                      <article className="platform-row" key={t.id}>
                        <div className="platform-inline">
                          <strong>{t.name}</strong>
                          <span>
                            {t.target || '未填写目标'} · {t.mode} ·{' '}
                            {t.architecture}
                          </span>
                          <button
                            disabled={!!busy || !t.enabled}
                            onClick={() =>
                              run('撤销任务', () =>
                                action('agentRevoke', { id: t.id }),
                              )
                            }
                          >
                            {t.enabled ? '撤销任务' : '已撤销'}
                          </button>
                        </div>
                        <code>{t.id}</code>
                        <p>
                          {t.batches} 个已入库批次 · 最近 {stamp(t.lastSeen)} ·
                          到期 {stamp(t.expiresAt)}
                        </p>
                      </article>
                    ))
                  )}
                </div>
              </>
            )}
            {page === 'flows' && (
              <>
                <div
                  className="platform-card platform-note"
                  data-panel="flow-scope"
                >
                  <Activity size={20} />
                  <h2>观测范围</h2>
                  <p>
                    Linux 目标使用 eBPF socket filter +
                    AF_PACKET，在当前网络命名空间聚合流量。每窗最多 2000
                    条流，界面及自动 AI 摘要保留前 100
                    条，完整窗口关联原始证据。
                  </p>
                  <p>
                    不解密 TLS、不做 TCP 重组、不关联
                    PID；可见性受网卡、权限、内核、丢包和解析限制影响。当前
                    macOS 环境未验证真实 Linux 内核挂载。
                  </p>
                </div>
                <div
                  className="platform-card flow-master"
                  data-panel="flow-list"
                >
                  <h2>
                    采集窗口 <small>{data.flows.length}</small>
                  </h2>
                  {!data.flows.length ? (
                    <Empty text="等待 Agent 回传" />
                  ) : (
                    data.flows.map((w) => (
                      <button
                        key={w.id}
                        className={`flow-select ${(flowId || data.flows[0]?.id) === w.id ? 'selected' : ''}`}
                        onClick={() => setFlowId(w.id)}
                      >
                        <strong>{w.target || w.taskId}</strong>
                        <small>{stamp(w.createdAt)}</small>
                        <span>
                          {w.observedPackets} 包 · {w.flowCount} 流 ·{' '}
                          {w.listHitCount} 名单命中
                        </span>
                      </button>
                    ))
                  )}
                </div>
                <div className="platform-card" data-panel="flow-main">
                  <h2>流量窗口</h2>
                  {!data.flows.length ? (
                    <Empty text="在「采集 Agent」生成 Linux eBPF 任务，回传或导入后展示流量窗口。" />
                  ) : (
                    data.flows
                      .filter((w) => w.id === (flowId || data.flows[0]?.id))
                      .map((w) => (
                        <article className="platform-row" key={w.id}>
                          <div className="platform-inline">
                            <strong>{w.target || w.taskId}</strong>
                            <span>{stamp(w.createdAt)}</span>
                            <button onClick={() => onEvidence(w.evidenceId)}>
                              证据 / AI <ArrowUpRight size={13} />
                            </button>
                          </div>
                          <div className="platform-metrics">
                            <span>
                              观测包 <b>{w.observedPackets}</b>
                            </span>
                            <span>
                              聚合流 <b>{w.flowCount}</b>
                            </span>
                            <span>
                              内核丢包 <b>{w.kernelDrops ?? '未提供'}</b>
                            </span>
                            <span>
                              未解析 <b>{w.unparsedPackets}</b>
                            </span>
                            <span>
                              上限省略包 <b>{w.omittedFlowPackets}</b>
                            </span>
                            <span>
                              名单命中 <b>{w.listHitCount}</b>
                            </span>
                          </div>
                          <div className="platform-table-wrap">
                            <table className="platform-table">
                              <thead>
                                <tr>
                                  <th>源</th>
                                  <th>目标</th>
                                  <th>协议</th>
                                  <th>包 / 字节</th>
                                </tr>
                              </thead>
                              <tbody>
                                {w.flows.slice(0, 100).map((f, i) => (
                                  <tr key={i}>
                                    <td>
                                      <code>
                                        {f.sourceIp}:{f.sourcePort}
                                      </code>
                                    </td>
                                    <td>
                                      <code>
                                        {f.destinationIp}:{f.destinationPort}
                                      </code>
                                    </td>
                                    <td>{f.protocol}</td>
                                    <td>
                                      {f.packets} / {f.bytes}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          <button
                            onClick={() =>
                              onRecord(
                                w.evidenceId,
                                '重点主机流量观测 · 待复核',
                                `窗口 ${w.id}\n目标 ${w.target}\n观测包 ${w.observedPackets} / 内核丢包 ${w.kernelDrops ?? '未提供'}\n不解密 TLS；完整流与采集范围见关联证据。`,
                              )
                            }
                          >
                            记录时间线
                          </button>
                        </article>
                      ))
                  )}
                </div>
              </>
            )}
            <div className="platform-card" data-panel="ai-settings">
              <h2>
                自动 AI 研判{' '}
                <small>
                  {data.aiLocked
                    ? 'AI 外发锁定'
                    : data.aiSettings.enabled
                      ? '已授权'
                      : '已关闭'}
                </small>
              </h2>
              <p className="muted">
                向已配置的模型 API 发送观测摘要、名单匹配及最多前 100
                条流，不发送完整网页、JS 和采集文件。AI 请求会保留
                Prompt、耗时、引用和失败记录。仅处理授权事件在保存启用后新增的观测，历史积压保留给人工选择。
              </p>
              <p className="muted">
                当前事件可自动处理 {data.aiQueue.eligible} 条 · 保留待人工选择{' '}
                {data.aiQueue.retained} 条
              </p>
              {data.aiSettings.needsConfirmation && (
                <p className="muted">
                  旧版全工作区授权已停止，请核对范围后重新启用。
                </p>
              )}
              {data.aiSettings.enabled && (
                <p className="muted">
                  授权事件：
                  {workspace.cases.find(
                    (c) => c.id === data.aiSettings.scopeCaseId,
                  )?.title || '其他事件'}{' '}
                  · 新观测起点 {stamp(data.aiSettings.enabledAfter)}
                </p>
              )}
              <p className="muted">
                同一工作区一次授权一个事件。每次保存启用都从此刻开始，替换原授权；切换事件不会扩大范围。外发锁可在“隐私与外发”管理。
              </p>
              <div className="platform-form">
                <label className="platform-check">
                  <input
                    aria-label="启用监控自动 AI"
                    type="checkbox"
                    disabled={data.aiLocked}
                    checked={ai.enabled}
                    onChange={(e) =>
                      setAi({ ...ai, enabled: e.target.checked })
                    }
                  />
                  仅授权当前事件的新观测
                </label>
                <label>
                  两次调用最小间隔（秒）
                  <input
                    type="number"
                    min={15}
                    max={3600}
                    value={ai.minIntervalSecs}
                    onChange={(e) =>
                      setAi({ ...ai, minIntervalSecs: +e.target.value })
                    }
                  />
                </label>
                <label>
                  每小时调用上限
                  <input
                    type="number"
                    min={1}
                    max={240}
                    value={ai.maxPerHour}
                    onChange={(e) =>
                      setAi({ ...ai, maxPerHour: +e.target.value })
                    }
                  />
                </label>
              </div>
              <button
                disabled={!!busy}
                onClick={() =>
                  run('保存 AI 调度', () => action('monitorAiSave', ai))
                }
              >
                {ai.enabled ? '授权当前事件并保存' : '停止自动 AI 并保存'}
              </button>
            </div>
            <div className="platform-card" data-panel="queue">
              <h2>
                观测与研判队列 <small>最近 200 条</small>
              </h2>
              {!data.observations.length ? (
                <Empty text="页面变化与 Agent 批次会进入观测队列。" />
              ) : (
                data.observations.map((o) => (
                  <article className="platform-row" key={o.id}>
                    <div className="platform-inline">
                      <strong>{o.subject}</strong>
                      <span>
                        {o.kind} · {labels[o.aiState] || o.aiState} ·{' '}
                        {stamp(o.createdAt)}
                      </span>
                    </div>
                    <p>{o.summary}</p>
                    {o.error && <p>{o.error}</p>}
                    <button onClick={() => onEvidence(o.evidenceId)}>
                      <FileSearch size={13} />
                      查看证据与分析过程
                    </button>
                  </article>
                ))
              )}
            </div>
          </>
        )}
        {page === 'environment' && (
          <>
            <div className="platform-actions" data-panel="env-actions">
              <button
                disabled={!!busy}
                onClick={() =>
                  run('本机环境检查', async () => {
                    // 全部为只读检查；模型就绪状态来自配置，不读取 Key 或发送验证请求。
                    const results = await Promise.allSettled([
                      action<Record<string, unknown>>('environment'),
                      invoke<Record<string, unknown>>('check_docker'),
                      invoke<{ imageId: string | null }>('reverse_environment'),
                    ]);
                    const errors: string[] = [];
                    const local = results[0],
                      runtime = results[1],
                      isolated = results[2];
                    if (local.status === 'fulfilled') setEnv(local.value);
                    else {
                      setEnv(null);
                      errors.push('本机：' + String(local.reason));
                    }
                    if (runtime.status === 'fulfilled')
                      setDocker(runtime.value);
                    else {
                      setDocker(null);
                      errors.push('Docker：' + String(runtime.reason));
                    }
                    if (isolated.status === 'fulfilled')
                      setStaticEnvironment(isolated.value);
                    else {
                      setStaticEnvironment(null);
                      errors.push('静态隔离：' + String(isolated.reason));
                    }
                    setEnvironmentErrors(errors);
                  })
                }
              >
                <Server size={14} />
                检查本机环境
              </button>
              <button
                disabled={!!busy}
                onClick={() =>
                  run(
                    'Docker 检查',
                    () => invoke<Record<string, unknown>>('check_docker'),
                    setDocker,
                  )
                }
              >
                检查 Docker
              </button>
            </div>
            <div className="setup-summary" data-panel="setup-summary">
              <section className="setup-item">
                <h2>本地分析与存储</h2>
                <span
                  className="setup-status"
                  data-state={env?.writable ? 'ready' : 'pending'}
                >
                  {env
                    ? env.writable
                      ? '存储可用'
                      : '需要检查工作区权限'
                    : '等待检查'}
                </span>
                <p>HTTP、日志、情报与报告可本地使用，不依赖模型或 Docker。</p>
              </section>
              <section className="setup-item">
                <h2>四家官方模型</h2>
                <span
                  className="setup-status"
                  data-state={
                    aiConfig.hasKey && !aiConfig.validationError
                      ? 'ready'
                      : 'pending'
                  }
                >
                  {aiConfig.hasKey && !aiConfig.validationError
                    ? '已配置 · 连接待手动验证'
                    : '需要配置'}
                </span>
                <p>
                  {aiConfig.model || 'DeepSeek / Qwen / GLM / Kimi'}
                  。环境检查不会调用模型或发送证据。
                </p>
                <button onClick={onSettings}>打开模型设置</button>
              </section>
              <section className="setup-item">
                <h2>样本静态隔离</h2>
                <span
                  className="setup-status"
                  data-state={
                    docker?.daemonReady && staticEnvironment?.imageId
                      ? 'ready'
                      : 'pending'
                  }
                >
                  {docker
                    ? !docker.daemonReady
                      ? 'Docker 尚未就绪'
                      : staticEnvironment?.imageId
                        ? 'Docker 与静态镜像已就绪'
                        : '静态镜像待准备'
                    : '等待检查'}
                </span>
                <p>
                  WebShell 与 PE / ELF
                  解析需要禁网容器；在隔离环境页显式准备镜像。
                </p>
                <button onClick={onIsolation}>打开隔离环境</button>
              </section>
              <section className="setup-item">
                <h2>远端采集与行为观察</h2>
                <span className="setup-status">按目标环境单独检查</span>
                <p>
                  Agent
                  模板状态见下方。动态运行不可信样本需要专用隔离虚拟机；目标
                  Linux 权限和内核在 Agent 侧验证。
                </p>
              </section>
            </div>
            {environmentErrors.length > 0 && (
              <p role="alert" className="setup-error">
                {environmentErrors.join('\n')}
              </p>
            )}
            <div className="platform-card" data-panel="env-main">
              <h2>客户端运行环境</h2>
              {env ? (
                <>
                  <div className="platform-stats">
                    <div>
                      <b>{String(env.os)}</b>
                      <span>系统</span>
                    </div>
                    <div>
                      <b>{String(env.architecture)}</b>
                      <span>架构</span>
                    </div>
                    <div>
                      <b>{String(env.cpuThreads)}</b>
                      <span>逻辑线程</span>
                    </div>
                    <div>
                      <b>
                        {typeof env.availableBytes === 'number'
                          ? (env.availableBytes / 1024 ** 3).toFixed(1) + ' GiB'
                          : '未知'}
                      </b>
                      <span>可用磁盘</span>
                    </div>
                  </div>
                  <p>存储可写：{env.writable ? '通过' : '失败'}</p>
                  <code>{String(env.dataDir)}</code>
                  <Detail title="Agent 模板" value={env.templates} />
                  <p>{String(env.ebpf)}</p>
                  <p>{String(env.scheduler)}</p>
                  <p>{String(env.database)}</p>
                </>
              ) : (
                <Empty text="点击检查，获取当前机器的真实状态。" />
              )}
            </div>
            {docker && (
              <div className="platform-card" data-panel="env-docker">
                <h2>Docker 状态</h2>
                <p>{String(docker.message)}</p>
                <Detail title="检测结果" value={docker} />
              </div>
            )}
            <div className="platform-card platform-note" data-panel="env-info">
              <h2>终端与目标主机各司其职</h2>
              <p>
                macOS / Windows 客户端管理事件、证据、情报与模型；Linux Agent
                执行固定只读采集或 eBPF 观测。目标侧执行 -check
                检查内核、权限与网卡，客户端不会自动提权。
              </p>
              <p>
                Docker 和 Windows 沙箱配置位于「动态行为分析」；模型
                API、主题与启动动画位于「AI 与设置」。用户运行安装包无需
                Node、Rust 或 Go。
              </p>
            </div>
          </>
        )}
      </div>
      <footer className="platform-status">
        <span>
          <span className="status-dot" /> SQLite 本地工作区
        </span>
        <span>
          {data.assets.filter((a) => a.enabled).length} 项资产定时启用
        </span>
        <span>
          待 AI 研判 {queue} · 已有研判 {reviewed}
        </span>
        <span>{busy || '就绪'}</span>
      </footer>
    </section>
  );
}
