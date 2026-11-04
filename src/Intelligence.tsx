import { TextEditor } from './TextEditor';
import { useCallback, useEffect, useState } from 'react';
import { invoke, isTauri } from './bridge';
import { listen } from '@tauri-apps/api/event';
import type { Evidence, Workspace } from './types';
import {
  Search,
  ShieldCheck,
  LockKeyhole,
  FilePlus2,
  RefreshCw,
} from 'lucide-react';
import './intelligence.css';

type Provider = {
  id: string;
  enabled: boolean;
  hasKey: boolean;
  authorized: boolean;
  revision: string;
};
type Config = { locked: boolean; providers: Provider[] };
type Job = {
  id: string;
  caseId: string;
  provider: string;
  operation: string;
  kind: string;
  indicator: string;
  state: string;
  outcome: string;
  message: string;
  createdAt: string;
  fetchedAt: string | null;
  sourceUrl: string;
  sourceJobId: string | null;
  resultSha256: string | null;
  result: unknown;
  resultEvidenceId: string | null;
  currentOnly: boolean;
};
const services = [
  {
    id: 'threatbook',
    title: '微步 ThreatBook',
    note: '需绑定出口 IP，并开通对应接口权限。无结果和处理中也可能消耗配额。',
  },
  {
    id: 'rdap',
    title: 'RDAP 注册信息',
    note: '无需 Key。查询当前域名注册信息，可能脱敏；不提供历史 WHOIS 或身份认定。',
  },
  {
    id: 'abuseipdb',
    title: 'AbuseIPDB',
    note: '查询最近 30 天 IP 举报背景；评分不代表本机入侵或攻击成功。',
  },
  {
    id: 'virustotal',
    title: 'VirusTotal',
    note: '仅查询已有文件 Hash 报告。Public API 有商业和业务工作流限制；持有 Key 不等于符合使用条件。',
  },
];
const operations: Record<
  string,
  { id: string; title: string; kinds: string[] }[]
> = {
  threatbook: [
    { id: 'inbound', title: '入站攻击源信誉', kinds: ['ip'] },
    { id: 'outbound', title: '出站 C2 / 失陷线索', kinds: ['ip', 'domain'] },
    { id: 'ip_context', title: 'IP 完整上下文', kinds: ['ip'] },
    { id: 'domain_context', title: '域名上下文', kinds: ['domain'] },
    { id: 'hash', title: '已有文件报告', kinds: ['sha256', 'sha1', 'md5'] },
  ],
  rdap: [{ id: 'registration', title: '当前域名注册信息', kinds: ['domain'] }],
  abuseipdb: [{ id: 'reports', title: 'IP 举报记录 · 30 天', kinds: ['ip'] }],
  virustotal: [
    {
      id: 'hash',
      title: '已有文件 Hash 报告',
      kinds: ['sha256', 'sha1', 'md5'],
    },
  ],
};
const names: Record<string, string> = {
  queued: '排队中',
  running: '查询中',
  completed: '查询完成',
  skipped: '未外发',
  failed: '查询失败',
  cancelled: '已取消',
  interrupted: '已中断',
  data: '有情报',
  no_data: '暂无记录',
  pending: '报告生成中',
  partial: '部分结果',
  unauthorized: '凭据或账号无效',
  forbidden: '权限不足',
  quota: '限频 / 额度不足',
  ip_not_bound: '出口 IP 未绑定',
  expired: '授权已到期',
  unknown: '尚无结果',
};
const title = (id: string) => services.find((s) => s.id === id)?.title ?? id;
const stamp = (s: string | null) =>
  s ? new Date(s).toLocaleString('zh-CN', { hour12: false }) : '尚未取得';

export function ThreatIntelSettings() {
  const [cfg, setCfg] = useState<Config>();
  const [id, setId] = useState('threatbook');
  const [key, setKey] = useState('');
  const [enabled, setEnabled] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  useEffect(() => {
    let active = true;
    if (isTauri())
      invoke<Config>('get_intel_config')
        .then((v) => {
          if (active) setCfg(v);
        })
        .catch((e) => {
          if (active) setError(String(e));
        });
    return () => {
      active = false;
    };
  }, []);
  useEffect(() => {
    const p = cfg?.providers.find((p) => p.id === id);
    setEnabled(p?.enabled ?? false);
    setAuthorized(p?.authorized ?? false);
    setKey('');
  }, [cfg, id]);
  async function act(fn: () => Promise<Config>, message: string) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      setCfg(await fn());
      setNotice(message);
      setKey('');
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  const p = cfg?.providers.find((p) => p.id === id);
  return (
    <div className="ti-settings">
      <h2>情报服务</h2>
      <p className="muted">
        由本客户端直连官方服务，密钥仅保存在系统凭据库。与四家 AI 模型独立配置。
      </p>
      {error && (
        <div className="error-banner" role="alert">
          {error}
        </div>
      )}
      {notice && <p role="status">{notice}</p>}
      <div className="ti-lock">
        <LockKeyhole size={20} />
        <div>
          <strong>
            {cfg?.locked !== false ? '情报外发已锁定' : '情报查询允许外发'}
          </strong>
          <p>
            锁定会取消尚未完成的情报查询。已发送的数据不能撤回；AI
            外发由隐私设置单独控制。
          </p>
        </div>
        <button
          disabled={!cfg || busy}
          onClick={() =>
            act(
              () => invoke<Config>('set_intel_lock', { locked: !cfg?.locked }),
              cfg?.locked
                ? '情报查询已解锁，发起查询前仍需确认指标范围。'
                : '情报查询已锁定。',
            )
          }
        >
          {cfg?.locked ? '解锁情报查询' : '锁定情报查询'}
        </button>
      </div>
      <label>
        服务
        <select
          value={id}
          disabled={busy}
          onChange={(e) => {
            setId(e.target.value);
            setNotice('');
          }}
        >
          {services.map((s) => (
            <option key={s.id} value={s.id}>
              {s.title}
            </option>
          ))}
        </select>
      </label>
      <p>{services.find((s) => s.id === id)?.note}</p>
      {id !== 'rdap' && (
        <label>
          API Key · {p?.hasKey ? '系统凭据已保存' : '尚未配置'}
          <input
            aria-label="情报 API Key"
            type="password"
            autoComplete="off"
            value={key}
            disabled={busy}
            placeholder={p?.hasKey ? '留空保留现有密钥' : '填写官方服务 Key'}
            onChange={(e) => setKey(e.target.value)}
          />
        </label>
      )}
      <label className="check">
        <input
          type="checkbox"
          checked={authorized}
          disabled={busy}
          onChange={(e) => setAuthorized(e.target.checked)}
        />
        我已确认账号允许当前用途、本地保存及报告引用；待查询指标允许发送给此服务。
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={enabled}
          disabled={busy}
          onChange={(e) => setEnabled(e.target.checked)}
        />
        启用此服务
      </label>
      <div className="ti-actions">
        <button
          disabled={!cfg || busy || (enabled && !authorized)}
          onClick={() =>
            act(
              () =>
                invoke<Config>('save_intel_provider', {
                  id,
                  enabled,
                  authorized,
                  apiKey: key,
                  removeKey: false,
                }),
              '配置已保存。尚未发出查询，不代表鉴权已验证。',
            )
          }
        >
          保存服务配置
        </button>
        {id !== 'rdap' && (
          <button
            disabled={busy || !p?.hasKey}
            onClick={() =>
              act(
                () =>
                  invoke<Config>('save_intel_provider', {
                    id,
                    enabled: false,
                    authorized,
                    apiKey: '',
                    removeKey: true,
                  }),
                '系统凭据已删除，此服务已停用。',
              )
            }
          >
            删除密钥并停用
          </button>
        )}
      </div>
      <p className="setting-note">
        在「威胁情报 →
        在线查询」输入允许外发的指标，可实际验证权限、连接和返回结果；可能消耗额度。首批不上传文件、不发送完整
        URL、不主动扫描目标。
      </p>
    </div>
  );
}

export type IntelSeed = {
  caseId: string;
  kind: string;
  value: string;
  evidenceId?: string;
};
export function OnlineIntelligence({
  workspace,
  seed,
  onSettings,
  onEvidence,
  onRecord,
  refresh,
}: {
  workspace: Workspace;
  seed?: IntelSeed;
  onSettings: () => void;
  onEvidence: (id: string) => void;
  onRecord: (id: string, title: string, body: string) => void;
  refresh: () => Promise<Workspace>;
}) {
  const [service, setService] = useState('rdap');
  const [operation, setOperation] = useState('registration');
  const [kind, setKind] = useState('domain');
  const [input, setInput] = useState('');
  const [consent, setConsent] = useState(false);
  const [currentOnly, setCurrentOnly] = useState(true);
  const [fresh, setFresh] = useState(false);
  const [rows, setRows] = useState<Job[]>([]);
  const [selected, setSelected] = useState('');
  const [detailRevision, setDetailRevision] = useState(0);
  const [detail, setDetail] = useState<Job>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [cfg, setCfg] = useState<Config>();
  const [originEvidenceId, setOriginEvidenceId] = useState<string | null>(null);
  const caseId = workspace.activeCase;
  const load = useCallback(async () => {
    const [jobs, settings] = await Promise.all([
      invoke<Job[]>('get_intel_jobs', { caseId }),
      invoke<Config>('get_intel_config'),
    ]);
    return { jobs, settings };
  }, [caseId]);
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const schedule = (delay: number) => {
      clearTimeout(timer);
      timer = setTimeout(tick, delay);
    };
    async function tick() {
      if (!active) return;
      // The native event stream remains authoritative while the window is
      // hidden. Defer the fallback query until the user returns to the app.
      if (document.hidden) {
        schedule(8000);
        return;
      }
      try {
        const { jobs, settings } = await load();
        if (!active) return;
        setRows(jobs);
        setCfg(settings);
        schedule(
          jobs.some((j) => ['queued', 'running'].includes(j.state))
            ? 1500
            : 8000,
        );
      } catch (e) {
        if (active) {
          setError(String(e));
          schedule(8000);
        }
      }
    }
    const onVisibilityChange = () => {
      if (!document.hidden) {
        clearTimeout(timer);
        void tick();
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    if (isTauri()) void tick();
    return () => {
      active = false;
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [load]);
  useEffect(() => {
    if (!isTauri()) return;
    let active = true;
    let stop: (() => void) | undefined;
    listen('intel-jobs-changed', () => {
      load()
        .then(({ jobs, settings }) => {
          if (active) {
            setRows(jobs);
            setCfg(settings);
            setDetailRevision((v) => v + 1);
          }
        })
        .catch((e) => {
          if (active) setError(String(e));
        });
    })
      .then((fn) => {
        if (active) stop = fn;
        else fn();
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
      stop?.();
    };
  }, [load]);
  useEffect(() => {
    if (!seed) return;
    const k = ['ip', 'domain', 'sha256', 'sha1', 'md5'].includes(seed.kind)
      ? seed.kind
      : 'domain';
    const p = k === 'domain' ? 'rdap' : 'threatbook';
    setService(p);
    setOperation(
      k === 'domain' ? 'registration' : k === 'ip' ? 'inbound' : 'hash',
    );
    setKind(k);
    setInput(seed.value);
    setOriginEvidenceId(seed.evidenceId ?? null);
    setConsent(false);
  }, [seed]);
  const status = rows.find((r) => r.id === selected);
  useEffect(() => {
    let active = true;
    setDetail(undefined);
    if (selected)
      invoke<Job>('get_intel_job', { caseId, id: selected })
        .then((j) => {
          if (active) setDetail(j);
        })
        .catch((e) => {
          if (active) setError(String(e));
        });
    return () => {
      active = false;
    };
  }, [
    caseId,
    selected,
    status?.state,
    status?.resultEvidenceId,
    detailRevision,
  ]);
  const opts = operations[service];
  const choice = opts.find((o) => o.id === operation) ?? opts[0];
  const values = input
    .split(/\r?\n/)
    .map((v) => v.trim())
    .filter(Boolean);
  const allowed = cfg?.providers.find((p) => p.id === service);
  const ready =
    cfg &&
    !cfg.locked &&
    allowed?.enabled &&
    allowed.authorized &&
    (service === 'rdap' || allowed.hasKey);
  async function submit() {
    setBusy(true);
    setError('');
    try {
      const jobs = await invoke<Job[]>('start_intel_query', {
        query: {
          caseId,
          evidenceId: originEvidenceId,
          provider: service,
          operation,
          kind,
          indicators: values,
          currentOnly,
          fresh,
          consent,
        },
      });
      const state = await load();
      setRows(state.jobs);
      setCfg(state.settings);
      setSelected(jobs[0]?.id ?? '');
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function cancel(id: string) {
    try {
      await invoke('cancel_intel_job', { id });
      setRows((await load()).jobs);
    } catch (e) {
      setError(String(e));
    }
  }
  async function cite(j: Job) {
    setBusy(true);
    setError('');
    try {
      const e = await invoke<Evidence>('archive_intel_result', { id: j.id });
      await refresh();
      setRows((await load()).jobs);
      onRecord(
        e.id,
        `${title(j.provider)} · ${j.indicator}`,
        `外部情报待复核，不能单独证明本机已失陷。\n指标：${j.indicator}\n查询范围：${operations[j.provider]?.find((o) => o.id === j.operation)?.title ?? j.operation}\n取得时间：${stamp(j.fetchedAt)}\n结果：${j.message}\n来源：${j.sourceUrl}\n快照 SHA-256：${j.resultSha256 ?? '无'}\n请补充现场证据、判断依据及复核人。`,
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  const json = detail?.result ? JSON.stringify(detail.result, null, 2) : '';
  return (
    <div className="ti-workspace">
      {error && (
        <div className="error-banner" role="alert">
          <span>{error}</span>
          <button onClick={() => setError('')}>关闭</button>
        </div>
      )}
      <div className="ti-query platform-card">
        <div className="ti-head">
          <h2>
            <Search size={18} />
            在线情报查询
          </h2>
          <button onClick={onSettings}>配置情报服务</button>
        </div>
        {!ready && (
          <p className="ti-hint">
            {cfg?.locked !== false
              ? '情报外发已锁定。'
              : '所选服务尚未启用、授权或配置凭据。'}{' '}
            在设置中完成配置后查询。
          </p>
        )}
        <div className="ti-fields">
          <label>
            服务
            <select
              aria-label="情报查询服务"
              value={service}
              disabled={busy}
              onChange={(e) => {
                const p = e.target.value;
                setService(p);
                setOperation(operations[p][0].id);
                setKind(operations[p][0].kinds[0]);
                setConsent(false);
              }}
            >
              {services.map((s) => (
                <option value={s.id} key={s.id}>
                  {s.title}
                </option>
              ))}
            </select>
          </label>
          <label>
            调查方向
            <select
              aria-label="情报查询方向"
              value={operation}
              disabled={busy}
              onChange={(e) => {
                setOperation(e.target.value);
                setKind(opts.find((o) => o.id === e.target.value)!.kinds[0]);
                setConsent(false);
              }}
            >
              {opts.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.title}
                </option>
              ))}
            </select>
          </label>
          <label>
            指标类型
            <select
              aria-label="情报指标类型"
              value={kind}
              disabled={busy}
              onChange={(e) => {
                setKind(e.target.value);
                setConsent(false);
              }}
            >
              {choice.kinds.map((k) => (
                <option value={k} key={k}>
                  {k.toUpperCase()}
                </option>
              ))}
            </select>
          </label>
        </div>
        <TextEditor
          label="将发送的指标 · 每行一个，最多 20 个"
          code
          aria-label="待查询指标"
          rows={4}
          value={input}
          onChange={(e) => {
            setInput(e.target.value);
            if (e.target.value.trim() !== seed?.value)
              setOriginEvidenceId(null);
            setConsent(false);
          }}
          placeholder="粘贴公网 IP、域名或文件 Hash；选择对应类型"
        />
        <p className="muted">
          仅发送所列指标及查询参数。私网、测试和特殊用途地址会跳过；Hash
          也可能暴露调查线索。无结果不等于安全。
        </p>
        <div className="ti-options">
          {service === 'threatbook' &&
            ['inbound', 'outbound'].includes(operation) && (
              <label className="check">
                <input
                  type="checkbox"
                  checked={currentOnly}
                  onChange={(e) => {
                    setCurrentOnly(e.target.checked);
                    setConsent(false);
                  }}
                />
                仅当前有效情报；取消则纳入历史过期情报
              </label>
            )}
          <label className="check">
            <input
              type="checkbox"
              checked={fresh}
              onChange={(e) => setFresh(e.target.checked)}
            />
            跳过一小时缓存重新查询，可能再次计费
          </label>
          <label className="check">
            <input
              aria-label="确认情报指标外发"
              type="checkbox"
              checked={consent}
              onChange={(e) => setConsent(e.target.checked)}
            />
            确认以上指标可发送给 {title(service)}；查询可能消耗额度
          </label>
        </div>
        <button
          className="primary"
          disabled={
            busy || !ready || !consent || !values.length || values.length > 20
          }
          onClick={submit}
        >
          <Search size={14} />
          {busy ? '提交中…' : `查询 ${values.length} 个指标`}
        </button>
      </div>
      <div className="ti-results platform-card">
        <div className="ti-head">
          <h2>
            本事件查询记录 <small>{rows.length} / 最新 200 条</small>
          </h2>
          <button
            aria-label="刷新情报查询记录"
            disabled={busy}
            onClick={async () => {
              try {
                const s = await load();
                setRows(s.jobs);
                setCfg(s.settings);
              } catch (e) {
                setError(String(e));
              }
            }}
          >
            <RefreshCw size={14} />
          </button>
        </div>
        <div className="ti-result-layout">
          <div className="ti-job-list">
            {!rows.length ? (
              <p className="ti-empty">
                <ShieldCheck size={24} />
                查询后在这里查看来源、状态和取得时间。
              </p>
            ) : (
              rows.map((j) => (
                <div
                  className="ti-job"
                  data-selected={j.id === selected}
                  key={j.id}
                >
                  <button
                    onClick={() => {
                      setSelected(j.id);
                      setDetailRevision((v) => v + 1);
                    }}
                  >
                    <strong>{j.indicator}</strong>
                    <span>
                      {title(j.provider)} · {names[j.state] ?? j.state} ·{' '}
                      {names[j.outcome] ?? j.outcome}
                      {j.sourceJobId ? ' · 缓存' : ''}
                    </span>
                    <small>{stamp(j.createdAt)}</small>
                  </button>
                  {['queued', 'running'].includes(j.state) && (
                    <button className="ti-cancel" onClick={() => cancel(j.id)}>
                      取消
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
          <div className="ti-result-detail">
            {detail ? (
              <>
                <h3>{detail.indicator}</h3>
                <p>{detail.message}</p>
                <dl>
                  <dt>操作</dt>
                  <dd>
                    {operations[detail.provider]?.find(
                      (o) => o.id === detail.operation,
                    )?.title ?? detail.operation}
                  </dd>
                  <dt>实际取得时间</dt>
                  <dd>{stamp(detail.fetchedAt)}</dd>
                  <dt>来源</dt>
                  <dd>{detail.sourceUrl || '尚未发送或未取得响应'}</dd>
                  <dt>结果摘要</dt>
                  <dd>
                    <code>{detail.resultSha256 || '尚无快照'}</code>
                  </dd>
                </dl>
                {detail.provider === 'threatbook' &&
                  ['inbound', 'outbound'].includes(detail.operation) && (
                    <p>
                      范围：
                      {detail.currentOnly
                        ? '仅当前有效情报'
                        : '包含历史过期情报'}
                    </p>
                  )}
                <div className="ti-actions">
                  {detail.state === 'completed' &&
                    ['data', 'no_data', 'partial'].includes(detail.outcome) && (
                      <button disabled={busy} onClick={() => cite(detail)}>
                        <FilePlus2 size={14} />
                        复核并加入事件报告
                      </button>
                    )}
                  {detail.resultEvidenceId && (
                    <button
                      onClick={() => onEvidence(detail.resultEvidenceId!)}
                    >
                      打开证据快照
                    </button>
                  )}
                </div>
                {json && (
                  <details>
                    <summary>来源响应 · 未经人工判定</summary>
                    <pre>
                      {json.slice(0, 64000)}
                      {json.length > 64000
                        ? '\n…界面预览已截断，举证保留完整有界快照。'
                        : ''}
                    </pre>
                  </details>
                )}
              </>
            ) : (
              <p className="ti-empty">选择一条记录查看详情。</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
