import { useEffect, useRef, useState } from 'react';
import { invoke, isTauri } from './bridge';
import {
  Clock3,
  LoaderCircle,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  ShieldQuestion,
  Search,
  Plus,
  Sparkles,
  RefreshCw,
} from 'lucide-react';
import type { Evidence, Workspace } from './types';
type Event = {
  evidenceId: string;
  evidenceName: string;
  line: number;
  rawTime: string;
  at: string | null;
  sourceIp: string | null;
  kind: string;
  title: string;
  excerpt: string;
  timeBasis: string;
};
type Cursor = { at: string; evidenceId: string; line: number };
type Data = {
  events: Event[];
  next: Cursor | null;
  total: number;
  unknownTimes: number;
  sources: {
    id: string;
    name: string;
    indexed: boolean;
    metadata?: { options?: { referenceYear?: number; offsetMinutes?: number } };
  }[];
};
declare global {
  interface Window {
    __GAGA_LOG_TIMELINE_FIXTURE__?: Record<string, Data>;
  }
}
const kinds = [
  ['', '全部行为'],
  ['ssh_failure', 'SSH 失败'],
  ['ssh_success', 'SSH 成功'],
  ['sudo', 'sudo 命令'],
  ['cron', '定时任务'],
  ['sensitive_path', '敏感路径'],
  ['script_access', '脚本访问'],
  ['traversal', '路径穿越'],
  ['injection', '注入特征'],
];
export function LogTimelinePanel({
  evidence,
  onAI,
  onRecorded,
}: {
  evidence: Evidence;
  onAI: (material: string, question: string) => void;
  onRecorded: (w: Workspace) => void;
}) {
  const [data, setData] = useState<Data | null>(null),
    [error, setError] = useState(''),
    [working, setWorking] = useState(''),
    [all, setAll] = useState(false),
    [ip, setIp] = useState(''),
    [filterIp, setFilterIp] = useState(''),
    [kind, setKind] = useState(''),
    [year, setYear] = useState(''),
    [offset, setOffset] = useState(''),
    [cursor, setCursor] = useState<Cursor | null>(null),
    [history, setHistory] = useState<(Cursor | null)[]>([]),
    [selected, setSelected] = useState<Event | null>(null);
  const epoch = useRef(0);
  const optionsFor = useRef('');
  async function load() {
    if (!isTauri()) {
      if (import.meta.env.DEV) {
        const fixture = window.__GAGA_LOG_TIMELINE_FIXTURE__?.[evidence.id];
        if (fixture) {
          setData(fixture);
          setSelected(fixture.events[0] || null);
        }
      }
      return;
    }
    const key = ++epoch.current;
    setWorking('读取时间线');
    setError('');
    try {
      const d = await invoke<Data>('query_log_timeline', {
        filter: {
          evidenceId: all ? null : evidence.id,
          sourceIp: filterIp || null,
          kind: kind || null,
          after: cursor,
        },
      });
      if (epoch.current === key) {
        setData(d);
        setSelected(d.events[0] || null);
        if (optionsFor.current !== evidence.id) {
          const options = d.sources.find((s) => s.id === evidence.id)?.metadata
            ?.options;
          setYear(options?.referenceYear?.toString() ?? '');
          setOffset(options?.offsetMinutes?.toString() ?? '');
          optionsFor.current = evidence.id;
        }
      }
    } catch (e) {
      if (epoch.current === key) setError(String(e));
    } finally {
      if (epoch.current === key) setWorking('');
    }
  }
  useEffect(() => {
    setData(null);
    void load();
    return () => {
      epoch.current++;
    };
  }, [evidence.id, all, filterIp, kind, cursor]);
  async function run(label: string, fn: () => Promise<void>) {
    if (working) return;
    setWorking(label);
    setError('');
    try {
      await fn();
    } catch (e) {
      setError(String(e));
    } finally {
      setWorking('');
    }
  }
  return (
    <div className="log-investigation">
      <header className="investigation-intro">
        <div>
          <h3>
            <Clock3 size={16} />
            行为时间线与攻击链复核
          </h3>
          <p>
            按可确定时间排序；命中行全部入索引。未知时间不使用导入时间代替。
          </p>
        </div>
        <button
          className="button primary"
          disabled={!!working || !isTauri()}
          onClick={() =>
            run('准备 AI 材料', async () =>
              onAI(
                await invoke<string>('log_ai_material', {
                  evidenceId: evidence.id,
                }),
                '请还原有证据支持的行为时间线，关联相同来源，逐项引用原文行号和时间依据；区分合法操作、攻击尝试、成功证据、未覆盖阶段和证据缺口。',
              ),
            )
          }
        >
          <Sparkles size={14} />
          AI 还原与研判
        </button>
      </header>
      <div className="log-filters">
        <select
          aria-label="日志时间线范围"
          value={all ? 'all' : 'file'}
          disabled={!!working}
          onChange={(e) => {
            setAll(e.target.value === 'all');
            setCursor(null);
            setHistory([]);
          }}
        >
          <option value="file">当前日志</option>
          <option value="all">当前事件全部日志</option>
        </select>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setFilterIp(ip.trim());
            setCursor(null);
            setHistory([]);
          }}
        >
          <Search size={13} />
          <input
            aria-label="时间线源 IP"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="源 IP"
          />
          <button disabled={!!working}>筛选</button>
        </form>
        <select
          aria-label="时间线行为类型"
          value={kind}
          disabled={!!working}
          onChange={(e) => {
            setKind(e.target.value);
            setCursor(null);
            setHistory([]);
          }}
        >
          {kinds.map(([k, label]) => (
            <option key={k} value={k}>
              {label}
            </option>
          ))}
        </select>
        <button
          className="icon-button"
          disabled={!!working}
          onClick={() => void load()}
          aria-label="刷新日志时间线"
        >
          <RefreshCw size={14} />
        </button>
      </div>
      <div className="log-index-status">
        <span>
          {working ? (
            <>
              <LoaderCircle className="spinning" size={13} />
              {working}…
            </>
          ) : (
            <>
              已索引 {data?.total.toLocaleString() ?? '—'} 条 · 时间待补{' '}
              {data?.unknownTimes.toLocaleString() ?? '—'}
            </>
          )}
        </span>
        <small>仅当前事件 · AI 研判当前文件</small>
      </div>
      {data?.sources.some((s) => !s.indexed) && (
        <p className="coverage-notice">
          有旧日志尚未建立索引，请逐份打开建立。空列表不代表没有行为。
        </p>
      )}
      <details className="log-index-options">
        <summary>索引与时间补充（当前文件）</summary>
        <p>无年份的 syslog 需补充来源年份和时区；不会猜测跨年与时钟偏差。</p>
        <div>
          <input
            aria-label="日志来源年份"
            value={year}
            onChange={(e) => setYear(e.target.value)}
            placeholder="年份：可留空"
          />
          <select
            aria-label="日志来源时区"
            value={offset}
            onChange={(e) => setOffset(e.target.value)}
          >
            <option value="">时区：未确定</option>
            <option value="480">UTC+8</option>
            <option value="0">UTC</option>
            <option value="-300">UTC-5 固定偏移</option>
          </select>
          <button
            className="button"
            disabled={!!working || !isTauri()}
            onClick={() =>
              run('建立索引', async () => {
                if (year && !/^\d{4}$/.test(year))
                  throw Error('请填写四位年份');
                const d = await invoke<Data>('rebuild_log_timeline', {
                  evidenceId: evidence.id,
                  options: {
                    referenceYear: year ? +year : null,
                    offsetMinutes: offset ? +offset : null,
                  },
                });
                setAll(false);
                setCursor(null);
                setHistory([]);
                setData(d);
                setSelected(d.events[0] || null);
              })
            }
          >
            <RefreshCw size={13} />
            建立 / 更新时间线
          </button>
        </div>
      </details>
      {error && (
        <p className="coverage-notice error" role="alert">
          {error}
        </p>
      )}
      <div className="log-event-grid">
        <div className="log-event-list" aria-label="日志行为时间线">
          {data?.events.map((e) => (
            <button
              key={e.evidenceId + e.line}
              className={
                selected?.evidenceId === e.evidenceId &&
                selected?.line === e.line
                  ? 'selected'
                  : ''
              }
              onClick={() => setSelected(e)}
            >
              <time>
                {e.at
                  ? new Date(e.at).toLocaleString('zh-CN', {
                      timeZone: 'Asia/Shanghai',
                      hour12: false,
                    })
                  : e.rawTime || '时间未知'}
                <small>{e.at ? '显示 UTC+8' : '年份 / 时区待补'}</small>
              </time>
              <span>
                <strong>{e.title}</strong>
                <small>
                  {e.sourceIp || '源 IP 未提取'} · {e.evidenceName} · 第{' '}
                  {e.line.toLocaleString()} 行
                </small>
              </span>
              <ArrowRight size={13} />
            </button>
          ))}
        </div>
        <aside className="log-event-proof">
          {selected ? (
            <>
              <div className="detail-head">
                <h3>原文举证</h3>
                <button
                  className="button small"
                  disabled={!!working || !selected.at}
                  title={
                    selected.at
                      ? '按原文时间加入事件'
                      : '请先补全来源年份和时区'
                  }
                  onClick={() =>
                    run('记录日志事件', async () =>
                      onRecorded(
                        await invoke<Workspace>('record_log_event', {
                          evidenceId: selected.evidenceId,
                          line: selected.line,
                          actor: '本地分析员',
                        }),
                      ),
                    )
                  }
                >
                  <Plus size={13} />
                  加入事件
                </button>
              </div>
              <p>
                {selected.evidenceName} · 第 {selected.line.toLocaleString()} 行
              </p>
              <pre>{selected.excerpt}</pre>
              <p>{selected.timeBasis}</p>
              <p className="small-note">
                同源 IP 和先后顺序仅用于关联。脚本 URL 访问不证明 WebShell
                落地，成功认证也需核对授权。
              </p>
            </>
          ) : (
            <p className="quiet-empty">选择时间线记录查看原文</p>
          )}
        </aside>
      </div>
      <footer className="log-pagination">
        <span>每页最多 100 条 · 当前 {data?.events.length ?? 0} 条</span>
        <div>
          <button
            className="button small"
            disabled={!!working || !history.length}
            onClick={() => {
              setCursor(history.at(-1) || null);
              setHistory((h) => h.slice(0, -1));
            }}
          >
            <ChevronLeft size={13} />
            上一页
          </button>
          <button
            className="button small"
            disabled={!!working || !data?.next}
            onClick={() => {
              setHistory((h) => [...h, cursor]);
              setCursor(data?.next || null);
            }}
          >
            下一页
            <ChevronRight size={13} />
          </button>
        </div>
      </footer>
    </div>
  );
}
const statusLabels: Record<string, string> = {
  risk: '发现风险',
  clear: '本项未命中',
  unknown: '数据未知',
  not_covered: '未覆盖',
};
export function CoveragePanel({
  evidence,
  onRefresh,
}: {
  evidence: Evidence;
  onRefresh: (w: Workspace) => void;
}) {
  const [filter, setFilter] = useState('all'),
    [working, setWorking] = useState(false),
    [error, setError] = useState(''),
    [limit, setLimit] = useState(50);
  const checks = evidence.report.coverage || [],
    visible = checks.filter((c) => filter === 'all' || c.status === filter);
  return (
    <div className="coverage-panel">
      <header className="investigation-intro">
        <div>
          <h3>
            <ShieldQuestion size={16} />
            检查覆盖与证据缺口
          </h3>
          <p>配置未命中、字段未知与能力未覆盖分别呈现。</p>
        </div>
        <button
          className="button"
          disabled={working || !isTauri()}
          onClick={async () => {
            setWorking(true);
            setError('');
            try {
              onRefresh(
                await invoke<Workspace>('refresh_container_coverage', {
                  evidenceId: evidence.id,
                }),
              );
            } catch (e) {
              setError(String(e));
            } finally {
              setWorking(false);
            }
          }}
        >
          {working ? (
            <LoaderCircle size={13} className="spinning" />
          ) : (
            <RefreshCw size={13} />
          )}
          更新检查覆盖
        </button>
      </header>
      {error && <p className="coverage-notice error">{error}</p>}
      {!checks.length ? (
        <p className="coverage-notice">
          旧分析未保存覆盖状态，请更新检查覆盖；原始文件与已有发现引用保留。
        </p>
      ) : (
        <>
          <div className="coverage-summary">
            {Object.entries(statusLabels).map(([id, label]) => (
              <button
                key={id}
                aria-pressed={filter === id}
                onClick={() => {
                  setFilter(filter === id ? 'all' : id);
                  setLimit(50);
                }}
              >
                <strong>{checks.filter((c) => c.status === id).length}</strong>
                <span>{label}</span>
              </button>
            ))}
          </div>
          <div className="coverage-checks">
            {visible.slice(0, limit).map((c, i) => (
              <details
                key={c.location + c.title + i}
                className={'coverage-check ' + c.status}
              >
                <summary>
                  <span>{statusLabels[c.status]}</span>
                  <strong>{c.title}</strong>
                  <small>{c.location}</small>
                </summary>
                <p>{c.reason}</p>
                <pre>{c.value}</pre>
              </details>
            ))}
          </div>
          {visible.length > limit && (
            <button className="button" onClick={() => setLimit((l) => l + 50)}>
              继续显示 50 项
            </button>
          )}
        </>
      )}
    </div>
  );
}
