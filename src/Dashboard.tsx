import React, { useCallback, useEffect, useRef, useState } from 'react';
import { invoke, isTauri } from './bridge';
import { listen } from '@tauri-apps/api/event';
import {
  Activity,
  ArrowUpRight,
  BarChart3,
  Check,
  Database,
  FileSearch,
  FlaskConical,
  Image,
  LoaderCircle,
  Monitor,
  Radio,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react';
import { WorkflowGuide } from './Support';
import type { Module, Workspace } from './types';
import { moduleInfo } from './types';

type CountGroup = { key: string; count: number };
export type DashboardRecord = {
  id: string;
  caseId: string;
  caseTitle: string;
  title: string;
  createdAt: string;
  category: string;
  module: string;
  evidenceId: string | null;
  detail: string;
};
export type DashboardData = {
  scope: 'case' | 'all';
  caseId: string;
  isDemo: boolean;
  hasDemo: boolean;
  updatedAt: string;
  days: number;
  timezone: string;
  cases: {
    id: string;
    title: string;
    createdAt: string;
    evidence: number;
    assets: number;
  }[];
  counts: {
    evidence: number;
    bytes: number;
    pendingReviews: number;
    latestReviews: number;
    reviews: number;
    assets: number;
    assetsEnabled: number;
    assetFailures: number;
    indicators: number;
    indicatorsReviewed: number;
    tasks: number;
    validTasks: number;
    nodes: number;
    nodesMissingScreenshots: number;
    flows: number;
  };
  findings: CountGroup[];
  evidenceKinds: CountGroup[];
  indicatorKinds: CountGroup[];
  queue: CountGroup[];
  runs: CountGroup[];
  sandbox: CountGroup[];
  series: { day: string; evidence: number; analyses: number; failed: number }[];
  activity: DashboardRecord[];
  pending: DashboardRecord[];
  failures: DashboardRecord[];
  runtime: { receiverRunning: boolean; autoAiEnabled: boolean };
};
declare global {
  interface Window {
    __GAGA_DASHBOARD_FIXTURE__?: DashboardData;
    __GAGA_WORKSPACE_FIXTURE__?: Workspace;
  }
}
const native = isTauri();
const groupCount = (items: CountGroup[] | undefined, key: string) =>
  items?.find((g) => g.key === key)?.count || 0;
const number = (n: number | undefined) =>
  n == null ? '—' : n.toLocaleString('zh-CN');
const date = (s: string, full = false) =>
  new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    ...(full ? { month: '2-digit', day: '2-digit' } : {}),
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date(s));
const dayOf = (s: string) =>
  new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(new Date(s));
const bytes = (n = 0) =>
  n >= 1048576
    ? `${(n / 1048576).toFixed(1)} MiB`
    : `${(n / 1024).toFixed(1)} KiB`;
const categories: Record<string, string> = {
  evidence: '证据归档',
  review: 'AI 草稿',
  failure: '执行失败',
  timeline: '人工记录',
  monitor: '监控观测',
};
const distributionNames: Record<string, string> = {
  high: '高风险线索',
  medium: '中风险线索',
  low: '低风险线索',
  info: '信息',
  unknown: '未分类',
  ip: 'IP 地址',
  cidr: 'IP 网段',
  domain: '域名',
  url: 'URL',
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
};
interface Props {
  workspace: Workspace;
  busy: string;
  onNavigate: (page: Module) => void;
  onRecord: (record: DashboardRecord) => Promise<void>;
}
export function Dashboard({ workspace, busy, onNavigate, onRecord }: Props) {
  const [scope, setScope] = useState<'case' | 'all'>('case');
  const [days, setDays] = useState<7 | 30>(7);
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activityTab, setActivityTab] = useState<
    'all' | 'pending' | 'failures' | 'cases'
  >('all');
  const [browsePage, setBrowsePage] = useState<Module>('evidence');
  const browse = (page: Module) => {
    if (
      scope === 'all' &&
      !['knowledge', 'settings', 'environment'].includes(page)
    ) {
      setBrowsePage(page);
      setActivityTab('cases');
      setSelectedDay(null);
    } else onNavigate(page);
  };
  const [distribution, setDistribution] = useState<
    'evidence' | 'ioc' | 'findings'
  >('evidence');
  const [chartTable, setChartTable] = useState(false);
  const [hoverDay, setHoverDay] = useState<string | null>(null);
  const [selectedDay, setSelectedDay] = useState<string | null>(null);
  const requestId = useRef(0);
  const caseId = workspace.activeCase;
  const load = useCallback(async () => {
    const id = ++requestId.current;
    setLoading(true);
    setError('');
    try {
      if (!native) {
        const fixture = import.meta.env.DEV
          ? window.__GAGA_DASHBOARD_FIXTURE__
          : undefined;
        if (id === requestId.current)
          setData(
            fixture
              ? { ...fixture, days, series: fixture.series.slice(-days) }
              : null,
          );
        return;
      }
      const result = await invoke<DashboardData>('get_dashboard', {
        caseId,
        scope,
        days,
      });
      if (id === requestId.current) setData(result);
    } catch (e) {
      if (id === requestId.current) setError(String(e));
    } finally {
      if (id === requestId.current) setLoading(false);
    }
  }, [caseId, scope, days]);
  useEffect(() => {
    setData(null);
    setSelectedDay(null);
    load();
    const timer = setInterval(() => {
      if (!document.hidden) load();
    }, 15000);
    let disposed = false;
    let debounce: ReturnType<typeof setTimeout> | undefined;
    const stops: (() => void)[] = [];
    if (native)
      for (const name of [
        'platform-updated',
        'analysis-progress',
        'sandbox-progress',
      ])
        listen(name, () => {
          if (document.hidden) return;
          clearTimeout(debounce);
          debounce = setTimeout(load, 400);
        })
          .then((stop) => (disposed ? stop() : stops.push(stop)))
          .catch(() => {});
    return () => {
      disposed = true;
      requestId.current++;
      clearInterval(timer);
      clearTimeout(debounce);
      stops.forEach((stop) => stop());
    };
  }, [load]);
  const c = data?.counts;
  const chart = data?.series || [];
  const maximum = Math.max(
    1,
    ...chart.map((d) => Math.max(d.evidence, d.analyses)),
  );
  const chartDay =
    chart.find((d) => d.day === (selectedDay || hoverDay)) ||
    chart[chart.length - 1];
  const caseRecords: DashboardRecord[] = (data?.cases || []).map((c) => ({
    id: c.id,
    caseId: c.id,
    caseTitle: c.title,
    title: c.title,
    createdAt: c.createdAt,
    category: 'case',
    module: browsePage,
    evidenceId: null,
    detail: `${c.evidence} 份证据 · ${c.assets} 个资产 · 打开${moduleInfo[browsePage].title}`,
  }));
  const source =
    activityTab === 'cases'
      ? caseRecords
      : activityTab === 'pending'
        ? data?.pending
        : activityTab === 'failures'
          ? data?.failures
          : data?.activity;
  const rows = (source || []).filter(
    (r) =>
      activityTab === 'cases' ||
      !selectedDay ||
      dayOf(r.createdAt) === selectedDay,
  );
  const distributionItems =
    (distribution === 'evidence'
      ? data?.evidenceKinds
      : distribution === 'ioc'
        ? data?.indicatorKinds
        : data?.findings) || [];
  const distributionMax = Math.max(1, ...distributionItems.map((d) => d.count));
  const title =
    scope === 'all'
      ? '全部业务事件'
      : workspace.cases.find((c) => c.id === caseId)?.title || '当前事件';
  return (
    <section className="dashboard-page" aria-label="调查总览">
      <header className="dashboard-heading">
        <div>
          <div className="eyebrow">本地工作区 / OVERVIEW</div>
          <h1>
            调查总览
            {data?.isDemo && (
              <span className="dashboard-demo-tag">演示事件</span>
            )}
          </h1>
          <p>{title} · 指标为累计记录，规则命中与 AI 判断均需人工复核</p>
        </div>
        <div className="dashboard-heading-actions">
          <div className="dashboard-segment" aria-label="总览范围">
            {(
              [
                ['case', '当前事件'],
                ['all', '全部业务事件'],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                aria-pressed={scope === id}
                disabled={loading}
                onClick={() => setScope(id)}
              >
                {label}
              </button>
            ))}
          </div>
          <button
            className="button"
            disabled={!!busy || loading}
            onClick={() => load()}
            aria-label="刷新调查总览"
          >
            <RefreshCw size={14} className={loading ? 'spinning' : ''} />
            <span>刷新</span>
          </button>
        </div>
      </header>
      <WorkflowGuide workspace={workspace} onNavigate={onNavigate} />
      {error && (
        <div className="dashboard-error" role="alert">
          <TriangleAlert size={14} />
          {error}
          {data && ' · 当前显示上次成功快照'}
        </div>
      )}
      {data?.isDemo && (
        <div className="dashboard-demo-note">
          <FlaskConical size={13} />
          本地样例经过实际分析器生成；不代表真实攻击。演示资产默认停用，全部业务统计排除演示事件。
        </div>
      )}
      <div className="dashboard-metrics">
        <button
          className="dashboard-metric"
          data-metric="evidence"
          onClick={() => browse('evidence')}
        >
          <div>
            <FileSearch size={15} />
            证据材料
            <ArrowUpRight size={13} />
          </div>
          <strong>{number(c?.evidence)}</strong>
          <small>{bytes(c?.bytes)} · 原始材料本地归档</small>
        </button>
        <button
          className="dashboard-metric"
          data-metric="pending"
          onClick={() => setActivityTab('pending')}
        >
          <div>
            <ShieldCheck size={15} />
            待复核研判
            <ArrowUpRight size={13} />
          </div>
          <strong>{number(c?.pendingReviews)}</strong>
          <small>
            {number(c?.latestReviews)} 份证据有 AI 草稿 · 每份取最新一条
          </small>
        </button>
        <button
          className="dashboard-metric"
          data-metric="assets"
          onClick={() => browse('assets')}
        >
          <div>
            <Monitor size={15} />
            监控资产
            <ArrowUpRight size={13} />
          </div>
          <strong>
            {number(c?.assetsEnabled)}
            <span> / {number(c?.assets)}</span>
          </strong>
          <small>已启用 / 已登记 · 巡检失败 {number(c?.assetFailures)}</small>
        </button>
        <button
          className="dashboard-metric"
          data-metric="indicators"
          onClick={() => browse('knowledge')}
        >
          <div>
            <Database size={15} />
            本地 IOC
            <ArrowUpRight size={13} />
          </div>
          <strong>{number(c?.indicators)}</strong>
          <small>已人工分类 {number(c?.indicatorsReviewed)} · 保留来源</small>
        </button>
      </div>
      <div className="dashboard-body">
        <section className="dashboard-card dashboard-trend">
          <header>
            <div>
              <h2>采集与分析趋势</h2>
              <small>按北京时间归档 / 启动日期统计，含失败分析</small>
            </div>
            <div className="dashboard-card-actions">
              <select
                aria-label="趋势时间范围"
                value={days}
                onChange={(e) => setDays(Number(e.target.value) as 7 | 30)}
              >
                <option value={7}>近 7 天</option>
                <option value={30}>近 30 天</option>
              </select>
              <button
                className="icon-button"
                aria-label={chartTable ? '切换趋势图' : '查看趋势数据表'}
                onClick={() => setChartTable(!chartTable)}
              >
                <BarChart3 size={15} />
              </button>
            </div>
          </header>
          <div className="dashboard-chart-legend">
            <span>
              <i />
              证据归档 {number(chart.reduce((s, d) => s + d.evidence, 0))}
            </span>
            <span>
              <i />
              分析次数 {number(chart.reduce((s, d) => s + d.analyses, 0))}
            </span>
            <small>
              分析失败 {number(chart.reduce((s, d) => s + d.failed, 0))}
            </small>
          </div>
          {chartTable ? (
            <div className="dashboard-chart-table">
              <table>
                <thead>
                  <tr>
                    <th>日期（北京时间）</th>
                    <th>证据</th>
                    <th>分析</th>
                    <th>失败</th>
                  </tr>
                </thead>
                <tbody>
                  {chart.map((d) => (
                    <tr key={d.day}>
                      <td>{d.day}</td>
                      <td>{d.evidence}</td>
                      <td>{d.analyses}</td>
                      <td>{d.failed}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div
              className="dashboard-chart"
              role="group"
              aria-label="每日证据与分析数量"
            >
              <div className="dashboard-chart-axis">
                <span>{maximum}</span>
                <span>{Math.round(maximum / 2)}</span>
                <span>0</span>
              </div>
              <div className="dashboard-chart-bars" data-days={days}>
                {chart.length ? (
                  chart.map((d, i) => (
                    <button
                      key={d.day}
                      className="dashboard-chart-day"
                      aria-pressed={selectedDay === d.day}
                      aria-label={`${d.day}：证据 ${d.evidence}，分析 ${d.analyses}，失败 ${d.failed}`}
                      title={`${d.day}\n证据 ${d.evidence} · 分析 ${d.analyses} · 失败 ${d.failed}\n点击筛选最新记录`}
                      onMouseEnter={() => setHoverDay(d.day)}
                      onMouseLeave={() => setHoverDay(null)}
                      onFocus={() => setHoverDay(d.day)}
                      onBlur={() => setHoverDay(null)}
                      onClick={() =>
                        setSelectedDay(selectedDay === d.day ? null : d.day)
                      }
                    >
                      <span className="dashboard-bar-pair">
                        <i
                          style={{ height: `${(d.evidence / maximum) * 100}%` }}
                        />
                        <i
                          style={{ height: `${(d.analyses / maximum) * 100}%` }}
                        />
                      </span>
                      <small>
                        {days === 7 ||
                        i === 0 ||
                        i === chart.length - 1 ||
                        i % 5 === 0
                          ? d.day.slice(5).replace('-', '/')
                          : ' '}
                      </small>
                    </button>
                  ))
                ) : (
                  <div className="dashboard-chart-empty">
                    {loading ? '读取本地统计…' : '导入材料后显示实际趋势'}
                  </div>
                )}
              </div>
            </div>
          )}
          <footer>
            {chartDay ? (
              <span>
                {chartDay.day} · 证据 {chartDay.evidence} / 分析{' '}
                {chartDay.analyses} / 失败 {chartDay.failed}
              </span>
            ) : (
              <span>没有工作区数据</span>
            )}
            {selectedDay ? (
              <button onClick={() => setSelectedDay(null)}>
                清除日期筛选 <Check size={12} />
              </button>
            ) : (
              <small>点击日期柱筛选最新记录</small>
            )}
          </footer>
        </section>
        <section className="dashboard-card dashboard-runtime">
          <header>
            <div>
              <h2>任务与举证状态</h2>
              <small>来自任务记录和当前客户端进程</small>
            </div>
            <Radio size={15} />
          </header>
          <div className="dashboard-status-list">
            <button onClick={() => browse('agents')}>
              <span>
                <Monitor size={14} />
                采集任务
              </span>
              <b>
                {number(c?.validTasks)} 有效 / {number(c?.tasks)} 总计
              </b>
              <small>有效期不等于主机在线</small>
            </button>
            <button onClick={() => browse('agents')}>
              <span>
                <Radio size={14} />
                HTTPS 接收端
              </span>
              <b>{data?.runtime.receiverRunning ? '运行中' : '未启动'}</b>
              <small>客户端退出即停止</small>
            </button>
            <button onClick={() => browse('flows')}>
              <span>
                <Activity size={14} />
                监控 AI 队列
              </span>
              <b>{number(groupCount(data?.queue, 'pending'))} 待处理</b>
              <small>
                {data?.runtime.autoAiEnabled
                  ? '自动研判已开启'
                  : '自动研判关闭'}{' '}
                · 失败 {number(groupCount(data?.queue, 'failed'))}
              </small>
            </button>
            <button onClick={() => setActivityTab('failures')}>
              <span>
                <TriangleAlert size={14} />
                分析执行失败
              </span>
              <b>{number(groupCount(data?.runs, 'failed'))} 次</b>
              <small>点击查看失败记录</small>
            </button>
            <button onClick={() => browse('timeline')}>
              <span>
                <Image size={14} />
                报告节点缺图
              </span>
              <b>{number(c?.nodesMissingScreenshots)} 个</b>
              <small>仅统计已选入报告的节点</small>
            </button>
          </div>
        </section>
        <section className="dashboard-card dashboard-activity">
          <header>
            <div className="dashboard-inline-tabs" aria-label="调查记录分类">
              {(
                [
                  ['all', '最新动态'],
                  ['pending', '待复核'],
                  ['failures', '失败记录'],
                  ...(activityTab === 'cases'
                    ? ([['cases', '按事件查看']] as const)
                    : []),
                ] as const
              ).map(([id, label]) => (
                <button
                  key={id}
                  aria-selected={activityTab === id}
                  onClick={() => setActivityTab(id)}
                >
                  {label}
                  {id === 'pending' && !!c?.pendingReviews && (
                    <em>{c.pendingReviews}</em>
                  )}
                </button>
              ))}
            </div>
            <small>{selectedDay ? selectedDay : '最近 20 条'}</small>
          </header>
          <div className="dashboard-activity-list">
            {rows.length ? (
              rows.map((r) => (
                <button
                  className="dashboard-activity-row"
                  key={r.category + r.id}
                  disabled={!!busy}
                  onClick={() => onRecord(r)}
                >
                  <span className={'dashboard-record-icon ' + r.category}>
                    {r.category === 'failure' ? (
                      <TriangleAlert size={15} />
                    ) : r.category === 'review' ? (
                      <ShieldCheck size={15} />
                    ) : (
                      <FileSearch size={15} />
                    )}
                  </span>
                  <div>
                    <strong title={r.title}>{r.title}</strong>
                    <small title={r.detail}>
                      {scope === 'all' ? r.caseTitle + ' · ' : ''}
                      {r.detail}
                    </small>
                  </div>
                  <span className="dashboard-record-kind">
                    {categories[r.category] ||
                      (r.category === 'case' ? '业务事件' : r.category)}
                  </span>
                  <time title={date(r.createdAt, true)}>
                    {date(r.createdAt)}
                  </time>
                  <ArrowUpRight size={13} />
                </button>
              ))
            ) : (
              <div className="dashboard-empty">
                <FileSearch size={24} />
                <strong>
                  {activityTab === 'pending'
                    ? '当前没有待复核的最新 AI 研判'
                    : activityTab === 'failures'
                      ? '当前没有分析失败记录'
                      : selectedDay
                        ? '最新 20 条中没有该日期记录'
                        : '还没有调查记录'}
                </strong>
                <p>
                  {c?.evidence
                    ? '可从趋势和类型分布查看记录数量，点击条目回到原始依据。'
                    : '从 HTTP 报文、日志或采集材料开始建立调查记录。'}
                </p>
                {!c?.evidence && (
                  <button className="button" onClick={() => browse('http')}>
                    粘贴请求与响应 <ArrowUpRight size={13} />
                  </button>
                )}
              </div>
            )}
          </div>
        </section>
        <section className="dashboard-card dashboard-distribution">
          <header>
            <div className="dashboard-inline-tabs" aria-label="数据分布类型">
              {(
                [
                  ['evidence', '证据类型'],
                  ['ioc', 'IOC 类型'],
                  ['findings', '风险线索'],
                ] as const
              ).map(([id, label]) => (
                <button
                  key={id}
                  aria-selected={distribution === id}
                  onClick={() => setDistribution(id)}
                >
                  {label}
                </button>
              ))}
            </div>
          </header>
          <div className="dashboard-distribution-list">
            {distributionItems.length ? (
              distributionItems.map((item) => (
                <button
                  key={item.key}
                  className="dashboard-distribution-row"
                  onClick={() =>
                    browse(
                      distribution === 'ioc'
                        ? 'knowledge'
                        : ((item.key in moduleInfo
                            ? item.key
                            : 'evidence') as Module),
                    )
                  }
                >
                  <span>
                    {distributionNames[item.key] ||
                      moduleInfo[item.key as Module]?.title ||
                      item.key}
                    <b>{number(item.count)}</b>
                  </span>
                  <i>
                    <i
                      style={{
                        width: `${(item.count / distributionMax) * 100}%`,
                      }}
                    />
                  </i>
                </button>
              ))
            ) : (
              <div className="dashboard-empty compact">
                <Database size={24} />
                <p>有相关材料后显示实际分布</p>
              </div>
            )}
          </div>
          <footer>
            {distribution === 'findings'
              ? '规则风险级别，不代表确认入侵。'
              : distribution === 'ioc'
                ? scope === 'case'
                  ? '本事件证据关联的去重指标；手工导入在情报库查看。'
                  : '排除仅在演示证据中出现的指标。'
                : '同一原始材料的再次归档分别计数。'}
          </footer>
        </section>
      </div>
      <footer className="dashboard-footer">
        <span>
          <i />
          {native ? 'SQLite 本地快照' : '浏览器界面预览'}
          {data?.updatedAt ? ' · 更新于 ' + date(data.updatedAt) : ''}
          {loading && <LoaderCircle size={11} className="spinning" />}
        </span>
        <span>
          {scope === 'all' ? '全部业务范围排除演示事件' : '当前事件范围'} ·
          可见时每 15 秒刷新
        </span>
      </footer>
    </section>
  );
}
