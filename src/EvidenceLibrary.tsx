import { useDeferredValue, useMemo, useState } from 'react';
import { ArrowUpRight, FileText, Search } from 'lucide-react';
import {
  moduleInfo,
  type Evidence,
  type Workspace,
  type Module,
} from './types';
export function EvidenceLibrary({
  workspace,
  onOpen,
}: {
  workspace: Workspace;
  onOpen: (e: Evidence) => void;
}) {
  const [query, setQuery] = useState(''),
    [kind, setKind] = useState(''),
    [scope, setScope] = useState('all'),
    [page, setPage] = useState(0);
  const deferred = useDeferredValue(query.trim().toLowerCase());
  const linked = useMemo(
    () =>
      new Set(
        workspace.nodes.flatMap((n) => (n.evidenceId ? [n.evidenceId] : [])),
      ),
    [workspace.nodes],
  );
  const rows = useMemo(
    () =>
      workspace.evidence.filter(
        (e) =>
          (!kind || e.kind === kind) &&
          (!deferred ||
            `${e.name} ${e.sha256} ${e.report.title} ${e.report.summary}`
              .toLowerCase()
              .includes(deferred)) &&
          (scope === 'all' ||
            (scope === 'linked'
              ? linked.has(e.id)
              : scope === 'unlinked'
                ? !linked.has(e.id)
                : scope === 'hits'
                  ? e.report.findings.length > 0
                  : e.report.findings.length === 0)),
      ),
    [workspace.evidence, kind, deferred, scope, linked],
  );
  const last = Math.max(0, Math.ceil(rows.length / 24) - 1),
    current = Math.min(page, last),
    visible = rows.slice(current * 24, current * 24 + 24);
  const reset = () => {
    setQuery('');
    setKind('');
    setScope('all');
    setPage(0);
  };
  return (
    <section className="evidence-library">
      <div className="evidence-filters">
        <label className="evidence-search">
          <Search size={15} />
          <input
            aria-label="搜索本事件证据"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(0);
            }}
            placeholder="文件名、SHA-256 或分析摘要"
          />
        </label>
        <select
          aria-label="证据类型筛选"
          value={kind}
          onChange={(e) => {
            setKind(e.target.value);
            setPage(0);
          }}
        >
          <option value="">全部类型</option>
          {['http', 'logs', 'triage', 'containers', 'webshell', 'binary'].map(
            (k) => (
              <option key={k} value={k}>
                {moduleInfo[k as Module].title}
              </option>
            ),
          )}
        </select>
        <select
          aria-label="证据举证筛选"
          value={scope}
          onChange={(e) => {
            setScope(e.target.value);
            setPage(0);
          }}
        >
          <option value="all">全部资料</option>
          <option value="unlinked">尚未关联节点</option>
          <option value="linked">已有关联节点</option>
          <option value="hits">有规则线索</option>
          <option value="no-hits">规则未命中</option>
        </select>
        {(query || kind || scope !== 'all') && (
          <button className="button small" onClick={reset}>
            清除筛选
          </button>
        )}
      </div>
      <div className="evidence-list">
        {visible.map((e) => (
          <button key={e.id} data-evidence-id={e.id} onClick={() => onOpen(e)}>
            <FileText size={18} />
            <div>
              <strong>{e.name}</strong>
              <small>
                {moduleInfo[e.kind as Module]?.title} ·{' '}
                {(e.size / 1048576).toFixed(2)} MiB ·{' '}
                {new Date(e.createdAt).toLocaleString('zh-CN', {
                  timeZone: 'Asia/Shanghai',
                  hour12: false,
                })}{' '}
                · {linked.has(e.id) ? '已关联举证' : '尚未关联节点'}
              </small>
              <code>{e.sha256}</code>
            </div>
            <ArrowUpRight size={16} />
          </button>
        ))}
      </div>
      {!rows.length && (
        <p className="small-note evidence-no-results">
          没有符合筛选条件的资料。
          <button className="button small" onClick={reset}>
            显示全部
          </button>
        </p>
      )}
      <div className="evidence-pagination">
        <span>
          匹配 {rows.length} / {workspace.evidence.length} 份 · 第 {current + 1}{' '}
          / {last + 1} 页
        </span>
        <button
          className="button small"
          disabled={!current}
          onClick={() => setPage(current - 1)}
        >
          上一页
        </button>
        <button
          className="button small"
          disabled={current === last}
          onClick={() => setPage(current + 1)}
        >
          下一页
        </button>
      </div>
    </section>
  );
}
