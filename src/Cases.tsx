import { useEffect, useRef, useState } from 'react';
import { invoke, isTauri } from './bridge';
import { FolderOpen, Plus, ArrowUpRight, LoaderCircle } from 'lucide-react';
import type { Workspace } from './types';
import { Modal } from './Modal';
type Case = {
  id: string;
  title: string;
  status: string;
  createdAt: string;
  evidence: number;
  nodes: number;
  bytes: number;
  demo: boolean;
};
declare global {
  interface Window {
    __GAGA_CASES_FIXTURE__?: { cases: Case[]; total: number };
  }
}
export function CasesPanel({
  active,
  onNew,
  onOpen,
  onUpdate,
}: {
  active: string;
  onNew: () => void;
  onOpen: (id: string) => void;
  onUpdate: (w: Workspace) => void;
}) {
  const [data, setData] = useState<{ cases: Case[]; total: number }>({
      cases: [],
      total: 0,
    }),
    [query, setQuery] = useState(''),
    [search, setSearch] = useState(''),
    [status, setStatus] = useState('all'),
    [offset, setOffset] = useState(0),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [edit, setEdit] = useState<Case | null>(null);
  const epoch = useRef(0);
  async function load() {
    if (!isTauri()) {
      if (import.meta.env.DEV && window.__GAGA_CASES_FIXTURE__)
        setData(window.__GAGA_CASES_FIXTURE__);
      return;
    }
    const token = ++epoch.current;
    setBusy(true);
    setError('');
    try {
      const result = await invoke<{ cases: Case[]; total: number }>(
        'get_case_list',
        { query: search, status, offset },
      );
      if (epoch.current === token) setData(result);
    } catch (e) {
      if (epoch.current === token) setError(String(e));
    } finally {
      if (epoch.current === token) setBusy(false);
    }
  }
  useEffect(() => {
    void load();
    return () => {
      epoch.current++;
    };
  }, [active, search, status, offset]);
  return (
    <div className="cases-page">
      <header className="investigation-intro">
        <div>
          <h1>事件管理</h1>
          <p>
            每个事件独立保存证据、分析、时间线与报告。打开事件后，工作台默认只查看该事件。
          </p>
        </div>
        <button className="button primary" onClick={onNew}>
          <Plus size={14} />
          新建事件
        </button>
      </header>
      <div className="log-filters">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setSearch(query);
            setOffset(0);
          }}
        >
          <input
            aria-label="搜索事件"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索事件名称"
          />
          <button>搜索</button>
        </form>
        <select
          aria-label="事件状态筛选"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setOffset(0);
          }}
        >
          <option value="all">全部状态</option>
          <option value="open">进行中</option>
          <option value="closed">已结束</option>
        </select>
        <span>
          {busy ? (
            <LoaderCircle className="spinning" size={14} />
          ) : (
            `${data.total} 个事件`
          )}
        </span>
      </div>
      {error && (
        <p role="alert" className="coverage-notice error">
          {error}
        </p>
      )}
      <div className="case-list">
        {data.cases.map((c) => (
          <article key={c.id} className={c.id === active ? 'selected' : ''}>
            <FolderOpen size={20} />
            <div>
              <h3>
                {c.title}
                {c.demo && <small>演示</small>}
              </h3>
              <p>
                {c.status === 'closed' ? '已结束' : '进行中'} · {c.evidence}{' '}
                份证据 · {c.nodes} 个节点 · {(c.bytes / 1048576).toFixed(1)} MiB
              </p>
              <small>
                {c.id} · {new Date(c.createdAt).toLocaleDateString('zh-CN')}
              </small>
            </div>
            <button
              className="button small"
              onClick={() => {
                setError('');
                setEdit(c);
              }}
            >
              管理
            </button>
            <button
              className="button"
              disabled={busy}
              onClick={() => onOpen(c.id)}
            >
              {c.id === active ? '查看当前事件' : '打开事件'}
              <ArrowUpRight size={13} />
            </button>
          </article>
        ))}
      </div>
      <footer className="log-pagination">
        <span>每页 50 个事件</span>
        <div>
          <button
            className="button small"
            disabled={!offset || busy}
            onClick={() => setOffset((x) => x - 50)}
          >
            上一页
          </button>
          <button
            className="button small"
            disabled={offset + 50 >= data.total || busy}
            onClick={() => setOffset((x) => x + 50)}
          >
            下一页
          </button>
        </div>
      </footer>
      {edit && (
        <Modal title="管理事件" busy={busy} onClose={() => setEdit(null)}>
          <form
            className="modal"
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              try {
                onUpdate(
                  await invoke<Workspace>('update_case', {
                    id: edit.id,
                    title: edit.title,
                    status: edit.status,
                  }),
                );
                setEdit(null);
                await load();
              } catch (e) {
                setError(String(e));
              } finally {
                setBusy(false);
              }
            }}
          >
            <h2>管理事件</h2>
            {error && (
              <p className="modal-error" role="alert">
                {error}
              </p>
            )}
            <label>
              事件名称
              <input
                aria-label="编辑事件名称"
                value={edit.title}
                maxLength={120}
                onChange={(e) => setEdit({ ...edit, title: e.target.value })}
              />
            </label>
            <label>
              事件状态
              <select
                value={edit.status}
                onChange={(e) => setEdit({ ...edit, status: e.target.value })}
              >
                <option value="open">进行中</option>
                <option value="closed">已结束</option>
              </select>
            </label>
            <p className="small-note">
              结束状态保留所有材料，仍可打开复核；各事件证据不会合并。
            </p>
            <div className="toolbar-group">
              <button
                type="button"
                className="button"
                disabled={busy}
                onClick={() => setEdit(null)}
              >
                取消
              </button>
              <button className="button primary" disabled={busy}>
                保存
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}
