import { useCallback, useEffect, useState } from 'react';
import { invoke, isTauri } from './bridge';
import { save } from '@tauri-apps/plugin-dialog';
import './runtime-logs.css';
type Entry = {
  id: string;
  time: string;
  level: string;
  component: string;
  code: string;
  message: string;
  contextId: string | null;
};
type Snapshot = {
  path: string;
  entries: Entry[];
  maxBytes: number;
  suppressed: number;
  writeError: string | null;
};
export function RuntimeLogs() {
  const [data, setData] = useState<Snapshot>();
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [level, setLevel] = useState('all');
  const [notice, setNotice] = useState('');
  const refresh = useCallback(async () => {
    if (!isTauri()) {
      setError('运行日志需在桌面客户端查看。');
      return;
    }
    try {
      setData(await invoke<Snapshot>('get_runtime_logs'));
      setError('');
    } catch (e) {
      setError(String(e));
    }
  }, []);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  async function exportIndex() {
    try {
      const path = await save({
        defaultPath: `gaga-errors-${Date.now()}.json`,
        filters: [{ name: '错误索引', extensions: ['json'] }],
      });
      if (path) {
        await invoke('export_runtime_logs', { path });
        setNotice('错误索引已导出，不包含消息正文和本机目录。');
      }
    } catch (e) {
      setError(String(e));
    }
  }
  const rows =
    data?.entries.filter(
      (row) =>
        (level === 'all' || row.level === level) &&
        `${row.component} ${row.code} ${row.message} ${row.id} ${row.contextId || ''}`
          .toLowerCase()
          .includes(query.toLowerCase()),
    ) || [];
  return (
    <div className="runtime-logs">
      <h2>运行日志与错误记录</h2>
      <p className="setting-note">
        按时间记录启动、接口、界面与后台报告任务。最近 200 条；日志轮转上限 10
        MiB。常见凭据会遮盖，完整本地日志仍应按敏感资料保管。
      </p>
      <div className="runtime-log-tools">
        <input
          aria-label="搜索运行日志"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="搜索错误、功能或任务 / 记录 ID"
        />
        <select
          aria-label="日志级别"
          value={level}
          onChange={(e) => setLevel(e.target.value)}
        >
          <option value="all">全部级别</option>
          <option value="error">错误</option>
          <option value="warn">警告</option>
          <option value="info">运行信息</option>
        </select>
        <button className="button" onClick={() => void refresh()}>
          刷新日志
        </button>
        <button className="button" onClick={() => void exportIndex()}>
          导出错误索引
        </button>
      </div>
      {error && (
        <p role="alert" className="report-error">
          {error}
        </p>
      )}
      {data?.writeError && (
        <p role="alert" className="report-error">
          日志写入异常：{data.writeError}
          。部分记录可能未保存，请检查磁盘空间与权限。
        </p>
      )}
      {notice && <p role="status">{notice}</p>}
      {data && (
        <details className="runtime-log-location">
          <summary>本机日志位置与保存范围</summary>
          <code>{data.path}</code>
          <p>
            不记录接口参数、报文、样本或模型正文。同一任务及级别的连续重复错误会合并；本次已合并{' '}
            {data.suppressed}{' '}
            条。错误索引用于反馈定位，不包含本地错误详情；需要详情时在这里复制单条，核对后再提供。
          </p>
        </details>
      )}
      <div className="runtime-log-list" aria-label="运行日志记录">
        {!rows.length && <p className="setting-note">当前筛选下没有记录。</p>}
        {rows.map((row) => (
          <article
            key={row.id}
            data-log-level={row.level}
            data-context-id={row.contextId || undefined}
          >
            <header>
              <strong>{row.code}</strong>
              <span>
                {row.component} · {row.level}
              </span>
              <time>
                {new Date(row.time).toLocaleString('zh-CN', { hour12: false })}
              </time>
            </header>
            <pre>{row.message}</pre>
            <footer>
              <div className="runtime-log-ids">
                <code>记录 ID：{row.id}</code>
                {row.contextId && <code>任务 ID：{row.contextId}</code>}
              </div>
              <button
                className="button small"
                onClick={() =>
                  void navigator.clipboard
                    .writeText(
                      `${row.time} ${row.code} ${row.component}\n${row.message}\nID: ${row.id}${row.contextId ? `\n任务 ID: ${row.contextId}` : ''}`,
                    )
                    .then(() => setNotice('已复制此条本地记录。'))
                    .catch((e) => setError(String(e)))
                }
              >
                复制记录
              </button>
            </footer>
          </article>
        ))}
      </div>
    </div>
  );
}
