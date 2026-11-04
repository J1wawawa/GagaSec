import { useEffect, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import {
  Activity,
  ArrowUpRight,
  ChevronDown,
  LoaderCircle,
  Square,
  X,
} from 'lucide-react';
import { invoke, isTauri } from './bridge';
import {
  localRunning,
  mergeLocalJobs,
  type LocalAnalysisJob,
} from './local-analysis-state';
import './local-analysis.css';

const phases: Record<string, string> = {
  queued: '准备任务',
  archiving: '归档与 SHA-256',
  scanning: '日志解析与规则检查',
  indexing: '提交时间线索引',
  environment: '检查隔离环境',
  isolated: '隔离静态工具运行',
  committing: '保存分析证据',
  completed: '已保存结果',
};
const states: Record<string, string> = {
  running: '进行中',
  cancelling: '正在停止',
  cancelled: '已取消',
  failed: '失败',
  completed: '已完成',
  interrupted: '上次中断',
};
const bytes = (value: number) =>
  value >= 1048576
    ? `${(value / 1048576).toFixed(1)} MiB`
    : `${(value / 1024).toFixed(1)} KiB`;
export function useLocalAnalysis(enabled: boolean, onCompleted: () => void) {
  const [jobs, setJobs] = useState<LocalAnalysisJob[]>([]);
  const [opened, setOpened] = useState(false);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState('');
  const completed = useRef(new Set<string>());
  const latestJobs = useRef<LocalAnalysisJob[]>([]);
  const runningRef = useRef(false);
  const callback = useRef(onCompleted);
  callback.current = onCompleted;
  const mounted = useRef(false);
  const accept = (incoming: LocalAnalysisJob[]) => {
    if (!mounted.current) return;
    // Polls and events can arrive out of order; derive polling cadence from the
    // merged state so a delayed running snapshot cannot revive a finished job.
    latestJobs.current = mergeLocalJobs(latestJobs.current, incoming);
    setJobs(latestJobs.current);
    runningRef.current = latestJobs.current.some(localRunning);
    let changed = false;
    for (const job of incoming)
      if (job.state === 'completed' && !completed.current.has(job.id)) {
        completed.current.add(job.id);
        changed = true;
      }
    if (changed) callback.current();
  };
  useEffect(() => {
    if (!enabled || !isTauri()) return;
    let disposed = false,
      loading = false;
    let lastLoaded = 0;
    let stop: (() => void) | undefined;
    mounted.current = true;
    const load = async () => {
      if (disposed || loading) return;
      loading = true;
      lastLoaded = Date.now();
      try {
        const value = await invoke<LocalAnalysisJob[]>(
          'get_local_analysis_jobs',
          { caseId: null },
        );
        if (!disposed) accept(value);
      } catch (e) {
        if (!disposed) setError(`分析任务同步失败：${String(e)}`);
      } finally {
        loading = false;
      }
    };
    void listen<LocalAnalysisJob>('local-analysis-progress', (event) => {
      if (!disposed) accept([event.payload]);
    })
      .then((unlisten) => {
        if (disposed) unlisten();
        else {
          stop = unlisten;
          void load();
        }
      })
      .catch((e) => {
        if (!disposed) {
          setError(`进度订阅失败，正在定期同步：${String(e)}`);
          void load();
        }
      });
    const timer = setInterval(() => {
      if (
        !document.hidden &&
        (runningRef.current || Date.now() - lastLoaded >= 15000)
      )
        void load();
    }, 3000);
    const onVisibilityChange = () => {
      if (!document.hidden) void load();
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      disposed = true;
      mounted.current = false;
      stop?.();
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [enabled]);
  return {
    jobs,
    opened,
    setOpened,
    error,
    setError,
    selected,
    setSelected,
    active: jobs.find(localRunning),
    async start(caseId: string, path: string, kind: string) {
      setError('');
      const job = await invoke<LocalAnalysisJob>('start_local_analysis', {
        caseId,
        path,
        kind,
      });
      accept([job]);
      setSelected(job.id);
      setOpened(true);
    },
    async cancel(job: LocalAnalysisJob) {
      try {
        await invoke('cancel_local_analysis', {
          id: job.id,
          caseId: job.caseId,
        });
      } catch (e) {
        if (mounted.current) setError(String(e));
      }
    },
  };
}
export type LocalAnalysisModel = ReturnType<typeof useLocalAnalysis>;
export function LocalAnalysisPanel({
  model,
  cases,
  onOpen,
}: {
  model: LocalAnalysisModel;
  cases: { id: string; title: string }[];
  onOpen: (job: LocalAnalysisJob) => void;
}) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!model.active) return;
    const timer = setInterval(() => {
      if (!document.hidden) setNow(Date.now());
    }, 500);
    const onVisibilityChange = () => {
      if (!document.hidden) setNow(Date.now());
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [!!model.active]);
  if (!model.opened) return null;
  const job =
    model.jobs.find((j) => j.id === model.selected) ||
    model.active ||
    model.jobs[0];
  const running = job && localRunning(job);
  const elapsed = job
    ? (running
        ? Math.max(job.elapsedMs, now - new Date(job.startedAt).valueOf())
        : job.elapsedMs) / 1000
    : 0;
  const scanStart = job?.stages?.find(
    (stage) => stage.phase === 'scanning',
  )?.elapsedMs;
  const scanEnd = job?.stages?.find(
    (stage) => stage.phase === 'indexing',
  )?.elapsedMs;
  const scanSeconds =
    scanStart == null ? 0 : ((scanEnd ?? elapsed * 1000) - scanStart) / 1000;
  const read =
    job?.phase === 'archiving' ? job.copiedBytes : job?.counts.bytes || 0;
  const determinate =
    job && ['archiving', 'scanning'].includes(job.phase) && job.totalBytes > 0;
  return (
    <section
      className="local-analysis-panel"
      aria-label="本地分析任务"
      data-local-analysis
    >
      <header>
        <strong>
          <Activity size={15} />
          分析任务
        </strong>
        <span>当前设备 · 任务固定归属原事件</span>
        <button
          className="icon-button"
          aria-label="收起分析任务"
          onClick={() => model.setOpened(false)}
        >
          <X size={15} />
        </button>
      </header>
      {model.error && (
        <p className="local-task-error" role="alert">
          {model.error}
        </p>
      )}
      {!job ? (
        <p>暂无任务。从日志或样本页导入文件即可开始。</p>
      ) : (
        <>
          <div className="local-task-controls">
            <select
              aria-label="选择分析任务"
              value={job.id}
              onChange={(e) => model.setSelected(e.target.value)}
            >
              {model.jobs.map((j) => (
                <option key={j.id} value={j.id}>
                  {states[j.state]} · {j.name} ·{' '}
                  {cases.find((c) => c.id === j.caseId)?.title || '原事件'}
                </option>
              ))}
            </select>
            {running && (
              <button
                className="button small"
                data-action="cancel-local-analysis"
                disabled={
                  job.state === 'cancelling' || job.phase === 'committing'
                }
                onClick={() => void model.cancel(job)}
              >
                <Square size={12} />
                {job.state === 'cancelling' ? '等待停止与清理' : '停止分析'}
              </button>
            )}
            {job.state === 'completed' && job.evidenceId && (
              <button
                className="button small"
                data-action="open-local-result"
                onClick={() => onOpen(job)}
              >
                打开结果
                <ArrowUpRight size={13} />
              </button>
            )}
          </div>
          <div
            className="local-task-phase"
            data-state={job.state}
            data-phase={job.phase}
          >
            <span>
              {running && <LoaderCircle size={13} className="spinning" />}
              {states[job.state]} · {phases[job.phase] || job.phase}
            </span>
            <span>{elapsed.toFixed(1)} s</span>
          </div>
          {running && (
            <progress
              aria-label="当前分析阶段进度"
              {...(determinate
                ? { value: Math.min(read, job.totalBytes), max: job.totalBytes }
                : {})}
            />
          )}
          <div className="local-task-stats">
            <span>归档 {bytes(job.copiedBytes)}</span>
            {job.kind === 'logs' ? (
              <>
                <span>
                  扫描 {bytes(job.counts.bytes)} / {bytes(job.totalBytes)}
                </span>
                <span>{job.counts.lines.toLocaleString()} 行</span>
                {scanSeconds > 0 && job.counts.bytes > 0 && (
                  <span>
                    扫描均速 {bytes(job.counts.bytes / scanSeconds)}/s
                  </span>
                )}
                <span>结构化 {job.counts.parsed.toLocaleString()}</span>
                <span>
                  未识别{' '}
                  {Math.max(
                    0,
                    job.counts.lines -
                      job.counts.parsed -
                      job.counts.invalid -
                      job.counts.oversized,
                  ).toLocaleString()}
                </span>
                <span>
                  跳过{' '}
                  {(job.counts.invalid + job.counts.oversized).toLocaleString()}
                </span>
                <span>规则命中 {job.counts.hits.toLocaleString()}</span>
              </>
            ) : (
              <span>禁网临时容器 · 不执行样本 · 工具结果经校验后展示</span>
            )}
          </div>
          <ol
            className="local-task-stages"
            aria-label="阶段进入时刻，相对任务开始"
          >
            {job.stages?.map((stage, index) => (
              <li key={index}>
                {phases[stage.phase] || stage.phase}
                <small>+{(stage.elapsedMs / 1000).toFixed(1)} s</small>
              </li>
            ))}
          </ol>
          {job.error && <p className="local-task-error">{job.error}</p>}
          {job.state === 'cancelling' && (
            <p>正在停止读取或隔离工具；环境检查及容器清理结束后确认状态。</p>
          )}
          <details className="local-task-previews" open>
            <summary>
              发现预览 · {job.previews.length} 项（最多 24 项）
              <ChevronDown size={12} />
            </summary>
            <p>
              预览为待复核线索；仅已完成任务可打开完整证据，取消或失败不作为完整结果。新发现不会抢焦点。
            </p>
            <div>
              {job.previews.map((f) => (
                <article key={f.id}>
                  <strong>{f.title}</strong>
                  <span>{f.location}</span>
                  <code>{f.excerpt}</code>
                </article>
              ))}
              {!job.previews.length && (
                <p>
                  {running
                    ? '尚无可展示发现，正在处理材料。'
                    : '当前任务未产生预览；无命中不代表安全。'}
                </p>
              )}
            </div>
          </details>
          <small className="local-task-id">
            任务 ID：{job.id} · 前端预览有上限，完整命中按索引分页查看
          </small>
        </>
      )}
    </section>
  );
}
