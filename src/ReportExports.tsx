import { useCallback, useEffect, useRef, useState } from 'react';
import { invoke, isTauri } from './bridge';
import { listen } from '@tauri-apps/api/event';

export type ReportExport = {
  id: string;
  caseId: string;
  format: string;
  outputPath: string;
  state: string;
  phase: string;
  verifiedBytes: number;
  totalBytes: number;
  revision: number;
  error: string | null;
};
export const reportRunning = (job: ReportExport) =>
  !['completed', 'cancelled', 'failed'].includes(job.state);
const phases: Record<string, string> = {
  snapshot: '读取报告快照',
  verifying: '校验原始证据',
  rendering: '编排正文与截图',
  writing: '写入临时报告',
  committing: '最终提交',
};
export function useReportExports() {
  const [jobs, setJobs] = useState<ReportExport[]>([]);
  const [error, setError] = useState('');
  const live = useRef(false);
  const generation = useRef(0);
  const refresh = useCallback(async () => {
    if (!isTauri()) return;
    const token = ++generation.current;
    try {
      const rows = await invoke<ReportExport[]>('get_report_exports');
      if (live.current && token === generation.current) {
        setJobs(rows);
        setError('');
      }
    } catch (e) {
      if (live.current && token === generation.current) setError(String(e));
    }
  }, []);
  useEffect(() => {
    live.current = true;
    let stop: (() => void) | undefined;
    if (isTauri())
      listen('report-export-updated', () => void refresh())
        .then((unlisten) => {
          if (!live.current) return unlisten();
          stop = unlisten;
          void refresh();
        })
        .catch((e) => {
          if (live.current) setError(String(e));
        });
    return () => {
      live.current = false;
      generation.current++;
      stop?.();
    };
  }, [refresh]);
  const active = jobs.find(reportRunning);
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => void refresh(), 750);
    return () => clearInterval(timer);
  }, [active?.id, refresh]);
  async function cancel(id: string) {
    try {
      await invoke('cancel_report_export', { id });
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  }
  return { jobs, active, error, refresh, cancel };
}
export type ReportExportsModel = ReturnType<typeof useReportExports>;
const size = (bytes: number) => `${(bytes / 1048576).toFixed(1)} MiB`;

export function ReportExportPanel({
  model,
  caseId,
  cases,
}: {
  model: ReportExportsModel;
  caseId: string;
  cases: { id: string; title: string }[];
}) {
  const rows = model.jobs
    .filter((j) => j.caseId === caseId || j.id === model.active?.id)
    .slice(0, 2);
  if (!rows.length && !model.error && !model.active) return null;
  return (
    <div className="report-export-panel print-hide" aria-label="报告导出任务">
      {model.active && model.active.caseId !== caseId && (
        <p>另一事件的报告正在后台导出。完成或取消后可开始新任务。</p>
      )}
      {rows.map((job) => (
        <div
          className="report-export-job"
          key={job.id}
          data-export-state={job.state}
        >
          <div className="report-export-line">
            <strong>{job.format.toUpperCase()}</strong>
            <span role="status">
              {job.state === 'cancelling'
                ? '正在取消，等待当前步骤退出…'
                : job.state === 'completed'
                  ? '已导出'
                  : job.state === 'cancelled'
                    ? '已取消，原文件保留'
                    : job.state === 'failed'
                      ? '导出失败'
                      : phases[job.phase] || job.phase}
            </span>
            {reportRunning(job) && (
              <button
                className="button small"
                data-action="cancel-report-export"
                disabled={
                  job.state === 'cancelling' || job.phase === 'committing'
                }
                onClick={() => void model.cancel(job.id)}
              >
                取消导出
              </button>
            )}
          </div>
          {reportRunning(job) &&
            job.phase === 'verifying' &&
            job.totalBytes > 0 && (
              <div className="report-export-progress">
                <progress
                  aria-label="原始证据校验进度"
                  value={job.verifiedBytes}
                  max={job.totalBytes}
                />
                <span>
                  {size(job.verifiedBytes)} / {size(job.totalBytes)}
                </span>
              </div>
            )}
          <small title={job.outputPath}>{job.outputPath}</small>
          <small title={job.caseId}>
            事件：{cases.find((c) => c.id === job.caseId)?.title || job.caseId}
          </small>
          {job.error && job.state === 'failed' && (
            <>
              <p role="alert">{job.error}</p>
              <small>
                任务 ID：<code>{job.id}</code> · 可在设置 → 运行日志中查询
              </small>
            </>
          )}
        </div>
      ))}
      {model.error && <p role="alert">导出状态读取或操作失败：{model.error}</p>}
      <small>
        任务可在当前客户端内后台完成；退出不会自动续传。校验进度按实际读取字节计算。
      </small>
    </div>
  );
}
