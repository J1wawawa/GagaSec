import type { Finding } from './types';
export interface LocalAnalysisJob {
  id: string;
  caseId: string;
  kind: string;
  name: string;
  state: string;
  phase: string;
  startedAt: string;
  elapsedMs: number;
  revision: number;
  totalBytes: number;
  copiedBytes: number;
  counts: {
    bytes: number;
    lines: number;
    parsed: number;
    invalid: number;
    oversized: number;
    hits: number;
  };
  stages: { phase: string; elapsedMs: number }[];
  previews: Finding[];
  evidenceId: string | null;
  error: string | null;
}
export const localRunning = (job: LocalAnalysisJob) =>
  ['running', 'cancelling'].includes(job.state);
// A delayed initial response or poll must never replace newer event data.
export function mergeLocalJobs(
  previous: LocalAnalysisJob[],
  incoming: LocalAnalysisJob[],
) {
  const jobs = new Map(previous.map((job) => [job.id, job]));
  for (const job of incoming) {
    const old = jobs.get(job.id);
    if (!old || job.revision > old.revision) jobs.set(job.id, job);
  }
  return [...jobs.values()]
    .sort(
      (a, b) =>
        b.startedAt.localeCompare(a.startedAt) || b.id.localeCompare(a.id),
    )
    .slice(0, 80);
}
