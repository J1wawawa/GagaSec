export type ReverseJob = {
  revision?: number;
  provider?: string;
  model?: string;
  sampleName?: string;
  configRevision?: string;
  requestSha256?: string[];
  id: string;
  caseId: string;
  evidenceId: string;
  sampleSha256: string;
  createdAt: string;
  state: string;
  imageId: string;
  question: string;
  content: string;
  events: { at: string; title: string }[];
  artifacts: {
    id: string;
    tool: string;
    params: unknown;
    sha256: string;
    preview: string;
  }[];
  modelRequests: number;
  error: string | null;
  reportEvidenceId: string | null;
  cleanupConfirmed: boolean;
};

/** 合并事件和快照，保持事件归属；迟到的旧 revision 不能覆盖已完成任务。 */
export function mergeReverseJobs(
  current: ReverseJob[],
  incoming: ReverseJob[],
  caseId: string,
): ReverseJob[] {
  const map = new Map(
    current.filter((j) => j.caseId === caseId).map((j) => [j.id, j]),
  );
  for (const job of incoming) {
    if (job.caseId !== caseId) continue;
    const old = map.get(job.id);
    if (
      old &&
      ((old.revision ?? 0) > (job.revision ?? 0) ||
        ((old.revision ?? 0) === (job.revision ?? 0) &&
          old.state !== 'running' &&
          job.state === 'running'))
    )
      continue;
    map.set(job.id, job);
  }
  return [...map.values()]
    .sort(
      (a, b) =>
        b.createdAt.localeCompare(a.createdAt) || b.id.localeCompare(a.id),
    )
    .slice(0, 100);
}
