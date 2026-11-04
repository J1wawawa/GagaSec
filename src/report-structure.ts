// 章节数组采用先父后子的顺序；移动父章节时必须带上全部子章节。
// 标识独立于标题和序号，改名、排序不会改变证据关联。
export type ReportStep = {
  id: string;
  title: string;
  body: string;
  parentId: string | null;
  owner: string;
  startedAt: string;
  completedAt: string;
  status: string;
  nodeIds: string[];
};
export const fiveStepTemplate = [
  ['assessment', '危害评估与影响范围'],
  ['containment', '事件紧急处置'],
  ['investigation', '事件过程排查（包含木马分析）'],
  ['attribution', '攻击或威胁溯源'],
  ['outcome', '处置结果'],
] as const;
export function newSection(
  title: string,
  parentId: string | null = null,
): ReportStep {
  return {
    id: crypto.randomUUID(),
    title,
    body: '',
    parentId,
    owner: '',
    startedAt: '',
    completedAt: '',
    status: 'todo',
    nodeIds: [],
  };
}
export function sectionNumbers(steps: ReportStep[]): Record<string, string> {
  const result: Record<string, string> = {};
  let root = 0,
    child = 0;
  for (const step of steps) {
    if (!step.parentId) {
      root++;
      child = 0;
      result[step.id] = `${root}.`;
    } else {
      child++;
      result[step.id] = `${root}.${child}`;
    }
  }
  return result;
}
export function sectionBlock(steps: ReportStep[], id: string) {
  const start = steps.findIndex((s) => s.id === id);
  if (start < 0) return { start: -1, end: -1, rows: [] as ReportStep[] };
  let end = start + 1;
  if (!steps[start].parentId)
    while (end < steps.length && steps[end].parentId === id) end++;
  return { start, end, rows: steps.slice(start, end) };
}
export function moveSection(
  steps: ReportStep[],
  id: string,
  direction: -1 | 1,
): ReportStep[] {
  const current = steps.find((s) => s.id === id);
  if (!current) return steps;
  const siblings = steps.filter((s) => s.parentId === current.parentId);
  const sibling = siblings[siblings.findIndex((s) => s.id === id) + direction];
  if (!sibling) return steps;
  const first = sectionBlock(steps, direction < 0 ? sibling.id : id);
  const second = sectionBlock(steps, direction < 0 ? id : sibling.id);
  return [
    ...steps.slice(0, first.start),
    ...second.rows,
    ...first.rows,
    ...steps.slice(second.end),
  ];
}
