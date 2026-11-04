/** 报告编辑的本地恢复日志。SQLite 成功确认前保留，避免关闭窗口或保存失败丢字。 */
export type DraftBackup<T> = { draft: T; baseVersion: string };
export const draftBackupKey = (workspace: string, caseId: string) =>
  `gaga-report-draft/1/${encodeURIComponent(workspace)}/${encodeURIComponent(caseId)}`;
export function readDraftBackup<T>(
  storage: Storage,
  key: string,
): DraftBackup<T> | null {
  const raw = storage.getItem(key);
  if (!raw) return null;
  const value = JSON.parse(raw);
  if (
    !value ||
    typeof value.baseVersion !== 'string' ||
    typeof value.draft !== 'object' ||
    value.draft === null
  )
    return null;
  return value;
}
export function writeDraftBackup<T>(
  storage: Storage,
  key: string,
  draft: T,
  baseVersion: string,
) {
  storage.setItem(key, JSON.stringify({ draft, baseVersion }));
}
export function acknowledgeDraftBackup<T>(
  storage: Storage,
  key: string,
  saved: T,
) {
  const pending = readDraftBackup<T>(storage, key);
  // 迟到的保存回执只能清除自己的版本，不能清除用户刚输入的新版本。
  if (pending && JSON.stringify(pending.draft) === JSON.stringify(saved))
    storage.removeItem(key);
}
