import { useCallback, useEffect, useRef, useState } from 'react';
import { invoke, isTauri } from './bridge';
import { ImagePlus, RefreshCw, X } from 'lucide-react';
import { draftBackupKey } from './draft-journal';
import { sectionNumbers, type ReportStep } from './report-structure';
import { TextEditor } from './TextEditor';

export type RecordOptionsValue = {
  id: string;
  caseId: string;
  sectionIds: string[];
  newSectionTitle: string;
  reportVersion: string;
  screenshot: { dataUrl: string; caption: string } | null;
};
type Directory = { steps: ReportStep[]; updatedAt: string };
export function RecordOptions({
  caseId,
  dataDir,
  onChange,
  focusScreenshot = false,
}: {
  caseId: string;
  dataDir: string;
  onChange: (v: RecordOptionsValue) => void;
  focusScreenshot?: boolean;
}) {
  const screenshotRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focusScreenshot) screenshotRef.current?.focus();
  }, [focusScreenshot]);
  const [value, setValue] = useState<RecordOptionsValue>(() => ({
    id: crypto.randomUUID(),
    caseId,
    sectionIds: [],
    newSectionTitle: '',
    reportVersion: '',
    screenshot: null,
  }));
  const [directory, setDirectory] = useState<Directory>();
  const [selection, setSelection] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const generation = useRef(0);
  const load = useCallback(async () => {
    if (!isTauri()) return;
    const request = ++generation.current;
    setLoading(true);
    setError('');
    try {
      const pending = !!localStorage.getItem(draftBackupKey(dataDir, caseId));
      const d = await invoke<Directory>('get_report_draft', { caseId });
      if (request !== generation.current) return;
      setBlocked(pending);
      setDirectory(d);
      if (pending) setSelection('');
      setValue((v) => ({
        ...v,
        reportVersion: d.updatedAt,
        sectionIds: pending
          ? []
          : v.sectionIds.filter((id) => d.steps.some((s) => s.id === id)),
        newSectionTitle: pending ? '' : v.newSectionTitle,
      }));
    } catch (e) {
      if (request === generation.current) {
        setError(String(e));
        setDirectory(undefined);
        setSelection('');
        setValue((v) => ({ ...v, sectionIds: [], newSectionTitle: '' }));
      }
    } finally {
      if (request === generation.current) setLoading(false);
    }
  }, [caseId, dataDir]);
  useEffect(() => {
    void load();
    return () => {
      generation.current++;
    };
  }, [load]);
  useEffect(() => onChange(value), [value, onChange]);
  const numbers = sectionNumbers(directory?.steps || []);
  async function image(file: File) {
    if (
      !['image/png', 'image/jpeg', 'image/webp'].includes(file.type) ||
      file.size > 8 * 1024 * 1024
    ) {
      setError('请选择不超过 8 MiB 的 PNG、JPEG 或 WebP 图片。');
      return;
    }
    const reader = new FileReader();
    reader.onerror = () => setError('图片读取失败，请重新选择。');
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        setError('');
        setValue((v) => ({
          ...v,
          screenshot: {
            dataUrl: String(reader.result),
            caption: v.screenshot?.caption || '',
          },
        }));
      }
    };
    reader.readAsDataURL(file);
  }
  return (
    <aside className="capture-options">
      <h3>报告与截图</h3>
      <p className="small-note">在这里一起整理，保存后可继续当前分析。</p>
      <label>
        关联报告章节
        <select
          aria-label="快速关联报告章节"
          disabled={loading || blocked || !directory}
          value={selection}
          onChange={(e) => {
            const id = e.target.value;
            setSelection(id);
            setValue((v) => ({
              ...v,
              sectionIds: id && id !== 'new' ? [id] : [],
              newSectionTitle: '',
            }));
          }}
        >
          <option value="">仅记录时间线，稍后编排</option>
          {directory?.steps.map((s) => (
            <option key={s.id} value={s.id}>
              {numbers[s.id]} {s.title}
              {s.owner ? ' · ' + s.owner : ''}
            </option>
          ))}
          <option value="new">＋ 新建报告章节</option>
        </select>
      </label>
      {selection === 'new' && (
        <label>
          新章节标题
          <input
            aria-label="快速新章节标题"
            maxLength={120}
            required
            value={value.newSectionTitle}
            onChange={(e) =>
              setValue((v) => ({ ...v, newSectionTitle: e.target.value }))
            }
          />
        </label>
      )}
      {blocked ? (
        <p className="capture-warning">
          报告有未确认草稿，请先到报告页保存或恢复；当前仍可保存时间线与截图。
        </p>
      ) : (
        <small>关联时仅补全空缺的章节负责人。</small>
      )}
      <button
        className="button small"
        type="button"
        disabled={loading}
        onClick={() => void load()}
      >
        <RefreshCw size={12} className={loading ? 'spinning' : ''} />
        刷新章节
      </button>
      <div
        className="capture-image"
        ref={screenshotRef}
        tabIndex={0}
        aria-label="快速举证截图"
        onPaste={(e) => {
          const f = Array.from(e.clipboardData.files).find((f) =>
            f.type.startsWith('image/'),
          );
          if (f) {
            e.preventDefault();
            void image(f);
          }
        }}
      >
        {value.screenshot ? (
          <>
            <img src={value.screenshot.dataUrl} alt="待保存举证截图" />
            <button
              className="icon-button"
              type="button"
              aria-label="移除待保存截图"
              onClick={() => setValue((v) => ({ ...v, screenshot: null }))}
            >
              <X size={14} />
            </button>
          </>
        ) : (
          <>
            <ImagePlus size={22} />
            <span>点击后 ⌘V / Ctrl+V 粘贴截图</span>
            <small>可选，支持 PNG / JPEG / WebP</small>
          </>
        )}
      </div>
      <label className="capture-file">
        或选择图片
        <input
          aria-label="快速选择截图"
          type="file"
          accept="image/png,image/jpeg,image/webp"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void image(file);
            e.target.value = '';
          }}
        />
      </label>
      {value.screenshot && (
        <TextEditor
          label="截图图注"
          aria-label="快速截图图注"
          rows={2}
          maxLength={1000}
          required
          value={value.screenshot.caption}
          onChange={(e) =>
            setValue((v) => ({
              ...v,
              screenshot: v.screenshot
                ? { ...v.screenshot, caption: e.target.value }
                : null,
            }))
          }
          placeholder="说明这张图证明了什么"
        />
      )}
      {error && (
        <p role="alert" className="capture-warning">
          {error}
        </p>
      )}
    </aside>
  );
}
