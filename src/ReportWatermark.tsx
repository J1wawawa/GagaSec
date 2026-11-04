import { useState } from 'react';
import { invoke } from './bridge';
import { open, save } from '@tauri-apps/plugin-dialog';
import { Modal } from './Modal';

export type WatermarkSettings = { enabled: boolean; name: string };
type Inspection = {
  pdfPages: number | null;
  present: boolean;
  verification: string;
  watermark: {
    id: string;
    name: string;
    createdAt: string;
    reportTitle: string;
  } | null;
  notice: string;
};
export function ReportWatermark({
  settings,
  onChange,
  onClose,
}: {
  settings: WatermarkSettings;
  onChange: (value: WatermarkSettings) => void;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<Inspection | null>(null);
  const [filename, setFilename] = useState('');
  async function query() {
    setError('');
    setBusy(true);
    try {
      const path = await open({
        title: '查询报告电子水印',
        multiple: false,
        filters: [
          { name: '调查报告', extensions: ['html', 'htm', 'docx', 'pdf'] },
        ],
      });
      if (typeof path !== 'string') return;
      setResult(null);
      setFilename(path.split(/[/\\]/).at(-1) || '报告');
      setResult(await invoke<Inspection>('inspect_report_watermark', { path }));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function stampPdf() {
    setError('');
    setBusy(true);
    try {
      if (!settings.name.trim()) throw Error('请先填写水印名称。');
      const source = await open({
        title: '选择已经保存的 PDF 报告',
        multiple: false,
        filters: [{ name: 'PDF 报告', extensions: ['pdf'] }],
      });
      if (typeof source !== 'string') return;
      const destination = await save({
        title: '保存带电子水印的 PDF 副本',
        defaultPath: source.replace(/\.pdf$/i, '-水印版.pdf'),
        filters: [{ name: 'PDF 报告', extensions: ['pdf'] }],
      });
      if (!destination) return;
      setResult(null);
      setFilename(destination.split(/[/\\]/).at(-1) || 'PDF 报告');
      setResult(
        await invoke<Inspection>('stamp_report_pdf', {
          source,
          destination,
          name: settings.name,
        }),
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title="报告电子水印" busy={busy} onClose={onClose}>
      <div className="watermark-panel">
        <div className="watermark-header">
          <h2>报告电子水印</h2>
          <button
            className="button"
            aria-label="关闭电子水印"
            disabled={busy}
            onClick={onClose}
          >
            关闭
          </button>
        </div>
        <p>
          将自定义名称、生成时间、报告标题和批次 ID
          加密写入文档元数据，由当前工作区密钥解读核验，保持正文排版。
        </p>
        <label className="check">
          <input
            type="checkbox"
            aria-label="导出报告嵌入电子水印"
            checked={settings.enabled}
            onChange={(e) =>
              onChange({ ...settings, enabled: e.target.checked })
            }
          />
          HTML / DOCX 导出时嵌入电子水印
        </label>
        <label className="watermark-name">
          水印名称
          <input
            aria-label="电子水印名称"
            value={settings.name}
            maxLength={120}
            onChange={(e) => onChange({ ...settings, name: e.target.value })}
            placeholder="如 J4team · 交付复核版"
          />
        </label>
        <p className="watermark-hint">
          设置随本事件报告自动保存。PDF
          经系统打印保存后，可在此写入水印并另存副本。支持 64 MiB 以内的报告。
        </p>
        <div className="toolbar-group">
          <button
            className="button"
            disabled={busy}
            onClick={() => void query()}
          >
            查询电子水印
          </button>
          <button
            className="button primary"
            disabled={busy}
            onClick={() => void stampPdf()}
          >
            为 PDF 写入水印
          </button>
        </div>
        {busy && <p role="status">正在处理报告文件…</p>}
        {error && (
          <p className="report-error" role="alert">
            {error}
          </p>
        )}
        {result && (
          <div className="watermark-result" role="status">
            <strong>{filename}</strong>
            {result.pdfPages !== null && (
              <p>
                PDF 可解析 · {result.pdfPages}{' '}
                页。流转前请用阅读器核对排版与截图。
              </p>
            )}
            {result.watermark ? (
              <dl>
                <dt>DIY 名称</dt>
                <dd>{result.watermark.name}</dd>
                <dt>生成时间 / UTC+8</dt>
                <dd>
                  {new Date(result.watermark.createdAt).toLocaleString(
                    'zh-CN',
                    { timeZone: 'Asia/Shanghai', hour12: false },
                  )}
                </dd>
                <dt>报告标题</dt>
                <dd>{result.watermark.reportTitle}</dd>
                <dt>导出批次</dt>
                <dd>{result.watermark.id}</dd>
              </dl>
            ) : (
              <p>
                {result.present
                  ? '发现加密水印，当前工作区密钥无法解读，或标识已改动。'
                  : '未找到水印标识；无法判断是否曾经写入或已被移除。'}
              </p>
            )}
            <p className="watermark-hint">{result.notice}</p>
          </div>
        )}
      </div>
    </Modal>
  );
}
