import { investigationTemplates } from './report-templates';
import { TextEditor } from './TextEditor';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { invoke, isTauri, reportError } from './bridge';
import {
  ArrowUp,
  ArrowDown,
  Trash2,
  Download,
  FileText,
  ImagePlus,
  Plus,
  Printer,
  Save,
  ArrowLeft,
  ArrowUpRight,
  X,
  LayoutDashboard,
  PanelLeft,
} from 'lucide-react';
import type { Screenshot, TimelineNode, Workspace } from './types';
import './reports.css';
import { ReportInsightsView, type ReportInsights } from './ReportInsights';
import { ReportWatermark, type WatermarkSettings } from './ReportWatermark';
import { Modal } from './Modal';
import {
  fiveStepTemplate,
  newSection,
  sectionNumbers,
  sectionBlock,
  moveSection,
  type ReportStep as Step,
} from './report-structure';
import { ReportExportPanel, type ReportExportsModel } from './ReportExports';
import {
  draftBackupKey,
  readDraftBackup,
  writeDraftBackup,
  acknowledgeDraftBackup,
} from './draft-journal';

const legacySteps = [
  [
    'assessment',
    '1. 危害评估与影响范围',
    'assessment',
    '危害评估',
    '说明实际危害、业务影响、波及资产和评估依据。',
  ],
  [
    'containment',
    '2. 事件紧急处置',
    'containment',
    '紧急处置记录',
    '区分处置计划、已下达指令和已收到的执行回执。',
  ],
  [
    'investigation',
    '3. 事件过程排查',
    'investigation',
    '过程排查与木马分析',
    '按证据还原过程，包含日志、HTTP、木马静态或动态分析及未确认环节。',
  ],
  [
    'attribution',
    '4. 攻击或威胁溯源',
    'attribution',
    '溯源分析',
    '记录 IOC、基础设施及关联依据；不能确认攻击者归属时明确保留未知。',
  ],
  [
    'outcome',
    '5. 处置结果',
    'conclusion',
    '调查结论',
    '记录清理、恢复、复测结果和仍未消除的风险，避免把计划写成已完成。',
  ],
] as const;
const statuses: Record<string, string> = {
  todo: '待开展',
  in_progress: '进行中',
  completed: '已完成',
  blocked: '待补证 / 阻塞',
};
const emptySteps = (): Step[] => [];
const timeInput = (value: string) => {
  if (!value) return '';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '';
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 23);
};
const savedTime = (value: string) =>
  value ? new Date(value).toISOString() : '';
type Draft = {
  structureVersion: number;
  title: string;
  author: string;
  summary: string;
  scope: string;
  conclusion: string;
  recommendations: string;
  updatedAt: string;
  eventType: string;
  discoveredAt: string;
  discoveredBy: string;
  severity: string;
  harm: string;
  assessment: string;
  containment: string;
  investigation: string;
  attribution: string;
  steps: Step[];
  watermark: WatermarkSettings;
};
function selectedContent(draft: Draft) {
  return (
    [draft.summary, draft.harm, draft.scope, draft.recommendations].some(
      (v) => !!v.trim(),
    ) || draft.steps.some((s) => !!s.body.trim())
  );
}
function normalizeDraft(value: Draft): Draft {
  value = {
    ...value,
    watermark: value.watermark || { enabled: true, name: 'J4team' },
  };
  if (value.structureVersion === 2) return value;
  const rows = value.steps?.length
    ? value.steps
    : fiveStepTemplate.map(([id, title]) => ({ ...newSection(title), id }));
  return {
    ...value,
    structureVersion: 2,
    steps: rows.map((s) => {
      const legacy = legacySteps.find((row) => row[0] === s.id);
      return {
        ...s,
        title: s.title || legacy?.[1].replace(/^\d+\. /, '') || '未命名章节',
        body: s.body || (legacy ? value[legacy[2]] : '') || '',
        parentId: s.parentId || null,
      };
    }),
  };
}
type Props = {
  entry?: 'home' | 'write' | 'delivery';
  workspace: Workspace;
  busy: boolean;
  onExport: (format: 'html' | 'docx', caseId: string) => Promise<void>;
  exports: ReportExportsModel;
  onPrint: () => void;
  onEdit: (node: TimelineNode) => void;
  onSource: (node: TimelineNode) => void;
  onPaste: (node: TimelineNode) => void;
  onAttach: (node: TimelineNode) => void;
  onToggle: (node: TimelineNode, included: boolean) => void;
  onNew: () => void;
  renderShot: (shot: Screenshot, eager?: boolean) => ReactNode;
};
const stamp = (value: string) =>
  new Date(value).toLocaleString('zh-CN', {
    timeZone: 'Asia/Shanghai',
    hour12: false,
  });

export function ReportEditor(props: Props) {
  const { workspace: w } = props;
  const caseId = w.activeCase;
  const [draft, setDraft] = useState<Draft>({
    structureVersion: 2,
    title: w.cases.find((c) => c.id === caseId)?.title || '调查报告',
    author: '',
    summary: '',
    scope: '',
    conclusion: '',
    recommendations: '',
    updatedAt: '',
    eventType: '',
    discoveredAt: '',
    discoveredBy: '',
    severity: '',
    harm: '',
    assessment: '',
    containment: '',
    investigation: '',
    attribution: '',
    steps: emptySteps(),
    watermark: { enabled: true, name: 'J4team' },
  });
  const [section, setSection] = useState('basics');
  const [showOutline, setShowOutline] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const numbers = sectionNumbers(draft.steps);
  const hasContent = selectedContent(draft);
  const [view, setView] = useState<
    'home' | 'write' | 'nodes' | 'insights' | 'preview'
  >(props.entry === 'write' ? 'write' : 'home');
  const [insights, setInsights] = useState<ReportInsights | null>(null);
  const [insightsError, setInsightsError] = useState('');
  const [openingView, setOpeningView] = useState(false);
  const [showWatermark, setShowWatermark] = useState(false);
  const [showDelivery, setShowDelivery] = useState(props.entry === 'delivery');
  const [preparingPrint, setPreparingPrint] = useState(false);
  const [state, setState] = useState('loading');
  const [error, setError] = useState('');
  const [ready, setReady] = useState(false);
  // 父级以事件 ID 作为 key：保存队列始终绑定创建它的事件，不能改用当下的活动事件。
  const latest = useRef({ draft, dirty: false });
  const baseVersion = useRef('');
  const backupKey = draftBackupKey(w.dataDir, caseId);
  const [recovery, setRecovery] = useState<Draft | null>(null);
  const alive = useRef(true);
  const writes = useRef(Promise.resolve());
  const selected = w.nodes.filter((n) => n.included);
  async function readInsights() {
    const value = await invoke<ReportInsights>('get_report_insights', {
      caseId,
      draft: latest.current.draft,
    });
    if (alive.current) {
      setInsights(value);
      setInsightsError('');
    }
    return value;
  }
  useEffect(() => {
    if (!ready || !['insights', 'preview'].includes(view)) return;
    if (!isTauri()) {
      setInsightsError('请在桌面客户端查看当前事件的统计。');
      return;
    }
    let disposed = false;
    const timer = setTimeout(() => {
      invoke<ReportInsights>('get_report_insights', { caseId, draft })
        .then((value) => {
          if (!disposed) {
            setInsights(value);
            setInsightsError('');
          }
        })
        .catch((e) => {
          if (!disposed) setInsightsError(String(e));
        });
    }, 80);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [caseId, draft, ready, view, w.nodes, w.evidence]);
  function persist(value = latest.current.draft): Promise<void> {
    if (!isTauri()) {
      setError('请在桌面客户端保存报告。');
      return Promise.reject(Error('需要桌面客户端'));
    }
    if (alive.current) setState('saving');
    const task = writes.current.then(async () => {
      const saved = await invoke<Draft>('save_report_draft', {
        caseId,
        draft: value,
      });
      baseVersion.current = saved.updatedAt;
      try {
        acknowledgeDraftBackup(localStorage, backupKey, value);
        if (latest.current.draft !== value && latest.current.dirty)
          writeDraftBackup(
            localStorage,
            backupKey,
            latest.current.draft,
            saved.updatedAt,
          );
      } catch {
        /* SQLite 已保存；本机 WebView 存储不可用时不能把成功伪装为失败。 */
      }
      if (latest.current.draft === value) latest.current.dirty = false;
      if (alive.current) {
        setState(latest.current.dirty ? 'dirty' : 'saved');
        setError('');
      }
    });
    writes.current = task.catch(() => {});
    return task.catch((e) => {
      if (alive.current) {
        setError(String(e));
        setState('error');
      }
      throw e;
    });
  }
  useEffect(() => {
    alive.current = true;
    let disposed = false;
    if (isTauri())
      invoke<Draft>('get_report_draft', { caseId })
        .then((value) => {
          if (!disposed) {
            baseVersion.current = value.updatedAt;
            let recovered = false;
            try {
              const backup = readDraftBackup<Draft>(localStorage, backupKey);
              if (backup) {
                if (backup.baseVersion === value.updatedAt) {
                  value = { ...value, ...backup.draft };
                  recovered = true;
                } else setRecovery(backup.draft);
              }
            } catch {
              setError('本机草稿恢复日志读取失败；数据库报告仍可编辑。');
            }
            value = normalizeDraft(value);
            setDraft(value);
            latest.current = { draft: value, dirty: recovered };
            setState(recovered ? 'dirty' : 'saved');
            setReady(true);
          }
        })
        .catch((e) => {
          if (alive.current) {
            setError(String(e));
            setState('error');
          }
        });
    else {
      setReady(true);
      setState('preview');
    }
    return () => {
      disposed = true;
      alive.current = false;
      if (latest.current.dirty && isTauri()) void persist().catch(() => {});
    };
  }, [caseId]);
  useEffect(() => {
    if (!ready || !latest.current.dirty) return;
    const timer = setTimeout(() => {
      void persist().catch(() => {});
    }, 600);
    return () => clearTimeout(timer);
  }, [draft, ready]);
  function update(patch: Partial<Draft>) {
    const next = { ...draft, ...patch };
    latest.current = { draft: next, dirty: true };
    try {
      writeDraftBackup(localStorage, backupKey, next, baseVersion.current);
    } catch {
      setError(
        '本机恢复日志写入失败，请及时点击保存；尚未确认保存的内容请勿关闭窗口。',
      );
    }
    setDraft(next);
    setState('dirty');
  }
  function change(
    key: Exclude<keyof Draft, 'steps' | 'watermark'>,
    value: string,
  ) {
    update({ [key]: value });
  }
  function changeStep(id: string, patch: Partial<Step>) {
    update({
      steps: draft.steps.map((s) => (s.id === id ? { ...s, ...patch } : s)),
    });
  }
  function assignNode(nodeId: string, id: string, included: boolean) {
    changeStep(id, {
      nodeIds: [
        ...draft.steps
          .find((s) => s.id === id)!
          .nodeIds.filter((n) => n !== nodeId),
        ...(included ? [nodeId] : []),
      ],
    });
  }
  function addSection(parentId: string | null = null) {
    if (draft.steps.length >= 64) return;
    const step = newSection(parentId ? '新子章节' : '新章节', parentId);
    const next = [...draft.steps];
    const index = parentId ? sectionBlock(next, parentId).end : next.length;
    next.splice(index, 0, step);
    update({ steps: next });
    setSection(step.id);
    setShowOutline(false);
    requestAnimationFrame(() => {
      const input = document.querySelector<HTMLInputElement>(
        '[data-section-title]',
      );
      input?.focus();
      input?.select();
    });
  }
  async function newNode() {
    try {
      await persist();
      props.onNew();
    } catch {
      // 保留报告编辑错误，未确认保存前不启动会改动章节引用的快捷录入。
    }
  }
  function reparent(id: string, parentId: string | null) {
    const row = draft.steps.find((s) => s.id === id)!;
    const next = draft.steps.filter((s) => s.id !== id);
    const index = parentId ? sectionBlock(next, parentId).end : next.length;
    next.splice(index, 0, { ...row, parentId });
    update({ steps: next });
  }
  function insertTemplate(kind: string) {
    const entries: readonly (readonly [string, string])[] =
      kind === 'five'
        ? fiveStepTemplate.map(([, title]) => [title, ''] as const)
        : kind === 'phases'
          ? [
              '初始入侵',
              '权限提升与持久化',
              '横向移动与影响',
              '处置与恢复',
            ].map((title) => [title, ''] as const)
          : investigationTemplates[kind]?.sections || [];
    const rows = entries.map(([title, body], i) => ({
      ...newSection(title),
      body,
      id:
        kind === 'five' &&
        !draft.steps.some((s) => s.id === fiveStepTemplate[i][0])
          ? fiveStepTemplate[i][0]
          : crypto.randomUUID(),
    }));
    if (!rows.length) return;
    if (draft.steps.length + rows.length > 64) return;
    update({ steps: [...draft.steps, ...rows] });
    setSection(rows[0].id);
    setShowOutline(false);
  }
  function textField(
    key: Exclude<keyof Draft, 'steps' | 'watermark'>,
    label: string,
    hint: string,
  ) {
    return (
      <TextEditor
        label={label}
        hint={hint}
        aria-label={label}
        rows={5}
        maxLength={12000}
        disabled={!ready}
        value={String(draft[key])}
        onChange={(e) => change(key, e.target.value)}
      />
    );
  }
  function renderNode(n: TimelineNode) {
    const e = w.evidence.find((e) => e.id === n.evidenceId);
    const f = e?.report.findings.find((f) => f.id === n.findingId);
    return (
      <section className="report-section" key={n.id}>
        <div className="report-node-head">
          <h2>{n.title}</h2>
        </div>
        <p>
          {stamp(n.occurredAt)} · {n.actor}
        </p>
        <p className="body-text">{n.body}</p>
        {e ? (
          <>
            <div className="report-citation">
              来源：{e.name}
              <br />
              SHA-256：{e.sha256}
              {f && (
                <>
                  <br />
                  定位：{f.location}
                </>
              )}
            </div>
            {f && <pre>{f.excerpt}</pre>}
            <button
              type="button"
              className="button small print-hide"
              disabled={props.busy || !ready}
              onClick={() => void deliver(() => props.onSource(n))}
            >
              查看原证据与分析
            </button>
          </>
        ) : (
          <p>人工记录 · 尚未关联原始证据</p>
        )}
        {n.screenshots.length ? (
          n.screenshots.map((shot) => props.renderShot(shot, preparingPrint))
        ) : (
          <div className="report-placeholder">截图预留 · 待补图及图注</div>
        )}
      </section>
    );
  }
  async function deliver(action: () => void | Promise<void>) {
    try {
      await persist();
      if (alive.current) await action();
    } catch {
      /* The editor or export action displays the error. */
    }
  }
  async function openReportView(target: typeof view) {
    if (target === 'preview' || target === 'insights') {
      setOpeningView(true);
      try {
        await readInsights();
      } catch (error) {
        if (alive.current) setInsightsError(String(error));
      } finally {
        if (alive.current) setOpeningView(false);
      }
    }
    if (alive.current) setView(target);
  }
  async function printReport() {
    try {
      await readInsights();
      setShowDelivery(false);
      setView('preview');
      setPreparingPrint(true);
      // Evidence lists load screenshots on visibility. Printing must request
      // every referenced image and wait for decoded pixels, including offscreen
      // chapters, before handing this WebView to the operating system.
      await new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
      );
      const started = Date.now();
      while (alive.current) {
        const paper = document.querySelector('.report-paper');
        if (!paper) throw Error('报告预览已切换，请重新选择打印。');
        if (paper.querySelector('.shot-error'))
          throw Error('报告截图读取或校验失败，请修复后再打印。');
        const shots = [...paper.querySelectorAll('.shot')];
        if (
          shots.every((shot) => {
            const image = shot.querySelector('img');
            return image?.complete && image.naturalWidth > 0;
          })
        ) {
          props.onPrint();
          return;
        }
        if (Date.now() - started > 30000)
          throw Error('报告截图加载超时，请检查原图后重试打印。');
        await new Promise((resolve) => setTimeout(resolve, 80));
      }
    } catch (e) {
      if (alive.current) setError(String(e));
      reportError('report-print-preflight', e);
    } finally {
      if (alive.current) setPreparingPrint(false);
    }
  }
  return (
    <section
      className="report-workspace"
      data-view={view}
      data-case-id={caseId}
    >
      {showWatermark && (
        <ReportWatermark
          settings={draft.watermark}
          onChange={(watermark) => update({ watermark })}
          onClose={() => setShowWatermark(false)}
        />
      )}
      {deleting && (
        <Modal title="删除报告章节" onClose={() => setDeleting(null)}>
          <p>
            删除“{draft.steps.find((s) => s.id === deleting)?.title}
            ”及其子章节的正文和分组。原始调查节点、证据和截图会保留，未被其他章节引用的节点仍在附录中。
          </p>
          <div className="toolbar-group">
            <button className="button" onClick={() => setDeleting(null)}>
              取消
            </button>
            <button
              className="button primary"
              data-action="confirm-delete-section"
              onClick={() => {
                const block = sectionBlock(draft.steps, deleting);
                update({
                  steps: [
                    ...draft.steps.slice(0, block.start),
                    ...draft.steps.slice(block.end),
                  ],
                });
                setSection('basics');
                setDeleting(null);
              }}
            >
              确认删除章节
            </button>
          </div>
        </Modal>
      )}
      {recovery && (
        <div className="report-error" role="alert">
          发现另一版本的本机未保存草稿。数据库报告已更新，请确认是否恢复旧草稿。
          <button
            className="button"
            onClick={() => {
              update(normalizeDraft(recovery));
              setRecovery(null);
            }}
          >
            恢复本机未保存草稿
          </button>
          <button
            className="button"
            onClick={() => {
              localStorage.removeItem(backupKey);
              setRecovery(null);
            }}
          >
            使用数据库版本
          </button>
        </div>
      )}
      <header className="page-head print-hide">
        <div className="report-page-identity">
          {preparingPrint && <span role="status">正在校验并加载报告截图…</span>}
          {view !== 'home' && (
            <button
              className="button report-back"
              aria-label="返回报告中心"
              onClick={() => void deliver(() => setView('home'))}
            >
              <ArrowLeft size={15} />
              报告中心
            </button>
          )}
          <div>
            <h1>{view === 'home' ? '报告中心' : '报告编辑器'}</h1>
            <p>{w.cases.find((c) => c.id === caseId)?.title}</p>
          </div>
        </div>
        <div className="toolbar-group report-header-actions">
          <span className="report-save-status" role="status" data-state={state}>
            {
              {
                loading: '读取中',
                dirty: '待保存',
                saving: '保存中',
                saved: '已保存到本事件',
                error: '保存失败',
                preview: '界面预览',
              }[state]
            }
          </span>
          {view !== 'home' && (
            <button
              className="button"
              disabled={!ready || props.busy || state === 'saving'}
              onClick={() => void persist().catch(() => {})}
            >
              <Save size={14} />
              保存
            </button>
          )}
          <button
            className="button primary"
            onClick={() => setShowDelivery(true)}
            disabled={!ready}
          >
            <Download size={14} />
            导出报告
          </button>
        </div>
      </header>
      {showDelivery && (
        <Modal title="报告导出与水印" onClose={() => setShowDelivery(false)}>
          <section className="modal report-delivery">
            <div className="modal-title">
              <h2>报告导出与水印</h2>
              <button
                className="icon-button"
                aria-label="关闭报告导出"
                onClick={() => setShowDelivery(false)}
              >
                <X size={16} />
              </button>
            </div>
            <p className="small-note">
              {draft.title} · 已选 {selected.length} 个节点 ·{' '}
              {selected.filter((n) => !n.screenshots.length).length} 个待补截图
            </p>
            {error && (
              <p className="modal-error" role="alert">
                {error}
              </p>
            )}
            <div className="report-delivery-formats">
              <button
                className="button"
                disabled={
                  !ready ||
                  props.busy ||
                  !!props.exports.active ||
                  (!selected.length && !hasContent)
                }
                onClick={() =>
                  void deliver(() => props.onExport('html', caseId))
                }
              >
                <FileText size={18} />
                <strong>保存 HTML</strong>
                <small>完整排版，可在浏览器查看</small>
              </button>
              <button
                className="button"
                disabled={
                  !ready ||
                  props.busy ||
                  preparingPrint ||
                  (!selected.length && !hasContent)
                }
                onClick={() => void deliver(printReport)}
              >
                <Printer size={18} />
                <strong>打印 / PDF</strong>
                <small>系统打印对话框保存为 PDF</small>
              </button>
              <button
                className="button"
                disabled={
                  !ready ||
                  props.busy ||
                  !!props.exports.active ||
                  (!selected.length && !hasContent)
                }
                onClick={() =>
                  void deliver(() => props.onExport('docx', caseId))
                }
              >
                <Download size={18} />
                <strong>导出 DOCX</strong>
                <small>可编辑，便于协作与交付</small>
              </button>
            </div>
            <div className="report-delivery-watermark">
              <div>
                <strong>电子水印</strong>
                <p>
                  {draft.watermark.enabled ? draft.watermark.name : '未启用'}
                </p>
              </div>
              <button className="button" onClick={() => setShowWatermark(true)}>
                配置电子水印
              </button>
            </div>
            <ReportExportPanel
              model={props.exports}
              caseId={caseId}
              cases={w.cases}
            />
          </section>
        </Modal>
      )}
      {view === 'home' && (
        <div className="report-home print-hide">
          <section className="report-home-intro">
            <div className="report-home-icon">
              <FileText size={30} strokeWidth={1.4} />
            </div>
            <div>
              <small>当前事件的独立报告</small>
              <h2>{draft.title}</h2>
              <p>
                按入侵阶段、资产或子事件组织内容，保留每一步的负责人、证据和截图。
              </p>
            </div>
            <button
              className="button primary"
              data-action="open-report-editor"
              disabled={!ready}
              onClick={() => setView('write')}
            >
              打开报告编辑器
              <ArrowUpRight size={15} />
            </button>
          </section>
          <div className="report-home-stats">
            <div>
              <strong>{draft.steps.length}</strong>
              <span>报告章节</span>
            </div>
            <div>
              <strong>{selected.length}</strong>
              <span>纳入报告的节点</span>
            </div>
            <div>
              <strong>
                {selected.reduce((total, n) => total + n.screenshots.length, 0)}
              </strong>
              <span>举证截图</span>
            </div>
            <div>
              <strong>
                {selected.filter((n) => !n.screenshots.length).length}
              </strong>
              <span>节点尚未附图</span>
            </div>
          </div>
          <div className="report-home-entries">
            <button onClick={() => setView('nodes')}>
              <ImagePlus size={21} />
              <strong>节点与截图</strong>
              <span>核对原始来源，粘贴或附入截图。</span>
              <ArrowUpRight size={16} />
            </button>
            <button onClick={() => setView('insights')}>
              <LayoutDashboard size={21} />
              <strong>统计与时间胶囊</strong>
              <span>查看事件进展、举证覆盖和关键时刻。</span>
              <ArrowUpRight size={16} />
            </button>
            <button onClick={() => setView('preview')}>
              <FileText size={21} />
              <strong>报告预览</strong>
              <span>检查排版、时间线与证据引用。</span>
              <ArrowUpRight size={16} />
            </button>
          </div>
          {!!props.exports.active && (
            <button className="button" onClick={() => setShowDelivery(true)}>
              查看正在导出的报告
            </button>
          )}
        </div>
      )}
      {error && (
        <p className="coverage-notice error print-hide" role="alert">
          {error}
        </p>
      )}
      {view !== 'home' && (
        <div
          className="report-modebar print-hide"
          role="tablist"
          aria-label="报告工作区"
        >
          {(
            [
              ['write', '正文编辑'],
              ['nodes', '节点与截图'],
              ['insights', '统计与时间胶囊'],
              ['preview', '报告预览'],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              role="tab"
              aria-selected={view === id}
              disabled={openingView}
              onClick={() => void openReportView(id)}
            >
              {label}
            </button>
          ))}
          <span role="status">
            {openingView ? '正在准备报告…' : '正文自动保存'}
          </span>
        </div>
      )}
      {view === 'insights' && (
        <div className="report-insights-panel print-hide">
          {insights ? (
            <ReportInsightsView
              data={insights}
              onOpen={(id) => {
                const node = selected.find((n) => n.id === id);
                if (node) void deliver(() => props.onSource(node));
              }}
              onEdit={(id) => {
                const node = selected.find((n) => n.id === id);
                if (node) props.onEdit(node);
              }}
            />
          ) : (
            <p className="insight-empty" role="status">
              {insightsError || '正在统计本事件报告…'}
            </p>
          )}
        </div>
      )}
      {view === 'write' && (
        <div className="report-writing-layout print-hide">
          <div className="report-writing-tools">
            <button
              className="button"
              aria-label="打开报告目录"
              aria-haspopup="dialog"
              onClick={(event) => {
                event.currentTarget.focus();
                setShowOutline(true);
              }}
            >
              <PanelLeft size={15} /> 目录与章节
            </button>
            <span>
              {section === 'basics'
                ? '基本信息'
                : `${numbers[section]} ${draft.steps.find((s) => s.id === section)?.title || ''}`}
            </span>
            <button
              className="button"
              data-action="add-report-section"
              disabled={!ready || draft.steps.length >= 64}
              onClick={() => addSection()}
            >
              <Plus size={14} />
              新增章节
            </button>
          </div>
          {showOutline && (
            <Modal title="报告目录与章节" onClose={() => setShowOutline(false)}>
              <section className="modal report-outline-dialog">
                <header>
                  <h2>目录与章节</h2>
                  <button
                    className="icon-button"
                    aria-label="关闭报告目录"
                    onClick={() => setShowOutline(false)}
                  >
                    <X size={17} />
                  </button>
                </header>
                <nav className="report-section-nav" aria-label="报告章节">
                  <button
                    type="button"
                    data-report-section="basics"
                    aria-current={section === 'basics' ? 'step' : undefined}
                    onClick={() => {
                      setSection('basics');
                      setShowOutline(false);
                    }}
                  >
                    基本信息
                  </button>
                  {draft.steps.map((step) => (
                    <button
                      key={step.id}
                      type="button"
                      data-report-section={step.id}
                      className={step.parentId ? 'report-subsection-link' : ''}
                      aria-current={section === step.id ? 'step' : undefined}
                      onClick={() => {
                        setSection(step.id);
                        setShowOutline(false);
                      }}
                    >
                      <span>
                        {numbers[step.id]} {step.title}
                      </span>
                      <small>{statuses[step.status] || '待开展'}</small>
                    </button>
                  ))}
                  <div className="report-outline-actions">
                    <button
                      type="button"
                      className="button small"
                      data-action="add-report-section"
                      disabled={!ready || draft.steps.length >= 64}
                      onClick={() => addSection()}
                    >
                      <Plus size={13} />
                      新增章节
                    </button>
                    <select
                      aria-label="插入报告模板"
                      value=""
                      disabled={!ready}
                      onChange={(e) => insertTemplate(e.target.value)}
                    >
                      <option value="" disabled>
                        插入模板…
                      </option>
                      <option
                        value="five"
                        disabled={draft.steps.length + 5 > 64}
                      >
                        五步处置
                      </option>
                      <option
                        value="phases"
                        disabled={draft.steps.length + 4 > 64}
                      >
                        入侵阶段
                      </option>
                      {Object.entries(investigationTemplates).map(
                        ([id, template]) => (
                          <option
                            key={id}
                            value={id}
                            disabled={
                              draft.steps.length + template.sections.length > 64
                            }
                          >
                            {template.label}
                          </option>
                        ),
                      )}
                    </select>
                    <small>按阶段、资产或子事件组织，最多两级、64 节。</small>
                  </div>
                </nav>
              </section>
            </Modal>
          )}
          <form
            className="report-writing"
            onSubmit={(e) => {
              e.preventDefault();
              void persist().catch(() => {});
            }}
          >
            {section === 'basics' ? (
              <>
                <h2>事件基本信息</h2>
                <div className="report-cover-fields">
                  <label>
                    报告标题
                    <input
                      aria-label="报告标题"
                      value={draft.title}
                      disabled={!ready}
                      required
                      maxLength={200}
                      onChange={(e) => change('title', e.target.value)}
                    />
                  </label>
                  <label>
                    编写 / 复核人员
                    <input
                      aria-label="报告署名"
                      value={draft.author}
                      disabled={!ready}
                      maxLength={100}
                      onChange={(e) => change('author', e.target.value)}
                      placeholder="填写人员或团队"
                    />
                  </label>
                </div>
                <div className="report-metadata-fields">
                  <label>
                    事件类型
                    <input
                      aria-label="事件类型"
                      value={draft.eventType}
                      disabled={!ready}
                      maxLength={100}
                      placeholder="如 Web 入侵、异常认证、恶意代码"
                      onChange={(e) => change('eventType', e.target.value)}
                    />
                  </label>
                  <label>
                    危害等级
                    <select
                      aria-label="危害等级"
                      value={draft.severity}
                      disabled={!ready}
                      onChange={(e) => change('severity', e.target.value)}
                    >
                      {['', '低', '中', '高', '严重'].map((v) => (
                        <option key={v} value={v}>
                          {v || '待评估'}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    发现时间
                    <input
                      aria-label="发现时间"
                      type="datetime-local"
                      step="0.001"
                      value={timeInput(draft.discoveredAt)}
                      disabled={!ready}
                      onChange={(e) =>
                        change('discoveredAt', savedTime(e.target.value))
                      }
                    />
                  </label>
                  <label>
                    发现人
                    <input
                      aria-label="发现人"
                      value={draft.discoveredBy}
                      maxLength={100}
                      disabled={!ready}
                      onChange={(e) => change('discoveredBy', e.target.value)}
                    />
                  </label>
                </div>
                {textField(
                  'harm',
                  '危害概述',
                  '描述已观察到或可能造成的危害，尚未评估时保留待评估。',
                )}
                {textField(
                  'summary',
                  '事件摘要',
                  '概述发现经过、涉及资产和当前调查状态。',
                )}
                {textField(
                  'scope',
                  '调查范围与限制',
                  '填写全部相关资产、时段和未覆盖部分。',
                )}
                {textField(
                  'recommendations',
                  '处置与改进建议',
                  '记录全局待办、复测和跟进要求。',
                )}
              </>
            ) : (
              draft.steps
                .filter((step) => step.id === section)
                .map((step) => {
                  const { id, title } = step;
                  const legacy = legacySteps.find((row) => row[0] === id);
                  const siblings = draft.steps.filter(
                    (s) => s.parentId === step.parentId,
                  );
                  const position = siblings.findIndex((s) => s.id === id);
                  const hasChildren = draft.steps.some(
                    (s) => s.parentId === id,
                  );
                  const linked = selected.filter((n) =>
                    step.nodeIds.includes(n.id),
                  );
                  return (
                    <div className="report-step-form" key={id}>
                      <div className="report-chapter-toolbar">
                        <h2>
                          {numbers[id]} {title}
                        </h2>
                        <div className="toolbar-group">
                          <button
                            className="button small"
                            type="button"
                            aria-label="上移章节"
                            disabled={!ready || position === 0}
                            onClick={() =>
                              update({
                                steps: moveSection(draft.steps, id, -1),
                              })
                            }
                          >
                            <ArrowUp size={13} />
                          </button>
                          <button
                            className="button small"
                            type="button"
                            aria-label="下移章节"
                            disabled={
                              !ready || position === siblings.length - 1
                            }
                            onClick={() =>
                              update({ steps: moveSection(draft.steps, id, 1) })
                            }
                          >
                            <ArrowDown size={13} />
                          </button>
                          {!step.parentId && (
                            <button
                              className="button small"
                              type="button"
                              aria-label="新增子章节"
                              disabled={!ready || draft.steps.length >= 64}
                              onClick={() => addSection(id)}
                            >
                              <Plus size={13} />
                              子章节
                            </button>
                          )}
                          <button
                            className="button small"
                            type="button"
                            aria-label="删除章节"
                            disabled={!ready}
                            onClick={() => setDeleting(id)}
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </div>
                      <div className="report-cover-fields">
                        <label>
                          章节标题
                          <input
                            data-section-title
                            aria-label="章节标题"
                            maxLength={120}
                            value={title}
                            disabled={!ready}
                            onChange={(e) =>
                              changeStep(id, { title: e.target.value })
                            }
                          />
                        </label>
                        <label>
                          所属主章节
                          <select
                            aria-label="所属主章节"
                            value={step.parentId || ''}
                            disabled={!ready || hasChildren}
                            onChange={(e) =>
                              reparent(id, e.target.value || null)
                            }
                          >
                            <option value="">独立主章节</option>
                            {draft.steps
                              .filter((s) => !s.parentId && s.id !== id)
                              .map((s) => (
                                <option key={s.id} value={s.id}>
                                  {s.title}
                                </option>
                              ))}
                          </select>
                          {hasChildren && (
                            <small>移动主章节会同时移动其子章节。</small>
                          )}
                        </label>
                      </div>
                      <div className="report-metadata-fields">
                        <label>
                          负责人
                          <input
                            aria-label={`${id}-负责人`}
                            value={step.owner}
                            disabled={!ready}
                            maxLength={100}
                            onChange={(e) =>
                              changeStep(id, { owner: e.target.value })
                            }
                          />
                        </label>
                        <label>
                          状态
                          <select
                            aria-label={`${id}-状态`}
                            value={step.status}
                            disabled={!ready}
                            onChange={(e) =>
                              changeStep(id, { status: e.target.value })
                            }
                          >
                            {Object.entries(statuses).map(([v, t]) => (
                              <option key={v} value={v}>
                                {t}
                              </option>
                            ))}
                          </select>
                        </label>
                        <label>
                          开始时间
                          <input
                            aria-label={`${id}-开始时间`}
                            type="datetime-local"
                            step="0.001"
                            value={timeInput(step.startedAt)}
                            disabled={!ready}
                            onChange={(e) =>
                              changeStep(id, {
                                startedAt: savedTime(e.target.value),
                              })
                            }
                          />
                        </label>
                        <label>
                          完成时间
                          <input
                            aria-label={`${id}-完成时间`}
                            type="datetime-local"
                            step="0.001"
                            value={timeInput(step.completedAt)}
                            disabled={!ready}
                            onChange={(e) =>
                              changeStep(id, {
                                completedAt: savedTime(e.target.value),
                              })
                            }
                          />
                        </label>
                      </div>
                      <TextEditor
                        label={legacy?.[3] || '章节正文'}
                        hint="填写本阶段、资产或子事件的事实、研判、处置和未确认事项。"
                        size="document"
                        aria-label={legacy?.[3] || '章节正文'}
                        rows={8}
                        maxLength={12000}
                        disabled={!ready}
                        value={step.body}
                        onChange={(e) =>
                          changeStep(id, { body: e.target.value })
                        }
                      />
                      <details className="report-step-evidence" open>
                        <summary>
                          关联证据与截图 · {linked.length} 个节点
                        </summary>
                        <p>
                          选择已纳入报告的调查节点。节点可携带原始来源、AI
                          分析、Hash 和截图，同一节点可被多个章节引用。
                        </p>
                        <div className="report-step-node-list">
                          {selected.map((n) => (
                            <label className="check" key={n.id}>
                              <input
                                type="checkbox"
                                aria-label={`${id}-关联节点-${n.id}`}
                                checked={step.nodeIds.includes(n.id)}
                                disabled={!ready}
                                onChange={(e) =>
                                  assignNode(n.id, id, e.target.checked)
                                }
                              />
                              <span>{n.title}</span>
                            </label>
                          ))}
                        </div>
                        {linked.map((n) => (
                          <div
                            className="report-linked-proof"
                            key={n.id}
                            data-node={n.id}
                          >
                            <strong>{n.title}</strong>
                            <div className="toolbar-group">
                              {n.evidenceId && (
                                <button
                                  type="button"
                                  className="button small"
                                  disabled={props.busy || !ready}
                                  onClick={() =>
                                    void deliver(() => props.onSource(n))
                                  }
                                >
                                  查看原证据与分析
                                </button>
                              )}
                              <button
                                className="button small"
                                type="button"
                                disabled={props.busy}
                                onClick={() => props.onEdit(n)}
                              >
                                编辑节点
                              </button>
                              <button
                                className="button small"
                                type="button"
                                disabled={props.busy}
                                onClick={() => props.onPaste(n)}
                              >
                                粘贴截图
                              </button>
                              <button
                                className="button small"
                                type="button"
                                disabled={props.busy}
                                onClick={() => props.onAttach(n)}
                              >
                                附图
                              </button>
                              <small>
                                {n.screenshots.length
                                  ? `${n.screenshots.length} 张举证图`
                                  : '截图待补'}
                              </small>
                            </div>
                            {n.screenshots.map((shot) =>
                              props.renderShot(shot),
                            )}
                          </div>
                        ))}
                        {!linked.length && (
                          <p>
                            本章节尚未关联举证；可先在「节点与截图」新增节点。
                          </p>
                        )}
                      </details>
                    </div>
                  );
                })
            )}
          </form>
        </div>
      )}
      {view === 'nodes' && (
        <div className="report-node-editor print-hide">
          <div className="detail-head">
            <p>
              选择报告内容、编辑调查说明，并将截图直接粘贴到对应节点。节点修改也会同步到事件时间线。
            </p>
            <button
              className="button"
              onClick={() => void newNode()}
              disabled={props.busy}
            >
              <Plus size={14} />
              新增节点
            </button>
          </div>
          {!w.nodes.length && (
            <div className="report-editor-empty">
              <FileText size={28} />
              <h2>还没有调查节点</h2>
              <p>可在分析结果中记录研判结论，或在这里新增调查说明。</p>
              <button className="button primary" onClick={() => void newNode()}>
                新增节点
              </button>
            </div>
          )}
          {w.nodes.map((n) => (
            <article key={n.id} className="report-node-card" data-node={n.id}>
              <div className="detail-head">
                <label className="check">
                  <input
                    aria-label={`纳入报告-${n.id}`}
                    type="checkbox"
                    checked={n.included}
                    disabled={props.busy}
                    onChange={(e) => props.onToggle(n, e.target.checked)}
                  />
                  <strong>{n.title}</strong>
                </label>
                <span>{stamp(n.occurredAt)}</span>
              </div>
              <details className="report-node-assignment">
                <summary>
                  所属章节 ·{' '}
                  {draft.steps
                    .filter((s) => s.nodeIds.includes(n.id))
                    .map((s) => s.title)
                    .join('、') || '未分章节 / 时间线附录'}
                </summary>
                <div className="report-step-node-list">
                  {draft.steps.map((step) => (
                    <label className="check" key={step.id}>
                      <input
                        type="checkbox"
                        aria-label={`所属章节-${n.id}-${step.id}`}
                        disabled={!ready}
                        checked={step.nodeIds.includes(n.id)}
                        onChange={(e) =>
                          assignNode(n.id, step.id, e.target.checked)
                        }
                      />
                      <span>
                        {numbers[step.id]} {step.title}
                      </span>
                    </label>
                  ))}
                </div>
              </details>
              <p className="body-text">{n.body}</p>
              <div className="toolbar-group">
                {n.evidenceId && (
                  <button
                    type="button"
                    className="button small"
                    disabled={props.busy || !ready}
                    onClick={() => void deliver(() => props.onSource(n))}
                  >
                    查看原证据与分析
                  </button>
                )}
                <button
                  className="button small"
                  disabled={props.busy}
                  onClick={() => props.onEdit(n)}
                >
                  编辑节点
                </button>
                <button
                  className="button small"
                  disabled={props.busy}
                  onClick={() => props.onPaste(n)}
                >
                  粘贴截图
                </button>
                <button
                  className="button small"
                  disabled={props.busy}
                  onClick={() => props.onAttach(n)}
                >
                  <ImagePlus size={13} />
                  附图
                </button>
                <small>
                  {n.screenshots.length
                    ? `${n.screenshots.length} 张举证图`
                    : '尚未附图 · 导出时保留待补位置'}
                </small>
              </div>
              {n.screenshots.map((shot) => props.renderShot(shot))}
            </article>
          ))}
        </div>
      )}
      {view === 'preview' && (
        <article className="report-paper printable">
          <div className="report-brand">
            <img src="/gaga-icon.svg" alt="" />
            <span>嘎嘎安全助手 / J4team</span>
          </div>
          <h1>{draft.title}</h1>
          <p className="report-subtitle">事件调查报告 · 待人工复核</p>
          {draft.author && <p>编写：{draft.author}</p>}
          <div className="report-intro">
            {selected.length
              ? '本报告依据所选节点和原始材料编写。规则命中与 AI 研判需人工核对，不自动证明入侵或利用成功。'
              : '本报告为人工编写正文，尚未关联调查节点。相关判断和举证仍需复核补充。'}
          </div>
          <dl className="report-basic-info">
            <div>
              <dt>事件类型</dt>
              <dd>{draft.eventType || '待分类'}</dd>
            </div>
            <div>
              <dt>危害等级</dt>
              <dd>{draft.severity || '待评估'}</dd>
            </div>
            <div>
              <dt>发现时间</dt>
              <dd>
                {draft.discoveredAt ? stamp(draft.discoveredAt) : '待补充'}
              </dd>
            </div>
            <div>
              <dt>发现人</dt>
              <dd>{draft.discoveredBy || '待补充'}</dd>
            </div>
          </dl>
          <section className="report-prose">
            <h2>危害概述</h2>
            <p className="body-text">{draft.harm || '待评估'}</p>
          </section>
          {draft.summary && (
            <section className="report-prose">
              <h2>事件摘要</h2>
              <p className="body-text">{draft.summary}</p>
            </section>
          )}
          {insights ? (
            <ReportInsightsView data={insights} />
          ) : (
            <p className="insight-empty" role="status">
              {insightsError || '正在统计本事件报告…'}
            </p>
          )}
          {draft.scope && (
            <section className="report-prose">
              <h2>影响范围与调查限制</h2>
              <p className="body-text">{draft.scope}</p>
            </section>
          )}
          {draft.steps.map((step) => {
            const linked = selected.filter((n) => step.nodeIds.includes(n.id));
            const Heading = step.parentId ? 'h3' : 'h2';
            return (
              <section
                className={`report-prose report-phase ${step.parentId ? 'report-child-phase' : ''}`}
                key={step.id}
              >
                <Heading>
                  {numbers[step.id]} {step.title}
                </Heading>
                <p className="report-step-meta">
                  负责人：{step.owner || '待指定'} · {statuses[step.status]}
                  <br />
                  开始：{step.startedAt ? stamp(step.startedAt) : '待补充'} ·
                  完成：{step.completedAt ? stamp(step.completedAt) : '待补充'}
                </p>
                <p className="body-text">{step.body || '本章节内容待补充。'}</p>
                {linked.map(renderNode)}
                {!linked.length && (
                  <p className="report-step-meta">本章节尚未关联举证节点。</p>
                )}
              </section>
            );
          })}
          {draft.recommendations && (
            <section className="report-prose">
              <h2>后续处置与改进建议</h2>
              <p className="body-text">{draft.recommendations}</p>
            </section>
          )}
          {selected.some(
            (n) => !draft.steps.some((s) => s.nodeIds.includes(n.id)),
          ) && (
            <section className="report-prose">
              <h2>附录：事件时间线与未分章节证据</h2>
              {selected
                .filter(
                  (n) => !draft.steps.some((s) => s.nodeIds.includes(n.id)),
                )
                .map(renderNode)}
            </section>
          )}
          <div className="report-end">
            嘎嘎安全助手 · J4team · 原始证据与派生分析分别保存
          </div>
        </article>
      )}
    </section>
  );
}
