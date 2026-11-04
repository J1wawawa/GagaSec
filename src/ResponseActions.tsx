import { useState } from 'react';
import {
  Check,
  ClipboardCheck,
  Play,
  RotateCcw,
  ShieldAlert,
  Plus,
  X,
} from 'lucide-react';
import { invoke, isTauri } from './bridge';
import type { ResponseAction, Workspace } from './types';
import { Modal } from './Modal';
import { TextEditor } from './TextEditor';

const labels: Record<string, string> = {
  draft: '草稿',
  pending_approval: '待审批',
  approved: '已审批',
  executing: '执行中',
  succeeded: '执行成功',
  failed: '执行失败',
  rolled_back: '已回滚',
  verified: '恢复已验证',
  cancelled: '已取消',
};
const next: Record<string, { status: string; label: string }[]> = {
  draft: [{ status: 'pending_approval', label: '提交审批' }],
  pending_approval: [
    { status: 'approved', label: '批准' },
    { status: 'cancelled', label: '取消' },
  ],
  approved: [{ status: 'executing', label: '开始执行' }],
  executing: [
    { status: 'succeeded', label: '记录成功' },
    { status: 'failed', label: '记录失败' },
  ],
  succeeded: [
    { status: 'verified', label: '恢复验证' },
    { status: 'rolled_back', label: '回滚' },
  ],
  failed: [{ status: 'rolled_back', label: '回滚' }],
  rolled_back: [{ status: 'verified', label: '验证恢复' }],
};

export function ResponseActionsPanel({
  workspace,
  onChange,
}: {
  workspace: Workspace;
  onChange: (w: Workspace) => void;
}) {
  const [title, setTitle] = useState('');
  const [target, setTarget] = useState('');
  const [description, setDescription] = useState('');
  const [actor, setActor] = useState('');
  const [kind, setKind] = useState('containment');
  const [evidenceId, setEvidenceId] = useState('');
  const [nodeId, setNodeId] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [creating, setCreating] = useState(false);
  const [transitionDraft, setTransitionDraft] = useState<{
    action: ResponseAction;
    status: string;
    detail: string;
    receipt: string;
    plan: string;
    committed: boolean;
  } | null>(null);
  async function reload() {
    const rows = await invoke<ResponseAction[]>('get_response_actions', {
      caseId: workspace.activeCase,
    });
    onChange({ ...workspace, responseActions: rows });
  }
  async function create() {
    if (!isTauri()) return;
    setBusy('create');
    setError('');
    try {
      await invoke<ResponseAction>('create_response_action', {
        action: {
          id: '',
          caseId: workspace.activeCase,
          title,
          actionType: kind,
          target,
          description,
          requestedBy: actor,
          approvedBy: null,
          executedBy: null,
          status: 'draft',
          requestedAt: '',
          approvedAt: null,
          startedAt: null,
          completedAt: null,
          receipt: null,
          failureReason: null,
          rollbackPlan: null,
          rollbackAt: null,
          verification: null,
          evidenceIds: evidenceId ? [evidenceId] : [],
          nodeIds: nodeId ? [nodeId] : [],
          createdAt: '',
          updatedAt: '',
        },
      });
      setTitle('');
      setTarget('');
      setDescription('');
      setEvidenceId('');
      setNodeId('');
      await reload();
      setCreating(false);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy('');
    }
  }
  async function transition(a: ResponseAction, status: string) {
    if (['verified', 'failed', 'succeeded', 'rolled_back'].includes(status)) {
      setError('');
      setTransitionDraft({
        action: a,
        status,
        detail: '',
        receipt: '',
        plan: a.rollbackPlan || '',
        committed: false,
      });
      return;
    }
    setBusy(a.id);
    setError('');
    try {
      const updated = await invoke<ResponseAction>(
        'update_response_action_status',
        { actionId: a.id, status, actor: actor || '当前分析员' },
      );
      if (updated) await reload();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy('');
    }
  }
  async function saveTransition() {
    if (!transitionDraft) return;
    const draft = transitionDraft;
    setBusy(draft.action.id);
    setError('');
    let committed = draft.committed;
    try {
      // Receipt and status use separate existing APIs. If the latter succeeds
      // first, retries only save the missing material rather than repeat it.
      if (!committed) {
        await invoke('update_response_action_status', {
          actionId: draft.action.id,
          status: draft.status,
          actor: actor || '当前分析员',
          detail: draft.detail || undefined,
        });
        committed = true;
        setTransitionDraft({ ...draft, committed: true });
      }
      if (draft.status === 'rolled_back' && draft.plan.trim())
        await invoke('save_response_rollback_plan', {
          actionId: draft.action.id,
          plan: draft.plan,
        });
      if (
        ['succeeded', 'failed'].includes(draft.status) &&
        draft.receipt.trim()
      )
        await invoke('record_response_receipt', {
          actionId: draft.action.id,
          receipt: draft.receipt,
        });
      await reload();
      setTransitionDraft(null);
    } catch (e) {
      setError(
        `${committed ? '状态已记录，补充材料尚未全部保存；可重试保存。' : ''}${String(e)}`,
      );
      if (committed) await reload().catch(() => {});
    } finally {
      setBusy('');
    }
  }
  return (
    <section className="response-actions" aria-label="处置动作">
      <div className="detail-head">
        <div>
          <h2>处置动作与回执</h2>
          <p className="small-note">
            动作只记录审批、执行和验证事实，不会直接在客户主机执行封禁。
          </p>
        </div>
        <button className="button" onClick={() => setCreating(true)}>
          <Plus size={14} />
          新增处置动作
        </button>
      </div>
      {transitionDraft && (
        <Modal
          title={`记录${labels[transitionDraft.status]}`}
          busy={!!busy}
          onClose={() => setTransitionDraft(null)}
        >
          <form
            className="modal response-action-editor"
            onSubmit={(event) => {
              event.preventDefault();
              void saveTransition();
            }}
          >
            <div className="modal-title">
              <h2>记录{labels[transitionDraft.status]}</h2>
              <button
                type="button"
                className="icon-button"
                disabled={!!busy}
                aria-label="关闭处置记录"
                onClick={() => setTransitionDraft(null)}
              >
                <X size={17} />
              </button>
            </div>
            <p className="small-note">
              {transitionDraft.action.title} · {transitionDraft.action.target}
            </p>
            {error && (
              <p role="alert" className="modal-error">
                {error}
              </p>
            )}
            <label>
              记录人员
              <input
                aria-label="处置记录人员"
                value={actor}
                maxLength={80}
                disabled={!!busy || transitionDraft.committed}
                onChange={(event) => setActor(event.target.value)}
                placeholder="填写记录 / 验证人员"
              />
            </label>
            {['verified', 'failed'].includes(transitionDraft.status) && (
              <TextEditor
                label={
                  transitionDraft.status === 'verified'
                    ? '恢复验证结果'
                    : '失败原因'
                }
                size="large"
                maxLength={4000}
                required
                disabled={!!busy || transitionDraft.committed}
                value={transitionDraft.detail}
                onChange={(event) =>
                  setTransitionDraft({
                    ...transitionDraft,
                    detail: event.target.value,
                  })
                }
                hint="记录事实、观察时间与相关证据，确认后再提交。"
              />
            )}
            {['succeeded', 'failed'].includes(transitionDraft.status) && (
              <TextEditor
                label="执行回执"
                size="large"
                maxLength={12000}
                code
                disabled={!!busy}
                value={transitionDraft.receipt}
                onChange={(event) =>
                  setTransitionDraft({
                    ...transitionDraft,
                    receipt: event.target.value,
                  })
                }
                placeholder="粘贴命令输出、工单号或设备回执；可留空后补充。"
              />
            )}
            {transitionDraft.status === 'rolled_back' && (
              <TextEditor
                label="回滚方案与实际记录"
                size="large"
                maxLength={4000}
                required
                disabled={!!busy}
                value={transitionDraft.plan}
                onChange={(event) =>
                  setTransitionDraft({
                    ...transitionDraft,
                    plan: event.target.value,
                  })
                }
                hint="包含工单号、时间、操作范围与验证点。"
              />
            )}
            <div className="response-action-footer">
              <button
                type="button"
                className="button"
                disabled={!!busy}
                onClick={() => setTransitionDraft(null)}
              >
                返回
              </button>
              <button className="button primary" disabled={!!busy}>
                {busy ? '保存中…' : '保存记录'}
              </button>
            </div>
          </form>
        </Modal>
      )}
      {creating && (
        <Modal
          title="新增处置动作"
          busy={!!busy}
          onClose={() => setCreating(false)}
        >
          <form
            className="modal response-action-editor"
            onSubmit={(event) => {
              event.preventDefault();
              void create();
            }}
          >
            <div className="modal-title">
              <h2>
                <ShieldAlert size={18} />
                新增处置动作
              </h2>
              <button
                className="icon-button"
                type="button"
                aria-label="关闭处置动作"
                disabled={!!busy}
                onClick={() => setCreating(false)}
              >
                <X size={16} />
              </button>
            </div>
            {error && (
              <p className="modal-error" role="alert">
                {error}
              </p>
            )}
            <div className="response-action-form">
              <label>
                动作标题
                <input
                  aria-label="动作标题"
                  placeholder="动作标题，如：封禁可疑源 IP"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                />
              </label>
              <label>
                动作类型
                <select
                  aria-label="动作类型"
                  value={kind}
                  onChange={(e) => setKind(e.target.value)}
                >
                  <option value="containment">遏制</option>
                  <option value="block">封禁</option>
                  <option value="eradication">清除</option>
                  <option value="recovery">恢复</option>
                  <option value="verification">验证</option>
                </select>
              </label>
              <label>
                目标资产 / IP / 文件
                <input
                  aria-label="动作目标"
                  placeholder="目标资产 / IP / 文件"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                />
              </label>
              <label>
                申请人
                <input
                  aria-label="申请人"
                  placeholder="申请人"
                  value={actor}
                  onChange={(e) => setActor(e.target.value)}
                />
              </label>
              <label>
                关联证据
                <select
                  aria-label="关联证据"
                  value={evidenceId}
                  onChange={(e) => setEvidenceId(e.target.value)}
                >
                  <option value="">不关联证据</option>
                  {workspace.evidence.map((e) => (
                    <option key={e.id} value={e.id}>
                      {e.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                关联时间线节点
                <select
                  aria-label="关联时间线节点"
                  value={nodeId}
                  onChange={(e) => setNodeId(e.target.value)}
                >
                  <option value="">不关联节点</option>
                  {workspace.nodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.occurredAt} · {n.title}
                    </option>
                  ))}
                </select>
              </label>
              <TextEditor
                label="说明、依据与回滚方案"
                fieldClassName="response-action-description"
                size="large"
                aria-label="动作说明"
                placeholder="说明范围、依据和回滚方案"
                value={description}
                maxLength={4000}
                onChange={(e) => setDescription(e.target.value)}
                rows={4}
              />
            </div>
            <div className="response-action-footer">
              <button
                className="button"
                type="button"
                disabled={!!busy}
                onClick={() => setCreating(false)}
              >
                取消
              </button>
              <button
                className="button primary"
                disabled={
                  !!busy || !title.trim() || !target.trim() || !actor.trim()
                }
                type="submit"
              >
                <ClipboardCheck size={14} />
                记录处置动作
              </button>
            </div>
          </form>
        </Modal>
      )}
      {error && (
        <p className="small-note danger-text" role="alert">
          {error}
        </p>
      )}
      {!workspace.responseActions.length ? (
        <p className="placeholder-note">当前事件还没有处置动作。</p>
      ) : (
        <div className="response-action-list">
          {workspace.responseActions.map((a) => (
            <article className="response-action-card" key={a.id}>
              <div className="detail-head">
                <strong>{a.title}</strong>
                <span className={'status-chip status-' + a.status}>
                  {labels[a.status] || a.status}
                </span>
              </div>
              <p>{a.description}</p>
              <small>
                {a.actionType} · {a.target} · 申请人 {a.requestedBy}
              </small>
              {a.receipt && (
                <details>
                  <summary>执行回执</summary>
                  <pre>{a.receipt}</pre>
                </details>
              )}
              {a.verification && (
                <p className="small-note">恢复验证：{a.verification}</p>
              )}
              <div className="response-action-buttons">
                {(next[a.status] || []).map((n) => (
                  <button
                    className="button small"
                    key={n.status}
                    disabled={!!busy}
                    onClick={() => void transition(a, n.status)}
                  >
                    {n.status === 'executing' ? (
                      <Play size={12} />
                    ) : n.status === 'rolled_back' ? (
                      <RotateCcw size={12} />
                    ) : (
                      <Check size={12} />
                    )}
                    {n.label}
                  </button>
                ))}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
