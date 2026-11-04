import type { TimelineNode } from './types';
import './report-insights.css';

// 数值和时间由 Rust 的同一计算入口提供，避免预览与导出口径不同。
export type ReportInsights = {
  caseId: string;
  scope: string;
  metrics: { key: string; label: string; value: string; detail: string }[];
  evidenceKinds: { label: string; count: number }[];
  indicatorKinds: { label: string; count: number }[];
  completedSections: number;
  totalSections: number;
  blockedSections: number;
  invalidNodeTimes: number;
  stages: {
    title: string;
    child: boolean;
    owner: string;
    status: string;
    startedAt: string;
    completedAt: string;
    duration: string;
    durationMs: number | null;
    widthPercent: number;
    nodes: number;
  }[];
  capsules: {
    id: string;
    anchor: string;
    date: string;
    time: string;
    gap: string;
    title: string;
    summary: string;
    actor: string;
    evidenceId: string | null;
    evidenceName: string;
    sha256: string;
    location: string;
    screenshots: number;
    sections: string[];
  }[];
};
export function ReportInsightsView({
  data,
  onOpen,
  onEdit,
}: {
  data: ReportInsights;
  onOpen?: (id: TimelineNode['id']) => void;
  onEdit?: (id: TimelineNode['id']) => void;
}) {
  const largest = Math.max(1, ...data.evidenceKinds.map((v) => v.count));
  return (
    <div className="report-insights" data-insights-case={data.caseId}>
      <div className="insight-overview">
        <div className="insight-heading">
          <div>
            <span className="insight-eyebrow">CASE OVERVIEW</span>
            <h2>事件数据概览</h2>
          </div>
          <span className="insight-tag">当前报告</span>
        </div>
        <p className="insight-scope">{data.scope}</p>
        <div className="insight-metrics">
          {data.metrics.map((m) => (
            <div className="insight-metric" key={m.key} data-metric={m.key}>
              <span>{m.label}</span>
              <strong>{m.value}</strong>
              <small>{m.detail}</small>
            </div>
          ))}
        </div>
        <div className="insight-distributions">
          <div className="insight-distribution">
            <strong>材料构成</strong>
            {data.evidenceKinds.length ? (
              data.evidenceKinds.map((v) => (
                <div className="insight-count" key={v.label}>
                  <span>{v.label}</span>
                  <div className="insight-track">
                    <i style={{ width: `${(v.count / largest) * 100}%` }} />
                  </div>
                  <b>{v.count}</b>
                </div>
              ))
            ) : (
              <p>关联原件后显示材料分布。</p>
            )}
          </div>
          <div className="insight-distribution">
            <strong>章节推进</strong>
            <div className="insight-progress-number">
              {data.completedSections}
              <small> / {data.totalSections} 节已完成</small>
            </div>
            <div
              className="insight-track"
              role="progressbar"
              aria-label="章节完成进度"
              aria-valuemin={0}
              aria-valuemax={Math.max(1, data.totalSections)}
              aria-valuenow={data.completedSections}
            >
              <i
                style={{
                  width: `${data.totalSections ? (data.completedSections / data.totalSections) * 100 : 0}%`,
                }}
              />
            </div>
            <p>{data.blockedSections} 节待补证 / 阻塞 · 状态来自章节填写</p>
            <div className="insight-ioc-kinds">
              {data.indicatorKinds.map((v) => (
                <span key={v.label}>
                  {v.label} <b>{v.count}</b>
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
      <div className="insight-stages">
        <div className="insight-heading">
          <div>
            <span className="insight-eyebrow">PHASE TRACKING</span>
            <h2>阶段与责任</h2>
          </div>
        </div>
        <p className="insight-scope">
          耗时使用填写的起止时间；条形按最长已知阶段展示，阶段可以并行，不相加为总耗时。
        </p>
        {data.stages.length ? (
          data.stages.map((s, index) => (
            <div
              className={`insight-stage ${s.child ? 'is-child' : ''}`}
              key={index}
            >
              <div>
                <strong>{s.title}</strong>
                <small>
                  {s.owner} · {s.status} · {s.nodes} 个举证节点
                </small>
                <small>
                  {s.startedAt} → {s.completedAt}
                </small>
              </div>
              <div className="insight-stage-duration">
                <span>{s.duration}</span>
                <div
                  className={`insight-track ${s.durationMs === null ? 'is-unknown' : ''}`}
                >
                  <i style={{ width: `${s.widthPercent}%` }} />
                </div>
              </div>
            </div>
          ))
        ) : (
          <p className="insight-empty">可在正文编辑中新增阶段或子事件。</p>
        )}
      </div>
      <div className="insight-capsules">
        <div className="insight-heading">
          <div>
            <span className="insight-eyebrow">INCIDENT TIME CAPSULE</span>
            <h2>事件时间胶囊</h2>
          </div>
          <span className="insight-tag">{data.capsules.length} 个节点</span>
        </div>
        <p className="insight-scope">
          按节点发生时间排列，保留人员、原件及章节关联；缺少证据的人工记录明确标注。
        </p>
        {!!data.invalidNodeTimes && (
          <p className="insight-notice">
            {data.invalidNodeTimes}{' '}
            个节点缺少有效时间，置于末尾且不参与跨度计算。
          </p>
        )}
        <ol className="insight-timeline">
          {data.capsules.map((c) => (
            <li className="insight-capsule" key={c.id} data-capsule-id={c.id}>
              <div className="insight-time">
                <span>{c.date}</span>
                <strong>{c.time}</strong>
                <small>{c.gap}</small>
              </div>
              <div className="insight-capsule-card">
                <div className="insight-capsule-title">
                  <strong>{c.title}</strong>
                  <span>{c.actor}</span>
                </div>
                <p>{c.summary || '节点说明待补充。'}</p>
                {!!c.sections.length && (
                  <div className="insight-section-tags">
                    {c.sections.map((s, i) => (
                      <span key={i}>章节：{s}</span>
                    ))}
                  </div>
                )}
                <div className="insight-proof">
                  <span>
                    {c.evidenceName}
                    {c.location && ` · ${c.location}`}
                  </span>
                  <span>{c.screenshots} 张举证图</span>
                </div>
                {(onOpen || onEdit) && (
                  <div className="insight-actions print-hide">
                    {c.evidenceId && onOpen && (
                      <button
                        className="button small"
                        onClick={() => onOpen(c.id)}
                      >
                        查看原证据
                      </button>
                    )}
                    {onEdit && (
                      <button
                        className="button small"
                        onClick={() => onEdit(c.id)}
                      >
                        编辑记录
                      </button>
                    )}
                  </div>
                )}
              </div>
            </li>
          ))}
        </ol>
        {!data.capsules.length && (
          <p className="insight-empty">
            纳入调查节点后，在这里还原有据可查的事件过程。
          </p>
        )}
      </div>
    </div>
  );
}
