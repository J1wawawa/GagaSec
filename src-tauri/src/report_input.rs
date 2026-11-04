//! 在同一数据库锁内捕获指定事件的报告输入；只加载纳入节点及其引用，
//! 不携带其他事件、AI 对话或未引用证据，后台执行不能再次读取活动事件。
use crate::{
    report_draft::ReportDraft,
    store::{Case, Evidence, Screenshot, Store, TimelineNode, Workspace},
};

pub struct Input {
    pub workspace: Workspace,
    pub draft: ReportDraft,
    pub watermark: Option<String>,
}

pub fn capture(store: &Store, case_id: &str) -> Result<Input, String> {
    capture_inner(store, case_id, false)
}

/// 空事件也能查看统计；导出仍使用 capture 的正文/节点非空校验。
pub fn capture_insights(store: &Store, case_id: &str) -> Result<Input, String> {
    capture_inner(store, case_id, true)
}

fn capture_inner(store: &Store, case_id: &str, allow_empty: bool) -> Result<Input, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let case = db
        .query_row(
            "SELECT id,title,created_at FROM cases WHERE id=?1",
            [case_id],
            |r| {
                Ok(Case {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    created_at: r.get(2)?,
                })
            },
        )
        .map_err(|_| "报告事件不存在。".to_string())?;
    let draft = crate::report_draft::load_db(&db, case_id)?;
    let mut q = db.prepare("SELECT id,case_id,evidence_id,finding_id,occurred_at,recorded_at,title,body,actor,included FROM nodes WHERE case_id=?1 AND included=1 ORDER BY julianday(occurred_at) IS NULL,julianday(occurred_at),recorded_at,id").map_err(|e|e.to_string())?;
    let mut nodes = q
        .query_map([case_id], |r| {
            Ok(TimelineNode {
                id: r.get(0)?,
                case_id: r.get(1)?,
                evidence_id: r.get(2)?,
                finding_id: r.get(3)?,
                occurred_at: r.get(4)?,
                recorded_at: r.get(5)?,
                title: r.get(6)?,
                body: r.get(7)?,
                actor: r.get(8)?,
                included: r.get(9)?,
                screenshots: vec![],
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if !allow_empty && nodes.is_empty() && !draft.has_content() {
        return Err("请填写报告正文或纳入调查节点。".into());
    }
    let mut q = db.prepare("SELECT id,node_id,name,sha256,size,mime,caption FROM screenshots WHERE node_id=?1 ORDER BY rowid").map_err(|e|e.to_string())?;
    for node in &mut nodes {
        node.screenshots = q
            .query_map([&node.id], |r| {
                Ok(Screenshot {
                    id: r.get(0)?,
                    node_id: r.get(1)?,
                    name: r.get(2)?,
                    sha256: r.get(3)?,
                    size: r.get(4)?,
                    mime: r.get(5)?,
                    caption: r.get(6)?,
                })
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
    }
    let mut q = db.prepare("SELECT e.id,e.case_id,e.name,e.kind,e.sha256,e.size,e.created_at,e.report FROM evidence e WHERE e.case_id=?1 AND (EXISTS(SELECT 1 FROM nodes n WHERE n.case_id=?1 AND n.included=1 AND n.evidence_id=e.id) OR EXISTS(SELECT 1 FROM response_actions a, json_each(a.record,'$.evidenceIds') j WHERE a.case_id=?1 AND j.value=e.id)) ORDER BY e.id").map_err(|e|e.to_string())?;
    let rows = q
        .query_map([case_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, u64>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut evidence = vec![];
    for row in rows {
        let (id, case_id, name, kind, sha256, size, created_at, json) =
            row.map_err(|e| e.to_string())?;
        evidence.push(Evidence {
            id,
            case_id,
            name,
            kind,
            sha256,
            size,
            created_at,
            report: serde_json::from_str(&json).map_err(|e| e.to_string())?,
        });
    }
    if nodes
        .iter()
        .filter_map(|n| n.evidence_id.as_ref())
        .any(|id| !evidence.iter().any(|e| &e.id == id))
    {
        return Err("报告节点引用了缺失或其他事件的证据，请重新关联。".into());
    }
    Ok(Input {
        watermark: if allow_empty {
            None
        } else {
            crate::report_watermark::create(&draft)?
                .as_ref()
                .map(|m| crate::report_watermark::seal(store, m))
                .transpose()?
        },
        draft,
        workspace: Workspace {
            cases: vec![case],
            active_case: case_id.into(),
            evidence,
            nodes,
            ai_reviews: vec![],
            analysis_runs: vec![],
            followups: vec![],
            review_feedback: vec![],
            response_actions: {
                let mut q = db.prepare("SELECT record FROM response_actions WHERE case_id=?1 ORDER BY json_extract(record,'$.requestedAt'),id").map_err(|e| e.to_string())?;
                let rows = q
                    .query_map([case_id], |r| r.get::<_, String>(0))
                    .map_err(|e| e.to_string())?;
                rows.map(|r| {
                    serde_json::from_str(&r.map_err(|e| e.to_string())?).map_err(|e| e.to_string())
                })
                .collect::<Result<Vec<crate::response_actions::ResponseAction>, String>>()?
            },
            data_dir: store.root.display().to_string(),
        },
    })
}
