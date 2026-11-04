use crate::store::Store;
use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;

pub const STEP_IDS: [&str; 5] = [
    "assessment",
    "containment",
    "investigation",
    "attribution",
    "outcome",
];
pub const STEP_TITLES: [&str; 5] = [
    "1. 危害评估与影响范围",
    "2. 事件紧急处置",
    "3. 事件过程排查（包含木马分析）",
    "4. 攻击或威胁溯源",
    "5. 处置结果",
];
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReportStep {
    pub id: String,
    pub title: String,
    pub body: String,
    pub parent_id: Option<String>,
    pub owner: String,
    pub started_at: String,
    pub completed_at: String,
    pub status: String,
    pub node_ids: Vec<String>,
}
pub(crate) fn default_steps() -> Vec<ReportStep> {
    STEP_IDS
        .iter()
        .enumerate()
        .map(|(i, id)| ReportStep {
            id: (*id).into(),
            title: STEP_TITLES[i].split_once(". ").unwrap().1.into(),
            body: String::new(),
            parent_id: None,
            owner: String::new(),
            started_at: String::new(),
            completed_at: String::new(),
            status: "todo".into(),
            node_ids: vec![],
        })
        .collect()
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReportDraft {
    pub structure_version: u32,
    pub title: String,
    pub author: String,
    pub summary: String,
    pub scope: String,
    pub conclusion: String,
    pub recommendations: String,
    pub event_type: String,
    pub discovered_at: String,
    pub discovered_by: String,
    pub severity: String,
    pub harm: String,
    pub assessment: String,
    pub containment: String,
    pub investigation: String,
    pub attribution: String,
    #[serde(default = "default_steps")]
    pub steps: Vec<ReportStep>,
    pub updated_at: String,
    pub watermark: crate::report_watermark::Settings,
}
impl ReportDraft {
    /// 老版五步正文迁入章节；新版空数组代表用户确实删除了全部章节，不能复活。
    pub fn normalize(&mut self) -> Result<(), String> {
        if self.structure_version > 2 {
            return Err("报告结构来自较新版本，请升级客户端。".into());
        }
        if self.structure_version < 2 {
            if self.steps.is_empty() {
                self.steps = default_steps();
            }
            for step in &mut self.steps {
                if step.title.is_empty() {
                    step.title = STEP_IDS
                        .iter()
                        .position(|id| *id == step.id)
                        .map(|i| STEP_TITLES[i].split_once(". ").unwrap().1.to_string())
                        .unwrap_or_else(|| "未命名章节".into());
                }
                if step.body.is_empty() {
                    step.body = match step.id.as_str() {
                        "assessment" => self.assessment.clone(),
                        "containment" => self.containment.clone(),
                        "investigation" => self.investigation.clone(),
                        "attribution" => self.attribution.clone(),
                        "outcome" => self.conclusion.clone(),
                        _ => String::new(),
                    };
                }
            }
            self.structure_version = 2;
        }
        Ok(())
    }
    pub fn step_body(&self, id: &str) -> &str {
        self.steps
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.body.as_str())
            .unwrap_or("")
    }
    pub fn numbered_titles(&self) -> Vec<String> {
        let (mut root, mut child) = (0, 0);
        self.steps
            .iter()
            .map(|s| {
                if s.parent_id.is_none() {
                    root += 1;
                    child = 0;
                    format!("{root}. {}", s.title)
                } else {
                    child += 1;
                    format!("{root}.{child} {}", s.title)
                }
            })
            .collect()
    }
    pub fn has_content(&self) -> bool {
        [
            &self.summary,
            &self.harm,
            &self.scope,
            &self.recommendations,
        ]
        .iter()
        .any(|v| !v.trim().is_empty())
            || self.steps.iter().any(|s| !s.body.trim().is_empty())
    }
    pub fn step_metadata(step: &ReportStep) -> String {
        let status = match step.status.as_str() {
            "in_progress" => "进行中",
            "completed" => "已完成",
            "blocked" => "待补证 / 阻塞",
            _ => "待开展",
        };
        format!(
            "负责人：{} · 状态：{}\n开始时间：{}\n完成时间：{}",
            if step.owner.is_empty() {
                "待指定"
            } else {
                &step.owner
            },
            status,
            if step.started_at.is_empty() {
                "待补充"
            } else {
                &step.started_at
            },
            if step.completed_at.is_empty() {
                "待补充"
            } else {
                &step.completed_at
            }
        )
    }
}
pub fn load(store: &Store, case_id: &str) -> Result<ReportDraft, String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    load_db(&db, case_id)
}

pub(crate) fn load_db(db: &rusqlite::Connection, case_id: &str) -> Result<ReportDraft, String> {
    let title: String = db
        .query_row("SELECT title FROM cases WHERE id=?1", [case_id], |r| {
            r.get(0)
        })
        .map_err(|_| "事件不存在。")?;
    let raw: Option<String> = db
        .query_row(
            "SELECT value FROM settings WHERE key=?1",
            [format!("report_draft:{case_id}")],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    match raw {
        Some(raw) => {
            let mut draft: ReportDraft = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
            draft.normalize()?;
            Ok(draft)
        }
        None => Ok(ReportDraft {
            title,
            structure_version: 2,
            steps: vec![],
            ..Default::default()
        }),
    }
}
#[tauri::command]
pub fn get_report_draft(
    case_id: String,
    store: State<'_, Arc<Store>>,
) -> Result<ReportDraft, String> {
    load(&store, &case_id)
}
// The explicit case ID also makes delayed autosaves safe after switching cases.
#[tauri::command]
pub fn save_report_draft(
    case_id: String,
    mut draft: ReportDraft,
    store: State<'_, Arc<Store>>,
) -> Result<ReportDraft, String> {
    save(&store, &case_id, &mut draft)?;
    Ok(draft)
}
pub fn save(store: &Store, case_id: &str, draft: &mut ReportDraft) -> Result<(), String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    save_db(&db, case_id, draft)
}

/// 同一数据库事务内复用校验，供节点、截图与章节引用一并提交，避免保存一半。
pub(crate) fn save_db(
    db: &rusqlite::Connection,
    case_id: &str,
    draft: &mut ReportDraft,
) -> Result<(), String> {
    draft.normalize()?;
    crate::report_watermark::validate(&draft.watermark)?;
    if draft.title.trim().is_empty()
        || draft.title.chars().count() > 200
        || draft.author.chars().count() > 100
        || [
            &draft.summary,
            &draft.scope,
            &draft.conclusion,
            &draft.recommendations,
            &draft.harm,
            &draft.assessment,
            &draft.containment,
            &draft.investigation,
            &draft.attribution,
        ]
        .iter()
        .any(|s| s.chars().count() > 12000)
    {
        return Err("报告标题不能为空；标题限 200 字，署名限 100 字，各正文段限 12000 字。".into());
    }
    if draft.event_type.chars().count() > 100
        || draft.discovered_by.chars().count() > 100
        || draft.severity.chars().count() > 30
        || draft.steps.len() > 64
        || draft.steps.iter().map(|s| s.node_ids.len()).sum::<usize>() > 50000
        || draft
            .steps
            .iter()
            .map(|s| s.body.chars().count())
            .sum::<usize>()
            > 240000
    {
        return Err("报告基本信息过长；最多 64 个章节，章节正文合计最多 24 万字。".into());
    }
    let mut ids = std::collections::HashSet::new();
    let mut current_parent: Option<&str> = None;
    for step in &draft.steps {
        if step.id.is_empty()
            || step.id.len() > 100
            || !step
                .id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
            || !ids.insert(step.id.as_str())
            || step.title.trim().is_empty()
            || step.title.chars().count() > 120
            || step.body.chars().count() > 12000
        {
            return Err("章节标识不可重复，标题需为 1–120 字，单节正文限 12000 字。".into());
        }
        if let Some(parent) = &step.parent_id {
            if current_parent != Some(parent.as_str()) {
                return Err("子章节须紧随所属主章节，最多支持两级结构。".into());
            }
        } else {
            current_parent = Some(&step.id);
        }
    }
    let valid_time =
        |value: &str| value.is_empty() || chrono::DateTime::parse_from_rfc3339(value).is_ok();
    if !valid_time(&draft.discovered_at) {
        return Err("发现时间需包含日期、时间和时区。".into());
    }
    let mut linked = std::collections::HashSet::new();
    for step in &draft.steps {
        if step.owner.chars().count() > 100
            || !["todo", "in_progress", "completed", "blocked"].contains(&step.status.as_str())
            || !valid_time(&step.started_at)
            || !valid_time(&step.completed_at)
            || step.node_ids.len() > 5000
        {
            return Err("章节负责人、状态、时间或证据数量不符合约定。".into());
        }
        if !step.started_at.is_empty()
            && !step.completed_at.is_empty()
            && chrono::DateTime::parse_from_rfc3339(&step.completed_at).unwrap()
                < chrono::DateTime::parse_from_rfc3339(&step.started_at).unwrap()
        {
            return Err("章节完成时间不能早于开始时间。".into());
        }
        let mut local = std::collections::HashSet::new();
        for id in &step.node_ids {
            if !local.insert(id) {
                return Err("同一章节不能重复引用同一节点。".into());
            }
            linked.insert(id);
        }
    }
    draft.updated_at = Utc::now().to_rfc3339();
    if linked.len() > 25000 {
        return Err("单份报告最多引用 25000 个独立节点。".into());
    }
    let exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
            [case_id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !exists {
        return Err("事件不存在。".into());
    }
    for id in linked {
        let valid: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=?1 AND case_id=?2)",
                params![id, case_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !valid {
            return Err("报告步骤只能引用本事件的调查节点。".into());
        }
    }
    db.execute(
        "INSERT OR REPLACE INTO settings VALUES(?1,?2)",
        params![
            format!("report_draft:{case_id}"),
            serde_json::to_string(draft).map_err(|e| e.to_string())?
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn custom_structure_validates_hierarchy_and_keeps_explicit_empty_layout() {
        let root = std::env::temp_dir().join(format!("gaga-report-tree-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let case = store.active().unwrap();
        let mut draft = load(&store, &case).unwrap();
        assert_eq!(draft.structure_version, 2);
        assert!(draft.steps.is_empty());
        let chapter = ReportStep {
            id: "phase1".into(),
            title: "阶段一：初始入侵".into(),
            body: "实际观察与限制".into(),
            status: "todo".into(),
            ..Default::default()
        };
        let child = ReportStep {
            id: "event1".into(),
            title: "事件 1：Web 服务器".into(),
            parent_id: Some("phase1".into()),
            status: "todo".into(),
            ..Default::default()
        };
        draft.steps = vec![chapter.clone(), child.clone()];
        save(&store, &case, &mut draft).unwrap();
        assert_eq!(
            load(&store, &case).unwrap().numbered_titles(),
            vec!["1. 阶段一：初始入侵", "1.1 事件 1：Web 服务器"]
        );
        draft.steps.swap(0, 1);
        assert!(save(&store, &case, &mut draft).is_err());
        draft.steps = vec![chapter.clone(), child.clone(), child];
        assert!(save(&store, &case, &mut draft).is_err());
        draft.steps = (0..65)
            .map(|i| ReportStep {
                id: format!("section{i}"),
                ..chapter.clone()
            })
            .collect();
        assert!(save(&store, &case, &mut draft).is_err());
        draft.steps.clear();
        save(&store, &case, &mut draft).unwrap();
        drop(store);
        let reopened = Store::open(root.clone()).unwrap();
        assert!(load(&reopened, &case).unwrap().steps.is_empty());
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn five_step_reports_migrate_old_drafts_and_validate_times_and_case_links() {
        let root = std::env::temp_dir().join(format!("gaga-five-steps-{}", uuid::Uuid::new_v4()));
        let s = Store::open(root.clone()).unwrap();
        let a = s.create_case("A".into()).unwrap();
        let old = serde_json::json!({"title":"旧报告","author":"张三","summary":"旧摘要","scope":"旧范围","conclusion":"旧结论","recommendations":"旧建议"});
        s.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO settings VALUES(?1,?2)",
                params![format!("report_draft:{}", a.id), old.to_string()],
            )
            .unwrap();
        let mut draft = load(&s, &a.id).unwrap();
        assert_eq!(draft.steps.len(), 5);
        assert_eq!(draft.step_body("outcome"), "旧结论");
        assert_eq!(draft.scope, "旧范围");
        s.add_node(
            "A 举证".into(),
            "真实存储的测试节点".into(),
            "2026-10-27T10:21:00+08:00".into(),
            "张三".into(),
            None,
            None,
        )
        .unwrap();
        let node = s.workspace().unwrap().nodes[0].id.clone();
        draft.steps[0].node_ids.push(node.clone());
        draft.steps[0].owner = "李四".into();
        draft.steps[0].started_at = "2026-10-27T10:21:00+08:00".into();
        draft.steps[0].completed_at = "2026-10-27T10:20:00+08:00".into();
        assert!(save(&s, &a.id, &mut draft).is_err());
        draft.steps[0].completed_at = "2026-10-27T10:24:00+08:00".into();
        draft.discovered_at = "2026-10-27T10:21:00".into();
        assert!(save(&s, &a.id, &mut draft).is_err());
        draft.discovered_at = "2026-10-27T10:21:00+08:00".into();
        draft.steps[1].node_ids.push(node.clone());
        save(&s, &a.id, &mut draft).unwrap();
        draft.steps[1].node_ids.clear();
        let b = s.create_case("B".into()).unwrap();
        assert!(save(&s, &b.id, &mut draft).is_err());
        save(&s, &a.id, &mut draft).unwrap();
        assert_eq!(s.active().unwrap(), b.id);
        drop(s);
        let s = Store::open(root.clone()).unwrap();
        let saved = load(&s, &a.id).unwrap();
        assert_eq!(saved.steps[0].owner, "李四");
        assert_eq!(saved.steps[0].node_ids, vec![node]);
        assert_eq!(saved.conclusion, "旧结论");
        assert!(load(&s, &b.id)
            .unwrap()
            .steps
            .iter()
            .all(|s| s.owner.is_empty() && s.node_ids.is_empty()));
        drop(s);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn interrupted_analysis_is_failed_after_workspace_reopen() {
        let root = std::env::temp_dir().join(format!("gaga-recover-{}", uuid::Uuid::new_v4()));
        let s = Store::open(root.clone()).unwrap();
        let e = s.analyze_alert_text("合成测试，缺少报文".into()).unwrap();
        let mut trace = crate::investigation::Trace::start(
            &s,
            None,
            &e.id,
            "review",
            "fixture",
            &["系统凭据", "模型 API 请求"],
        )
        .unwrap();
        trace.begin(0, "模拟上次退出时尚未完成").unwrap();
        let id = trace.run.id.clone();
        std::mem::forget(trace);
        drop(s);
        let s = Store::open(root.clone()).unwrap();
        let w = s.workspace().unwrap();
        let r = w.analysis_runs.iter().find(|r| r.id == id).unwrap();
        assert_eq!(r.state, "failed");
        assert_eq!(r.stages[0].status, "failed");
        assert_eq!(r.stages[1].status, "skipped");
        assert!(r.error.as_ref().unwrap().contains("未自动重试"));
        assert!(w.ai_reviews.is_empty());
        drop(s);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn report_node_edits_preserve_proof_seconds_and_revisions() {
        let root = std::env::temp_dir().join(format!("gaga-report-node-{}", uuid::Uuid::new_v4()));
        let s = Store::open(root.clone()).unwrap();
        let a = s.create_case("A".into()).unwrap();
        let input = root.join("auth.log");
        std::fs::write(
            &input,
            "2026-10-27T08:50:12+08:00 lab sudo[1]: analyst : USER=root ; COMMAND=/usr/bin/id\n",
        )
        .unwrap();
        let e = s
            .analyze_file(input.display().to_string(), "logs".into())
            .unwrap();
        s.add_node(
            "原始节点".into(),
            "原始说明".into(),
            "2026-10-27T08:50:12+08:00".into(),
            "分析员".into(),
            Some(e.id.clone()),
            Some(e.report.findings[0].id.clone()),
        )
        .unwrap();
        let node = s.workspace().unwrap().nodes[0].clone();
        s.create_case("B".into()).unwrap();
        assert!(s
            .update_node(
                node.id.clone(),
                "越界编辑".into(),
                "不得写入".into(),
                node.occurred_at.clone(),
                "复核员".into()
            )
            .is_err());
        s.switch_case(a.id).unwrap();
        s.update_node(
            node.id.clone(),
            "复核节点".into(),
            "复核说明".into(),
            node.occurred_at.clone(),
            "复核员".into(),
        )
        .unwrap();
        let edited = s.workspace().unwrap().nodes[0].clone();
        assert_eq!(edited.occurred_at, "2026-10-27T08:50:12+08:00");
        assert_eq!(edited.evidence_id, node.evidence_id);
        assert_eq!(edited.finding_id, node.finding_id);
        assert_eq!(edited.recorded_at, node.recorded_at);
        assert_eq!(
            std::fs::read(root.join("evidence").join(e.id)).unwrap(),
            std::fs::read(input).unwrap()
        );
        let previous: String =
            s.db.lock()
                .unwrap()
                .query_row(
                    "SELECT previous FROM node_revisions WHERE node_id=?1",
                    [node.id],
                    |r| r.get(0),
                )
                .unwrap();
        assert!(previous.contains("原始说明"));
        drop(s);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn report_edits_are_isolated_and_late_save_keeps_original_case() {
        let root = std::env::temp_dir().join(format!("gaga-draft-{}", uuid::Uuid::new_v4()));
        let s = Store::open(root.clone()).unwrap();
        let a = s.create_case("A".into()).unwrap();
        let b = s.create_case("B".into()).unwrap();
        let mut draft = ReportDraft {
            title: "A 的报告 <&>".into(),
            summary: "A 专属摘要".into(),
            ..Default::default()
        };
        save(&s, &a.id, &mut draft).unwrap();
        assert_eq!(s.active().unwrap(), b.id);
        assert_eq!(load(&s, &b.id).unwrap().summary, "");
        assert_eq!(load(&s, &a.id).unwrap().summary, "A 专属摘要");
        assert!(save(&s, "missing", &mut draft).is_err());
        draft.title.clear();
        assert!(save(&s, &a.id, &mut draft).is_err());
        drop(s);
        let s = Store::open(root.clone()).unwrap();
        assert_eq!(load(&s, &a.id).unwrap().title, "A 的报告 <&>");
        drop(s);
        std::fs::remove_dir_all(root).unwrap();
    }
}
