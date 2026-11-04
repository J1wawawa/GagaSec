use crate::store::Store;
use chrono::Utc;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tauri::Emitter;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stage {
    pub name: String,
    pub status: String,
    pub elapsed_ms: Option<u64>,
    pub note: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisRun {
    pub id: String,
    pub evidence_id: String,
    pub case_id: String,
    pub kind: String,
    pub state: String,
    pub started_at: String,
    pub elapsed_ms: u64,
    pub model: String,
    pub stages: Vec<Stage>,
    pub review_id: Option<String>,
    pub error: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Feedback {
    pub id: String,
    pub review_id: String,
    pub disposition: String,
    pub feedback: String,
    pub notes: String,
    pub actor: String,
    pub recorded_at: String,
}
pub fn recover_interrupted(store: &Store) -> Result<(), String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let records = {
        let mut q = db
            .prepare(
                "SELECT record FROM analysis_runs WHERE json_extract(record,'$.state')='running'",
            )
            .map_err(|e| e.to_string())?;
        let rows = q
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        rows
    };
    for raw in records {
        let mut run: AnalysisRun = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        let error =
            "上次客户端退出时分析未完成，无法确认远程请求结果；未自动重试。耗时仅保留最后记录值。";
        run.state = "failed".into();
        run.error = Some(error.into());
        for stage in &mut run.stages {
            if stage.status == "running" {
                stage.status = "failed".into();
                stage.note = error.into();
            } else if stage.status == "pending" {
                stage.status = "skipped".into();
                stage.note = "上次分析中断，未执行".into();
            }
        }
        db.execute(
            "UPDATE analysis_runs SET record=?1 WHERE id=?2",
            params![
                serde_json::to_string(&run).map_err(|e| e.to_string())?,
                run.id
            ],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub struct Trace<'a> {
    store: &'a Store,
    app: Option<&'a tauri::AppHandle>,
    pub run: AnalysisRun,
    total: Instant,
    step: Option<Instant>,
}
impl<'a> Trace<'a> {
    pub fn start(
        store: &'a Store,
        app: Option<&'a tauri::AppHandle>,
        evidence_id: &str,
        kind: &str,
        model: &str,
        stages: &[&str],
    ) -> Result<Self, String> {
        let case = store.active()?;
        Self::start_for_case(store, app, &case, evidence_id, kind, model, stages)
    }
    pub(crate) fn start_for_case(
        store: &'a Store,
        app: Option<&'a tauri::AppHandle>,
        case: &str,
        evidence_id: &str,
        kind: &str,
        model: &str,
        stages: &[&str],
    ) -> Result<Self, String> {
        store.evidence_for_case(case, evidence_id)?;
        let trace = Self {
            store,
            app,
            run: AnalysisRun {
                id: format!("incident-{}", uuid::Uuid::new_v4()),
                evidence_id: evidence_id.into(),
                case_id: case.into(),
                kind: kind.into(),
                state: "running".into(),
                started_at: Utc::now().to_rfc3339(),
                elapsed_ms: 0,
                model: model.into(),
                stages: stages
                    .iter()
                    .map(|name| Stage {
                        name: (*name).into(),
                        status: "pending".into(),
                        elapsed_ms: None,
                        note: String::new(),
                    })
                    .collect(),
                review_id: None,
                error: None,
            },
            total: Instant::now(),
            step: None,
        };
        trace.save()?;
        Ok(trace)
    }
    fn save(&self) -> Result<(), String> {
        let db = self.store.db.lock().map_err(|e| e.to_string())?;
        db.execute("INSERT OR REPLACE INTO analysis_runs(id,evidence_id,case_id,record) VALUES(?1,?2,?3,?4)",params![self.run.id,self.run.evidence_id,self.run.case_id,serde_json::to_string(&self.run).map_err(|e|e.to_string())?]).map_err(|e|e.to_string())?;
        drop(db);
        if let Some(app) = self.app {
            let _ = app.emit("analysis-progress", &self.run);
        }
        Ok(())
    }
    pub fn begin(&mut self, index: usize, note: &str) -> Result<(), String> {
        self.step = Some(Instant::now());
        let stage = &mut self.run.stages[index];
        stage.status = "running".into();
        stage.note = note.into();
        self.run.elapsed_ms = self.total.elapsed().as_millis() as u64;
        self.save()
    }
    pub fn end(&mut self, index: usize, note: &str) -> Result<(), String> {
        let elapsed = self
            .step
            .take()
            .ok_or("分析步骤未开始")?
            .elapsed()
            .as_millis() as u64;
        let stage = &mut self.run.stages[index];
        stage.status = "completed".into();
        stage.elapsed_ms = Some(elapsed);
        stage.note = note.into();
        self.run.elapsed_ms = self.total.elapsed().as_millis() as u64;
        self.save()
    }
    pub fn skip(&mut self, index: usize, note: &str) -> Result<(), String> {
        let stage = &mut self.run.stages[index];
        stage.status = "skipped".into();
        stage.note = note.into();
        self.save()
    }
    pub fn finish(&mut self, review_id: Option<String>) -> Result<(), String> {
        self.run.review_id = review_id;
        self.run.state = "completed".into();
        self.run.elapsed_ms = self.total.elapsed().as_millis() as u64;
        self.save()
    }
    pub fn fail(&mut self, error: &str) {
        for stage in &mut self.run.stages {
            if stage.status == "running" {
                stage.status = "failed".into();
                stage.elapsed_ms = self.step.take().map(|s| s.elapsed().as_millis() as u64);
                stage.note = error.into();
            } else if stage.status == "pending" {
                stage.status = "skipped".into();
                stage.note = "上游步骤失败，未执行".into();
            }
        }
        self.run.error = Some(error.into());
        self.run.state = "failed".into();
        self.run.elapsed_ms = self.total.elapsed().as_millis() as u64;
        let _ = self.save();
    }
}
impl Drop for Trace<'_> {
    fn drop(&mut self) {
        if self.run.state == "running" {
            self.fail("分析未完成或被中断；没有生成成功结论。");
        }
    }
}

pub fn save_feedback(
    store: &Store,
    review_id: String,
    disposition: String,
    feedback: String,
    notes: String,
    actor: String,
) -> Result<Feedback, String> {
    if !["pending", "investigate", "ignore", "false_positive"].contains(&disposition.as_str())
        || !["", "accurate", "inaccurate", "false_positive"].contains(&feedback.as_str())
        || notes.chars().count() > 10000
        || actor.trim().is_empty()
        || actor.chars().count() > 100
    {
        return Err("处置字段无效或超过限制。".into());
    }
    if (feedback == "false_positive" || disposition == "false_positive") && notes.trim().is_empty()
    {
        return Err("请填写标记误报的依据。".into());
    }
    let w = store.workspace()?;
    if !w.ai_reviews.iter().any(|r| r.id == review_id) {
        return Err("复核记录不属于当前事件。".into());
    }
    let item = Feedback {
        id: uuid::Uuid::new_v4().to_string(),
        review_id,
        disposition,
        feedback,
        notes,
        actor: actor.trim().into(),
        recorded_at: Utc::now().to_rfc3339(),
    };
    let db = store.db.lock().map_err(|e| e.to_string())?;
    db.execute(
        "INSERT INTO review_feedback(id,review_id,record) VALUES(?1,?2,?3)",
        params![
            item.id,
            item.review_id,
            serde_json::to_string(&item).map_err(|e| e.to_string())?
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(item)
}

pub fn local_analyze<F>(
    store: &Store,
    app: Option<&tauri::AppHandle>,
    work: F,
) -> Result<crate::store::Evidence, String>
where
    F: FnOnce() -> Result<crate::store::Evidence, String>,
{
    let started = Utc::now().to_rfc3339();
    let clock = Instant::now();
    let evidence = work()?;
    let elapsed = clock.elapsed().as_millis() as u64;
    let run = AnalysisRun {
        id: format!("incident-{}", uuid::Uuid::new_v4()),
        evidence_id: evidence.id.clone(),
        case_id: evidence.case_id.clone(),
        kind: "local".into(),
        state: "completed".into(),
        started_at: started,
        elapsed_ms: elapsed,
        model: String::new(),
        stages: vec![
            Stage {
                name: "输入归档与本地检查".into(),
                status: "completed".into(),
                elapsed_ms: Some(elapsed),
                note: format!("{}；原文、摘要与检查结果已保存", evidence.report.engine),
            },
            Stage {
                name: "知识检索".into(),
                status: "skipped".into(),
                elapsed_ms: None,
                note: "未接入 RAG".into(),
            },
            Stage {
                name: "威胁情报查询".into(),
                status: "skipped".into(),
                elapsed_ms: None,
                note: "未接入在线情报".into(),
            },
            Stage {
                name: "模型 API 请求".into(),
                status: "skipped".into(),
                elapsed_ms: None,
                note: "此次只执行本地检查；可继续发起 AI 研判".into(),
            },
        ],
        review_id: None,
        error: None,
    };
    let db = store.db.lock().map_err(|e| e.to_string())?;
    db.execute(
        "INSERT INTO analysis_runs(id,evidence_id,case_id,record) VALUES(?1,?2,?3,?4)",
        params![
            run.id,
            run.evidence_id,
            run.case_id,
            serde_json::to_string(&run).map_err(|e| e.to_string())?
        ],
    )
    .map_err(|e| e.to_string())?;
    drop(db);
    if let Some(app) = app {
        let _ = app.emit("analysis-progress", run);
    }
    Ok(evidence)
}
