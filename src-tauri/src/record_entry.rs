//! 把新增举证、可选截图和报告章节关联作为一次可重试提交。
//! 显式事件与报告版本防止迟到请求串案或覆盖正文；凭据和模型不参与此流程。
use crate::{analyzers::AnalysisReport, report_draft, store::Store};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, sync::Arc};
use tauri::State;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub case_id: String,
    pub title: String,
    pub body: String,
    pub actor: String,
    pub occurred_at: String,
    pub evidence_id: Option<String>,
    pub finding_id: Option<String>,
    pub section_ids: Vec<String>,
    pub new_section_title: String,
    pub report_version: String,
    pub screenshot: Option<Shot>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Shot {
    pub data_url: String,
    pub caption: String,
}

pub fn save(store: &Store, input: Entry) -> Result<String, String> {
    if uuid::Uuid::parse_str(&input.id).is_err()
        || input.title.trim().is_empty()
        || input.body.trim().is_empty()
        || input.actor.trim().is_empty()
        || input.title.chars().count() > 200
        || input.body.chars().count() > 30000
        || input.actor.chars().count() > 100
        || input.section_ids.len() > 64
        || input.new_section_title.chars().count() > 120
        || input.report_version.len() > 100
        || input
            .screenshot
            .as_ref()
            .is_some_and(|s| s.data_url.len() > 12 * 1024 * 1024)
    {
        return Err("举证字段为空或超过限制。".into());
    }
    let at = chrono::DateTime::parse_from_rfc3339(&input.occurred_at)
        .map_err(|_| "发生时间需要有效日期、秒与时区。")?
        .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
        .to_rfc3339();
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&input).map_err(|e| e.to_string())?)
    );
    let receipt = format!("record_receipt:{}", input.id);
    let mut db = store.db.lock().map_err(|e| e.to_string())?;
    let tx = db.transaction().map_err(|e| e.to_string())?;
    let previous: Option<String> = tx
        .query_row("SELECT value FROM settings WHERE key=?1", [&receipt], |r| {
            r.get(0)
        })
        .optional()
        .map_err(|e| e.to_string())?;
    if let Some(previous) = previous {
        return if previous == fingerprint {
            Ok(input.id)
        } else {
            Err("该记录已保存，请从事件时间线编辑，避免重复提交。".into())
        };
    }
    let mut report = report_draft::load_db(&tx, &input.case_id)?;
    let linking = !input.section_ids.is_empty() || !input.new_section_title.trim().is_empty();
    if linking && report.updated_at != input.report_version {
        return Err("报告已更新，请刷新章节后重试；本次节点和截图尚未保存。".into());
    }
    if let Some(id) = &input.evidence_id {
        let raw: String = tx
            .query_row(
                "SELECT report FROM evidence WHERE id=?1 AND case_id=?2",
                params![id, input.case_id],
                |r| r.get(0),
            )
            .map_err(|_| "证据不属于指定事件。")?;
        if let Some(finding) = &input.finding_id {
            let analysis: AnalysisReport = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
            if !analysis.findings.iter().any(|f| &f.id == finding) {
                return Err("关联发现不存在。".into());
            }
        }
    } else if input.finding_id.is_some() {
        return Err("关联发现需要原始证据。".into());
    }
    if input
        .section_ids
        .iter()
        .any(|id| !report.steps.iter().any(|s| &s.id == id))
    {
        return Err("所选章节不存在，请刷新章节后重试。".into());
    }
    let shot = if let Some(shot) = &input.screenshot {
        if shot.caption.trim().is_empty() || shot.caption.chars().count() > 1000 {
            return Err("截图需填写 1–1000 字图注。".into());
        }
        let (_, encoded) = shot
            .data_url
            .split_once(',')
            .filter(|(head, _)| {
                [
                    "data:image/png;base64",
                    "data:image/jpeg;base64",
                    "data:image/webp;base64",
                ]
                .contains(head)
            })
            .ok_or("仅支持 PNG、JPEG 与 WebP 图片。")?;
        let bytes = STANDARD.decode(encoded).map_err(|_| "截图编码无效。")?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err("截图不能超过 8 MiB。".into());
        }
        crate::store::read_image(&bytes)?;
        let mime = match image::guess_format(&bytes).map_err(|e| e.to_string())? {
            image::ImageFormat::Png => "image/png",
            image::ImageFormat::Jpeg => "image/jpeg",
            image::ImageFormat::WebP => "image/webp",
            _ => return Err("不支持的截图格式。".into()),
        };
        Some((
            uuid::Uuid::new_v4().to_string(),
            bytes,
            mime,
            shot.caption.clone(),
        ))
    } else {
        None
    };
    // 文件先完整写入，事务提交失败则清除本次原图；数据库不出现半条举证。
    let mut created = None;
    let result = (|| {
        tx.execute(
            "INSERT INTO nodes VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
            params![
                input.id,
                input.case_id,
                input.evidence_id,
                input.finding_id,
                at,
                chrono::Utc::now().to_rfc3339(),
                input.title.trim(),
                input.body,
                input.actor
            ],
        )
        .map_err(|e| e.to_string())?;
        if let Some((id, bytes, mime, caption)) = shot {
            let target = store.root.join("screenshots").join(&id);
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&target).map_err(|e| e.to_string())?;
            created = Some(target);
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
            drop(file);
            crate::store::protect_archive(created.as_ref().unwrap())?;
            tx.execute(
                "INSERT INTO screenshots VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id,
                    input.id,
                    "举证截图",
                    format!("{:x}", Sha256::digest(&bytes)),
                    bytes.len() as u64,
                    mime,
                    caption
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        for section in &mut report.steps {
            if input.section_ids.contains(&section.id) {
                if !section.node_ids.contains(&input.id) {
                    section.node_ids.push(input.id.clone());
                }
                if section.owner.trim().is_empty() {
                    section.owner = input.actor.clone();
                }
            }
        }
        if !input.new_section_title.trim().is_empty() {
            report.steps.push(report_draft::ReportStep {
                id: uuid::Uuid::new_v4().to_string(),
                title: input.new_section_title.trim().into(),
                owner: input.actor.clone(),
                status: "todo".into(),
                node_ids: vec![input.id.clone()],
                ..Default::default()
            });
        }
        if linking {
            report_draft::save_db(&tx, &input.case_id, &mut report)?;
        }
        tx.execute(
            "INSERT INTO settings VALUES(?1,?2)",
            params![receipt, fingerprint],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(input.id)
    })();
    if result.is_err() {
        if let Some(path) = created {
            crate::store::discard_snapshot(&path);
        }
    }
    result
}

#[tauri::command]
pub async fn save_record_entry(
    input: Entry,
    store: State<'_, Arc<Store>>,
) -> Result<String, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || save(&store, input))
        .await
        .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(case_id: &str) -> Entry {
        Entry {
            id: uuid::Uuid::new_v4().to_string(), case_id: case_id.into(),
            title: "合成材料复核".into(), body: "合成验收，不代表真实入侵。".into(), actor: "验收人员".into(),
            occurred_at: "2026-10-29T10:21:00+08:00".into(), evidence_id: None, finding_id: None,
            section_ids: vec![], new_section_title: "初始排查".into(), report_version: String::new(),
            screenshot: Some(Shot { data_url: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=".into(), caption: "合成图片".into() }),
        }
    }
    fn root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("gaga-entry-{}", uuid::Uuid::new_v4()))
    }
    fn no_rows(store: &Store) {
        let w = store.workspace().unwrap();
        assert!(w.nodes.is_empty());
        assert_eq!(
            fs::read_dir(store.root.join("screenshots"))
                .unwrap()
                .count(),
            0
        );
        let count: i64 = store
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM settings WHERE key LIKE 'record_receipt:%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn record_image_and_section_commit_once_and_survive_restart() {
        let root = root();
        let store = Store::open(root.clone()).unwrap();
        let case = store.active().unwrap();
        let mut draft = report_draft::load(&store, &case).unwrap();
        draft.summary = "原报告摘要必须保留".into();
        report_draft::save(&store, &case, &mut draft).unwrap();
        let mut input = entry(&case);
        input.report_version = draft.updated_at;
        let id = save(&store, input.clone()).unwrap();
        assert_eq!(save(&store, input.clone()).unwrap(), id);
        let d = report_draft::load(&store, &case).unwrap();
        assert_eq!(d.summary, "原报告摘要必须保留");
        assert_eq!(d.steps[0].node_ids, vec![id.clone()]);
        assert_eq!(d.steps[0].owner, "验收人员");
        let w = store.workspace().unwrap();
        assert_eq!(w.nodes.len(), 1);
        assert_eq!(w.nodes[0].screenshots.len(), 1);
        assert_eq!(fs::read_dir(root.join("screenshots")).unwrap().count(), 1);
        input.body = "不能用同一提交 ID 改写".into();
        assert!(save(&store, input).unwrap_err().contains("已保存"));
        drop(store);
        let reopened = Store::open(root.clone()).unwrap();
        let w = reopened.workspace().unwrap();
        assert_eq!(w.nodes[0].id, id);
        assert!(reopened
            .screenshot_data(w.nodes[0].screenshots[0].id.clone())
            .unwrap()
            .starts_with("data:image/png;base64,"));
        assert_eq!(
            report_draft::load(&reopened, &case).unwrap().steps[0].node_ids,
            vec![id]
        );
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn stale_report_cannot_leave_partial_node_image_or_receipt() {
        let root = root();
        let store = Store::open(root.clone()).unwrap();
        let case = store.active().unwrap();
        let input = entry(&case);
        let mut d = report_draft::load(&store, &case).unwrap();
        d.summary = "其他窗口已修改".into();
        report_draft::save(&store, &case, &mut d).unwrap();
        assert!(save(&store, input).unwrap_err().contains("报告已更新"));
        no_rows(&store);
        assert_eq!(
            report_draft::load(&store, &case).unwrap().summary,
            "其他窗口已修改"
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn full_report_rolls_back_database_and_removes_written_image() {
        let root = root();
        let store = Store::open(root.clone()).unwrap();
        let case = store.active().unwrap();
        let mut d = report_draft::load(&store, &case).unwrap();
        d.steps = (0..64)
            .map(|i| report_draft::ReportStep {
                id: format!("s{i}"),
                title: format!("章节 {i}"),
                status: "todo".into(),
                ..Default::default()
            })
            .collect();
        report_draft::save(&store, &case, &mut d).unwrap();
        let mut input = entry(&case);
        input.report_version = d.updated_at.clone();
        assert!(save(&store, input.clone()).unwrap_err().contains("64"));
        no_rows(&store);
        input.new_section_title.clear();
        input.section_ids = vec!["s0".into()];
        save(&store, input).unwrap();
        let result = report_draft::load(&store, &case).unwrap();
        assert_eq!(result.steps.len(), 64);
        assert_eq!(result.steps[0].node_ids.len(), 1);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn cross_case_and_missing_finding_are_rejected_before_writing() {
        let root = root();
        let store = Store::open(root.clone()).unwrap();
        let a = store.active().unwrap();
        let evidence = store
            .analyze_http_pair(
                "GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n".into(),
                String::new(),
            )
            .unwrap();
        let b = store.create_case("另一个事件".into()).unwrap();
        let mut input = entry(&b.id);
        input.evidence_id = Some(evidence.id.clone());
        assert!(save(&store, input.clone())
            .unwrap_err()
            .contains("证据不属于"));
        no_rows(&store);
        input.case_id = a;
        input.finding_id = Some("不存在".into());
        assert!(save(&store, input).unwrap_err().contains("关联发现不存在"));
        no_rows(&store);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn invalid_image_cannot_create_records_and_existing_owner_is_preserved() {
        let root = root();
        let store = Store::open(root.clone()).unwrap();
        let case = store.active().unwrap();
        let mut input = entry(&case);
        input.screenshot.as_mut().unwrap().data_url =
            "data:image/png;base64,bm90LWFuLWltYWdl".into();
        assert!(save(&store, input.clone()).is_err());
        no_rows(&store);
        input.screenshot = None;
        input.new_section_title.clear();
        let mut d = report_draft::load(&store, &case).unwrap();
        d.steps.push(report_draft::ReportStep {
            id: "s1".into(),
            title: "既有章节".into(),
            owner: "既有负责人".into(),
            status: "in_progress".into(),
            ..Default::default()
        });
        report_draft::save(&store, &case, &mut d).unwrap();
        input.report_version = d.updated_at;
        input.section_ids = vec!["s1".into()];
        save(&store, input).unwrap();
        let d = report_draft::load(&store, &case).unwrap();
        assert_eq!(d.steps[0].owner, "既有负责人");
        assert_eq!(d.steps[0].status, "in_progress");
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
