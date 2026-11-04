//! 报告统计的唯一计算入口，供客户端预览和 HTML / DOCX 共用。
//! 只使用指定事件已纳入报告的节点及引用原件；章节复用不会放大计数。
//! 节点跨度、章节耗时均不等同于事件响应 SLA 或已经完成处置。
use crate::{
    report_draft::ReportDraft,
    store::{Store, Workspace},
};
use chrono::{DateTime, FixedOffset};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
};
use tauri::State;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metric {
    pub key: &'static str,
    pub label: &'static str,
    pub value: String,
    pub detail: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Count {
    pub label: String,
    pub count: usize,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stage {
    pub title: String,
    pub child: bool,
    pub owner: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration: String,
    pub duration_ms: Option<i64>,
    pub width_percent: u32,
    pub nodes: usize,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capsule {
    pub id: String,
    pub anchor: String,
    pub date: String,
    pub time: String,
    pub gap: String,
    pub title: String,
    pub summary: String,
    pub actor: String,
    pub evidence_id: Option<String>,
    pub evidence_name: String,
    pub sha256: String,
    pub location: String,
    pub screenshots: usize,
    pub sections: Vec<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Insights {
    pub case_id: String,
    pub scope: &'static str,
    pub metrics: Vec<Metric>,
    pub evidence_kinds: Vec<Count>,
    pub indicator_kinds: Vec<Count>,
    pub completed_sections: usize,
    pub total_sections: usize,
    pub blocked_sections: usize,
    pub invalid_node_times: usize,
    pub stages: Vec<Stage>,
    pub capsules: Vec<Capsule>,
}
pub const SCOPE: &str = "仅统计当前报告已选节点及引用原件，按记录 ID 去重；候选 IOC 按类型和值去重，尚不代表恶意。章节完成率不代表事件结案，节点跨度不代表响应耗时。时间统一为北京时间 UTC+8。";
fn instant(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|v| v.timestamp_millis())
}
fn date_time(value: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|v| v.with_timezone(&FixedOffset::east_opt(8 * 3600).unwrap()))
}
fn stamp(value: &str) -> String {
    date_time(value)
        .map(|v| v.format("%Y/%m/%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "待补有效时间".into())
}
fn duration(ms: i64) -> String {
    let seconds = ms / 1000;
    let (days, hours, minutes, seconds) = (
        seconds / 86400,
        seconds % 86400 / 3600,
        seconds % 3600 / 60,
        seconds % 60,
    );
    let mut text = String::new();
    for (n, unit) in [
        (days, "天"),
        (hours, "时"),
        (minutes, "分"),
        (seconds, "秒"),
    ] {
        if n > 0 {
            text.push_str(&format!("{n}{unit}"));
        }
    }
    if text.is_empty() {
        if ms > 0 {
            "不足 1 秒".into()
        } else {
            "0秒".into()
        }
    } else {
        text
    }
}
fn status(value: &str) -> &'static str {
    match value {
        "completed" => "已完成",
        "in_progress" => "进行中",
        "blocked" => "待补证 / 阻塞",
        _ => "待开展",
    }
}
fn kind(value: &str) -> String {
    match value {
        "http" => "HTTP 报文",
        "logs" => "日志",
        "containers" => "容器",
        "webshell" => "WebShell 静态材料",
        "binary" => "二进制样本",
        "triage" => "告警",
        "ip" => "IP",
        "domain" => "域名",
        "url" => "URL",
        "hash" | "sha256" | "sha1" | "md5" => "文件 Hash",
        _ => value,
    }
    .into()
}
fn counts(values: impl Iterator<Item = String>) -> Vec<Count> {
    let mut result = BTreeMap::new();
    for label in values {
        *result.entry(label).or_insert(0) += 1;
    }
    result
        .into_iter()
        .map(|(label, count)| Count { label, count })
        .collect()
}

pub fn summarize(w: &Workspace, draft: &ReportDraft) -> Insights {
    // 防御性限制事件范围；即使调用方意外提供多事件集合也不混入其他调查。
    let mut seen = HashSet::new();
    let mut nodes: Vec<_> = w
        .nodes
        .iter()
        .filter(|n| n.case_id == w.active_case && n.included && seen.insert(&n.id))
        .collect();
    nodes.sort_by(|a, b| {
        let a_time = instant(&a.occurred_at);
        let b_time = instant(&b.occurred_at);
        a_time
            .is_none()
            .cmp(&b_time.is_none())
            .then_with(|| a_time.cmp(&b_time))
            .then_with(|| a.id.cmp(&b.id))
    });
    let source_ids: HashSet<_> = nodes
        .iter()
        .filter_map(|n| n.evidence_id.as_ref())
        .collect();
    let mut seen = HashSet::new();
    let sources: Vec<_> = w
        .evidence
        .iter()
        .filter(|e| e.case_id == w.active_case && source_ids.contains(&e.id) && seen.insert(&e.id))
        .collect();
    let source_map: BTreeMap<_, _> = sources.iter().map(|e| (&e.id, *e)).collect();
    let people: BTreeSet<_> = nodes
        .iter()
        .map(|n| n.actor.trim())
        .filter(|v| !v.is_empty())
        .collect();
    let shots: HashSet<_> = nodes
        .iter()
        .flat_map(|n| n.screenshots.iter().map(|s| &s.id))
        .collect();
    let pictured = nodes.iter().filter(|n| !n.screenshots.is_empty()).count();
    let with_source = nodes
        .iter()
        .filter(|n| {
            n.evidence_id
                .as_ref()
                .is_some_and(|id| source_map.contains_key(id))
        })
        .count();
    let candidate_iocs: BTreeSet<_> = sources
        .iter()
        .flat_map(|e| e.report.indicators.iter())
        .filter(|i| !i.value.trim().is_empty())
        .map(|i| {
            let key = i.kind.trim().to_ascii_lowercase();
            let value = if matches!(key.as_str(), "domain" | "hash" | "sha256" | "sha1" | "md5") {
                i.value.trim().to_ascii_lowercase()
            } else {
                i.value.trim().to_string()
            };
            (key, value)
        })
        .collect();
    let valid_times: Vec<_> = nodes
        .iter()
        .filter_map(|n| instant(&n.occurred_at))
        .collect();
    let span = match (valid_times.first(), valid_times.last()) {
        (Some(a), Some(b)) if valid_times.len() > 1 => duration(b - a),
        (Some(_), _) => "单个时间点".into(),
        _ => "待记录".into(),
    };
    let span_detail = if valid_times.is_empty() {
        "没有有效发生时间".into()
    } else {
        format!(
            "{} — {}",
            stamp(&nodes[0].occurred_at),
            stamp(&nodes[valid_times.len() - 1].occurred_at)
        )
    };
    let mut stages: Vec<_> = draft
        .steps
        .iter()
        .map(|s| {
            let elapsed = instant(&s.started_at)
                .zip(instant(&s.completed_at))
                .and_then(|(a, b)| (b >= a).then_some(b - a));
            let invalid = (!s.started_at.is_empty() && instant(&s.started_at).is_none())
                || (!s.completed_at.is_empty() && instant(&s.completed_at).is_none())
                || instant(&s.started_at)
                    .zip(instant(&s.completed_at))
                    .is_some_and(|(a, b)| b < a);
            Stage {
                title: s.title.clone(),
                child: s.parent_id.is_some(),
                owner: if s.owner.trim().is_empty() {
                    "待指定".into()
                } else {
                    s.owner.clone()
                },
                status: status(&s.status).into(),
                started_at: stamp(&s.started_at),
                completed_at: stamp(&s.completed_at),
                duration: elapsed.map(duration).unwrap_or_else(|| {
                    if invalid {
                        "起止时间需复核".into()
                    } else {
                        "起止待补".into()
                    }
                }),
                duration_ms: elapsed,
                width_percent: 0,
                nodes: nodes.iter().filter(|n| s.node_ids.contains(&n.id)).count(),
            }
        })
        .collect();
    let max_duration = stages
        .iter()
        .filter_map(|s| s.duration_ms)
        .max()
        .unwrap_or(0);
    for stage in &mut stages {
        stage.width_percent = stage
            .duration_ms
            .filter(|_| max_duration > 0)
            .map(|v| ((v as f64 / max_duration as f64) * 100.0).round() as u32)
            .unwrap_or(0);
    }
    let mut previous = None;
    let capsules = nodes
        .iter()
        .enumerate()
        .map(|(index, n)| {
            let at = date_time(&n.occurred_at);
            let gap = match (previous, instant(&n.occurred_at)) {
                (Some(a), Some(b)) => format!("距上一节点 {}", duration(b - a)),
                (None, Some(_)) => "时间线起点".into(),
                _ => "时间待复核".into(),
            };
            if let Some(value) = instant(&n.occurred_at) {
                previous = Some(value);
            }
            let source = n
                .evidence_id
                .as_ref()
                .and_then(|id| source_map.get(id))
                .copied();
            Capsule {
                id: n.id.clone(),
                anchor: format!("timeline-proof-{}", index + 1),
                date: at
                    .as_ref()
                    .map(|v| v.format("%Y/%m/%d").to_string())
                    .unwrap_or_else(|| "时间待补".into()),
                time: at
                    .map(|v| v.format("%H:%M:%S").to_string())
                    .unwrap_or_else(|| "—".into()),
                gap,
                title: n.title.clone(),
                summary: crate::analyzers::cut(&n.body, 180),
                actor: if n.actor.trim().is_empty() {
                    "待指定".into()
                } else {
                    n.actor.clone()
                },
                evidence_id: source.map(|e| e.id.clone()),
                evidence_name: source
                    .map(|e| e.name.clone())
                    .unwrap_or_else(|| "人工记录 · 未关联原件".into()),
                sha256: source.map(|e| e.sha256.clone()).unwrap_or_default(),
                location: source
                    .and_then(|e| {
                        e.report
                            .findings
                            .iter()
                            .find(|f| Some(&f.id) == n.finding_id.as_ref())
                    })
                    .map(|f| f.location.clone())
                    .unwrap_or_default(),
                screenshots: n.screenshots.len(),
                sections: draft
                    .steps
                    .iter()
                    .filter(|s| s.node_ids.contains(&n.id))
                    .map(|s| format!("{} · {}", s.title, status(&s.status)))
                    .collect(),
            }
        })
        .collect();
    let completed = draft
        .steps
        .iter()
        .filter(|s| s.status == "completed")
        .count();
    Insights {
        case_id: w.active_case.clone(),
        scope: SCOPE,
        metrics: vec![
            Metric {
                key: "span",
                label: "节点时间跨度",
                value: span,
                detail: span_detail,
            },
            Metric {
                key: "nodes",
                label: "时间胶囊节点",
                value: nodes.len().to_string(),
                detail: format!("{with_source} 个已关联原件；章节复用只计一次"),
            },
            Metric {
                key: "evidence",
                label: "引用原始材料",
                value: sources.len().to_string(),
                detail: "按证据 ID 去重，不含未纳入材料".into(),
            },
            Metric {
                key: "screenshots",
                label: "截图举证覆盖",
                value: format!("{pictured}/{}", nodes.len()),
                detail: format!(
                    "{} 张附图；{} 个节点待补图",
                    shots.len(),
                    nodes.len() - pictured
                ),
            },
            Metric {
                key: "people",
                label: "记录人员",
                value: people.len().to_string(),
                detail: "按节点填写名称去重，不作身份认证".into(),
            },
            Metric {
                key: "iocs",
                label: "候选 IOC",
                value: candidate_iocs.len().to_string(),
                detail: "引用原件的规则提取结果，待研判".into(),
            },
        ],
        evidence_kinds: counts(sources.iter().map(|e| kind(&e.kind))),
        indicator_kinds: counts(candidate_iocs.iter().map(|(k, _)| kind(k))),
        completed_sections: completed,
        total_sections: draft.steps.len(),
        blocked_sections: draft.steps.iter().filter(|s| s.status == "blocked").count(),
        invalid_node_times: nodes.len() - valid_times.len(),
        stages,
        capsules,
    }
}

#[tauri::command]
pub async fn get_report_insights(
    case_id: String,
    draft: Option<ReportDraft>,
    store: State<'_, Arc<Store>>,
) -> Result<Insights, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut input = crate::report_input::capture_insights(&store, &case_id)?;
        if let Some(mut pending) = draft {
            pending.normalize()?;
            input.draft = pending;
        }
        Ok(summarize(&input.workspace, &input.draft))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::TimelineNode;
    #[test]
    fn chronology_dedup_scope_and_missing_times_are_explicit() {
        let store = Store::open(
            std::env::temp_dir().join(format!("gaga-insights-{}", uuid::Uuid::new_v4())),
        )
        .unwrap();
        let case = store.active().unwrap();
        let evidence = store.analyze_alert_text("203.0.113.10".into()).unwrap();
        let mut w = store.workspace().unwrap();
        let make = |id: &str, case_id: &str, time: &str, included| TimelineNode {
            id: id.into(),
            case_id: case_id.into(),
            evidence_id: Some(evidence.id.clone()),
            finding_id: None,
            occurred_at: time.into(),
            recorded_at: time.into(),
            title: format!("节点 {id}"),
            body: "证据需复核".into(),
            actor: "张三".into(),
            included,
            screenshots: vec![],
        };
        w.nodes = vec![
            make("b", &case, "2026-10-29T02:24:00Z", true),
            make("a", &case, "2026-10-29T10:22:00+08:00", true),
            make("bad", &case, "invalid", true),
            make("other", "other-case", "2026-10-20T10:00:00Z", true),
            make("excluded", &case, "2026-10-01T10:00:00Z", false),
        ];
        w.nodes.push(w.nodes[0].clone());
        let mut d = ReportDraft {
            structure_version: 2,
            steps: crate::report_draft::default_steps(),
            ..Default::default()
        };
        for s in &mut d.steps {
            s.node_ids = vec!["a".into(), "b".into()];
        }
        d.steps[0].started_at = "2026-10-29T10:20:00+08:00".into();
        d.steps[0].completed_at = "2026-10-29T02:24:00Z".into();
        d.steps[0].status = "completed".into();
        d.steps[1].started_at = "2026-10-29T10:25:00+08:00".into();
        d.steps[1].completed_at = "2026-10-29T10:24:00+08:00".into();
        let result = summarize(&w, &d);
        assert_eq!(
            result
                .capsules
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b", "bad"]
        );
        assert_eq!(result.capsules[1].time, "10:24:00");
        assert_eq!(result.capsules[1].gap, "距上一节点 2分");
        assert_eq!(result.invalid_node_times, 1);
        assert_eq!(result.metrics[0].value, "2分");
        assert_eq!(result.metrics[2].value, "1");
        assert_eq!(result.metrics[4].value, "1");
        assert_eq!(result.stages[0].duration_ms, Some(240000));
        assert_eq!(result.stages[0].width_percent, 100);
        assert_eq!(result.stages[1].duration, "起止时间需复核");
        assert_eq!(result.stages[2].duration, "起止待补");
        assert_eq!(result.capsules[0].sections.len(), 5);
        assert_eq!(result.completed_sections, 1);
        drop(store);
        std::fs::remove_dir_all(w.data_dir).unwrap();
    }
    #[test]
    fn empty_case_insights_do_not_allow_empty_export() {
        let store = Store::open(
            std::env::temp_dir().join(format!("gaga-empty-insights-{}", uuid::Uuid::new_v4())),
        )
        .unwrap();
        let case = store.active().unwrap();
        let input = crate::report_input::capture_insights(&store, &case).unwrap();
        let result = summarize(&input.workspace, &input.draft);
        assert!(result.capsules.is_empty());
        assert_eq!(result.metrics[0].value, "待记录");
        assert_eq!(result.metrics[3].value, "0/0");
        assert!(crate::report_input::capture(&store, &case).is_err());
        let root = store.root.clone();
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
