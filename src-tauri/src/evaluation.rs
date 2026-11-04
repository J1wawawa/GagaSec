//! 公开合成案例的可复现评测：测规则线索和证据保留，不宣称真实入侵检出率。
use crate::store::Store;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{fs, path::Path, time::Instant};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    id: String,
    class: String,
    request: String,
    response: String,
    required: Vec<String>,
    forbidden: Vec<String>,
    #[serde(default)]
    reject: bool,
    #[serde(default)]
    missing_response: bool,
}
pub fn run(root: &Path) -> Result<Value, String> {
    if root.exists() {
        return Err("评测必须使用新的独立目录".into());
    }
    let store = Store::open(root.into())?;
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../../fixtures/evaluation/http.json"))
            .map_err(|e| e.to_string())?;
    let mut results = vec![];
    let mut passed = 0;
    let mut fp = 0;
    let mut missed = 0;
    for case in cases {
        store.create_case(format!("[评测] {}", case.id))?;
        let started = Instant::now();
        let result = store.analyze_http_pair(case.request, case.response);
        let (ok, titles) = match result {
            Err(_) => (case.reject, vec![]),
            Ok(e) => {
                let titles: Vec<_> = e.report.findings.iter().map(|f| f.title.clone()).collect();
                let absent = case
                    .required
                    .iter()
                    .filter(|title| !titles.contains(title))
                    .count();
                let wrong = case
                    .forbidden
                    .iter()
                    .filter(|title| titles.contains(title))
                    .count();
                fp += wrong;
                missed += absent;
                let missing_ok = !case.missing_response
                    || e.report.http_exchanges.iter().all(|x| x.response.is_none());
                let proof = e
                    .report
                    .findings
                    .iter()
                    .all(|f| !f.excerpt.is_empty() && !f.location.is_empty());
                (
                    !case.reject && absent == 0 && wrong == 0 && missing_ok && proof,
                    titles,
                )
            }
        };
        if ok {
            passed += 1;
        }
        results.push(json!({"id":case.id,"class":case.class,"passed":ok,"elapsedMs":started.elapsed().as_millis(),"observedFindingTitles":titles}));
    }
    let report = json!({"format":"gaga-rule-evaluation/1","version":env!("CARGO_PKG_VERSION"),"cases":results.len(),"passed":passed,"missingRequiredClues":missed,"forbiddenCluesObserved":fp,"results":results,"officialModelCalled":false,"realMalwareExecuted":false,"scope":"10 synthetic HTTP cases only; not real-world detection accuracy or an AI benchmark"});
    fs::write(
        root.join("evaluation.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if passed != results.len() {
        return Err(format!(
            "评测有失败案例：{passed}/{}；见 evaluation.json",
            results.len()
        ));
    }
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_evaluation_cases_keep_controls_gaps_and_original_proof() {
        let root = std::env::temp_dir().join(format!("gaga-evaluation-{}", uuid::Uuid::new_v4()));
        assert_eq!(run(&root).unwrap()["passed"], 10);
        assert!(run(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
