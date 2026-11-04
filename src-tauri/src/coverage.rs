use crate::{
    analyzers::{self, AnalysisReport},
    store::{Store, Workspace},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::Path, sync::Arc};
use tauri::State;
// A known dangerous entry is a risk even in a partial array; malformed remaining
// entries may never establish a clean result.
fn array_risk(v: Option<&Value>, test: impl Fn(&Value) -> Option<bool>) -> Option<bool> {
    let a = v?.as_array()?;
    let mut unknown = false;
    for value in a {
        match test(value) {
            Some(true) => return Some(true),
            None => unknown = true,
            _ => (),
        }
    }
    if unknown {
        None
    } else {
        Some(false)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Check {
    pub title: String,
    pub status: String,
    pub location: String,
    pub value: String,
    pub reason: String,
}
pub fn analyze(path: &Path) -> Result<AnalysisReport, String> {
    let v: Value = serde_json::from_reader(std::fs::File::open(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let objects = if let Some(a) = v.as_array() {
        a.iter().collect::<Vec<_>>()
    } else {
        vec![&v]
    };
    if objects.is_empty()
        || objects
            .iter()
            .any(|c| !c.get("HostConfig").is_some_and(Value::is_object))
    {
        return Err("需要含 HostConfig 的 docker inspect 对象或数组。".into());
    }
    let mut out = analyzers::report("containers", "容器基线与检查覆盖");
    out.engine = "J4team container-coverage/0.6.0".into();
    for (i, c) in objects.iter().enumerate() {
        let name = c["Name"].as_str().unwrap_or("未命名容器");
        let mut check =
            |title: &str, pointer: &str, risk: Option<bool>, level: &str, note: &str| {
                let value = c.pointer(pointer);
                let status = match risk {
                    Some(true) => "risk",
                    Some(false) => "clear",
                    None => "unknown",
                };
                let location = format!("对象[{i}] {name} · {pointer}");
                let original = value
                    .map(|v| analyzers::cut(&v.to_string(), 1800))
                    .unwrap_or_else(|| "[字段缺失]".into());
                let reason = if risk.is_none() {
                    format!("缺少可判断字段或类型不受支持；{note}")
                } else {
                    note.into()
                };
                out.coverage.push(Check {
                    title: title.into(),
                    status: status.into(),
                    location: location.clone(),
                    value: original.clone(),
                    reason: reason.clone(),
                });
                if risk == Some(true) {
                    out.findings.push(analyzers::finding(
                    level,
                    title,
                    &reason,
                    location,
                    None,
                    &original,
                    "核对业务必要性与真实运行权限，按最小权限修复；配置风险不自动证明已被利用。",
                ));
                }
            };
        check(
            "容器启用 privileged",
            "/HostConfig/Privileged",
            c.pointer("/HostConfig/Privileged").and_then(Value::as_bool),
            "high",
            "配置特权标志扩大能力；未命中只说明这个字段未声明 true。",
        );
        for (title, p, level) in [
            ("共享宿主机网络", "/HostConfig/NetworkMode", "medium"),
            ("共享宿主机 PID 空间", "/HostConfig/PidMode", "high"),
            ("共享宿主机 IPC 空间", "/HostConfig/IpcMode", "medium"),
        ] {
            check(
                title,
                p,
                c.pointer(p).and_then(Value::as_str).map(|v| v == "host"),
                level,
                "核对主机命名空间共享是否必要。",
            );
        }
        check(
            "授予高权限 capability",
            "/HostConfig/CapAdd",
            match c.pointer("/HostConfig/CapAdd") {
                Some(Value::Null) => Some(false),
                v => array_risk(v, |x| {
                    let cap = x.as_str()?.to_ascii_uppercase();
                    Some(matches!(
                        cap.strip_prefix("CAP_").unwrap_or(&cap),
                        "SYS_ADMIN" | "ALL" | "SYS_MODULE" | "SYS_PTRACE" | "NET_ADMIN"
                    ))
                }),
            },
            "high",
            "检查显式新增能力，不代表默认能力和内核漏洞已经核查。",
        );
        check(
            "挂载敏感宿主机资源",
            "/Mounts",
            array_risk(c.get("Mounts"), |m| {
                let s = m.get("Source")?.as_str()?;
                if s.is_empty() {
                    return None;
                }
                Some(
                    s.ends_with("docker.sock")
                        || s == "/"
                        || s == "/proc"
                        || s.starts_with("/proc/")
                        || s == "/sys"
                        || s.starts_with("/sys/"),
                )
            }),
            "high",
            "检查可见挂载来源；读写模式与实际主机权限仍需复核。",
        );
        check(
            "容器默认 root 用户",
            "/Config/User",
            c.pointer("/Config/User").and_then(Value::as_str).map(|s| {
                s.is_empty() || s.split(':').next().is_some_and(|u| u == "0" || u == "root")
            }),
            "medium",
            "配置默认 root 不等于主机 root；入口程序也可能自行降权。",
        );
        check(
            "根文件系统可写",
            "/HostConfig/ReadonlyRootfs",
            c.pointer("/HostConfig/ReadonlyRootfs")
                .and_then(Value::as_bool)
                .map(|v| !v),
            "low",
            "只读根文件系统以配置字段判断，挂载目录仍可能可写。",
        );
        for (title, key) in [
            ("Seccomp 显式禁用", "seccomp=unconfined"),
            ("AppArmor 显式禁用", "apparmor=unconfined"),
        ] {
            check(
                title,
                "/HostConfig/SecurityOpt",
                array_risk(c.pointer("/HostConfig/SecurityOpt"), |v| {
                    Some(v.as_str()? == key)
                }),
                "medium",
                "未显式禁用不等于已核查主机实际安全模块。",
            );
        }
        check(
            "未设置 no-new-privileges",
            "/HostConfig/SecurityOpt",
            array_risk(c.pointer("/HostConfig/SecurityOpt"), |v| {
                let s = v.as_str()?;
                Some(
                    s == "no-new-privileges"
                        || s == "no-new-privileges:true"
                        || s == "no-new-privileges=true",
                )
            })
            .map(|enabled| !enabled),
            "low",
            "核对提权需求；字段缺失不按已启用处理。",
        );
        check(
            "未设置内存上限",
            "/HostConfig/Memory",
            c.pointer("/HostConfig/Memory")
                .and_then(Value::as_i64)
                .and_then(|n| if n < 0 { None } else { Some(n == 0) }),
            "low",
            "配置未限制内存；可能被上层 cgroup 约束，需结合宿主机确认。",
        );
        check(
            "未设置进程数量上限",
            "/HostConfig/PidsLimit",
            c.pointer("/HostConfig/PidsLimit")
                .and_then(Value::as_i64)
                .map(|n| n <= 0),
            "low",
            "检查显式 PID 限额，缺字段 / null 保留未知。",
        );
        for (title, reason) in [
            (
                "运行进程与启动链",
                "docker inspect 不包含完整进程树；需补充 Agent / 进程快照。",
            ),
            (
                "网络连接与实际流量",
                "配置不能证明运行期间没有异常连接；需 ss / 流量观测。",
            ),
            (
                "文件完整性与 WebShell",
                "配置不检查容器文件内容；需文件清单、Hash 与样本分析。",
            ),
            ("镜像漏洞与供应链", "未接入漏洞库、镜像签名及 SBOM 扫描。"),
            (
                "宿主机与 Kubernetes",
                "当前材料不包含宿主机取证、集群审计或 RBAC 配置。",
            ),
        ] {
            out.coverage.push(Check {
                title: title.into(),
                status: "not_covered".into(),
                location: format!("对象[{i}] {name}"),
                value: "未提供相应数据源".into(),
                reason: reason.into(),
            });
        }
    }
    let checked = out
        .coverage
        .iter()
        .filter(|c| matches!(c.status.as_str(), "risk" | "clear"))
        .count();
    let unknown = out
        .coverage
        .iter()
        .filter(|c| c.status == "unknown")
        .count();
    let missing = out
        .coverage
        .iter()
        .filter(|c| c.status == "not_covered")
        .count();
    out.metrics = vec![
        analyzers::metric("容器对象", objects.len()),
        analyzers::metric("风险配置", out.findings.len()),
        analyzers::metric("已检查项", checked),
        analyzers::metric("数据未知项", unknown),
        analyzers::metric("未覆盖项", missing),
    ];
    out.summary=format!("13 类配置规则：实际检查 {checked} 项，风险 {} 项，字段未知 {unknown} 项；另有 {missing} 项运行 / 主机能力未覆盖。未命中不代表没有入侵。",out.findings.len());
    out.warnings.push("配置快照仅反映提供的字段；覆盖表中的未命中、数据未知、未覆盖含义不同。AI 也不能凭空补足缺失数据。".into());
    Ok(out)
}
#[tauri::command]
pub async fn refresh_container_coverage(
    evidence_id: String,
    store: State<'_, Arc<Store>>,
) -> Result<Workspace, String> {
    let s = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let case = s.active()?;
        let e = s.evidence_for_case(&case, &evidence_id)?;
        if e.kind != "containers" {
            return Err("请选择容器配置证据".into());
        }
        crate::logbook::verify_archive(&s, &e)?;
        let new = analyze(&s.root.join("evidence").join(&e.id))?;
        // Retain original finding IDs referenced by timeline nodes; append new detections.
        let mut report = new;
        for old in &e.report.findings {
            if let Some(f) = report
                .findings
                .iter_mut()
                .find(|f| f.title == old.title && f.location == old.location)
            {
                f.id = old.id.clone()
            }
        }
        s.db.lock()
            .map_err(|e| e.to_string())?
            .execute(
                "UPDATE evidence SET report=?1 WHERE id=?2 AND case_id=?3",
                rusqlite::params![
                    serde_json::to_string(&report).map_err(|e| e.to_string())?,
                    e.id,
                    case
                ],
            )
            .map_err(|e| e.to_string())?;
        s.workspace()
    })
    .await
    .map_err(|e| e.to_string())?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_fields_are_unknown_not_clear() {
        let p = std::env::temp_dir().join(format!("coverage-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&p, r#"{"HostConfig":{"Privileged":true},"Config":{}}"#).unwrap();
        let r = analyze(&p).unwrap();
        assert_eq!(r.findings.len(), 1);
        assert_eq!(
            r.coverage.iter().filter(|c| c.status == "unknown").count(),
            12
        );
        assert_eq!(
            r.coverage
                .iter()
                .filter(|c| c.status == "not_covered")
                .count(),
            5
        );
        std::fs::remove_file(p).unwrap();
    }
}
