//! Docker 镜像与容器生命周期。所有输入必须在 inspect 验证后才可进入容器。
use super::{BUILD, IMAGE, MEMORY, VERSION};
use crate::{
    sandbox::{self, DockerCheck},
    store::Store,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Environment {
    pub docker: DockerCheck,
    pub image_id: Option<String>,
    pub policy: String,
    pub leftovers: Vec<String>,
}
pub(super) fn owner(store: &Store) -> String {
    format!(
        "{:x}",
        Sha256::digest(store.root.to_string_lossy().as_bytes())
    )[..16]
        .into()
}
/// 标签用于兼容性检查；运行时使用不可变 Image ID，避免任务中途 tag 变化。
/// 本地 Docker daemon 和镜像供应链仍属于信任边界，并非数字签名验证。
fn compatible_image(v: &Value) -> Option<String> {
    let id = v["Id"].as_str()?;
    let digest = id.strip_prefix("sha256:")?;
    (digest.len() == 64
        && digest.bytes().all(|b| b.is_ascii_hexdigit())
        && v["Config"]["Labels"]["team.j4.gaga.analysis"] == VERSION)
        .then(|| id.to_string())
}
pub fn environment(store: &Store) -> Environment {
    let check = sandbox::preflight(store);
    let mut image = None;
    let mut leftovers = vec![];
    if check.daemon_ready {
        if let Ok(out) = sandbox::docker(
            &check,
            &["image", "inspect", IMAGE, "--format", "{{json .}}"],
            None,
            10,
            4096,
        ) {
            if out.ok {
                if let Ok(v) = serde_json::from_slice::<Value>(&out.stdout) {
                    image = compatible_image(&v);
                }
            }
        }
        if let Ok(out) = sandbox::docker(
            &check,
            &[
                "ps",
                "-a",
                "--filter",
                &format!("label=team.j4.gaga.reverse={}", owner(store)),
                "--format",
                "{{.Names}}",
            ],
            None,
            10,
            8192,
        ) {
            if out.ok {
                leftovers = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter(|s| s.starts_with("gaga-analysis-"))
                    .map(String::from)
                    .collect()
            }
        }
    }
    Environment{docker:check,image_id:image,policy:"解析与 Pi 均在临时容器：禁网、只读根、非 root、无宿主机挂载、无额外权限；客户端仅归档、校验 Hash 与代理官方模型。".into(),leftovers}
}
pub fn build(store: &Store) -> Result<Environment, String> {
    let _lock = BUILD.try_lock().map_err(|_| "分析镜像正在构建")?;
    let env = environment(store);
    if !env.docker.daemon_ready {
        return Err(env.docker.message);
    }
    let dir = store.root.join("analysis-build");
    fs::create_dir_all(dir.join("src")).map_err(|e| e.to_string())?;
    for (name, data) in [
        (
            "cargo-config.toml",
            include_str!("../../../reverse-worker/cargo-config.toml"),
        ),
        (
            "Dockerfile",
            include_str!("../../../reverse-worker/Dockerfile"),
        ),
        (
            "Cargo.toml",
            include_str!("../../../reverse-worker/Cargo.toml"),
        ),
        (
            "Cargo.lock",
            include_str!("../../../reverse-worker/Cargo.lock"),
        ),
        (
            "src/main.rs",
            include_str!("../../../reverse-worker/src/main.rs"),
        ),
        (
            "src/tools.rs",
            include_str!("../../../reverse-worker/src/tools.rs"),
        ),
        (
            "src/types.rs",
            include_str!("../../../reverse-worker/src/types.rs"),
        ),
        (
            "src/sample_static.rs",
            include_str!("../../../reverse-worker/src/sample_static.rs"),
        ),
        (
            "src/webshell.rs",
            include_str!("../../../reverse-worker/src/webshell.rs"),
        ),
        (
            "src/webshell_schema.rs",
            include_str!("../../../reverse-worker/src/webshell_schema.rs"),
        ),
        (
            "package.json",
            include_str!("../../../reverse-worker/package.json"),
        ),
        (
            "package-lock.json",
            include_str!("../../../reverse-worker/package-lock.json"),
        ),
        (
            "agent.mjs",
            include_str!("../../../reverse-worker/agent.mjs"),
        ),
        (
            "disassemble.mjs",
            include_str!("../../../reverse-worker/disassemble.mjs"),
        ),
    ] {
        fs::write(dir.join(name), data).map_err(|e| e.to_string())?;
    }
    fs::write(
        dir.join("vendor.tar.gz"),
        include_bytes!("../../../reverse-worker/vendor.tar.gz"),
    )
    .map_err(|e| e.to_string())?;
    let out = sandbox::docker(
        &env.docker,
        &[
            "build",
            "--tag",
            IMAGE,
            "--pull=false",
            &dir.to_string_lossy(),
        ],
        None,
        900,
        128 * 1024,
    )?;
    if !out.ok {
        return Err(format!(
            "分析镜像构建失败：{}",
            out.stderr
                .chars()
                .rev()
                .take(6000)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>()
        ));
    }
    let env = environment(store);
    if env.image_id.is_none() {
        return Err("构建后未找到分析镜像".into());
    }
    Ok(env)
}
pub(super) fn validate(v: &Value) -> Result<(), String> {
    let h = &v["HostConfig"];
    let caps = h["CapDrop"]
        .as_array()
        .is_some_and(|a| a.iter().any(|x| x == "ALL"));
    let security = h["SecurityOpt"].as_array().is_some_and(|a| {
        a.iter()
            .any(|x| x == "no-new-privileges=true" || x == "no-new-privileges")
            && !a
                .iter()
                .any(|x| x.as_str().is_some_and(|s| s.contains("unconfined")))
    });
    let tmp = h["Tmpfs"].as_object().is_some_and(|m| m.len() == 1)
        && h["Tmpfs"]["/tmp"].as_str().is_some_and(|s| {
            ["noexec", "nosuid", "nodev"]
                .iter()
                .all(|x| s.split(',').any(|s| s == *x))
        });
    if h["NetworkMode"] != "none"
        || h["ReadonlyRootfs"] != true
        || h["Privileged"] != false
        || v["Config"]["User"] != "65534:65534"
        || !caps
        || !security
        || !tmp
        || h["Memory"].as_i64() != Some(MEMORY)
        || h["PidsLimit"].as_i64() != Some(64)
        || h["NanoCpus"].as_i64() != Some(1_000_000_000)
        || !v["Mounts"].as_array().is_some_and(|a| a.is_empty())
        || h["Binds"].as_array().is_some_and(|a| !a.is_empty())
        || h["CapAdd"].as_array().is_some_and(|a| !a.is_empty())
        || h["Devices"].as_array().is_some_and(|a| !a.is_empty())
        || h["DeviceRequests"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
        || h["VolumesFrom"].as_array().is_some_and(|a| !a.is_empty())
        || h["PidMode"].as_str().is_some_and(|s| !s.is_empty())
        || h["UTSMode"].as_str().is_some_and(|s| !s.is_empty())
        || h["UsernsMode"] == "host"
        || h["IpcMode"] != "none"
    {
        return Err("实际分析容器隔离配置不符，已拒绝输入样本或启动 Pi。".into());
    }
    Ok(())
}
pub(super) struct Container {
    pub(super) check: DockerCheck,
    pub(super) name: String,
    cleaned: bool,
    owner: String,
}
impl Container {
    pub(super) fn create(
        store: &Store,
        env: &Environment,
        agent: bool,
        kind: &str,
        operation: &str,
        params: &Value,
    ) -> Result<Self, String> {
        let image = env
            .image_id
            .as_ref()
            .ok_or("缺少隔离分析镜像。请到「样本分析 → 隔离环境」构建；不会使用宿主机解析。")?;
        let name = format!("gaga-analysis-{}", uuid::Uuid::new_v4());
        let label = format!("team.j4.gaga.reverse={}", owner(store));
        let serialized = params.to_string();
        let mut args = vec![
            "create",
            "-i",
            "--name",
            &name,
            "--label",
            &label,
            "--network",
            "none",
            "--read-only",
            "--user",
            "65534:65534",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            "64",
            "--memory",
            "768m",
            "--cpus",
            "1",
            "--ipc",
            "none",
            "--ulimit",
            "core=0",
            "--log-driver",
            "none",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=192m,mode=1777",
            "--entrypoint",
            if agent { "node" } else { "gaga-static-worker" },
            image,
        ];
        if agent {
            args.push("/opt/gaga/agent.mjs")
        } else {
            args.extend([kind, operation, &serialized])
        }
        let mut c = Self {
            check: env.docker.clone(),
            name: name.clone(),
            cleaned: false,
            owner: owner(store),
        };
        let out = sandbox::docker(&env.docker, &args, None, 20, 8192)?;
        if !out.ok {
            return Err(format!("创建隔离容器失败：{}", out.stderr));
        }
        let inspect = sandbox::docker(&c.check, &["inspect", &c.name], None, 12, 128 * 1024)?;
        if !inspect.ok {
            return Err("无法校验分析容器；拒绝启动".into());
        }
        let value: Value =
            serde_json::from_slice(&inspect.stdout).map_err(|_| "容器检查响应格式错误")?;
        if let Err(e) = validate(&value[0]) {
            let _ = c.clean();
            return Err(e);
        }
        Ok(c)
    }
    pub(super) fn clean(&mut self) -> Result<(), String> {
        if !self.cleaned {
            // 名称可能在 create 超时后才出现；删除前始终校验工作区归属。
            let out = sandbox::docker(&self.check, &["inspect", &self.name], None, 10, 128 * 1024)?;
            if !out.ok {
                if out.stderr.contains("No such object") || out.stderr.contains("No such container")
                {
                    self.cleaned = true;
                    return Ok(());
                }
                return Err("无法确认分析容器是否存在，清理尚未确认".into());
            }
            let value: Value =
                serde_json::from_slice(&out.stdout).map_err(|_| "清理检查响应无效")?;
            if value[0]["Config"]["Labels"]["team.j4.gaga.reverse"] != self.owner {
                return Err("容器工作区标签不符，拒绝删除".into());
            }
            let out = sandbox::docker(&self.check, &["rm", "-f", &self.name], None, 15, 8192)?;
            if !out.ok {
                return Err(format!("分析容器清理失败：{}", out.stderr));
            }
            self.cleaned = true
        }
        Ok(())
    }
}
impl Drop for Container {
    fn drop(&mut self) {
        let _ = self.clean();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn image_requires_current_worker_version_and_full_digest() {
        let mut v = json!({"Id":format!("sha256:{}", "a".repeat(64)),"Config":{"Labels":{"team.j4.gaga.analysis":VERSION}}});
        assert!(compatible_image(&v).is_some());
        v["Config"]["Labels"]["team.j4.gaga.analysis"] = json!("0.6.6");
        assert!(compatible_image(&v).is_none());
        v["Config"]["Labels"]["team.j4.gaga.analysis"] = json!(VERSION);
        v["Id"] = json!("sha256:partial");
        assert!(compatible_image(&v).is_none());
    }
}
