//! Networked website rendering is isolated from the evidence/malware workers.
//! No host files, credentials, Docker socket or reusable browser profile enter it.
use crate::{sandbox, store::Store};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
const IMAGE: &str = "gaga-monitor-browser:1";
static BUILD: std::sync::Mutex<()> = std::sync::Mutex::new(());
const SOURCES: [(&str, &[u8]); 4] = [
    (
        "Dockerfile",
        include_bytes!("../../monitor-browser/Dockerfile"),
    ),
    (
        "package.json",
        include_bytes!("../../monitor-browser/package.json"),
    ),
    (
        "package-lock.json",
        include_bytes!("../../monitor-browser/package-lock.json"),
    ),
    (
        "capture.mjs",
        include_bytes!("../../monitor-browser/capture.mjs"),
    ),
];
/// A worker update must invalidate an older local image even when its tag is
/// unchanged. This is compatibility checking, not image publisher attestation.
fn source_hash() -> String {
    let mut hash = Sha256::new();
    for (name, bytes) in SOURCES {
        hash.update(name.as_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    format!("{:x}", hash.finalize())
}
fn image_id(v: &Value) -> Option<&str> {
    let id = v["Id"].as_str()?;
    (v["Config"]["Labels"]["team.j4.gaga.browser"] == "1"
        && v["Config"]["Labels"]["team.j4.gaga.browser.source"] == source_hash()
        && id
            .strip_prefix("sha256:")
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())))
    .then_some(id)
}
fn image(check: &sandbox::DockerCheck) -> Result<String, String> {
    let out = sandbox::docker(
        check,
        &["image", "inspect", IMAGE, "--format", "{{json .}}"],
        None,
        10,
        8192,
    )?;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    if out.ok {
        if let Some(id) = image_id(&v) {
            return Ok(id.into());
        }
        return Err("自动截图环境版本需要更新，请在资产巡检设置中重新准备截图环境。".into());
    }
    Err("自动截图环境尚未准备，请在资产巡检设置中准备浏览器容器。".into())
}
pub fn environment(store: &Store) -> Value {
    let check = sandbox::preflight(store);
    let result = if check.daemon_ready {
        image(&check)
    } else {
        Err(check.message.clone())
    };
    json!({"ready":result.is_ok(),"message":result.err().unwrap_or_else(||"浏览器容器已就绪".into())})
}
pub fn build(store: &Store, mirror: &str) -> Result<Value, String> {
    let source = match mirror {
        "official" => "https://dl-cdn.alpinelinux.org/alpine",
        "aliyun" => "https://mirrors.aliyun.com/alpine",
        _ => return Err("请选择官方源或阿里云镜像源".into()),
    };
    let source_arg = format!("ALPINE_MIRROR={source}");
    let revision_arg = format!("GAGA_BROWSER_SOURCE_SHA256={}", source_hash());
    let _guard = BUILD.try_lock().map_err(|_| "浏览器容器正在准备")?;
    let check = sandbox::preflight(store);
    if !check.daemon_ready {
        return Err(check.message);
    }
    if image(&check).is_ok() {
        return Ok(environment(store));
    }
    let dir = store
        .root
        .join(format!("browser-build-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
    let result = (|| {
        for (name, bytes) in SOURCES {
            std::fs::write(dir.join(name), bytes).map_err(|e| e.to_string())?;
        }
        let out = sandbox::docker(
            &check,
            &[
                "build",
                "--build-arg",
                &source_arg,
                "--build-arg",
                &revision_arg,
                "-t",
                IMAGE,
                &dir.to_string_lossy(),
            ],
            None,
            600,
            1024 * 1024,
        )?;
        if !out.ok {
            return Err(format!(
                "浏览器容器准备失败：{}",
                crate::analyzers::cut(&out.stderr, 1800)
            ));
        }
        image(&check)?;
        Ok(environment(store))
    })();
    let _ = std::fs::remove_dir_all(dir);
    result
}
pub fn capture_root(root: &std::path::Path, url: &str, follow: bool) -> Result<Value, String> {
    let check = sandbox::preflight_root(root);
    if !check.daemon_ready {
        return Err(check.message);
    }
    let image = image(&check)?;
    let name = format!("gaga-browser-{}", uuid::Uuid::new_v4());
    let result = sandbox::docker(
        &check,
        &[
            "run",
            "--rm",
            "-i",
            "--pull=never",
            "--name",
            &name,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=128",
            "--memory=768m",
            "--cpus=1",
            "--user=1000:1000",
            "--network=bridge",
            "--tmpfs=/tmp:rw,nosuid,nodev,size=256m,mode=1777",
            "--env=HOME=/tmp",
            &image,
        ],
        Some(
            serde_json::to_vec(&json!({"url":url,"followRedirects":follow}))
                .map_err(|e| e.to_string())?,
        ),
        50,
        14 * 1024 * 1024,
    );
    // Killing docker CLI does not stop a daemon-owned container. Always remove
    // this exact random name after completion/timeout; never prune user containers.
    let _ = sandbox::docker(&check, &["rm", "-f", &name], None, 10, 1024);
    let out = result?;
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|_| {
        format!(
            "截图容器未返回有效结果：{}",
            crate::analyzers::cut(&out.stderr, 500)
        )
    })?;
    if !out.ok || v["error"].is_string() {
        return Err(v["error"].as_str().unwrap_or("截图失败").into());
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_image_rejects_stale_source_and_invalid_digest() {
        let mut v = json!({"Id":format!("sha256:{}", "a".repeat(64)),"Config":{"Labels":{"team.j4.gaga.browser":"1","team.j4.gaga.browser.source":source_hash()}}});
        assert!(image_id(&v).is_some());
        v["Config"]["Labels"]["team.j4.gaga.browser.source"] = json!("old-source");
        assert!(image_id(&v).is_none());
        v["Config"]["Labels"]["team.j4.gaga.browser.source"] = json!(source_hash());
        v["Id"] = json!("sha256:aaaa");
        assert!(image_id(&v).is_none());
    }
}
