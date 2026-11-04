use crate::store::{Evidence, Store};
use chrono::Utc;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::Emitter;

const IMAGE: &str = "gaga-observer:0.1.0";
static DOCKER_JOB: Mutex<()> = Mutex::new(());
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerCheck {
    pub cli_found: bool,
    pub daemon_ready: bool,
    pub cli_path: String,
    pub context: String,
    pub server_os: String,
    pub architecture: String,
    pub version: String,
    pub runner_image: Option<String>,
    pub leftovers: Vec<String>,
    pub leftover_volumes: Vec<String>,
    pub message: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobEvent {
    pub time: String,
    pub text: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxJob {
    pub id: String,
    pub case_id: String,
    pub evidence_id: String,
    pub provider: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
    pub container_name: String,
    pub image_id: String,
    pub task_id: Option<u64>,
    pub endpoint: String,
    pub events: Vec<JobEvent>,
    pub report_evidence_id: Option<String>,
    pub exit_code: Option<i64>,
    pub timed_out: bool,
    pub cleanup_confirmed: bool,
    pub output: String,
    pub trace_preview: String,
    pub error: Option<String>,
}
fn now() -> String {
    Utc::now().to_rfc3339()
}
pub fn jobs(store: &Store) -> Result<Vec<SandboxJob>, String> {
    let case = store.active()?;
    let db = store.db.lock().map_err(|e| e.to_string())?;
    let mut q = db
        .prepare("SELECT record FROM sandbox_jobs WHERE case_id=?1 ORDER BY rowid DESC LIMIT 30")
        .map_err(|e| e.to_string())?;
    let rows = q
        .query_map([case], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    rows.map(|v| serde_json::from_str(&v.map_err(|e| e.to_string())?).map_err(|e| e.to_string()))
        .collect()
}
pub fn save_job(
    store: &Store,
    app: Option<&tauri::AppHandle>,
    job: &SandboxJob,
) -> Result<(), String> {
    let db = store.db.lock().map_err(|e| e.to_string())?;
    db.execute("INSERT INTO sandbox_jobs(id,case_id,record) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET record=excluded.record",params![job.id,job.case_id,serde_json::to_string(job).map_err(|e|e.to_string())?]).map_err(|e|e.to_string())?;
    drop(db);
    if let Some(error) = &job.error {
        crate::runtime_log::event("error", "sandbox", "JOB_FAILED", error, Some(&job.id));
    }
    if let Some(app) = app {
        let _ = app.emit("sandbox-progress", job);
    }
    Ok(())
}
pub fn event(
    store: &Store,
    app: Option<&tauri::AppHandle>,
    job: &mut SandboxJob,
    text: &str,
) -> Result<(), String> {
    job.updated_at = now();
    job.events.push(JobEvent {
        time: now(),
        text: text.into(),
    });
    save_job(store, app, job)
}
pub fn new_job(e: &Evidence, provider: &str) -> SandboxJob {
    SandboxJob {
        id: uuid::Uuid::new_v4().to_string(),
        case_id: e.case_id.clone(),
        evidence_id: e.id.clone(),
        provider: provider.into(),
        state: "preparing".into(),
        created_at: now(),
        updated_at: now(),
        container_name: String::new(),
        image_id: String::new(),
        task_id: None,
        endpoint: String::new(),
        events: vec![],
        report_evidence_id: None,
        exit_code: None,
        timed_out: false,
        cleanup_confirmed: false,
        output: String::new(),
        trace_preview: String::new(),
        error: None,
    }
}
pub fn sample(store: &Store, id: &str) -> Result<(Evidence, Vec<u8>), String> {
    let e = store
        .workspace()?
        .evidence
        .into_iter()
        .find(|e| e.id == id && e.kind == "binary")
        .ok_or("请先导入样本，且只能选择当前事件的样本证据。")?;
    if e.size > 32 * 1024 * 1024 {
        return Err("动态任务样本上限 32 MiB。".into());
    }
    let mut bytes = Vec::new();
    crate::store::open_regular_read(&store.root.join("evidence").join(&e.id))
        .map_err(|e| e.to_string())?
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("归档样本超过动态任务大小限制。".into());
    }
    if format!("{:x}", Sha256::digest(&bytes)) != e.sha256 {
        return Err("归档样本摘要不符，已拒绝执行或上传。".into());
    }
    Ok((e, bytes))
}
pub(crate) fn docker_path() -> Option<PathBuf> {
    let executable = if cfg!(windows) {
        "docker.exe"
    } else {
        "docker"
    };
    let mut paths: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|v| std::env::split_paths(&v).collect())
        .unwrap_or_default();
    if cfg!(target_os = "macos") {
        paths.extend(
            [
                "/usr/local/bin",
                "/opt/homebrew/bin",
                "/Applications/Docker.app/Contents/Resources/bin",
            ]
            .map(PathBuf::from),
        );
        if let Some(user) = std::env::var_os("HOME") {
            paths.push(PathBuf::from(user).join(".local/bin"));
        }
    }
    paths
        .into_iter()
        .map(|p| p.join(executable))
        .find(|p| p.is_file())
}
pub(crate) struct Output {
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
}
pub(crate) fn command(
    path: &std::path::Path,
    args: &[String],
    input: Option<Vec<u8>>,
    seconds: u64,
    limit: usize,
) -> Result<Output, String> {
    command_checked(path, args, input, seconds, limit, || Ok(()))
}
pub(crate) fn command_checked(
    path: &std::path::Path,
    args: &[String],
    input: Option<Vec<u8>>,
    seconds: u64,
    limit: usize,
    mut check: impl FnMut() -> Result<(), String>,
) -> Result<Output, String> {
    check()?;
    let mut cmd = Command::new(path);
    cmd.args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().map_err(|e| format!("Docker 启动失败：{e}"))?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    fn reader(mut stream: impl Read, limit: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buffer = [0; 8192];
        while let Ok(n) = stream.read(&mut buffer) {
            if n == 0 {
                break;
            }
            let keep = n.min(limit.saturating_sub(out.len()));
            out.extend_from_slice(&buffer[..keep]);
        }
        out
    }
    let out = std::thread::spawn(move || reader(stdout, limit));
    let err = std::thread::spawn(move || reader(stderr, limit.min(1024 * 1024)));
    let writer = input.map(|data| {
        let mut pipe = child.stdin.take().unwrap();
        std::thread::spawn(move || pipe.write_all(&data))
    });
    let clock = Instant::now();
    let mut stopped = None;
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break Some(s);
        }
        let cancellation = check().err();
        if cancellation.is_some() || clock.elapsed() > Duration::from_secs(seconds) {
            stopped = cancellation;
            #[cfg(unix)]
            {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", &format!("-{}", child.id())])
                    .status();
            }
            #[cfg(windows)]
            {
                let _ = Command::new("taskkill.exe")
                    .args(["/PID", &child.id().to_string(), "/T", "/F"])
                    .status();
            }
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(80));
    };
    if let Some(w) = writer {
        let _ = w.join();
    }
    let stdout = out.join().map_err(|_| "读取 Docker 输出失败")?;
    let stderr =
        String::from_utf8_lossy(&err.join().map_err(|_| "读取 Docker 错误失败")?).into_owned();
    if let Some(error) = stopped {
        return Err(error);
    }
    let status = status.ok_or("Docker 命令超时；请检查引擎状态，并清理本助手遗留容器。")?;
    Ok(Output {
        ok: status.success(),
        code: status.code(),
        stdout,
        stderr,
    })
}
pub(crate) fn docker(
    check: &DockerCheck,
    args: &[&str],
    input: Option<Vec<u8>>,
    seconds: u64,
    limit: usize,
) -> Result<Output, String> {
    let mut flags = vec!["--context".into(), check.context.clone()];
    flags.extend(args.iter().map(|s| s.to_string()));
    command(
        std::path::Path::new(&check.cli_path),
        &flags,
        input,
        seconds,
        limit,
    )
}
fn owner(store: &Store) -> String {
    format!(
        "{:x}",
        Sha256::digest(store.root.to_string_lossy().as_bytes())
    )[..16]
        .into()
}
pub fn preflight(store: &Store) -> DockerCheck {
    preflight_root(&store.root)
}
pub(crate) fn preflight_root(root: &std::path::Path) -> DockerCheck {
    let mut result = DockerCheck {
        cli_found: false,
        daemon_ready: false,
        cli_path: String::new(),
        context: String::new(),
        server_os: String::new(),
        architecture: String::new(),
        version: String::new(),
        runner_image: None,
        leftovers: vec![],
        leftover_volumes: vec![],
        message: String::new(),
    };
    let run = (|| -> Result<(), String> {
        let path=docker_path().ok_or("没有找到 Docker CLI；请先安装并启动 Docker Desktop，或配置专用隔离虚拟机的 Docker context。")?;
        result.cli_found = true;
        result.cli_path = path.display().to_string();
        let context = command(&path, &["context".into(), "show".into()], None, 10, 4096)?;
        if !context.ok {
            return Err(context.stderr);
        }
        result.context = String::from_utf8_lossy(&context.stdout).trim().into();
        let version = docker(
            &result,
            &["version", "--format", "{{json .}}"],
            None,
            12,
            65536,
        )?;
        if !version.ok {
            return Err(format!("Docker CLI 存在，但引擎不可用：{}", version.stderr));
        }
        let v: Value = serde_json::from_slice(&version.stdout).map_err(|e| e.to_string())?;
        result.server_os = v["Server"]["Os"].as_str().unwrap_or("").into();
        result.architecture = v["Server"]["Arch"].as_str().unwrap_or("").into();
        result.version = v["Server"]["Version"].as_str().unwrap_or("").into();
        if result.server_os != "linux" {
            return Err(
                "当前 Docker 引擎不是 Linux；Windows 样本请使用 Windows 虚拟机沙箱。".into(),
            );
        }
        result.daemon_ready = true;
        let image = docker(
            &result,
            &["image", "inspect", IMAGE, "--format", "{{.Id}}"],
            None,
            10,
            4096,
        )?;
        if image.ok {
            let id = String::from_utf8_lossy(&image.stdout).trim().to_owned();
            if id.starts_with("sha256:") {
                result.runner_image = Some(id);
            }
        }
        let filter = format!(
            "team.j4.gaga.owner={}",
            &format!("{:x}", Sha256::digest(root.to_string_lossy().as_bytes()))[..16]
        );
        let leftovers = docker(
            &result,
            &[
                "ps",
                "-a",
                "--filter",
                &format!("label={filter}"),
                "--format",
                "{{.Names}}",
            ],
            None,
            10,
            8192,
        )?;
        if leftovers.ok {
            result.leftovers = String::from_utf8_lossy(&leftovers.stdout)
                .lines()
                .filter(|s| s.starts_with("gaga-lab-"))
                .map(String::from)
                .collect();
        }
        let volumes = docker(
            &result,
            &[
                "volume",
                "ls",
                "--filter",
                &format!("label={filter}"),
                "--format",
                "{{.Name}}",
            ],
            None,
            10,
            8192,
        )?;
        if volumes.ok {
            result.leftover_volumes = String::from_utf8_lossy(&volumes.stdout)
                .lines()
                .filter(|s| s.starts_with("gaga-sample-"))
                .map(String::from)
                .collect();
        }
        result.message = if result.runner_image.is_some() {
            "Docker 引擎和监控镜像可用；仍需确认专用隔离环境。"
        } else {
            "Docker 引擎可用；请先构建监控镜像。"
        }
        .into();
        Ok(())
    })();
    if let Err(e) = run {
        result.message = e;
    }
    result
}
pub fn build_runner(store: &Store, mirror: &str) -> Result<DockerCheck, String> {
    if ![
        "https://dl-cdn.alpinelinux.org/alpine",
        "https://mirrors.aliyun.com/alpine",
    ]
    .contains(&mirror)
    {
        return Err("请选择受支持的软件包仓库。".into());
    }
    let _lock = DOCKER_JOB
        .try_lock()
        .map_err(|_| "已有 Docker 操作在执行")?;
    let check = preflight(store);
    if !check.daemon_ready {
        return Err(check.message);
    }
    let dir = store.root.join("sandbox-tools");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::write(
        dir.join("Dockerfile"),
        include_str!("../../sandbox/Dockerfile"),
    )
    .map_err(|e| e.to_string())?;
    let out = docker(
        &check,
        &[
            "build",
            "--tag",
            IMAGE,
            "--pull=false",
            "--build-arg",
            &format!("APK_MIRROR={mirror}"),
            &dir.to_string_lossy(),
        ],
        None,
        300,
        65536,
    )?;
    if !out.ok {
        return Err(format!("监控镜像构建失败：{}", out.stderr));
    }
    Ok(preflight(store))
}
pub fn cleanup(store: &Store) -> Result<DockerCheck, String> {
    let _lock = DOCKER_JOB.try_lock().map_err(|_| "任务运行期间不能清理")?;
    let check = preflight(store);
    if !check.daemon_ready {
        return Err(check.message);
    }
    for name in &check.leftovers {
        let out = docker(&check, &["rm", "-f", name], None, 12, 4096)?;
        if !out.ok {
            return Err(out.stderr);
        }
    }
    for name in &check.leftover_volumes {
        let out = docker(&check, &["volume", "rm", name], None, 12, 4096)?;
        if !out.ok {
            return Err(out.stderr);
        }
    }
    Ok(preflight(store))
}
pub fn import_report(store: &Store, job: &SandboxJob, report: &Value) -> Result<String, String> {
    if store.active()? != job.case_id {
        return Err("任务期间当前事件发生变更，报告未导入其他事件。".into());
    }
    let dir = store.root.join("sandbox-reports");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("行为报告-{}.json", job.id));
    let data = serde_json::to_vec_pretty(report).map_err(|e| e.to_string())?;
    if data.len() > 32 * 1024 * 1024 {
        return Err("沙箱报告超过本版归档上限 32 MiB，请在沙箱端保留完整报告。".into());
    }
    fs::write(&path, data).map_err(|e| e.to_string())?;
    let evidence = store.analyze_file(path.display().to_string(), "triage".into());
    let _ = fs::remove_file(path);
    Ok(evidence?.id)
}
struct ContainerGuard<'a> {
    check: &'a DockerCheck,
    name: String,
    cleaned: bool,
}
struct VolumeGuard<'a> {
    check: &'a DockerCheck,
    name: String,
    cleaned: bool,
}
impl VolumeGuard<'_> {
    fn clean(&mut self) -> Result<(), String> {
        if self.cleaned {
            return Ok(());
        }
        let out = docker(self.check, &["volume", "rm", &self.name], None, 12, 4096)?;
        if !out.ok {
            return Err(out.stderr);
        }
        self.cleaned = true;
        Ok(())
    }
}
impl Drop for VolumeGuard<'_> {
    fn drop(&mut self) {
        let _ = self.clean();
    }
}
fn validate_isolation(v: &Value, volume: &str) -> Result<(), String> {
    let h = &v["HostConfig"];
    let no_mounts = v["Mounts"].as_array().is_some_and(|mounts| {
        mounts.len() == 1
            && mounts[0]["Type"] == "volume"
            && mounts[0]["Name"] == volume
            && mounts[0]["Destination"] == "/sample"
            && mounts[0]["RW"] == false
    });
    if h["NetworkMode"] != "none"
        || h["ReadonlyRootfs"] != true
        || h["Privileged"] != false
        || v["Config"]["User"] != "65534:65534"
        || !h["CapDrop"]
            .as_array()
            .is_some_and(|caps| caps.iter().any(|c| c == "ALL"))
        || !h["SecurityOpt"].as_array().is_some_and(|options| {
            options.iter().any(|s| {
                s.as_str()
                    .is_some_and(|s| s == "no-new-privileges=true" || s == "no-new-privileges")
            })
        })
        || !no_mounts
        || h["Binds"].as_array().is_some_and(|v| !v.is_empty())
        || h["Memory"].as_i64() != Some(268435456)
        || h["PidsLimit"].as_i64() != Some(64)
    {
        return Err("实际容器隔离配置与预期不符，已拒绝启动样本。".into());
    }
    Ok(())
}
impl ContainerGuard<'_> {
    fn clean(&mut self) -> Result<(), String> {
        if self.cleaned {
            return Ok(());
        }
        let out = docker(self.check, &["rm", "-f", &self.name], None, 12, 4096)?;
        if !out.ok {
            return Err(out.stderr);
        }
        self.cleaned = true;
        Ok(())
    }
}
impl Drop for ContainerGuard<'_> {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.clean();
        }
    }
}
pub fn run_docker(
    store: &Store,
    app: Option<&tauri::AppHandle>,
    evidence_id: String,
    seconds: u64,
    lab_ack: bool,
) -> Result<SandboxJob, String> {
    if !lab_ack {
        return Err(
            "请先确认当前 Docker 位于专用、可丢弃的隔离虚拟机中。普通容器不能保证隔离恶意样本。"
                .into(),
        );
    }
    if !(5..=60).contains(&seconds) {
        return Err("观察时间需为 5–60 秒。".into());
    }
    let _lock = DOCKER_JOB
        .try_lock()
        .map_err(|_| "同一时间只允许一个 Docker 任务")?;
    let (e, bytes) = sample(store, &evidence_id)?;
    let shell = bytes.starts_with(b"#!")
        && String::from_utf8_lossy(&bytes[..bytes.len().min(100)])
            .lines()
            .next()
            .is_some_and(|s| s.contains("/sh") || s.contains("/bash"));
    if !bytes.starts_with(b"\x7fELF") && !shell {
        return Err("Docker 入口仅接受 Linux ELF 或带 sh / bash shebang 的脚本；EXE / DLL 请使用 Windows 虚拟机。".into());
    }
    let check = preflight(store);
    if !check.daemon_ready {
        return Err(check.message);
    }
    let image = check.runner_image.clone().ok_or("请先构建监控镜像。")?;
    if bytes.starts_with(b"\x7fELF") && bytes.len() >= 20 {
        let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
        if bytes[5] != 1
            || !(check.architecture == "arm64" && machine == 183
                || check.architecture == "amd64" && machine == 62)
        {
            return Err("ELF 架构与 Linux 引擎不匹配；本版不自动安装模拟器。".into());
        }
    }
    let mut job = new_job(&e, "docker");
    job.image_id = image;
    job.container_name = format!("gaga-lab-{}", job.id);
    event(
        store,
        app,
        &mut job,
        "已核对归档 SHA-256；固定当前 Docker context 与镜像 ID",
    )?;
    let mut guard = ContainerGuard {
        check: &check,
        name: job.container_name.clone(),
        cleaned: true,
    };
    let volume_name = format!("gaga-sample-{}", job.id);
    let mut volume_guard = VolumeGuard {
        check: &check,
        name: volume_name.clone(),
        cleaned: true,
    };
    let run = (|| -> Result<(), String> {
        let deadline = seconds.to_string();
        let label = format!("team.j4.gaga.owner={}", owner(store));
        let volume = docker(
            &check,
            &["volume", "create", "--label", &label, &volume_name],
            None,
            10,
            4096,
        )?;
        if !volume.ok {
            return Err(volume.stderr);
        }
        volume_guard.cleaned = false;
        let stage = format!("{}-stage", job.container_name);
        let mut stage_guard = ContainerGuard {
            check: &check,
            name: stage.clone(),
            cleaned: false,
        };
        let mount = format!("type=volume,source={volume_name},target=/sample");
        // Fixed cat receives opaque bytes over stdin. The staging container never executes the sample.
        let staged = docker(
            &check,
            &[
                "run",
                "--name",
                &stage,
                "--label",
                &label,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges=true",
                "--pids-limit",
                "16",
                "--memory",
                "64m",
                "--cpus",
                "0.5",
                "--mount",
                &mount,
                "--user",
                "0:0",
                "--entrypoint",
                "/bin/sh",
                "-i",
                &job.image_id,
                "-c",
                "umask 022; cat > /sample/gaga-sample && chmod 0555 /sample/gaga-sample",
            ],
            Some(bytes.clone()),
            20,
            4096,
        )?;
        if !staged.ok {
            return Err(staged.stderr);
        }
        stage_guard.clean()?;
        event(
            store,
            app,
            &mut job,
            "已将样本作为不执行的字节流写入专属临时卷；运行容器只读挂载该卷",
        )?;
        let readonly_mount = format!("type=volume,source={volume_name},target=/sample,readonly");
        let mut args = vec![
            "create",
            "--name",
            &job.container_name,
            "--label",
            &label,
            "--network",
            "none",
            "--read-only",
            "--mount",
            &readonly_mount,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--memory-swap",
            "256m",
            "--cpus",
            "0.5",
            "--user",
            "65534:65534",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=32m",
            "--shm-size",
            "8m",
            "--ulimit",
            "fsize=16777216:16777216",
            "--ulimit",
            "nofile=256:256",
            "--restart",
            "no",
            "--log-driver",
            "local",
            "--log-opt",
            "max-size=1m",
            "--log-opt",
            "max-file=2",
            &job.image_id,
            "/usr/bin/timeout",
            "-s",
            "KILL",
            &deadline,
            "/usr/bin/strace",
            "-f",
            "-ttt",
            "-s",
            "160",
            "-yy",
            "-e",
            "trace=process,file,network",
            "-o",
            "/dev/stderr",
            "--",
        ];
        if shell {
            args.push("/bin/sh");
        }
        args.push("/sample/gaga-sample");
        // BusyBox supplies timeout at /usr/bin/timeout in Alpine.
        let out = docker(&check, &args, None, 15, 4096)?;
        if !out.ok {
            return Err(out.stderr);
        }
        guard.cleaned = false;
        let inspection = docker(&check, &["inspect", &job.container_name], None, 10, 262144)?;
        if !inspection.ok {
            return Err(inspection.stderr);
        }
        let inspection: Value =
            serde_json::from_slice(&inspection.stdout).map_err(|e| e.to_string())?;
        validate_isolation(&inspection[0], &volume_name)?;
        event(
            store,
            app,
            &mut job,
            "已创建临时容器：禁网、只读根文件系统、无主机挂载、无额外 capability、资源限额",
        )?;
        let out = docker(&check, &["start", &job.container_name], None, 12, 4096)?;
        if !out.ok {
            return Err(out.stderr);
        }
        job.state = "running".into();
        event(
            store,
            app,
            &mut job,
            "样本已启动；跟踪进程、文件与网络系统调用，默认 seccomp 保持启用",
        )?;
        let clock = Instant::now();
        let state = loop {
            let out = docker(
                &check,
                &[
                    "inspect",
                    "--format",
                    "{{json .State}}",
                    &job.container_name,
                ],
                None,
                5,
                65536,
            )?;
            if !out.ok {
                return Err(out.stderr);
            }
            let state: Value = serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
            if state["Running"] == false {
                break state;
            }
            if clock.elapsed() > Duration::from_secs(seconds + 3) {
                job.timed_out = true;
                let _ = docker(&check, &["kill", &job.container_name], None, 6, 4096);
                let out = docker(
                    &check,
                    &[
                        "inspect",
                        "--format",
                        "{{json .State}}",
                        &job.container_name,
                    ],
                    None,
                    5,
                    65536,
                )?;
                break serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
            }
            std::thread::sleep(Duration::from_millis(350));
        };
        job.exit_code = state["ExitCode"].as_i64();
        job.timed_out |= job.exit_code == Some(137);
        event(
            store,
            app,
            &mut job,
            "执行结束，收集容器退出状态、输出和系统调用轨迹",
        )?;
        let logs = docker(
            &check,
            &[
                "logs",
                "--timestamps",
                "--tail",
                "5000",
                &job.container_name,
            ],
            None,
            10,
            500000,
        )?;
        let output = String::from_utf8_lossy(&logs.stdout).into_owned();
        job.output = crate::analyzers::cut(&output, 12000);
        let trace_text = logs.stderr.clone();
        let trace_truncated = trace_text.len() >= 500000;
        job.trace_preview = crate::analyzers::cut(&trace_text, 30000);
        let captured = trace_text.contains("execve(");
        guard.clean()?;
        volume_guard.clean()?;
        job.cleanup_confirmed = true;
        event(
            store,
            app,
            &mut job,
            "临时容器与样本卷已删除；仅保留归档样本、报告和操作记录",
        )?;
        let report = json!({"format":"gaga-dynamic/1","provider":"docker-strace","jobId":job.id,"sampleEvidence":e.id,"sampleSha256":e.sha256,"dockerContext":check.context,"architecture":check.architecture,"imageId":job.image_id,"secondsLimit":seconds,"isolationConfig":{"hostConfig":inspection[0]["HostConfig"],"mounts":inspection[0]["Mounts"],"user":inspection[0]["Config"]["User"]},"state":state,"output":output,"syscallTrace":trace_text,"traceTruncated":trace_truncated,"capturePresent":captured,"events":job.events,"limitations":["普通容器共享内核，不能保证隔离恶意样本，须使用专用、可丢弃隔离虚拟机。","禁网仅记录网络调用尝试；没有互联网响应与完整 PCAP。","仅支持当前引擎架构的 Linux ELF 或 sh 脚本；Alpine 不保证兼容 glibc 动态程序。","系统调用跟踪可能被反调试、同权限篡改或规避，不构成完整可信行为链。","/tmp 禁止执行，写入行为受限；环境限制会改变样本行为。","采集器与样本 stderr 混合；最多读取 Docker 日志末 5000 行、每输出通道 500000 字节，日志轮转与截断可能丢失行为。","超时退出与被 SIGKILL 均可能返回 137，不能仅凭此区分。"]});
        job.report_evidence_id = Some(import_report(store, &job, &report)?);
        job.state = if captured {
            "completed"
        } else {
            "collection_incomplete"
        }
        .into();
        Ok(())
    })();
    if let Err(error) = run {
        let cleanup = guard.clean();
        let volume_cleanup = volume_guard.clean();
        job.cleanup_confirmed = cleanup.is_ok() && volume_cleanup.is_ok();
        job.error = Some(error);
        job.state = "failed".into();
    }
    event(store, app, &mut job, "任务结束；行为报告需人工复核")?;
    Ok(job)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn command_deadline_terminates_its_own_child_group() {
        let start = Instant::now();
        let result = command(
            std::path::Path::new("/bin/sh"),
            &["-c".into(), "sleep 30 & wait".into()],
            None,
            1,
            4096,
        );
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }
    #[test]
    fn isolation_checks_actual_settings_before_execution() {
        let safe = json!({"Config":{"User":"65534:65534"},"Mounts":[{"Type":"volume","Name":"test-volume","Destination":"/sample","RW":false}],"HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges=true"],"Memory":268435456,"PidsLimit":64,"Binds":null}});
        assert!(validate_isolation(&safe, "test-volume").is_ok());
        for (key, value) in [
            ("NetworkMode", json!("host")),
            ("Privileged", json!(true)),
            ("ReadonlyRootfs", json!(false)),
            ("CapDrop", json!([])),
            ("Binds", json!(["/:/host"])),
        ] {
            let mut altered = safe.clone();
            altered["HostConfig"][key] = value;
            assert!(validate_isolation(&altered, "test-volume").is_err());
        }
        let mut altered = safe.clone();
        altered["Mounts"] = json!([{"Type":"volume"}]);
        assert!(validate_isolation(&altered, "test-volume").is_err());
    }
    #[test]
    fn sample_integrity_and_execution_gate_are_enforced() {
        let root = std::env::temp_dir().join(format!("gaga-sample-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let p = root.join("test.sh");
        fs::write(&p, "#!/bin/sh\nprintf harmless").unwrap();
        let e = store
            .analyze_file(p.display().to_string(), "binary".into())
            .unwrap();
        assert!(run_docker(&store, None, e.id.clone(), 10, false)
            .err()
            .unwrap()
            .contains("专用"));
        assert!(sample(&store, &e.id).is_ok());
        crate::store::test_overwrite_archive(root.join("evidence").join(&e.id), "changed").unwrap();
        assert!(sample(&store, &e.id).is_err());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
