//! Explicit developer-only end-to-end exercise. Uses a new workspace and fixed inert fixtures.
use crate::{ai, collector, dashboard, investigation, report, sandbox, store::Store};
use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path, process::Command, time::Instant};

fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn docker(args: &[&str]) -> Result<String, String> {
    let out = Command::new("docker")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "Docker 失败：{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
struct Cleanup<'a>(&'a Store);
impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        collector::cleanup_smoke_credentials(self.0);
    }
}
struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}
fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 256 * 1024];
    loop {
        let n = file.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&chunk[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn metric(e: &crate::store::Evidence, label: &str) -> Option<String> {
    e.report
        .metrics
        .iter()
        .find(|m| m.label == label)
        .map(|m| m.value.clone())
}
/// 测试只解包自己生成的三个固定文件；不用 ZipArchive::extract，不恢复归档权限/链接。
/// 避免 RUSTSEC-2026-0367/0368/0369 涉及的通用提取路径。
fn extract_task(bundle: &Path, destination: &Path) -> Result<(), String> {
    use std::io::Write;
    let mut archive = zip::ZipArchive::new(fs::File::open(bundle).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if archive.len() != 3 {
        return Err("测试任务必须恰含三个固定文件".into());
    }
    fs::create_dir_all(destination).map_err(|e| e.to_string())?;
    for name in ["gaga-agent", "gaga-task.json", "README.txt"] {
        let mut item = archive.by_name(name).map_err(|e| e.to_string())?;
        if !item.is_file()
            || item.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000)
            || item.size() > 32 * 1024 * 1024
        {
            return Err("测试任务拒绝链接或超大文件".into());
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if name == "gaga-agent" { 0o700 } else { 0o600 });
        }
        let mut output = options
            .open(destination.join(name))
            .map_err(|e| e.to_string())?;
        std::io::copy(&mut item.by_ref().take(32 * 1024 * 1024 + 1), &mut output)
            .map_err(|e| e.to_string())?;
        output.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn run(root: &Path, fixtures: &Path, templates: &Path) -> Result<(), String> {
    require(
        !root.exists(),
        "必须使用新的隔离目录，避免读取真实凭据或覆盖调查数据。",
    )?;
    let store = Store::open(root.to_path_buf())?;
    let _cleanup = Cleanup(&store);
    store.create_case("[本机实测] Docker 采集与 1 GiB 系统日志".into())?;
    let manifest: Value = serde_json::from_slice(
        &fs::read(fixtures.join("manifest.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let preflight = sandbox::preflight(&store);
    require(
        preflight.daemon_ready && preflight.server_os == "linux",
        "需要可用的 Linux Docker Engine",
    )?;
    let image = manifest["image"].as_str().ok_or("缺少测试镜像")?;
    // No image download/build, no host network, and no access to a Docker socket in the container.
    let image_id = docker(&["image", "inspect", image, "--format", "{{.Id}}"])?;
    let php_path = fixtures.join("disabled-webshell.php");
    let php = investigation::local_analyze(&store, None, || {
        store.analyze_file(php_path.display().to_string(), "webshell".into())
    })?;
    require(
        php.report
            .findings
            .iter()
            .any(|f| f.title == "动态代码执行")
            && php
                .report
                .findings
                .iter()
                .any(|f| f.title == "系统命令调用"),
        "WebShell 特征未被定位",
    )?;
    require(
        php.report
            .findings
            .iter()
            .all(|f| f.line.is_some() && !f.excerpt.is_empty()),
        "缺少源码行号或举证原文",
    )?;
    let benign = investigation::local_analyze(&store, None, || {
        store.analyze_file(
            fixtures.join("benign.php").display().to_string(),
            "webshell".into(),
        )
    })?;
    require(benign.report.findings.is_empty(), "无害对照产生意外命中")?;
    let php_name = format!("gaga-field-php-{}", uuid::Uuid::new_v4().simple());
    let php_guard = Container(php_name.clone());
    let mount = format!("{}:/fixture:ro", fixtures.display());
    let output = docker(&[
        "run",
        "--rm",
        "--name",
        &php_name,
        "--label",
        "team.j4.gaga.field-test=1",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "128m",
        "--pids-limit",
        "32",
        "--user",
        "65534:65534",
        "-v",
        &mount,
        "--entrypoint",
        "php",
        image,
        "/fixture/disabled-webshell.php",
    ])?;
    require(
        output.trim() == "GAGA_DISABLED_WEBSHELL_FIXTURE",
        "禁用样例未按预期退出",
    )?;
    drop(php_guard);
    eprintln!("FIELD: WebShell 静态特征与 PHP 禁用入口容器验证通过");

    let arch = match preflight.architecture.as_str() {
        "aarch64" | "arm64" => "linux-arm64",
        "x86_64" | "amd64" => "linux-amd64",
        _ => return Err("不支持此 Docker 架构".into()),
    };
    let bundle = root.join("generated-task.zip");
    let task = collector::generate(
        &store,
        collector::TaskInput {
            name: "Docker 本机只读快照实测".into(),
            target: "一次性隔离测试容器".into(),
            mode: "snapshot".into(),
            architecture: arch.into(),
            interface: "eth0".into(),
            duration_seconds: 10,
            batch_seconds: 5,
            snaplen: 128,
            include_http: false,
            hours: 1,
            online: false,
        },
        &bundle,
        templates,
    )?;
    let task_dir = root.join("task");
    fs::create_dir_all(&task_dir).map_err(|e| e.to_string())?;
    extract_task(&bundle, &task_dir)?;
    let output_dir = root.join("agent-output");
    fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            task_dir.join("gaga-task.json"),
            fs::Permissions::from_mode(0o644),
        )
        .map_err(|e| e.to_string())?;
        fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o777))
            .map_err(|e| e.to_string())?;
    }
    let task_mount = format!("{}:/task:ro", task_dir.display());
    let output_mount = format!("{}:/output", output_dir.display());
    let name = format!("gaga-field-agent-{}", uuid::Uuid::new_v4().simple());
    let guard = Container(name.clone());
    let clock = Instant::now();
    let collection_output = docker(&[
        "run",
        "--name",
        &name,
        "--hostname",
        "gaga-isolated-fixture",
        "--label",
        "team.j4.gaga.field-test=1",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "128m",
        "--pids-limit",
        "32",
        "--user",
        "65534:65534",
        "-v",
        &task_mount,
        "-v",
        &output_mount,
        "--entrypoint",
        "/task/gaga-agent",
        image,
        "-config",
        "/task/gaga-task.json",
        "-out",
        "/output",
    ])?;
    let collect_ms = clock.elapsed().as_millis();
    let inspect = docker(&["inspect", &name])?;
    fs::write(root.join("container-inspect.json"), &inspect).map_err(|e| e.to_string())?;
    let inspect_evidence = investigation::local_analyze(&store, None, || {
        store.analyze_file(
            root.join("container-inspect.json").display().to_string(),
            "containers".into(),
        )
    })?;
    let artifacts = fs::read_dir(&output_dir)
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    require(artifacts.len() == 1, "预期单个快照加密包")?;
    let encrypted = fs::read(artifacts[0].path()).map_err(|e| e.to_string())?;
    let envelope: Value = serde_json::from_slice(&encrypted).map_err(|e| e.to_string())?;
    require(
        envelope["taskId"] == task.id
            && envelope.get("body").is_none()
            && !String::from_utf8_lossy(&encrypted).contains("gaga-isolated-fixture"),
        "采集输出未正确加密",
    )?;
    let decrypted = investigation::local_analyze(&store, None, || {
        collector::ingest(&store, None, &encrypted, None)
    })?;
    let payload: Value = serde_json::from_slice(
        &fs::read(root.join("evidence").join(&decrypted.id)).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    require(
        payload["hostname"] == "gaga-isolated-fixture"
            && payload["os"] == "linux"
            && payload["kind"] == "snapshot",
        "未得到真实容器快照",
    )?;
    let files = payload["body"]["files"].as_array().ok_or("缺少采集文件")?;
    let commands = payload["body"]["commands"]
        .as_array()
        .ok_or("缺少采集命令")?;
    require(files.len() == 6 && commands.len() == 4, "采集清单不完整")?;
    for file in files {
        require(
            file["sha256"]
                == format!(
                    "{:x}",
                    Sha256::digest(file["text"].as_str().ok_or("采集文件失败")?.as_bytes())
                ),
            "采集文件摘要错误",
        )?;
    }
    require(
        commands[0].get("error").is_none()
            && commands[0]["output"]
                .as_str()
                .unwrap_or("")
                .contains("gaga-agent"),
        "未采集到 Agent 实际进程",
    )?;
    let errors = commands.iter().filter(|r| r.get("error").is_some()).count();
    require(
        errors == 3 && metric(&decrypted, "采集错误项") == Some("3".into()),
        "最小容器的 ss / Docker 缺失必须明确显示",
    )?;
    let replay = collector::ingest(&store, None, &encrypted, None)
        .err()
        .ok_or("未拒绝重放")?;
    require(replay.contains("duplicate"), "重放错误原因不符")?;
    let mut tampered = envelope.clone();
    tampered["mac"] = json!("00".repeat(32));
    require(
        collector::ingest(&store, None, &serde_json::to_vec(&tampered).unwrap(), None).is_err(),
        "未拒绝篡改包",
    )?;
    let other = Store::open(root.join("other-client"))?;
    let other_cleanup = Cleanup(&other);
    collector::ensure_identity(&other)?;
    {
        let original = store.db.lock().map_err(|e| e.to_string())?;
        let row: (String, String, String, String, String) = original
            .query_row(
                "SELECT id,case_id,expires_at,token_box,record FROM collector_tasks WHERE id=?1",
                [&task.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .map_err(|e| e.to_string())?;
        let db = other.db.lock().map_err(|e| e.to_string())?;
        db.execute(
            "INSERT INTO cases VALUES(?1,'copied task test',?2)",
            rusqlite::params![row.1, Utc::now().to_rfc3339()],
        )
        .map_err(|e| e.to_string())?;
        db.execute(
            "INSERT INTO collector_tasks VALUES(?1,?2,1,?3,?4,?5)",
            rusqlite::params![row.0, row.1, row.2, row.3, row.4],
        )
        .map_err(|e| e.to_string())?;
    }
    let wrong = collector::ingest(&other, None, &encrypted, None)
        .err()
        .ok_or("其他客户端错误地解密了采集包")?;
    require(
        wrong.contains("无法解封任务凭据"),
        "其他客户端没有触发真实私钥校验",
    )?;
    drop(other_cleanup);
    drop(guard);
    require(
        Command::new("docker")
            .args(["inspect", &name])
            .output()
            .map_err(|e| e.to_string())?
            .status
            .code()
            != Some(0),
        "测试容器未清理",
    )?;
    eprintln!("FIELD: 实际 Agent 已完成容器采集、加密、原客户端解密、跨客户端拒绝与重放拒绝");

    let mut logs = Vec::new();
    for fixture in manifest["logs"].as_array().ok_or("缺少日志材料")? {
        let file = fixtures.join(fixture["name"].as_str().ok_or("日志文件名无效")?);
        let clock = Instant::now();
        let evidence = investigation::local_analyze(&store, None, || {
            store.analyze_file(file.display().to_string(), "logs".into())
        })?;
        let elapsed = clock.elapsed().as_millis();
        require(
            evidence.sha256 == fixture["sha256"]
                && evidence.size == fixture["bytes"].as_u64().unwrap_or(0),
            "大日志归档摘要或字节数不符",
        )?;
        require(
            metric(&evidence, "日志行数") == Some(fixture["lines"].to_string()),
            "日志行数不符",
        )?;
        require(
            metric(&evidence, "规则命中总数") == Some(fixture["hits"].to_string()),
            "完整命中计数不符",
        )?;
        require(
            evidence.report.findings.iter().any(|f| {
                f.line == fixture["lateSuccessLine"].as_u64().map(|n| n as usize)
                    && f.title.contains("登录成功")
            }),
            "日志尾部成功登录未被保留",
        )?;
        require(
            metric(&evidence, "结构化解析") == Some(fixture["parsed"].to_string()),
            "结构化解析计数不符",
        )?;
        require(
            hash_file(&root.join("evidence").join(&evidence.id))? == evidence.sha256,
            "归档后全文件摘要复核失败",
        )?;
        let prompt = ai::material(&store, &evidence.id)?;
        require(
            prompt.contains("Accepted publickey") && prompt.contains("COMMAND=/usr/bin/id"),
            "AI 材料遗漏少见但关键的尾部记录",
        )?;
        fs::write(
            root.join(format!(
                "{}-ai-material.txt",
                fixture["name"].as_str().unwrap()
            )),
            &prompt,
        )
        .map_err(|e| e.to_string())?;
        let indexed = crate::logbook::query(
            &store,
            crate::logbook::Filter {
                evidence_id: Some(evidence.id.clone()),
                kind: Some("ssh_success".into()),
                ..Default::default()
            },
        )?;
        let occurrence = indexed["events"][0]["at"]
            .as_str()
            .ok_or("尾部登录缺少原文时间")?
            .to_string();
        store.add_node(
            format!("[测试] {} 尾部登录记录", evidence.name),
            "生成的测试日志；不代表真实入侵。发生时间取自原文；已保留原文行号，等待人工复核。截图待补。".into(),
            occurrence,
            "J4team 本机验证".into(),
            Some(evidence.id.clone()),
            evidence
                .report
                .findings
                .iter()
                .find(|f| f.title.contains("登录成功"))
                .map(|f| f.id.clone()),
        )?;
        logs.push(json!({"evidenceId":evidence.id,"name":evidence.name,"bytes":evidence.size,"sha256":evidence.sha256,"elapsedMs":elapsed,"throughputMiBPerSecond":(evidence.size as f64/1048576.0)/(elapsed.max(1) as f64/1000.0),"report":evidence.report,"aiMaterialChars":prompt.chars().count(),"fullArchivedSha256Rechecked":true}));
        eprintln!(
            "FIELD: {} / {} 字节 / {} ms / 尾部举证与 AI 材料核对通过",
            evidence.name, evidence.size, elapsed
        );
    }
    // Separate executable diagnostic is harmless; the inert PHP fixture is never sent to this runner.
    let shell = investigation::local_analyze(&store, None, || {
        store.analyze_file(
            fixtures
                .join("harmless-diagnostic.sh")
                .display()
                .to_string(),
            "binary".into(),
        )
    })?;
    let job = sandbox::run_docker(&store, None, shell.id, 10, true)?;
    require(
        job.state == "completed"
            && job.cleanup_confirmed
            && job.trace_preview.contains("execve(")
            && job.trace_preview.contains("gaga-field-marker")
            && job.trace_preview.contains("connect("),
        "实际 strace 容器观测不完整",
    )?;
    store.add_node(
        "[测试] 容器采集与解密完成".into(),
        format!(
            "真实只读快照：{} 个文件项、{} 个命令项，{} 项工具缺失。测试容器已删除。",
            files.len(),
            commands.len(),
            errors
        ),
        Utc::now().to_rfc3339(),
        "J4team 本机验证".into(),
        Some(decrypted.id.clone()),
        None,
    )?;
    report::export_docx(&store, &root.join("field-report.docx"))?;
    report::export_html(&store, &root.join("field-report.html"))?;
    let dashboard = dashboard::snapshot(&store, &store.active()?, "case", 7, Utc::now(), false)?;
    fs::write(
        root.join("dashboard-snapshot.json"),
        serde_json::to_vec_pretty(&dashboard).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    let summary = json!({"format":"gaga-field-verification/1","version":env!("CARGO_PKG_VERSION"),"testedAt":Utc::now().to_rfc3339(),"nativeBackend":true,"buildProfile":"debug, unoptimized","source":"generated inert fixtures; actual Docker execution and actual Agent binary","docker":preflight,"imageId":image_id.trim(),"webshell":{"inert":true,"executedOnlyDisabledEntry":true,"output":output.trim(),"findings":php.report.findings,"benignControlFindings":benign.report.findings.len()},"agent":{"architecture":arch,"collectMs":collect_ms,"output":collection_output.trim(),"encryptedBytes":encrypted.len(),"files":files.len(),"commands":commands.len(),"commandErrors":errors,"originalClientDecrypted":true,"otherClientPrivateKeyRejected":true,"replayRejected":true,"tamperingRejected":true,"containerRemoved":true,"inspectEvidenceId":inspect_evidence.id,"decryptedEvidenceId":decrypted.id},"logs":logs,"dynamic":{"jobId":job.id,"state":job.state,"cleanupConfirmed":job.cleanup_confirmed,"execveObserved":true,"fileWriteObserved":true,"connectAttemptObserved":true},"dashboard":dashboard,"externalModelCalled":false,"realMalwareExecuted":false,"realWindowsTested":false});
    fs::write(
        root.join("field-verification.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    println!(
        "FIELD_VERIFIED: {}",
        root.join("field-verification.json").display()
    );
    Ok(())
}

/// A real kernel exercise, limited to a disposable network namespace and localhost fixture.
pub fn run_ebpf(root: &Path, templates: &Path) -> Result<(), String> {
    require(!root.exists(), "需要新的 eBPF 实测目录")?;
    let store = Store::open(root.to_path_buf())?;
    let _cleanup = Cleanup(&store);
    store.create_case("[实测] Linux 内核 eBPF · 隔离回环 HTTP".into())?;
    let preflight = sandbox::preflight(&store);
    require(
        preflight.daemon_ready && preflight.server_os == "linux",
        "需要 Linux Docker",
    )?;
    let architecture = if matches!(preflight.architecture.as_str(), "arm64" | "aarch64") {
        "linux-arm64"
    } else {
        "linux-amd64"
    };
    let bundle = root.join("ebpf-task.zip");
    let task = collector::generate(
        &store,
        collector::TaskInput {
            name: "真实内核回环流量验收".into(),
            target: "一次性容器 localhost · 不含宿主机流量".into(),
            mode: "ebpf".into(),
            architecture: architecture.into(),
            interface: "lo".into(),
            duration_seconds: 10,
            batch_seconds: 5,
            snaplen: 2048,
            include_http: true,
            hours: 1,
            online: false,
        },
        &bundle,
        templates,
    )?;
    let task_dir = root.join("task");
    extract_task(&bundle, &task_dir)?;
    let out_dir = root.join("agent-output");
    fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let task_mount = format!("{}:/task:ro", task_dir.display());
    let out_mount = format!("{}:/output", out_dir.display());
    let name = format!("gaga-ebpf-{}", uuid::Uuid::new_v4().simple());
    let _guard = Container(name.clone());
    // Dropped BPF capabilities must fail explicitly, never fabricate a zero-traffic success.
    let denied = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_RAW",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "128m",
            "--pids-limit",
            "32",
            "--tmpfs",
            "/output:rw,noexec,nosuid,size=8m",
            "-v",
            &task_mount,
            "--entrypoint",
            "/task/gaga-agent",
            "alpine:3.20",
            "-config",
            "/task/gaga-task.json",
            "-out",
            "/output",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let denied_error = String::from_utf8_lossy(&denied.stderr).into_owned();
    require(
        !denied.status.success() && denied_error.contains("eBPF program could not load"),
        "缺少 BPF 权限没有明确失败",
    )?;
    fs::write(root.join("missing-capability.log"), &denied_error).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let output = docker(&[
        "run", "--name", &name, "--label", "team.j4.gaga.field-test=1", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--cap-add", "BPF", "--cap-add", "NET_RAW", "--security-opt", "seccomp=unconfined",
        "--security-opt", "no-new-privileges", "--memory", "128m", "--pids-limit", "32", "--ulimit", "memlock=8388608:8388608",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", "-v", &task_mount, "-v", &out_mount,
        "--entrypoint", "/bin/sh", "alpine:3.20", "-c",
        "nc -lk -p 18080 -s 127.0.0.1 -e /bin/cat & /task/gaga-agent -config /task/gaga-task.json -out /output & agent_pid=$!; sleep 1; for n in 1 2 3 4 5 6; do printf 'GET /index.html HTTP/1.1\\r\\nHost: fixture.test\\r\\nX-Gaga-Sample: synthetic\\r\\n\\r\\n' | nc -w 1 127.0.0.1 18080 >/dev/null 2>&1 || true; done; wait $agent_pid"
    ])?;
    fs::write(root.join("agent-run.log"), output).map_err(|e| e.to_string())?;
    let kernel = docker(&[
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--cap-drop",
        "ALL",
        "alpine:3.20",
        "uname",
        "-r",
    ])?;
    let mut windows = Vec::new();
    for file in fs::read_dir(&out_dir).map_err(|e| e.to_string())? {
        let bytes = fs::read(file.map_err(|e| e.to_string())?.path()).map_err(|e| e.to_string())?;
        require(
            !String::from_utf8_lossy(&bytes).contains("GAGA_LOCAL_ONLY_HTTP_FIXTURE"),
            "加密包意外泄露正文",
        )?;
        let evidence = collector::ingest(&store, None, &bytes, None)?;
        let payload: Value = serde_json::from_slice(
            &fs::read(root.join("evidence").join(&evidence.id)).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        require(
            payload["kind"] == "ebpf"
                && payload["body"]["observedPackets"].as_u64().unwrap_or(0) > 0,
            "没有真实内核流量",
        )?;
        windows.push(payload);
    }
    require(!windows.is_empty(), "Agent 没有输出任何加密窗口")?;
    let flows: Vec<&Value> = windows
        .iter()
        .flat_map(|w| w["body"]["flows"].as_array().into_iter().flatten())
        .collect();
    require(
        flows
            .iter()
            .any(|f| f["destinationPort"] == 18080 && f["sourceIp"] == "127.0.0.1"),
        "缺少实际回环 TCP 五元组",
    )?;
    require(
        flows.iter().any(|f| {
            f["httpFragment"]
                .as_str()
                .unwrap_or("")
                .contains("GET /index.html")
        }),
        "开启 HTTP 片段却没有采集到请求",
    )?;
    require(
        collector::flow_windows(&store, &store.active()?)?.len() == windows.len(),
        "流量窗口未入库",
    )?;
    drop(_guard);
    let summary = json!({"format":"gaga-ebpf-kernel-verification/1","testedAt":Utc::now().to_rfc3339(),"kernel":kernel.trim(),"elapsedMs":started.elapsed().as_millis(),"taskId":task.id,"actualProgramLoadedAndAttached":true,"capabilities":["BPF","NET_RAW"],"seccomp":"disabled only for this disposable trusted collector container","hostNetwork":false,"network":"none, dedicated loopback namespace; HTTP-shaped requests to a local TCP echo fixture","missingCapabilityRejected":true,"originalClientDecrypted":true,"httpFragmentObserved":true,"containerRemoved":true,"windows":windows,"limitations":"Not host-wide traffic, no TLS decryption / TCP reassembly / process attribution; no external AI call."});
    fs::write(
        root.join("ebpf-verification.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    println!(
        "EBPF_VERIFIED: {}",
        root.join("ebpf-verification.json").display()
    );
    Ok(())
}

/// Reads metadata only from an existing workspace. Keys stay in the OS credential service.
pub fn run_official(root: &Path, source: &Path) -> Result<(), String> {
    require(!root.exists(), "需要新的官方模型验收目录")?;
    let source = rusqlite::Connection::open_with_flags(
        source.join("workspace.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| e.to_string())?;
    let mut query = source
        .prepare("SELECT value FROM settings WHERE key LIKE 'ai_profile:%' OR key='ai_config'")
        .map_err(|e| e.to_string())?;
    let configs = query
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let store = Store::open(root.to_path_buf())?;
    let mut results = Vec::new();
    for provider in ai::catalog().providers {
        let cfg = configs
            .iter()
            .filter_map(|s| serde_json::from_str::<ai::AiConfig>(s).ok())
            .find(|c| c.endpoint == provider.endpoint && c.has_key);
        let Some(cfg) = cfg else {
            results.push(
                json!({"provider":provider.id,"status":"not_configured","officialApiTested":false}),
            );
            continue;
        };
        store
            .db
            .lock()
            .map_err(|e| e.to_string())?
            .execute(
                "INSERT OR REPLACE INTO settings VALUES('ai_config',?1)",
                [serde_json::to_string(&cfg).unwrap()],
            )
            .map_err(|e| e.to_string())?;
        let connection =
            tauri::async_runtime::block_on(ai::test_connection(&store, &cfg.revision))?;
        let mut result = json!({"provider":provider.id,"model":cfg.model,"connection":connection,"officialApiTested":connection.success,"connectionAttempted":true,"credentialsCopied":false,"sourceWorkspaceModified":false});
        if connection.success {
            let evidence = store.analyze_http_pair(
                "GET /health HTTP/1.1\r\nHost: example.test\r\nX-Gaga-Sample: synthetic\r\n\r\n"
                    .into(),
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK".into(),
            )?;
            let material = ai::material(&store, &evidence.id)?;
            match tauri::async_runtime::block_on(ai::review_traced(&store,None,evidence.id,material,"这是隔离测试的合成健康检查报文。只根据材料研判，给出举证来源、缺失项；不能据此认定入侵。".into())) {
                Ok(review)=>{
                    result["structuredAssessmentParsed"]=json!(review.assessment.is_some());
                    result["reviewId"]=json!(review.id);
                    result["reviewSaved"]=json!(true);
                    let followup=tauri::async_runtime::block_on(ai::followup(&store,None,review.id,"列出这次合成测试还缺少哪些证据。".into()));
                    result["followupSaved"]=json!(followup.is_ok());
                    if let Err(error)=followup {result["followupError"]=json!(error);}
                },
                Err(error)=>{result["reviewSaved"]=json!(false);result["reviewError"]=json!(error);}
            }
        }
        results.push(result);
        fs::write(
            root.join("official-ai-verification.json"),
            serde_json::to_vec_pretty(
                &json!({"testedAt":Utc::now().to_rfc3339(),"results":results}),
            )
            .unwrap(),
        )
        .map_err(|e| e.to_string())?;
    }
    fs::write(
        root.join("official-ai-verification.json"),
        serde_json::to_vec_pretty(&json!({"testedAt":Utc::now().to_rfc3339(),"results":results}))
            .unwrap(),
    )
    .map_err(|e| e.to_string())?;
    println!(
        "OFFICIAL_AI_VERIFIED: {}",
        root.join("official-ai-verification.json").display()
    );
    Ok(())
}

#[cfg(test)]
mod archive_tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn generated_task_extraction_never_restores_privileged_bits_or_follows_links() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir(&root).unwrap();
        let bundle = root.join("task.zip");
        let mut zip = zip::ZipWriter::new(fs::File::create(&bundle).unwrap());
        for name in ["gaga-agent", "gaga-task.json", "README.txt"] {
            zip.start_file(
                name,
                zip::write::SimpleFileOptions::default().unix_permissions(0o4755),
            )
            .unwrap();
            zip.write_all(b"inert fixture").unwrap();
        }
        zip.finish().unwrap();
        extract_task(&bundle, &root.join("out")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.join("out/gaga-agent"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o700
            );
        }
        let mut bytes = fs::read(&bundle).unwrap();
        let header = bytes.windows(4).position(|p| p == b"PK\x01\x02").unwrap();
        bytes[header + 38..header + 42].copy_from_slice(&(0o120777u32 << 16).to_le_bytes());
        fs::write(&bundle, bytes).unwrap();
        assert!(extract_task(&bundle, &root.join("reject"))
            .unwrap_err()
            .contains("链接"));
        assert!(!root.join("reject/gaga-agent").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
