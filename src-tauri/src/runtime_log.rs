//! 有界本地运行日志，独立于事件数据库，数据库打不开时仍可查询。
//! 只记录错误/生命周期元数据，不记录 IPC 参数、样本、报文或模型正文。
//! 常见凭据二次遮盖；外发诊断投影进一步移除整条消息和本机目录。
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

const MAX_BYTES: u64 = 2 * 1024 * 1024;
const FILES: usize = 5;
static LOG: OnceLock<Mutex<Journal>> = OnceLock::new();
static INIT_ERROR: OnceLock<String> = OnceLock::new();

#[derive(Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    id: String,
    time: String,
    level: String,
    component: String,
    code: String,
    message: String,
    fingerprint: String,
    context_id: Option<String>,
}
pub struct Journal {
    root: PathBuf,
    last: Option<(String, Instant)>,
    suppressed: u64,
    write_error: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    path: String,
    entries: Vec<Entry>,
    suppressed: u64,
    write_error: Option<String>,
    max_bytes: u64,
}

fn scrub(text: &str) -> String {
    static PATTERNS: OnceLock<Vec<regex::Regex>> = OnceLock::new();
    let mut value: String = text
        .chars()
        .take(4096)
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    for pattern in PATTERNS.get_or_init(|| {
        [
            r#"(?im)(?:authorization|proxy-authorization|cookie|set-cookie)\s*[:=][^\r\n]+"#,
            r#"(?i)(?:api[_-]?key|token|password|passwd|secret)["']?\s*[:=]\s*["']?[^\s,;}]+"#,
            r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]+",
            r"\bsk-[A-Za-z0-9_-]{8,}",
            r#"https?://[^\s<>"']+"#,
            r#"/(?:Users|home|private|var|tmp|Volumes)/[^\s<>"',:]+"#,
            r#"[A-Za-z]:\\[^\r\n<>"',]+"#,
        ]
        .iter()
        .map(|p| regex::Regex::new(p).expect("static log redaction pattern"))
        .collect()
    }) {
        value = pattern.replace_all(&value, "[redacted]").into_owned();
    }
    value.chars().take(2048).collect()
}
fn label(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
        .take(80)
        .collect()
}

#[cfg(unix)]
fn refuse_final_symlink(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    const O_NOFOLLOW: i32 = 0x00000100;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const O_NOFOLLOW: i32 = 0x00020000;
    options.custom_flags(O_NOFOLLOW);
}
#[cfg(not(unix))]
fn refuse_final_symlink(_: &mut fs::OpenOptions) {}

// Different client processes share the platform log directory. A Rust Mutex
// only protects one process; serialize append/rotation/read across instances.
struct JournalLock(fs::File);
impl JournalLock {
    fn acquire(root: &Path) -> Result<Self, String> {
        let path = root.join("journal.lock");
        if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file() || m.file_type().is_symlink()) {
            return Err("日志锁文件类型异常".into());
        }
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        refuse_final_symlink(&mut options);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|e| e.to_string())?;
        let start = Instant::now();
        loop {
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => return Ok(Self(file)),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
                {
                    if start.elapsed() >= Duration::from_millis(250) {
                        return Err("运行日志正被另一客户端占用，请稍后重试".into());
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e.to_string()),
            }
        }
    }
}
impl Drop for JournalLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}
impl Journal {
    fn open(root: PathBuf) -> Result<Self, String> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root).map_err(|e| e.to_string())?;
        if fs::symlink_metadata(&root)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("日志目录不能为符号链接".into());
        }
        Ok(Self {
            root,
            last: None,
            suppressed: 0,
            write_error: None,
        })
    }
    fn path(&self, index: usize) -> PathBuf {
        self.root.join(format!("runtime-{index}.jsonl"))
    }
    fn write(
        &mut self,
        level: &str,
        component: &str,
        code: &str,
        message: &str,
        context_id: Option<&str>,
    ) -> Result<(), String> {
        let result = self.append(level, component, code, message, context_id);
        self.write_error = result.as_ref().err().map(|e| scrub(e));
        result
    }
    fn append(
        &mut self,
        level: &str,
        component: &str,
        code: &str,
        message: &str,
        context_id: Option<&str>,
    ) -> Result<(), String> {
        let message = scrub(message);
        let fingerprint = format!(
            "{:x}",
            Sha256::digest(format!("{component}:{code}:{message}"))
        );
        let context_id = context_id.filter(|s| uuid::Uuid::parse_str(s).is_ok());
        let dedup_key = format!("{level}:{fingerprint}:{}", context_id.unwrap_or_default());
        if self
            .last
            .as_ref()
            .is_some_and(|(key, at)| key == &dedup_key && at.elapsed() < Duration::from_secs(2))
        {
            self.suppressed += 1;
            return Ok(());
        }
        let entry = Entry {
            id: uuid::Uuid::new_v4().to_string(),
            time: chrono::Utc::now().to_rfc3339(),
            level: label(level),
            component: label(component),
            code: label(code),
            message,
            fingerprint,
            context_id: context_id.map(str::to_owned),
        };
        let mut bytes = serde_json::to_vec(&entry).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        let _lock = JournalLock::acquire(&self.root)?;
        let target = self.path(0);
        if fs::symlink_metadata(&target).is_ok_and(|m| !m.is_file() || m.file_type().is_symlink()) {
            return Err("日志文件类型异常".into());
        }
        // Reserve a delimiter for a previous partial line after forced exit.
        if fs::metadata(&target).map(|m| m.len()).unwrap_or(0) + bytes.len() as u64 + 1 > MAX_BYTES
        {
            let oldest = self.path(FILES - 1);
            if oldest.exists() {
                fs::remove_file(oldest).map_err(|e| e.to_string())?;
            }
            for i in (0..FILES - 1).rev() {
                if self.path(i).exists() {
                    fs::rename(self.path(i), self.path(i + 1)).map_err(|e| e.to_string())?;
                }
            }
        }
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).append(true);
        refuse_final_symlink(&mut options);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(target).map_err(|e| e.to_string())?;
        if file.metadata().map_err(|e| e.to_string())?.len() > 0 {
            file.seek(SeekFrom::End(-1)).map_err(|e| e.to_string())?;
            let mut last = [0];
            file.read_exact(&mut last).map_err(|e| e.to_string())?;
            if last[0] != b'\n' {
                file.write_all(b"\n").map_err(|e| e.to_string())?;
            }
        }
        file.write_all(&bytes)
            .and_then(|_| file.sync_data())
            .map_err(|e| e.to_string())?;
        // Only a persisted record may suppress later duplicates. A failed
        // append must allow the first successful retry through immediately.
        self.last = Some((dedup_key, Instant::now()));
        Ok(())
    }
    fn snapshot(&self) -> Result<Snapshot, String> {
        let _lock = JournalLock::acquire(&self.root)?;
        let mut entries = Vec::new();
        // Skip corrupt/incomplete final lines after forced termination, keeping prior records.
        for i in 0..FILES {
            let path = self.path(i);
            if !path.exists() {
                continue;
            }
            if fs::symlink_metadata(&path)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("日志文件不能为符号链接".into());
            }
            let mut bytes = Vec::new();
            fs::File::open(path)
                .map_err(|e| e.to_string())?
                .take(MAX_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() as u64 > MAX_BYTES {
                return Err("日志文件超过轮转上限".into());
            }
            let rows: Vec<_> = bytes
                .split(|b| *b == b'\n')
                .filter_map(|line| serde_json::from_slice::<Entry>(line).ok())
                .collect();
            entries.extend(rows.into_iter().rev().take(200 - entries.len()));
            if entries.len() == 200 {
                break;
            }
        }
        Ok(Snapshot {
            path: self.root.display().to_string(),
            entries,
            suppressed: self.suppressed,
            write_error: self.write_error.clone(),
            max_bytes: MAX_BYTES * FILES as u64,
        })
    }
}
pub fn init(root: PathBuf) {
    match Journal::open(root) {
        Ok(log) => {
            let _ = LOG.set(Mutex::new(log));
            event("info", "application", "START", "客户端启动", None);
        }
        Err(error) => {
            eprintln!("GAGA_LOG_INIT: {error}");
            let _ = INIT_ERROR.set(error);
        }
    }
}
pub fn event(level: &str, component: &str, code: &str, message: &str, context: Option<&str>) {
    if let Some(log) = LOG.get() {
        if let Ok(mut log) = log.lock() {
            if let Err(error) = log.write(level, component, code, message, context) {
                log.write_error = Some(scrub(&error));
                eprintln!("GAGA_LOG_WRITE_FAILED");
            }
        }
    }
}
pub fn panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("native panic");
        // A panic inside logging must not wait for its own mutex.
        if let Some(log) = LOG.get() {
            if let Ok(mut log) = log.try_lock() {
                let _ = log.write("error", "native", "PANIC", message, None);
            }
        }
        previous(info);
    }));
}
#[tauri::command]
pub async fn get_runtime_logs() -> Result<Snapshot, String> {
    tauri::async_runtime::spawn_blocking(|| {
        LOG.get()
            .ok_or_else(|| INIT_ERROR.get().cloned().unwrap_or("日志尚未初始化".into()))?
            .lock()
            .map_err(|e| e.to_string())?
            .snapshot()
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub fn record_client_error(component: String, message: String) -> Result<(), String> {
    if message.len() > 16384 || component.len() > 80 {
        return Err("错误记录过长".into());
    }
    event("error", &component, "CLIENT_ERROR", &message, None);
    Ok(())
}
#[tauri::command]
pub async fn export_runtime_logs(path: String) -> Result<(), String> {
    let snapshot = get_runtime_logs().await?;
    tauri::async_runtime::spawn_blocking(move || {
        let entries: Vec<_> = snapshot.entries.iter().map(|e| serde_json::json!({"id":e.id,"time":e.time,"level":e.level,"component":e.component,"code":e.code,"fingerprint":e.fingerprint})).collect();
        let value = serde_json::json!({"format":"gaga-error-index/1","version":env!("CARGO_PKG_VERSION"),"entries":entries,"messageIncluded":false,"pathsIncluded":false});
        let bytes = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
        crate::file_commit::write_new(Path::new(&path), |file| file.write_all(&bytes).map_err(|e| e.to_string()))
            .map_err(|e| format!("日志索引未提交，请选择新的文件名或检查保存目录：{e}"))
    }).await.map_err(|e|e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn different_tasks_and_severities_are_not_merged() {
        let root = std::env::temp_dir().join(format!("gaga-log-context-{}", uuid::Uuid::new_v4()));
        let mut log = Journal::open(root.clone()).unwrap();
        let a = uuid::Uuid::new_v4().to_string();
        let b = uuid::Uuid::new_v4().to_string();
        log.write("error", "report", "FAILED", "same failure", Some(&a))
            .unwrap();
        log.write("error", "report", "FAILED", "same failure", Some(&b))
            .unwrap();
        log.write("warn", "report", "FAILED", "same failure", Some(&b))
            .unwrap();
        log.write("warn", "report", "FAILED", "same failure", Some(&b))
            .unwrap();
        let snapshot = log.snapshot().unwrap();
        assert_eq!(
            snapshot.entries.len(),
            3,
            "Every task/severity needs its own record"
        );
        assert_eq!(snapshot.suppressed, 1);
        assert_eq!(snapshot.entries[2].context_id.as_deref(), Some(a.as_str()));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_write_does_not_suppress_the_first_successful_retry() {
        let root = std::env::temp_dir().join(format!("gaga-log-retry-{}", uuid::Uuid::new_v4()));
        let mut log = Journal::open(root.clone()).unwrap();
        fs::create_dir(log.path(0)).unwrap();
        assert!(log
            .write("error", "report", "FAILED", "retry needed", None)
            .is_err());
        assert!(log.write_error.is_some());
        fs::remove_dir(log.path(0)).unwrap();
        log.write("error", "report", "FAILED", "retry needed", None)
            .unwrap();
        let snapshot = log.snapshot().unwrap();
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.suppressed, 0);
        assert!(snapshot.write_error.is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn truncated_last_line_does_not_swallow_the_first_record_after_restart() {
        let root = std::env::temp_dir().join(format!("gaga-log-tail-{}", uuid::Uuid::new_v4()));
        let mut log = Journal::open(root.clone()).unwrap();
        log.write("info", "application", "START", "before interruption", None)
            .unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(log.path(0))
            .unwrap()
            .write_all(b"{\"id\":\"incomplete")
            .unwrap();
        let mut reopened = Journal::open(root.clone()).unwrap();
        reopened
            .write("error", "report", "FAILED", "first after restart", None)
            .unwrap();
        let snapshot = reopened.snapshot().unwrap();
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(snapshot.entries[0].code, "FAILED");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn separate_journals_respect_the_shared_file_lock_and_can_retry() {
        if let Ok(root) = std::env::var("GAGA_LOG_LOCK_TEST_ROOT") {
            let mut child = Journal::open(PathBuf::from(root)).unwrap();
            assert!(child
                .write("info", "application", "START", "other process", None)
                .is_err());
            assert!(child.write_error.is_some());
            return;
        }
        let root = std::env::temp_dir().join(format!("gaga-log-lock-{}", uuid::Uuid::new_v4()));
        let first = Journal::open(root.clone()).unwrap();
        let mut second = Journal::open(root.clone()).unwrap();
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(first.root.join("journal.lock"))
            .unwrap();
        fs2::FileExt::lock_exclusive(&lock).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime_log::tests::separate_journals_respect_the_shared_file_lock_and_can_retry",
                "--test-threads=1",
            ])
            .env("GAGA_LOG_LOCK_TEST_ROOT", &root)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "Child process must respect the journal lock: {}",
            String::from_utf8_lossy(&child.stdout)
        );
        assert!(second
            .write("info", "application", "START", "other client", None)
            .is_err());
        fs2::FileExt::unlock(&lock).unwrap();
        drop(lock);
        second
            .write("info", "application", "START", "other client", None)
            .unwrap();
        assert_eq!(first.snapshot().unwrap().entries.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn logs_redact_credentials_deduplicate_rotate_and_survive_reopen() {
        let root = std::env::temp_dir().join(format!("gaga-log-{}", uuid::Uuid::new_v4()));
        let mut log = Journal::open(root.clone()).unwrap();
        log.write("error", "http", "FAILED", "Authorization: Bearer private-canary\napi_key=private-canary\nhttps://user:pass@example.test/p?q=private-canary\n/Users/private-canary/record", None).unwrap();
        log.write("error", "http", "SAME", "repeat", None).unwrap();
        log.write("error", "http", "SAME", "repeat", None).unwrap();
        assert_eq!(log.suppressed, 1);
        assert!(!serde_json::to_string(&log.snapshot().unwrap())
            .unwrap()
            .contains("private-canary"));
        // Fill the current log to its bound to exercise the actual rename path.
        fs::write(log.path(0), vec![b' '; MAX_BYTES as usize]).unwrap();
        log.write("error", "report", "EXPORT_FAILED", "disk full", None)
            .unwrap();
        assert!(log.path(1).exists());
        let reopened = Journal::open(root.clone()).unwrap().snapshot().unwrap();
        assert_eq!(reopened.entries[0].code, "EXPORT_FAILED");
        assert_eq!(reopened.max_bytes, 10 * 1024 * 1024);
        fs::remove_dir_all(root).unwrap();
    }
}
