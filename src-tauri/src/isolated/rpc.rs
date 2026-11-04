//! 有界 JSONL 通信。写管道放到专用线程，主任务仍可响应取消与截止时间。
//! 销毁时先终止自己创建的 CLI 进程组，再 join 管道线程，避免等待卡死的写端。
use crate::sandbox::DockerCheck;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
const MAX_LINE: usize = 2 * 1024 * 1024;
type WriteRequest = (Vec<u8>, mpsc::Sender<Result<(), String>>);
struct Input {
    tx: SyncSender<WriteRequest>,
    thread: JoinHandle<()>,
}
impl Input {
    fn new(mut pipe: impl Write + Send + 'static) -> Self {
        let (tx, rx) = mpsc::sync_channel::<WriteRequest>(1);
        let thread = thread::spawn(move || {
            while let Ok((bytes, done)) = rx.recv() {
                let result = pipe
                    .write_all(&bytes)
                    .and_then(|_| pipe.flush())
                    .map_err(|e| e.to_string());
                let failed = result.is_err();
                let _ = done.send(result);
                if failed {
                    break;
                }
            }
        });
        Self { tx, thread }
    }
    fn send(&self, value: &Value, deadline: Instant, cancelled: &AtomicBool) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_LINE {
            return Err("Pi 控制输入超过 2 MiB".into());
        }
        bytes.push(b'\n');
        let (tx, rx) = mpsc::channel();
        self.tx
            .try_send((bytes, tx))
            .map_err(|_| "Pi 写入队列不可用")?;
        // 每次写入也有独立上限，不能让不读 stdin 的容器耗尽整个任务预算。
        let limit = deadline.min(Instant::now() + Duration::from_secs(10));
        loop {
            if cancelled.load(Ordering::SeqCst) {
                return Err("已取消 Pi 控制写入".into());
            }
            if Instant::now() >= limit {
                return Err("Pi 控制写入超时".into());
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(v) => return v,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return Err("Pi 控制写入中断".into()),
            }
        }
    }
    fn join(self) {
        drop(self.tx);
        let _ = self.thread.join();
    }
}
pub(super) enum Message {
    Line(String),
    Pending,
    Eof,
}
pub(super) struct Session {
    child: Child,
    input: Option<Input>,
    output: Option<Receiver<Result<String, String>>>,
    reader: Option<JoinHandle<()>>,
    errors: Option<JoinHandle<Vec<u8>>>,
}
impl Session {
    pub(super) fn start(check: &DockerCheck, name: &str) -> Result<Self, String> {
        let mut cmd = Command::new(&check.cli_path);
        cmd.args(["--context", &check.context, "start", "-a", "-i", name])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        let mut child = cmd.spawn().map_err(|e| e.to_string())?;
        let input = Input::new(child.stdin.take().ok_or("未创建 Pi 输入管道")?);
        let output = child.stdout.take().ok_or("未创建 Pi 输出管道")?;
        let stderr = child.stderr.take().ok_or("未创建 Pi 错误管道")?;
        let errors = thread::spawn(move || {
            let mut stream = stderr;
            let mut bytes = vec![];
            let mut chunk = [0; 4096];
            while let Ok(n) = stream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let take = n.min(16000usize.saturating_sub(bytes.len()));
                bytes.extend_from_slice(&chunk[..take]);
            }
            bytes
        });
        let (tx, rx) = mpsc::sync_channel(8);
        let reader = thread::spawn(move || {
            let mut r = BufReader::new(output);
            loop {
                let mut line = String::new();
                match r.by_ref().take(MAX_LINE as u64 + 1).read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) if line.len() <= MAX_LINE && line.ends_with('\n') => {
                        if tx.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    _ => {
                        let _ = tx.send(Err("Pi 控制输出超过限制或格式无效".into()));
                        break;
                    }
                }
            }
        });
        Ok(Self {
            child,
            input: Some(input),
            output: Some(rx),
            reader: Some(reader),
            errors: Some(errors),
        })
    }
    pub(super) fn send(
        &self,
        value: &Value,
        deadline: Instant,
        cancelled: &Arc<AtomicBool>,
    ) -> Result<(), String> {
        self.input
            .as_ref()
            .ok_or("Pi 通道已关闭")?
            .send(value, deadline, cancelled)
    }
    pub(super) fn receive(&self) -> Result<Message, String> {
        match self
            .output
            .as_ref()
            .ok_or("Pi 通道已关闭")?
            .recv_timeout(Duration::from_millis(100))
        {
            Ok(v) => v.map(Message::Line),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(Message::Pending),
            Err(_) => Ok(Message::Eof),
        }
    }
    pub(super) fn close(&mut self) -> Vec<u8> {
        // 先丢弃接收端，释放可能堵在 sync_channel 的 reader。
        self.output.take();
        #[cfg(unix)]
        {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", &format!("-{}", self.child.id())])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        #[cfg(windows)]
        {
            let _ = Command::new("taskkill.exe")
                .args(["/PID", &self.child.id().to_string(), "/T", "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(input) = self.input.take() {
            input.join();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.errors
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default()
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if self.input.is_some() {
            self.close();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Stalled(Receiver<()>);
    impl Write for Stalled {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            let _ = self.0.recv();
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn stalled_input_obeys_deadline_and_cancel_without_blocking_controller() {
        for cancelled in [false, true] {
            let (release, wait) = mpsc::channel();
            let input = Input::new(Stalled(wait));
            let flag = AtomicBool::new(cancelled);
            let now = Instant::now();
            let result = input.send(
                &serde_json::json!({"test":"no credentials"}),
                now + Duration::from_millis(120),
                &flag,
            );
            assert!(result
                .unwrap_err()
                .contains(if cancelled { "已取消" } else { "超时" }));
            assert!(now.elapsed() < Duration::from_secs(1));
            drop(release);
            input.join();
        }
    }
}
