//! 同目录生成唯一临时文件，完整写入并同步后再替换目标。
//! 写入或替换失败时保留旧文件；不先删除目标，避免工作区指针和报告出现空窗。
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

// Keep the guard alive until the write handle closes. Unwinding a renderer
// must not leave a partial report or key next to the chosen destination.
struct PartialOutput {
    path: PathBuf,
    file: Option<fs::File>,
}
impl Drop for PartialOutput {
    fn drop(&mut self) {
        drop(self.file.take()); // Windows cannot remove the open staging file.
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(not(windows))]
fn replace(source: &Path, target: &Path) -> Result<(), String> {
    fs::rename(source, target).map_err(|e| e.to_string())
}
#[cfg(windows)]
fn replace(source: &Path, target: &Path) -> Result<(), String> {
    move_windows(source, target, true)
}

#[cfg(windows)]
fn move_windows(source: &Path, target: &Path, overwrite: bool) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    if source[..source.len() - 1].contains(&0) || target[..target.len() - 1].contains(&0) {
        return Err("文件路径含无效字符".into());
    }
    // SAFETY: 两个切片均为有效、以 NUL 终止的 UTF-16 路径，生命周期覆盖调用。
    // 同目录移动；不启用 COPY_ALLOWED，禁止回退到复制后删除。
    let result =
        unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), u32::from(overwrite) | 0x8) };
    if result == 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn install_new(source: &Path, target: &Path) -> Result<(), String> {
    move_windows(source, target, false)
}
#[cfg(target_os = "macos")]
fn install_new(source: &Path, target: &Path) -> Result<(), String> {
    use std::{
        ffi::CString,
        os::raw::{c_char, c_int},
        os::unix::ffi::OsStrExt,
    };
    extern "C" {
        fn renamex_np(from: *const c_char, to: *const c_char, flags: u32) -> c_int;
    }
    let from = CString::new(source.as_os_str().as_bytes()).map_err(|_| "文件路径含无效字符")?;
    let to = CString::new(target.as_os_str().as_bytes()).map_err(|_| "文件路径含无效字符")?;
    // SAFETY: valid NUL-terminated paths live through the call. RENAME_EXCL
    // atomically refuses an existing target, so a racing key is never replaced.
    let result = unsafe { renamex_np(from.as_ptr(), to.as_ptr(), 0x00000004) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}
#[cfg(all(not(windows), not(target_os = "macos")))]
fn install_new(source: &Path, target: &Path) -> Result<(), String> {
    // No overwrite fallback: filesystems without hard links report an error.
    // The guard removes the staging name after linking the complete inode.
    fs::hard_link(source, target).map_err(|e| e.to_string())
}

/// Publish a complete new file without ever replacing an existing identity/key.
pub fn write_new(
    target: &Path,
    write: impl FnOnce(&mut fs::File) -> Result<(), String>,
) -> Result<(), String> {
    write_with_replace(target, write, install_new)
}

pub fn write_atomic(
    target: &Path,
    write: impl FnOnce(&mut fs::File) -> Result<(), String>,
) -> Result<(), String> {
    write_with_replace(target, write, replace)
}

/// 取消只在提交点之前接受；检查失败会清除临时文件并保留旧输出。
pub fn write_checked(
    target: &Path,
    write: impl FnOnce(&mut fs::File) -> Result<(), String>,
    before_commit: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    write_with_replace(target, write, |source, target| {
        before_commit()?;
        replace(source, target)
    })
}

fn write_with_replace(
    target: &Path,
    write: impl FnOnce(&mut fs::File) -> Result<(), String>,
    commit: impl FnOnce(&Path, &Path) -> Result<(), String>,
) -> Result<(), String> {
    let temporary = target.with_file_name(format!(".gaga-{}.partial", uuid::Uuid::new_v4()));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut partial = PartialOutput {
        file: Some(opts.open(&temporary).map_err(|e| e.to_string())?),
        path: temporary.clone(),
    };
    let file = partial.file.as_mut().expect("new staging file is present");
    let result = write(file).and_then(|()| file.sync_all().map_err(|e| e.to_string()));
    drop(partial.file.take()); // Windows 也需要在替换之前关闭写句柄。
    let result = result.and_then(|()| commit(&temporary, target));
    drop(partial);
    result
}

pub fn write_bytes(target: &Path, bytes: &[u8]) -> Result<(), String> {
    write_atomic(target, |file| {
        file.write_all(bytes).map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_files_are_complete_or_absent_and_existing_targets_are_preserved() {
        let root = std::env::temp_dir().join(format!("gaga-new-key-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let target = root.join("identity.json");
        assert!(write_new(&target, |file| {
            file.write_all(b"partial identity").unwrap();
            Err("synthetic disk failure".into())
        })
        .is_err());
        assert!(!target.exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        write_new(&target, |file| {
            file.write_all(b"original complete identity")
                .map_err(|e| e.to_string())
        })
        .unwrap();
        assert!(write_new(&target, |file| file
            .write_all(b"different identity")
            .map_err(|e| e.to_string()))
        .is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original complete identity");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn simultaneous_identity_creation_never_replaces_the_winner() {
        let root = std::env::temp_dir().join(format!("gaga-new-race-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let target = root.join("report-watermark.key");
        let threads: Vec<_> = b"ab"
            .iter()
            .copied()
            .map(|byte| {
                let barrier = barrier.clone();
                let target = target.clone();
                std::thread::spawn(move || {
                    let result = write_new(&target, |file| {
                        file.write_all(&[byte; 32]).map_err(|e| e.to_string())?;
                        barrier.wait();
                        Ok(())
                    });
                    (byte, result.is_ok())
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|(_, ok)| *ok).count(), 1);
        let winner = results.iter().find(|(_, ok)| *ok).unwrap().0;
        assert_eq!(fs::read(&target).unwrap(), [winner; 32]);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn unwinding_writer_cleans_partial_and_preserves_the_previous_file() {
        let root = std::env::temp_dir().join(format!("gaga-unwind-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let target = root.join("report.html");
        fs::write(&target, b"previous report").unwrap();
        assert!(std::panic::catch_unwind(|| {
            let _ = write_atomic(&target, |file| {
                file.write_all(b"sensitive partial report").unwrap();
                panic!("synthetic renderer panic");
            });
        })
        .is_err());
        assert_eq!(fs::read(&target).unwrap(), b"previous report");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn cancellation_after_writing_preserves_old_output_and_cleans_temporary() {
        let root =
            std::env::temp_dir().join(format!("gaga-cancel-commit-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let target = root.join("report.docx");
        fs::write(&target, b"previous report").unwrap();
        assert!(write_checked(
            &target,
            |f| f
                .write_all(&vec![1; 1024 * 1024])
                .map_err(|e| e.to_string()),
            || Err("cancelled before commit".into())
        )
        .is_err());
        assert_eq!(fs::read(&target).unwrap(), b"previous report");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn write_and_replace_failure_preserve_original_and_clean_partial_files() {
        let root = std::env::temp_dir().join(format!("gaga-commit-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let target = root.join("workspace-location.json");
        write_bytes(&target, b"original").unwrap();
        assert!(write_atomic(&target, |f| {
            f.write_all(b"incomplete").unwrap();
            Err("simulated full disk".into())
        })
        .is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original");
        assert!(write_with_replace(
            &target,
            |f| { f.write_all(b"new").map_err(|e| e.to_string()) },
            |_, _| Err("simulated sharing violation".into())
        )
        .is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        write_bytes(&target, b"complete").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"complete");
        fs::remove_dir_all(root).unwrap();
    }
}
