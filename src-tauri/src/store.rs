use crate::analyzers::{self, AnalysisReport};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Case {
    pub id: String,
    pub title: String,
    pub created_at: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub id: String,
    pub case_id: String,
    pub name: String,
    pub kind: String,
    pub sha256: String,
    pub size: u64,
    pub created_at: String,
    pub report: AnalysisReport,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Screenshot {
    pub id: String,
    pub node_id: String,
    pub name: String,
    pub sha256: String,
    pub size: u64,
    pub mime: String,
    pub caption: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineNode {
    pub id: String,
    pub case_id: String,
    pub evidence_id: Option<String>,
    pub finding_id: Option<String>,
    pub occurred_at: String,
    pub recorded_at: String,
    pub title: String,
    pub body: String,
    pub actor: String,
    pub included: bool,
    pub screenshots: Vec<Screenshot>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub cases: Vec<Case>,
    pub active_case: String,
    pub evidence: Vec<Evidence>,
    pub nodes: Vec<TimelineNode>,
    pub ai_reviews: Vec<crate::ai::AiReview>,
    pub analysis_runs: Vec<crate::investigation::AnalysisRun>,
    pub followups: Vec<crate::ai::Followup>,
    pub review_feedback: Vec<crate::investigation::Feedback>,
    pub response_actions: Vec<crate::response_actions::ResponseAction>,
    pub data_dir: String,
}
pub struct Store {
    #[cfg(debug_assertions)]
    pub allow_mock_ai: bool,
    pub root: PathBuf,
    pub db: Mutex<Connection>,
    _workspace_lock: fs::File,
}
fn now() -> String {
    Utc::now().to_rfc3339()
}
fn uid() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn require_workspace_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(err)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label}不能是符号链接或非普通目录。"));
    }
    Ok(())
}

fn open_workspace_lock(path: &Path) -> Result<fs::File, String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("工作区锁文件类型异常。".into());
        }
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
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
    options.open(path).map_err(err)
}

fn reject_workspace_file_links(root: &Path) -> Result<(), String> {
    for name in [
        "workspace.sqlite3",
        "workspace.sqlite3-wal",
        "workspace.sqlite3-shm",
    ] {
        let path = root.join(name);
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!("工作区文件 {name} 不是受信任的普通文件。"));
            }
        }
    }
    Ok(())
}

impl Store {
    pub fn open(root: PathBuf) -> Result<Self, String> {
        // 新工作区目录只允许当前用户访问；不改变用户已存在父目录的权限。
        let mut dirs = fs::DirBuilder::new();
        dirs.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            dirs.mode(0o700);
        }
        dirs.create(&root).map_err(err).or_else(
            |error| {
                if root.is_dir() {
                    Ok(())
                } else {
                    Err(error)
                }
            },
        )?;
        require_workspace_directory(&root, "工作区")?;
        dirs.create(root.join("evidence"))
            .map_err(err)
            .or_else(|error| {
                if root.join("evidence").is_dir() {
                    Ok(())
                } else {
                    Err(error)
                }
            })?;
        require_workspace_directory(&root.join("evidence"), "证据目录")?;
        fs::create_dir_all(root.join("screenshots")).map_err(err)?;
        require_workspace_directory(&root.join("screenshots"), "截图目录")?;
        reject_workspace_file_links(&root)?;
        let workspace_lock = open_workspace_lock(&root.join("workspace.lock"))?;
        fs2::FileExt::try_lock_exclusive(&workspace_lock)
            .map_err(|_| "该工作区已被另一个客户端打开，请使用已有窗口。")?;
        let db = Connection::open(root.join("workspace.sqlite3")).map_err(err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                root.join("workspace.sqlite3"),
                fs::Permissions::from_mode(0o600),
            )
            .map_err(err)?;
        }
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(err)?;
        crate::maintenance::migration_checkpoint(&db, &root)?;
        db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,title TEXT NOT NULL,created_at TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),name TEXT NOT NULL,kind TEXT NOT NULL,sha256 TEXT NOT NULL,size INTEGER NOT NULL,created_at TEXT NOT NULL,report TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),evidence_id TEXT REFERENCES evidence(id),finding_id TEXT,occurred_at TEXT NOT NULL,recorded_at TEXT NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,actor TEXT NOT NULL,included INTEGER NOT NULL DEFAULT 1);
          CREATE TABLE IF NOT EXISTS screenshots(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id),name TEXT NOT NULL,sha256 TEXT NOT NULL,size INTEGER NOT NULL,mime TEXT NOT NULL,caption TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS ai_reviews(id TEXT PRIMARY KEY,evidence_id TEXT NOT NULL REFERENCES evidence(id),record TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS local_analysis_jobs(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),record TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS analysis_runs(id TEXT PRIMARY KEY,evidence_id TEXT NOT NULL REFERENCES evidence(id),case_id TEXT NOT NULL REFERENCES cases(id),record TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS ai_followups(id TEXT PRIMARY KEY,review_id TEXT NOT NULL REFERENCES ai_reviews(id),record TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS review_feedback(id TEXT PRIMARY KEY,review_id TEXT NOT NULL REFERENCES ai_reviews(id),record TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS node_revisions(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id),edited_at TEXT NOT NULL,previous TEXT NOT NULL,current TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS sandbox_jobs(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),record TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS reverse_jobs(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),record TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS response_actions(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),record TEXT NOT NULL);
          UPDATE reverse_jobs SET record=json_set(record,'$.state','failed','$.error','上次退出时逆向任务未完成；未自动重试，请检查隔离容器遗留。') WHERE json_extract(record,'$.state')='running';
          CREATE INDEX IF NOT EXISTS evidence_case ON evidence(case_id);
          CREATE INDEX IF NOT EXISTS ai_review_evidence ON ai_reviews(evidence_id);
          CREATE INDEX IF NOT EXISTS feedback_review ON review_feedback(review_id);
          CREATE INDEX IF NOT EXISTS nodes_case_time ON nodes(case_id,occurred_at);
          CREATE INDEX IF NOT EXISTS screenshots_node ON screenshots(node_id);
          CREATE INDEX IF NOT EXISTS runs_case ON analysis_runs(case_id);
          CREATE INDEX IF NOT EXISTS followup_review ON ai_followups(review_id);
          CREATE INDEX IF NOT EXISTS reverse_case_created ON reverse_jobs(case_id,json_extract(record,'$.createdAt') DESC,id DESC);").map_err(err)?;
        let store = Self {
            #[cfg(debug_assertions)]
            allow_mock_ai: cfg!(test),
            root,
            db: Mutex::new(db),
            _workspace_lock: workspace_lock,
        };
        crate::intelligence::init(&store)?;
        crate::enrichment::init(&store)?;
        crate::investigation::recover_interrupted(&store)?;
        crate::analysis_jobs::recover(&store)?;
        crate::monitoring::init(&store)?;
        crate::collector::init(&store)?;
        crate::response_actions::init(&store)?;
        if store.cases()?.is_empty() {
            store.create_case("未命名调查".into())?;
        }
        store
            .db
            .lock()
            .map_err(err)?
            .execute_batch("PRAGMA user_version=1;")
            .map_err(err)?;
        Ok(store)
    }
    pub fn cases(&self) -> Result<Vec<Case>, String> {
        let db = self.db.lock().map_err(err)?;
        let mut q = db
            .prepare("SELECT id,title,created_at FROM cases ORDER BY created_at DESC")
            .map_err(err)?;
        let rows = q
            .query_map([], |r| {
                Ok(Case {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    created_at: r.get(2)?,
                })
            })
            .map_err(err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(err)
    }
    pub fn active(&self) -> Result<String, String> {
        let db = self.db.lock().map_err(err)?;
        db.query_row(
            "SELECT value FROM settings WHERE key='active_case'",
            [],
            |r| r.get(0),
        )
        .map_err(err)
    }
    pub fn create_case(&self, title: String) -> Result<Case, String> {
        let title = title.trim();
        if title.is_empty() || title.chars().count() > 120 {
            return Err("事件名称需为 1–120 个字符。".into());
        }
        let c = Case {
            id: uid(),
            title: title.into(),
            created_at: now(),
        };
        let db = self.db.lock().map_err(err)?;
        db.execute(
            "INSERT INTO cases VALUES(?1,?2,?3)",
            params![c.id, c.title, c.created_at],
        )
        .map_err(err)?;
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES('active_case',?1)",
            [&c.id],
        )
        .map_err(err)?;
        Ok(c)
    }
    pub fn switch_case(&self, id: String) -> Result<(), String> {
        let db = self.db.lock().map_err(err)?;
        let exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
                [&id],
                |r| r.get(0),
            )
            .map_err(err)?;
        if !exists {
            return Err("事件不存在。".into());
        }
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES('active_case',?1)",
            [id],
        )
        .map_err(err)?;
        Ok(())
    }
    pub fn workspace(&self) -> Result<Workspace, String> {
        let cases = self.cases()?;
        let active_case = self.active()?;
        let db = self.db.lock().map_err(err)?;
        let mut q=db.prepare("SELECT id,case_id,name,kind,sha256,size,created_at,report FROM evidence WHERE case_id=?1 ORDER BY created_at DESC").map_err(err)?;
        let tuples = q
            .query_map([&active_case], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, u64>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        let mut evidence = Vec::new();
        for (id, case_id, name, kind, sha256, size, created_at, json) in tuples {
            evidence.push(Evidence {
                id,
                case_id,
                name,
                kind,
                sha256,
                size,
                created_at,
                report: serde_json::from_str(&json).map_err(err)?,
            });
        }
        let mut q=db.prepare("SELECT id,case_id,evidence_id,finding_id,occurred_at,recorded_at,title,body,actor,included FROM nodes WHERE case_id=?1 ORDER BY occurred_at,recorded_at").map_err(err)?;
        let mut nodes = q
            .query_map([&active_case], |r| {
                Ok(TimelineNode {
                    id: r.get(0)?,
                    case_id: r.get(1)?,
                    evidence_id: r.get(2)?,
                    finding_id: r.get(3)?,
                    occurred_at: r.get(4)?,
                    recorded_at: r.get(5)?,
                    title: r.get(6)?,
                    body: r.get(7)?,
                    actor: r.get(8)?,
                    included: r.get(9)?,
                    screenshots: vec![],
                })
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        for node in &mut nodes {
            let mut q=db.prepare("SELECT id,node_id,name,sha256,size,mime,caption FROM screenshots WHERE node_id=?1 ORDER BY rowid").map_err(err)?;
            node.screenshots = q
                .query_map([&node.id], |r| {
                    Ok(Screenshot {
                        id: r.get(0)?,
                        node_id: r.get(1)?,
                        name: r.get(2)?,
                        sha256: r.get(3)?,
                        size: r.get(4)?,
                        mime: r.get(5)?,
                        caption: r.get(6)?,
                    })
                })
                .map_err(err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(err)?;
        }
        let mut q=db.prepare("SELECT a.record FROM ai_reviews a JOIN evidence e ON a.evidence_id=e.id WHERE e.case_id=?1 ORDER BY a.rowid DESC").map_err(err)?;
        let records = q
            .query_map([&active_case], |r| r.get::<_, String>(0))
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        let ai_reviews = records
            .into_iter()
            .map(|s| serde_json::from_str(&s).map_err(err))
            .collect::<Result<Vec<_>, _>>()?;
        let mut q = db
            .prepare(
                "SELECT record FROM analysis_runs WHERE case_id=?1 ORDER BY rowid DESC LIMIT 200",
            )
            .map_err(err)?;
        let analysis_runs = q
            .query_map([&active_case], |r| r.get::<_, String>(0))
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?
            .into_iter()
            .map(|s| serde_json::from_str(&s).map_err(err))
            .collect::<Result<Vec<_>, _>>()?;
        let read_related = |table: &str| -> Result<Vec<String>, String> {
            let mut q=db.prepare(&format!("SELECT t.record FROM {table} t JOIN ai_reviews a ON t.review_id=a.id JOIN evidence e ON a.evidence_id=e.id WHERE e.case_id=?1 ORDER BY t.rowid")).map_err(err)?;
            let values = q
                .query_map([&active_case], |r| r.get::<_, String>(0))
                .map_err(err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(err)?;
            Ok(values)
        };
        let followups = read_related("ai_followups")?
            .into_iter()
            .map(|s| serde_json::from_str(&s).map_err(err))
            .collect::<Result<Vec<_>, _>>()?;
        let review_feedback = read_related("review_feedback")?
            .into_iter()
            .map(|s| serde_json::from_str(&s).map_err(err))
            .collect::<Result<Vec<_>, _>>()?;
        let mut q = db
            .prepare("SELECT record FROM response_actions WHERE case_id=?1 ORDER BY json_extract(record,'$.requestedAt'),id")
            .map_err(err)?;
        let response_actions = q
            .query_map([&active_case], |r| r.get::<_, String>(0))
            .map_err(err)?
            .map(|r| serde_json::from_str(&r.map_err(err)?).map_err(err))
            .collect::<Result<Vec<crate::response_actions::ResponseAction>, String>>()?;
        Ok(Workspace {
            cases,
            active_case,
            evidence,
            nodes,
            ai_reviews,
            analysis_runs,
            followups,
            review_feedback,
            response_actions,
            data_dir: self.root.display().to_string(),
        })
    }
    /// 大型事件列表的分页读取接口。默认只返回元数据和截图摘要，图片正文仍由
    /// screenshot_data 按需读取，避免一次 IPC 搬运整个事件。
    pub fn timeline_page(
        &self,
        case_id: &str,
        offset: u64,
        limit: u64,
        query: &str,
    ) -> Result<serde_json::Value, String> {
        let limit = limit.clamp(1, 200);
        let offset = offset.min(10_000_000);
        let db = self.db.lock().map_err(err)?;
        let total: u64 = db.query_row("SELECT count(*) FROM nodes WHERE case_id=?1 AND (?2='' OR title LIKE '%'||?2||'%' OR body LIKE '%'||?2||'%')", rusqlite::params![case_id, query], |r| r.get(0)).map_err(err)?;
        let mut q = db.prepare("SELECT id,case_id,evidence_id,finding_id,occurred_at,recorded_at,title,body,actor,included FROM nodes WHERE case_id=?1 AND (?2='' OR title LIKE '%'||?2||'%' OR body LIKE '%'||?2||'%') ORDER BY occurred_at,recorded_at,id LIMIT ?3 OFFSET ?4").map_err(err)?;
        let rows = q.query_map(rusqlite::params![case_id, query, limit, offset], |r| Ok(serde_json::json!({
            "id": r.get::<_,String>(0)?, "caseId": r.get::<_,String>(1)?, "evidenceId": r.get::<_,Option<String>>(2)?,
            "findingId": r.get::<_,Option<String>>(3)?, "occurredAt": r.get::<_,String>(4)?, "recordedAt": r.get::<_,String>(5)?,
            "title": r.get::<_,String>(6)?, "body": r.get::<_,String>(7)?, "actor": r.get::<_,String>(8)?, "included": r.get::<_,bool>(9)?
        }))).map_err(err)?;
        let rows = rows.collect::<Result<Vec<_>, _>>().map_err(err)?;
        Ok(serde_json::json!({"rows": rows, "total": total, "offset": offset, "limit": limit}))
    }
    pub fn evidence_page(
        &self,
        case_id: &str,
        offset: u64,
        limit: u64,
        query: &str,
    ) -> Result<serde_json::Value, String> {
        let limit = limit.clamp(1, 100);
        let offset = offset.min(10_000_000);
        let db = self.db.lock().map_err(err)?;
        let total: u64 = db.query_row("SELECT count(*) FROM evidence WHERE case_id=?1 AND (?2='' OR name LIKE '%'||?2||'%' OR kind LIKE '%'||?2||'%')", rusqlite::params![case_id, query], |r| r.get(0)).map_err(err)?;
        let mut q = db.prepare("SELECT id,case_id,name,kind,sha256,size,created_at,report FROM evidence WHERE case_id=?1 AND (?2='' OR name LIKE '%'||?2||'%' OR kind LIKE '%'||?2||'%') ORDER BY created_at DESC,id LIMIT ?3 OFFSET ?4").map_err(err)?;
        let rows = q.query_map(rusqlite::params![case_id, query, limit, offset], |r| {
            let report: String = r.get(7)?;
            Ok(serde_json::json!({"id":r.get::<_,String>(0)?,"caseId":r.get::<_,String>(1)?,"name":r.get::<_,String>(2)?,"kind":r.get::<_,String>(3)?,"sha256":r.get::<_,String>(4)?,"size":r.get::<_,u64>(5)?,"createdAt":r.get::<_,String>(6)?,"report":serde_json::from_str::<serde_json::Value>(&report).unwrap_or_else(|_| serde_json::json!({}))}))
        }).map_err(err)?;
        let rows = rows.collect::<Result<Vec<_>, _>>().map_err(err)?;
        Ok(serde_json::json!({"rows": rows, "total": total, "offset": offset, "limit": limit}))
    }
    fn snapshot(
        &self,
        path: &str,
        id: &str,
        folder: &str,
        limit: u64,
    ) -> Result<(String, u64, String, PathBuf), String> {
        self.snapshot_observed(path, id, folder, limit, &crate::analysis_progress::Silent)
    }
    fn snapshot_observed(
        &self,
        path: &str,
        id: &str,
        folder: &str,
        limit: u64,
        observer: &dyn crate::analysis_progress::Observer,
    ) -> Result<(String, u64, String, PathBuf), String> {
        let source = Path::new(path);
        // Do not follow a user supplied link while taking an evidence snapshot.
        // A symlink can otherwise redirect the importer to a different file
        // between the picker and the analysis worker.
        let metadata = fs::symlink_metadata(source).map_err(err)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("请选择普通文件，不能使用符号链接。".into());
        }
        if metadata.len() > limit {
            return Err(format!(
                "文件超过本版 {} MiB 上限；请按文件大小或时间段拆分后导入。",
                limit / 1024 / 1024
            ));
        }
        let name = source
            .file_name()
            .ok_or("文件名无效")?
            .to_string_lossy()
            .to_string();
        observer.phase("archiving", metadata.len())?;
        let target = self.root.join(folder).join(id);
        let mut hash = Sha256::new();
        let mut size = 0u64;
        crate::file_commit::write_new(&target, |output| {
            let mut input = FileReader::open(source)?;
            let mut chunk = [0u8; 65536];
            loop {
                observer.check()?;
                let n = input.0.read(&mut chunk).map_err(err)?;
                if n == 0 {
                    break;
                }
                size += n as u64;
                if size > limit {
                    return Err("复制期间文件增长并超过限制，已中止。".into());
                }
                hash.update(&chunk[..n]);
                output.write_all(&chunk[..n]).map_err(err)?;
                observer.copied(size)?;
            }
            observer.check()
        })?;
        Ok((name, size, format!("{:x}", hash.finalize()), target))
    }
    pub fn analyze_file(&self, path: String, kind: String) -> Result<Evidence, String> {
        self.analyze_file_for_case(path, kind, self.active()?)
    }
    pub fn evidence_for_case(&self, case: &str, id: &str) -> Result<Evidence, String> {
        let db = self.db.lock().map_err(err)?;
        db.query_row("SELECT id,case_id,name,kind,sha256,size,created_at,report FROM evidence WHERE case_id=?1 AND id=?2",params![case,id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,u64>(5)?,r.get::<_,String>(6)?,r.get::<_,String>(7)?))).map_err(|_|"证据不属于指定事件。".to_string()).and_then(|r|Ok(Evidence{id:r.0,case_id:r.1,name:r.2,kind:r.3,sha256:r.4,size:r.5,created_at:r.6,report:serde_json::from_str(&r.7).map_err(err)?}))
    }
    pub fn archive_record(
        &self,
        case: &str,
        name: &str,
        record: &serde_json::Value,
    ) -> Result<Evidence, String> {
        let dir = self.root.join("record-input");
        fs::create_dir_all(&dir).map_err(err)?;
        let path = dir.join(format!(
            "{}-{}.json",
            name.chars()
                .filter(|c| c.is_alphanumeric() || *c == '-')
                .take(80)
                .collect::<String>(),
            uid()
        ));
        let bytes = serde_json::to_vec_pretty(record).map_err(err)?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err("观测记录超过 32 MiB。".into());
        }
        crate::file_commit::write_new(&path, |file| file.write_all(&bytes).map_err(err))?;
        let result =
            self.analyze_file_for_case(path.display().to_string(), "triage".into(), case.into());
        let _ = fs::remove_file(path);
        result
    }
    pub fn analyze_file_for_case(
        &self,
        path: String,
        kind: String,
        case_id: String,
    ) -> Result<Evidence, String> {
        self.analyze_file_observed(path, kind, case_id, &crate::analysis_progress::Silent)
    }
    pub fn analyze_file_observed(
        &self,
        path: String,
        kind: String,
        case_id: String,
        observer: &dyn crate::analysis_progress::Observer,
    ) -> Result<Evidence, String> {
        if !self.cases()?.iter().any(|case| case.id == case_id) {
            return Err("事件不存在。".into());
        }
        observer.check()?;
        let limit = match kind.as_str() {
            "logs" => 2 * 1024 * 1024 * 1024,
            "http" => 32 * 1024 * 1024,
            "triage" => 32 * 1024 * 1024,
            "webshell" => 8 * 1024 * 1024,
            "containers" => 16 * 1024 * 1024,
            "binary" => 128 * 1024 * 1024,
            _ => return Err("不支持的分析类型。".into()),
        };
        let id = uid();
        // 先保存不可变快照并计算摘要，所有后续分析以快照为准，失败时清除临时证据。
        let (name, size, sha256, snapshot) =
            self.snapshot_observed(&path, &id, "evidence", limit, observer)?;
        let failed_id = id.clone();
        let failed_case = case_id.clone();
        let failed_kind = kind.clone();
        let result = (|| {
            observer.phase(
                if kind == "logs" {
                    "scanning"
                } else {
                    "environment"
                },
                size,
            )?;
            let report = match kind.as_str() {
                "logs" => crate::logbook::index_observed(
                    self,
                    &snapshot,
                    &case_id,
                    &id,
                    Default::default(),
                    observer,
                ),
                "http" => crate::http::analyze(&snapshot),
                "triage" => crate::triage::analyze(&snapshot),
                "webshell" => crate::isolated::analyze_observed(
                    self, &snapshot, "webshell", &sha256, observer,
                ),
                "containers" => analyzers::analyze_container(&snapshot),
                _ => {
                    crate::isolated::analyze_observed(self, &snapshot, "binary", &sha256, observer)
                }
            }?;
            let item = Evidence {
                id,
                case_id,
                name,
                kind,
                sha256,
                size,
                created_at: now(),
                report,
            };
            observer.findings(&item.report.findings)?;
            observer.begin_commit(&item.id)?;
            protect_archive(&snapshot)?;
            let db = self.db.lock().map_err(err)?;
            db.execute(
                "INSERT INTO evidence VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    item.id,
                    item.case_id,
                    item.name,
                    item.kind,
                    item.sha256,
                    item.size,
                    item.created_at,
                    serde_json::to_string(&item.report).map_err(err)?
                ],
            )
            .map_err(err)?;
            drop(db);
            Ok(item)
        })();
        if result.is_err() {
            discard_snapshot(&snapshot);
            if failed_kind == "logs" {
                if let Err(error) = crate::logbook::discard_import(self, &failed_case, &failed_id) {
                    crate::runtime_log::event(
                        "error",
                        "analysis",
                        "INDEX_ROLLBACK_FAILED",
                        &error,
                        None,
                    );
                }
            }
        }
        if let Ok(item) = &result {
            if let Err(error) = crate::intelligence::index_evidence(self, item) {
                eprintln!("IOC indexing failed for {}: {}", item.id, error);
                if let Ok(db) = self.db.lock() {
                    let _ = db.execute(
                        "INSERT OR REPLACE INTO settings VALUES(?1,?2)",
                        params![format!("intel_index_error:{}", item.id), error],
                    );
                }
            }
        }
        result
    }
    pub fn analyze_http_pair(&self, request: String, response: String) -> Result<Evidence, String> {
        let case_id = self.active()?;
        if request.trim().is_empty()
            || request.len() > 2 * 1024 * 1024
            || response.len() > 2 * 1024 * 1024
        {
            return Err("请提供请求报文；每侧 UTF-8 文本不得超过 2 MiB。".into());
        }
        let dir = self.root.join("http-input");
        fs::create_dir_all(&dir).map_err(err)?;
        let path = dir.join(format!("HTTP-手动报文对-{}.json", uid()));
        let value = serde_json::json!({"format":"gaga-http-pair/1","association":"manual","request":request,"response":response});
        let bytes = serde_json::to_vec_pretty(&value).map_err(err)?;
        crate::file_commit::write_new(&path, |file| file.write_all(&bytes).map_err(err))?;
        let result = self.analyze_file_for_case(path.display().to_string(), "http".into(), case_id);
        let _ = fs::remove_file(path);
        result
    }
    pub fn analyze_alert_text(&self, text: String) -> Result<Evidence, String> {
        if text.trim().is_empty() || text.len() > 2 * 1024 * 1024 {
            return Err("请粘贴非空告警文本，最多 2 MiB。".into());
        }
        let dir = self.root.join("alert-input");
        fs::create_dir_all(&dir).map_err(err)?;
        let path = dir.join(format!("粘贴告警-{}.txt", uid()));
        crate::file_commit::write_new(&path, |file| file.write_all(text.as_bytes()).map_err(err))?;
        let result = self.analyze_file(path.display().to_string(), "triage".into());
        let _ = fs::remove_file(path);
        result
    }
    pub fn add_node(
        &self,
        title: String,
        body: String,
        occurred_at: String,
        actor: String,
        evidence_id: Option<String>,
        finding_id: Option<String>,
    ) -> Result<(), String> {
        if title.trim().is_empty()
            || body.trim().is_empty()
            || actor.trim().is_empty()
            || title.chars().count() > 200
            || body.chars().count() > 30_000
            || actor.chars().count() > 100
            || occurred_at.chars().count() > 80
        {
            return Err("节点字段为空或超过长度限制。".into());
        }
        let occurred_at = chrono::DateTime::parse_from_rfc3339(&occurred_at)
            .map_err(|_| "发生时间需要包含有效日期、秒与时区。")?
            .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
            .to_rfc3339();
        let case = self.active()?;
        let db = self.db.lock().map_err(err)?;
        if let Some(id) = &evidence_id {
            let same: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM evidence WHERE id=?1 AND case_id=?2)",
                    params![id, case],
                    |r| r.get(0),
                )
                .map_err(err)?;
            if !same {
                return Err("证据不属于当前事件。".into());
            }
        }
        if let Some(id) = &finding_id {
            let json: Option<String> = db
                .query_row(
                    "SELECT report FROM evidence WHERE id=?1",
                    [&evidence_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(err)?;
            let report: AnalysisReport =
                serde_json::from_str(&json.ok_or("缺少关联证据")?).map_err(err)?;
            if !report.findings.iter().any(|f| f.id == *id) {
                return Err("关联发现不存在。".into());
            }
        }
        db.execute(
            "INSERT INTO nodes VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
            params![
                uid(),
                case,
                evidence_id,
                finding_id,
                occurred_at,
                now(),
                title.trim(),
                body,
                actor
            ],
        )
        .map_err(err)?;
        Ok(())
    }
    pub fn update_node(
        &self,
        id: String,
        title: String,
        body: String,
        occurred_at: String,
        actor: String,
    ) -> Result<(), String> {
        if title.trim().is_empty()
            || body.trim().is_empty()
            || actor.trim().is_empty()
            || title.chars().count() > 200
            || body.chars().count() > 30_000
            || actor.chars().count() > 100
        {
            return Err("节点字段为空或超过长度限制。".into());
        }
        let occurred_at = chrono::DateTime::parse_from_rfc3339(&occurred_at)
            .map_err(|_| "发生时间需要包含有效日期、秒与时区。")?
            .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
            .to_rfc3339();
        let case_id = self.active()?;
        let mut db = self.db.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        let previous: (String, String, String, String) = tx
            .query_row(
                "SELECT title,body,occurred_at,actor FROM nodes WHERE id=?1 AND case_id=?2",
                params![id, case_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| "节点不属于当前事件。")?;
        let current = (title.trim().to_owned(), body, occurred_at, actor);
        tx.execute(
            "UPDATE nodes SET title=?1,body=?2,occurred_at=?3,actor=?4 WHERE id=?5 AND case_id=?6",
            params![current.0, current.1, current.2, current.3, id, case_id],
        )
        .map_err(err)?;
        tx.execute(
            "INSERT INTO node_revisions VALUES(?1,?2,?3,?4,?5)",
            params![
                uid(),
                id,
                now(),
                serde_json::to_string(&previous).map_err(err)?,
                serde_json::to_string(&current).map_err(err)?
            ],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(())
    }
    pub fn toggle_node(&self, id: String, included: bool) -> Result<(), String> {
        let case = self.active()?;
        let db = self.db.lock().map_err(err)?;
        let n = db
            .execute(
                "UPDATE nodes SET included=?1 WHERE id=?2 AND case_id=?3",
                params![included, id, case],
            )
            .map_err(err)?;
        if n == 0 {
            return Err("节点不存在。".into());
        }
        Ok(())
    }
    pub fn add_screenshot(
        &self,
        node_id: String,
        path: String,
        caption: String,
    ) -> Result<(), String> {
        if caption.trim().is_empty() || caption.chars().count() > 1000 {
            return Err("请填写 1–1000 字的举证图注。".into());
        }
        {
            let case = self.active()?;
            let db = self.db.lock().map_err(err)?;
            let exists: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=?1 AND case_id=?2)",
                    params![node_id, case],
                    |r| r.get(0),
                )
                .map_err(err)?;
            if !exists {
                return Err("节点不存在。".into());
            }
        }
        let id = uid();
        let (name, size, sha256, target) =
            self.snapshot(&path, &id, "screenshots", 8 * 1024 * 1024)?;
        let result = (|| {
            let image = read_image(&fs::read(&target).map_err(err)?)?;
            let _dimensions = (image.width(), image.height());
            let bytes = fs::read(&target).map_err(err)?;
            let mime = match image::guess_format(&bytes).map_err(err)? {
                image::ImageFormat::Png => "image/png",
                image::ImageFormat::Jpeg => "image/jpeg",
                image::ImageFormat::WebP => "image/webp",
                _ => return Err("仅支持 PNG、JPEG 与 WebP。".into()),
            };
            protect_archive(&target)?;
            let db = self.db.lock().map_err(err)?;
            db.execute(
                "INSERT INTO screenshots VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![id, node_id, name, sha256, size, mime, caption],
            )
            .map_err(err)?;
            Ok(())
        })();
        if result.is_err() {
            discard_snapshot(&target);
        }
        result
    }
    /// Background captures bind both the node and image to the captured case,
    /// independent of whichever case is active when the browser finishes.
    pub(crate) fn archive_monitor_screenshot(
        &self,
        case: &str,
        evidence: &str,
        png: &[u8],
        captured_at: &str,
        url: &str,
        html_hash: &str,
    ) -> Result<Screenshot, String> {
        if png.len() > 8 * 1024 * 1024
            || image::guess_format(png).map_err(err)? != image::ImageFormat::Png
        {
            return Err("自动截图需要不超过 8 MiB 的 PNG".into());
        }
        read_image(png)?;
        chrono::DateTime::parse_from_rfc3339(captured_at).map_err(err)?;
        let id = uid();
        let node_id = uid();
        let target = self.root.join("screenshots").join(&id);
        let shot = Screenshot {
            id,
            node_id,
            name: "页面自动截图.png".into(),
            sha256: format!("{:x}", Sha256::digest(png)),
            size: png.len() as u64,
            mime: "image/png".into(),
            caption: analyzers::cut(
                &format!("自动截图 · {captured_at} · {url} · 1440×900 视口；不含登录态"),
                1000,
            ),
        };
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .and_then(|mut f| {
                f.write_all(png)?;
                f.sync_all()
            })
            .map_err(err)?;
        let result = (|| {
            protect_archive(&target)?;
            let mut db = self.db.lock().map_err(err)?;
            let tx = db.transaction().map_err(err)?;
            let same: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM evidence WHERE id=?1 AND case_id=?2)",
                    params![evidence, case],
                    |r| r.get(0),
                )
                .map_err(err)?;
            if !same {
                return Err("截图证据不属于采集事件".into());
            }
            tx.execute("INSERT INTO nodes VALUES(?1,?2,?3,NULL,?4,?5,?6,?7,?8,1)", params![shot.node_id,case,evidence,captured_at,now(),"资产页面自动截图 · 待复核",analyzers::cut(&format!("最终 URL：{url}\n截图时间：{captured_at}\nHTTP HTML SHA-256：{html_hash}\n截图是浏览器独立请求的渲染结果，与 HTTP 原文分别留存；截图不能证明页面安全。"),30000),"嘎嘎自动巡检"]).map_err(err)?;
            tx.execute(
                "INSERT INTO screenshots VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    shot.id,
                    shot.node_id,
                    shot.name,
                    shot.sha256,
                    shot.size,
                    shot.mime,
                    shot.caption
                ],
            )
            .map_err(err)?;
            tx.commit().map_err(err)
        })();
        if let Err(error) = result {
            discard_snapshot(&target);
            return Err(error);
        }
        Ok(shot)
    }
    pub fn screenshot_data(&self, id: String) -> Result<String, String> {
        let case = self.active()?;
        let db = self.db.lock().map_err(err)?;
        let (mime, hash, size): (String, String, u64) = db
            .query_row("SELECT s.mime,s.sha256,s.size FROM screenshots s JOIN nodes n ON n.id=s.node_id WHERE s.id=?1 AND n.case_id=?2", params![id,case], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))
            .map_err(|_| "截图不属于当前事件。")?;
        drop(db);
        let bytes = verified_image_bytes(&self.root.join("screenshots").join(id), size, &hash)?;
        Ok(format!("data:{mime};base64,{}", STANDARD.encode(bytes)))
    }
}
/// 只读属性防止误写，不等同于管理员无法删除的 WORM 存储。
/// 所有派生索引、报告、AI 结果另存，原件读取仍须核对归档 SHA-256。
pub(crate) fn protect_archive(path: &Path) -> Result<(), String> {
    let mut permissions = fs::metadata(path).map_err(err)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).map_err(err)
}
pub(crate) fn discard_snapshot(path: &Path) {
    // 仅用于未提交的临时快照回滚；Windows 需先清除只读属性才能删除。
    #[cfg(windows)]
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        let _ = fs::set_permissions(path, permissions);
    }
    let _ = fs::remove_file(path);
}
#[cfg(test)]
pub(crate) fn test_overwrite_archive(
    path: impl AsRef<Path>,
    bytes: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    let path = path.as_ref();
    let mut permissions = match fs::metadata(path) {
        Ok(meta) => meta.permissions(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return fs::write(path, bytes),
        Err(e) => return Err(e),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o600);
    }
    #[cfg(windows)]
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)?;
    fs::write(path, bytes)
}
struct FileReader(fs::File);
impl FileReader {
    fn open(path: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path).map_err(err)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("输入文件在读取前变为符号链接，已拒绝导入。".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // O_NOFOLLOW closes the common final-component swap race on Unix.
            // Parent directories are still governed by the workspace/user ACL.
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
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(O_NOFOLLOW)
                .open(path)
                .map(Self)
                .map_err(err)
        }
        #[cfg(not(unix))]
        fs::File::open(path).map(Self).map_err(err)
    }
}

/// Open an ordinary file without following a user supplied final-component
/// symlink.  Commands that preview or re-read selected material use this
/// helper so the initial type check and the actual read share the same guard.
pub(crate) fn open_regular_read(path: &Path) -> Result<fs::File, String> {
    FileReader::open(path).map(|reader| reader.0)
}
pub fn verified_image_bytes(path: &Path, size: u64, hash: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(err)?
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    if bytes.len() > 8 * 1024 * 1024
        || bytes.len() as u64 != size
        || format!("{:x}", Sha256::digest(&bytes)) != hash
    {
        return Err("截图归档完整性校验失败。".into());
    }
    Ok(bytes)
}
pub fn read_image(bytes: &[u8]) -> Result<image::DynamicImage, String> {
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(err)?;
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(64 * 1024 * 1024);
    limits.max_image_width = Some(10000);
    limits.max_image_height = Some(10000);
    reader.limits(limits);
    reader.decode().map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_and_node_survive_reopening() {
        let root = std::env::temp_dir().join(format!("gaga-store-{}", uid()));
        let input = root.with_extension("log");
        fs::write(&input, "plain log\n").unwrap();
        let evidence_id;
        {
            let s = Store::open(root.clone()).unwrap();
            let e = s
                .analyze_file(input.display().to_string(), "logs".into())
                .unwrap();
            evidence_id = e.id.clone();
            s.add_node(
                "人工记录".into(),
                "依据保留".into(),
                "2026-10-27T10:22:00+08:00".into(),
                "张三".into(),
                Some(e.id),
                None,
            )
            .unwrap();
        }
        let s = Store::open(root.clone()).unwrap();
        let w = s.workspace().unwrap();
        assert_eq!(w.evidence[0].id, evidence_id);
        assert_eq!(w.nodes[0].actor, "张三");
        assert!(root.join("evidence").join(evidence_id).exists());
        drop(s);
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(input).unwrap();
    }
    #[test]
    fn http_pair_keeps_both_sides_and_redacts_only_ai_preview() {
        let root = std::env::temp_dir().join(format!("gaga-http-store-{}", uid()));
        let s = Store::open(root.clone()).unwrap();
        let request="GET /.env?token=demo-sensitive-token HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer demo-header-only\r\n\r\n";
        let response="HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDB_PASSWORD=demo-sensitive-response";
        let e = s
            .analyze_http_pair(request.into(), response.into())
            .unwrap();
        let source: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("evidence").join(&e.id)).unwrap()).unwrap();
        assert_eq!(source["request"], request);
        assert_eq!(source["response"], response);
        let material = crate::ai::material(&s, &e.id).unwrap();
        assert!(material.contains("请求视图"));
        assert!(material.contains("响应视图"));
        assert!(material.contains("已遮盖"));
        assert!(!material.contains("demo-sensitive-token"));
        assert!(!material.contains("demo-sensitive-response"));
        assert!(!material.contains("demo-header-only"));
        let f = e
            .report
            .findings
            .iter()
            .find(|f| f.title == "响应含敏感配置字段")
            .unwrap();
        s.add_node(
            "HTTP 关联复核".into(),
            "请求与响应均已归档，仍需人工复核影响。".into(),
            "2026-10-27T10:21:00+08:00".into(),
            "测试分析员".into(),
            Some(e.id.clone()),
            Some(f.id.clone()),
        )
        .unwrap();
        crate::report::export_docx(&s, &root.join("http-report.docx")).unwrap();
        let mut zip =
            zip::ZipArchive::new(fs::File::open(root.join("http-report.docx")).unwrap()).unwrap();
        let mut xml = String::new();
        zip.by_name("word/document.xml")
            .unwrap()
            .read_to_string(&mut xml)
            .unwrap();
        assert!(xml.contains("请求阅读视图"));
        assert!(xml.contains("响应阅读视图"));
        assert!(xml.contains("demo-sensitive-response"));
        assert!(xml.contains("/request"));
        assert!(xml.contains("/response"));
        drop(zip);
        drop(s);
        let reopened = Store::open(root.clone()).unwrap();
        let w = reopened.workspace().unwrap();
        assert_eq!(w.evidence[0].report.http_exchanges.len(), 1);
        assert!(w.evidence[0].report.http_exchanges[0]
            .request
            .sha256
            .is_some());
        assert_eq!(w.nodes.len(), 1);
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn invalid_http_pair_leaves_no_archived_or_temporary_file() {
        let root = std::env::temp_dir().join(format!("gaga-http-invalid-{}", uid()));
        let s = Store::open(root.clone()).unwrap();
        assert!(s
            .analyze_http_pair("not an HTTP request".into(), String::new())
            .is_err());
        assert!(s.workspace().unwrap().evidence.is_empty());
        assert_eq!(fs::read_dir(root.join("evidence")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(root.join("http-input")).unwrap().count(), 0);
        drop(s);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_analysis_does_not_leave_evidence() {
        let root = std::env::temp_dir().join(format!("gaga-store-{}", uid()));
        let input = root.with_extension("json");
        fs::write(&input, "not json").unwrap();
        let s = Store::open(root.clone()).unwrap();
        assert!(s
            .analyze_file(input.display().to_string(), "containers".into())
            .is_err());
        assert!(s.workspace().unwrap().evidence.is_empty());
        assert_eq!(fs::read_dir(root.join("evidence")).unwrap().count(), 0);
        drop(s);
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(input).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn evidence_import_rejects_symlink_inputs() {
        let root = std::env::temp_dir().join(format!("gaga-store-link-{}", uid()));
        let outside = root.with_extension("outside.log");
        fs::write(&outside, "outside material\n").unwrap();
        let link = root.with_extension("selected.log");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let store = Store::open(root.clone()).unwrap();
        let error = match store.analyze_file(link.display().to_string(), "logs".into()) {
            Ok(_) => panic!("a selected link must never become evidence"),
            Err(error) => error,
        };
        assert!(error.contains("符号链接"));
        assert!(store.workspace().unwrap().evidence.is_empty());
        drop(store);
        fs::remove_file(&link).unwrap();
        fs::remove_file(&outside).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn workspace_rejects_symlinked_storage_and_lock_paths() {
        let parent = std::env::temp_dir().join(format!("gaga-store-layout-{}", uid()));
        fs::create_dir(&parent).unwrap();
        let outside = parent.join("outside");
        fs::create_dir(&outside).unwrap();

        let linked_root = parent.join("linked-root");
        std::os::unix::fs::symlink(&outside, linked_root.join("evidence")).unwrap_or_else(|_| {
            fs::create_dir(&linked_root).unwrap();
            std::os::unix::fs::symlink(&outside, linked_root.join("evidence")).unwrap();
        });
        assert!(Store::open(linked_root).is_err());
        assert!(fs::read_dir(&outside).unwrap().next().is_none());

        let lock_root = parent.join("linked-lock");
        fs::create_dir(&lock_root).unwrap();
        fs::create_dir(lock_root.join("evidence")).unwrap();
        fs::create_dir(lock_root.join("screenshots")).unwrap();
        std::os::unix::fs::symlink(&outside, lock_root.join("workspace.lock")).unwrap();
        assert!(Store::open(lock_root).is_err());
        fs::remove_dir_all(parent).unwrap();
    }
}
