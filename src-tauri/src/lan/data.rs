//! 局域网私有数据与证据库分开。聊天正文、配对凭据和附件加密落盘；
//! 本机数据密钥受文件权限保护，不宣称能抵御当前用户或管理员。
use super::*;
use aes_gcm::{aead::Aead, aead::Payload, Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde_json::Value;

pub fn schema(store: &Store) -> Result<(), String> {
    store.db.lock().map_err(fail)?.execute_batch(
        "CREATE TABLE IF NOT EXISTS lan_contacts(id TEXT PRIMARY KEY,record TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS lan_messages(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,peer_id TEXT NOT NULL,direction TEXT NOT NULL,kind TEXT NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL,record TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS lan_groups(id TEXT PRIMARY KEY,record TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS lan_group_members(group_id TEXT NOT NULL,peer_id TEXT NOT NULL,record TEXT NOT NULL,PRIMARY KEY(group_id,peer_id));
         CREATE TABLE IF NOT EXISTS lan_group_messages(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,group_id TEXT NOT NULL,sender_id TEXT NOT NULL,sender_alias TEXT NOT NULL,kind TEXT NOT NULL,created_at TEXT NOT NULL,record TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS lan_notifications(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,group_id TEXT,kind TEXT NOT NULL,created_at TEXT NOT NULL,state TEXT NOT NULL,record TEXT NOT NULL);
         CREATE INDEX IF NOT EXISTS lan_messages_peer_seq ON lan_messages(peer_id,seq);
         CREATE INDEX IF NOT EXISTS lan_group_messages_group_seq ON lan_group_messages(group_id,seq);
         UPDATE lan_messages SET state='failed' WHERE direction='out' AND state='sending';
         UPDATE lan_messages SET state='offered' WHERE direction='in' AND state='receiving';
         UPDATE lan_messages SET state='recovered_metadata' WHERE direction='out' AND state='recovering';"
    ).map_err(fail)
}

/// 工作区交付备份不携带聊天、附件、配对关系及网络身份。
pub fn redact(db: &rusqlite::Connection) -> Result<(), String> {
    for table in [
        "lan_messages",
        "lan_contacts",
        "lan_group_members",
        "lan_groups",
        "lan_group_messages",
        "lan_notifications",
    ] {
        let exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
                [table],
                |r| r.get(0),
            )
            .map_err(fail)?;
        if exists {
            db.execute(&format!("DELETE FROM {table}"), [])
                .map_err(fail)?;
        }
    }
    db.execute("DELETE FROM settings WHERE key='lan_alias'", [])
        .map_err(fail)?;
    Ok(())
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    crate::file_commit::write_new(path, |file| file.write_all(bytes).map_err(fail))
}

pub struct Identity {
    pub cert: Vec<u8>,
    pub private: Vec<u8>,
    pub data_key: [u8; 32],
    pub id: String,
}
pub fn identity(store: &Store) -> Result<Identity, String> {
    let dir = store.root.join("lan-private");
    if !dir.exists() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).map_err(fail)?;
    }
    if fs::symlink_metadata(&dir)
        .map_err(fail)?
        .file_type()
        .is_symlink()
    {
        return Err("局域网私有数据目录不能是链接".into());
    }
    let bundle = dir.join("identity.json");
    if !bundle.exists() {
        let generated =
            rcgen::generate_simple_self_signed(vec!["gaga.local".into()]).map_err(fail)?;
        let mut data_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut data_key);
        private_write(&bundle, &serde_json::to_vec(&json!({"cert":B64.encode(generated.cert.der()),"private":B64.encode(generated.signing_key.serialize_der()),"dataKey":B64.encode(data_key)})).map_err(fail)?)?;
    }
    let meta = fs::symlink_metadata(&bundle).map_err(fail)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 32768 {
        return Err("局域网身份文件异常；请保留原文件并检查工作区".into());
    }
    let value: Value = serde_json::from_slice(&fs::read(bundle).map_err(fail)?).map_err(fail)?;
    let decode = |name: &str| {
        B64.decode(value[name].as_str().ok_or("局域网身份字段缺失")?)
            .map_err(fail)
    };
    let cert = decode("cert")?;
    let private = decode("private")?;
    let data_key = decode("dataKey")?
        .try_into()
        .map_err(|_| "局域网数据密钥异常")?;
    let id = hash(&cert);
    Ok(Identity {
        cert,
        private,
        data_key,
        id,
    })
}

fn seal(key: &[u8; 32], aad: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "本地加密初始化失败")?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: bytes,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "本地数据加密失败")?;
    Ok([nonce.as_slice(), ciphertext.as_slice()].concat())
}
fn unseal(key: &[u8; 32], aad: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 28 {
        return Err("本地聊天数据损坏".into());
    }
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| "本地解密初始化失败")?
        .decrypt(
            Nonce::from_slice(&bytes[..12]),
            Payload {
                msg: &bytes[12..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "本地聊天数据认证失败，请保留原件检查工作区".into())
}
fn encoded<T: Serialize>(m: &Manager, aad: &str, value: &T) -> Result<String, String> {
    Ok(B64.encode(seal(
        &m.identity.data_key,
        aad,
        &serde_json::to_vec(value).map_err(fail)?,
    )?))
}
fn decoded<T: serde::de::DeserializeOwned>(
    m: &Manager,
    aad: &str,
    value: &str,
) -> Result<T, String> {
    serde_json::from_slice(&unseal(
        &m.identity.data_key,
        aad,
        &B64.decode(value).map_err(fail)?,
    )?)
    .map_err(fail)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    pub id: String,
    pub alias: String,
    pub endpoint: String,
    pub secret: Option<String>,
    pub created_at: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: String,
    pub name: String,
    pub group_type: String,
    pub role: String,
    pub created_at: String,
    pub member_ids: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMessage {
    pub seq: i64,
    pub id: String,
    pub group_id: String,
    pub sender_id: String,
    pub sender_alias: String,
    pub kind: String,
    pub created_at: String,
    pub body: Body,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    pub seq: i64,
    pub id: String,
    pub group_id: Option<String>,
    pub kind: String,
    pub created_at: String,
    pub state: String,
    pub title: String,
    pub body: String,
    pub case_id: Option<String>,
    pub action_id: Option<String>,
}
pub fn contacts(m: &Manager) -> Result<Vec<Contact>, String> {
    let db = m.store.db.lock().map_err(fail)?;
    let mut q = db
        .prepare("SELECT id,record FROM lan_contacts ORDER BY rowid")
        .map_err(fail)?;
    let rows = q
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(fail)?;
    rows.map(|r| {
        let (id, text) = r.map_err(fail)?;
        decoded(m, &format!("contact:{id}"), &text)
    })
    .collect()
}
pub fn contact(m: &Manager, id: &str) -> Result<Contact, String> {
    contacts(m)?
        .into_iter()
        .find(|c| c.id == id)
        .ok_or_else(|| "设备尚未配对".into())
}
pub fn save_contact(m: &Manager, c: &Contact) -> Result<(), String> {
    let record = encoded(m, &format!("contact:{}", c.id), c)?;
    m.store.db.lock().map_err(fail)?.execute("INSERT INTO lan_contacts(id,record) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET record=excluded.record",params![c.id,record]).map_err(fail)?;
    Ok(())
}
pub fn groups(m: &Manager) -> Result<Vec<Group>, String> {
    let db = m.store.db.lock().map_err(fail)?;
    let mut q = db
        .prepare("SELECT record FROM lan_groups ORDER BY rowid")
        .map_err(fail)?;
    let rows = q.query_map([], |r| r.get::<_, String>(0)).map_err(fail)?;
    rows.map(|r| serde_json::from_str(&r.map_err(fail)?).map_err(fail))
        .collect()
}
pub fn save_group(m: &Manager, group: &Group) -> Result<(), String> {
    if group.name.trim().is_empty()
        || group.name.chars().count() > 80
        || group.member_ids.len() > 64
    {
        return Err("群组名称或成员数量无效".into());
    }
    let known = contacts(m)?;
    if group
        .member_ids
        .iter()
        .any(|id| id != &m.identity.id && !known.iter().any(|c| &c.id == id && c.secret.is_some()))
    {
        return Err("群组只能包含已配对联系人".into());
    }
    let record = serde_json::to_string(group).map_err(fail)?;
    let db = m.store.db.lock().map_err(fail)?;
    db.execute("INSERT INTO lan_groups(id,record) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET record=excluded.record", params![group.id, record]).map_err(fail)?;
    db.execute(
        "DELETE FROM lan_group_members WHERE group_id=?1",
        [&group.id],
    )
    .map_err(fail)?;
    for peer in &group.member_ids {
        db.execute(
            "INSERT INTO lan_group_members(group_id,peer_id,record) VALUES(?1,?2,'{}')",
            params![group.id, peer],
        )
        .map_err(fail)?;
    }
    Ok(())
}
pub fn save_remote_group(m: &Manager, group: &Group, sender_id: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(&group.id).is_err()
        || group.name.trim().is_empty()
        || group.name.chars().count() > 80
        || group.member_ids.is_empty()
        || group.member_ids.len() > 64
        || !group.member_ids.iter().any(|id| id == sender_id)
        || group.member_ids.iter().any(|id| !super::id_valid(id))
    {
        return Err("群组同步字段无效".into());
    }
    let record = serde_json::to_string(group).map_err(fail)?;
    let db = m.store.db.lock().map_err(fail)?;
    db.execute("INSERT INTO lan_groups(id,record) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET record=excluded.record", params![group.id, record]).map_err(fail)?;
    db.execute(
        "DELETE FROM lan_group_members WHERE group_id=?1",
        [&group.id],
    )
    .map_err(fail)?;
    for peer in &group.member_ids {
        db.execute(
            "INSERT INTO lan_group_members(group_id,peer_id,record) VALUES(?1,?2,'{}')",
            params![group.id, peer],
        )
        .map_err(fail)?;
    }
    Ok(())
}
pub fn group_message(
    m: &Manager,
    id: &str,
    group_id: &str,
    sender_id: &str,
    alias: &str,
    kind: &str,
    body: &Body,
) -> Result<(), String> {
    uuid::Uuid::parse_str(id).map_err(|_| "群消息标识无效")?;
    if !matches!(kind, "text" | "image" | "file") {
        return Err("群消息类型无效".into());
    }
    let record = encoded(m, &format!("group-message:{group_id}:{id}"), body)?;
    let db = m.store.db.lock().map_err(fail)?;
    db.execute("INSERT OR IGNORE INTO lan_group_messages(id,group_id,sender_id,sender_alias,kind,created_at,record) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![id,group_id,sender_id,alias,kind,now(),record]).map_err(fail)?;
    Ok(())
}
pub fn group_history(
    m: &Manager,
    group_id: &str,
    before: Option<i64>,
) -> Result<Vec<GroupMessage>, String> {
    let db = m.store.db.lock().map_err(fail)?;
    let mut q = db.prepare("SELECT seq,id,sender_id,sender_alias,kind,created_at,record FROM lan_group_messages WHERE group_id=?1 AND seq<?2 ORDER BY seq DESC LIMIT 100").map_err(fail)?;
    let rows = q
        .query_map(params![group_id, before.unwrap_or(i64::MAX)], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })
        .map_err(fail)?;
    let mut out = Vec::new();
    for row in rows {
        let (seq, id, sender_id, sender_alias, kind, created_at, record) = row.map_err(fail)?;
        let body = decoded(m, &format!("group-message:{group_id}:{id}"), &record)?;
        out.push(GroupMessage {
            seq,
            id,
            group_id: group_id.into(),
            sender_id,
            sender_alias,
            kind,
            created_at,
            body,
        });
    }
    out.reverse();
    Ok(out)
}
pub fn notification(
    m: &Manager,
    group_id: Option<&str>,
    kind: &str,
    title: &str,
    body: &str,
    case_id: Option<&str>,
    action_id: Option<&str>,
) -> Result<(), String> {
    if title.chars().count() > 160 || body.chars().count() > 4000 {
        return Err("通知内容过长".into());
    }
    let id = uuid::Uuid::new_v4().to_string();
    let value =
        serde_json::json!({"title":title,"body":body,"caseId":case_id,"actionId":action_id});
    m.store.db.lock().map_err(fail)?.execute("INSERT INTO lan_notifications(id,group_id,kind,created_at,state,record) VALUES(?1,?2,?3,?4,'unread',?5)", params![id,group_id,kind,now(),serde_json::to_string(&value).map_err(fail)?]).map_err(fail)?;
    Ok(())
}
pub fn notifications(m: &Manager) -> Result<Vec<Notification>, String> {
    let db = m.store.db.lock().map_err(fail)?;
    let mut q=db.prepare("SELECT seq,id,group_id,kind,created_at,state,record FROM lan_notifications ORDER BY seq DESC LIMIT 200").map_err(fail)?;
    let rows = q
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })
        .map_err(fail)?;
    rows.map(|r| {
        let (seq, id, group_id, kind, created_at, state, raw) = r.map_err(fail)?;
        let v: Value = serde_json::from_str(&raw).map_err(fail)?;
        Ok(Notification {
            seq,
            id,
            group_id,
            kind,
            created_at,
            state,
            title: v["title"].as_str().unwrap_or_default().into(),
            body: v["body"].as_str().unwrap_or_default().into(),
            case_id: v["caseId"].as_str().map(str::to_owned),
            action_id: v["actionId"].as_str().map(str::to_owned),
        })
    })
    .collect()
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    pub text: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub mime: String,
}
impl Body {
    pub fn text(value: String) -> Self {
        Self {
            text: value,
            name: String::new(),
            size: 0,
            sha256: String::new(),
            mime: String::new(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub seq: i64,
    pub id: String,
    pub peer_id: String,
    pub direction: String,
    pub kind: String,
    pub state: String,
    pub created_at: String,
    pub body: Body,
}
pub fn history(m: &Manager, peer: &str, before: Option<i64>) -> Result<Vec<Message>, String> {
    let db = m.store.db.lock().map_err(fail)?;
    let mut q=db.prepare("SELECT seq,id,peer_id,direction,kind,state,created_at,record FROM lan_messages WHERE peer_id=?1 AND seq<?2 ORDER BY seq DESC LIMIT 50").map_err(fail)?;
    let rows = q
        .query_map(params![peer, before.unwrap_or(i64::MAX)], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
            ))
        })
        .map_err(fail)?;
    let mut messages = Vec::new();
    for row in rows {
        let (seq, id, peer_id, direction, kind, state, created_at, record) = row.map_err(fail)?;
        let body = decoded(m, &format!("message:{peer_id}:{id}"), &record)?;
        messages.push(Message {
            seq,
            id,
            peer_id,
            direction,
            kind,
            state,
            created_at,
            body,
        });
    }
    messages.reverse();
    Ok(messages)
}
pub fn message(m: &Manager, id: &str) -> Result<Message, String> {
    let db = m.store.db.lock().map_err(fail)?;
    let row=db.query_row("SELECT seq,peer_id,direction,kind,state,created_at,record FROM lan_messages WHERE id=?1",[id],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?))).optional().map_err(fail)?.ok_or("消息不存在")?;
    let body = decoded(m, &format!("message:{}:{id}", row.1), &row.6)?;
    Ok(Message {
        seq: row.0,
        id: id.into(),
        peer_id: row.1,
        direction: row.2,
        kind: row.3,
        state: row.4,
        created_at: row.5,
        body,
    })
}
/// 相同消息 ID 的重试仅确认完全相同的正文，不能覆盖已保存内容或跨联系人复用 ID。
pub fn insert(
    m: &Manager,
    id: &str,
    peer: &str,
    direction: &str,
    kind: &str,
    state: &str,
    body: &Body,
) -> Result<(), String> {
    uuid::Uuid::parse_str(id).map_err(|_| "消息 ID 无效")?;
    let record = encoded(m, &format!("message:{peer}:{id}"), body)?;
    let db = m.store.db.lock().map_err(fail)?;
    let existing: Option<(String, String, String, String)> = db
        .query_row(
            "SELECT peer_id,direction,kind,record FROM lan_messages WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(fail)?;
    if let Some((p, d, k, r)) = existing {
        let previous: Body = decoded(m, &format!("message:{p}:{id}"), &r)?;
        if p != peer || d != direction || k != kind || previous != *body {
            return Err("重复消息标识与既有内容不符".into());
        }
        return Ok(());
    }
    db.execute("INSERT INTO lan_messages(id,peer_id,direction,kind,state,created_at,record) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![id,peer,direction,kind,state,now(),record]).map_err(fail)?;
    Ok(())
}
/// Merge a peer's already-authenticated history without replacing local data.
/// The body is encrypted with this workspace's LAN key and the original
/// timestamp is retained for a useful chronology.
pub fn merge_recovered(
    m: &Manager,
    msg: &Message,
    peer_id: &str,
    direction: &str,
    state: &str,
) -> Result<bool, String> {
    // A peer serializes its local view, where peer_id is this device's ID.
    // Store the recovered row under the remote contact ID in our view.
    if !super::id_valid(peer_id)
        || msg.peer_id != m.identity.id
        || !matches!(direction, "in" | "out")
    {
        return Err("恢复记录的联系人或方向无效".into());
    }
    if !matches!(state, "recovered" | "offered" | "recovered_metadata") {
        return Err("恢复记录状态无效".into());
    }
    if msg.created_at.len() > 80 || chrono::DateTime::parse_from_rfc3339(&msg.created_at).is_err() {
        return Err("恢复记录时间无效".into());
    }
    uuid::Uuid::parse_str(&msg.id).map_err(|_| "消息 ID 无效")?;
    super::validate_body(&msg.kind, &msg.body)?;
    let record = encoded(m, &format!("message:{peer_id}:{}", msg.id), &msg.body)?;
    let db = m.store.db.lock().map_err(fail)?;
    let existing: Option<(String, String, String, String)> = db
        .query_row(
            "SELECT peer_id,direction,kind,record FROM lan_messages WHERE id=?1",
            [&msg.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(fail)?;
    if let Some((peer, old_direction, old_kind, old_record)) = existing {
        let previous: Body = decoded(m, &format!("message:{peer}:{}", msg.id), &old_record)?;
        if peer != peer_id
            || old_direction != direction
            || old_kind != msg.kind
            || previous != msg.body
        {
            return Err("重复消息标识与既有内容不符".into());
        }
        // Existing local history is authoritative. In particular, a second
        // recovery must not rewrite its timestamp or state.
        return Ok(false);
    }
    db.execute(
        "INSERT INTO lan_messages(id,peer_id,direction,kind,state,created_at,record) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![msg.id, peer_id, direction, msg.kind, state, msg.created_at, record],
    )
    .map_err(fail)?;
    Ok(true)
}
pub fn state(m: &Manager, id: &str, state: &str) -> Result<(), String> {
    m.store
        .db
        .lock()
        .map_err(fail)?
        .execute(
            "UPDATE lan_messages SET state=?1 WHERE id=?2",
            params![state, id],
        )
        .map_err(fail)?;
    Ok(())
}
pub fn finish_send(m: &Manager, id: &str, state: &str) -> Result<(), String> {
    // 对端保存回执可能比发送线程处理通知 ACK 更快，不能用旧状态覆盖回执。
    m.store.db.lock().map_err(fail)?.execute(
        "UPDATE lan_messages SET state=?1 WHERE id=?2 AND state NOT IN ('accepted','declined_by_peer')",
        params![state,id],
    ).map_err(fail)?;
    Ok(())
}
pub fn put_file(m: &Manager, id: &str, bytes: &[u8]) -> Result<(), String> {
    uuid::Uuid::parse_str(id).map_err(|_| "附件标识无效")?;
    let dir = m.store.root.join("lan-private/attachments");
    fs::create_dir_all(&dir).map_err(fail)?;
    let path = dir.join(id);
    // 接收后数据库提交失败时可重试；只承认完整一致的既有密文，不覆盖损坏文件。
    if path.exists() {
        let existing = fs::read(&path).map_err(fail)?;
        if unseal(&m.identity.data_key, &format!("file:{id}"), &existing)? == bytes {
            return Ok(());
        }
        return Err("附件标识已存在且内容不一致".into());
    }
    let data = seal(&m.identity.data_key, &format!("file:{id}"), bytes)?;
    crate::file_commit::write_checked(&path, |f| f.write_all(&data).map_err(fail), || Ok(()))
}
pub fn file(m: &Manager, msg: &Message) -> Result<Vec<u8>, String> {
    uuid::Uuid::parse_str(&msg.id).map_err(|_| "附件标识无效")?;
    let path = m.store.root.join("lan-private/attachments").join(&msg.id);
    let meta = fs::symlink_metadata(&path).map_err(fail)?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > FILE_LIMIT + 28 {
        return Err("附件归档异常".into());
    }
    let data = unseal(
        &m.identity.data_key,
        &format!("file:{}", msg.id),
        &fs::read(path).map_err(fail)?,
    )?;
    if data.len() as u64 != msg.body.size || hash(&data) != msg.body.sha256 {
        return Err("附件大小或 SHA-256 校验失败".into());
    }
    Ok(data)
}
