//! 独立、显式启用的局域网协作。自动发现不授予通信权限；
//! 一次性邀请固定对端证书，配对后的消息经 TLS 与独立凭据认证。
mod data;
mod net;
#[cfg(test)]
mod tests;

use crate::store::Store;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tauri::State;

const FILE_LIMIT: u64 = 32 * 1024 * 1024;
const IMAGE_LIMIT: u64 = 8 * 1024 * 1024;
fn fail(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn random() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}
fn id_valid(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
fn local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        _ => false,
    }
}
fn endpoint(value: &str) -> Result<SocketAddr, String> {
    let a: SocketAddr = value.parse().map_err(|_| "请填写局域网 IPv4:端口")?;
    if !local(a.ip()) || a.port() == 0 {
        return Err("仅支持局域网、链路本地或回环 IPv4 地址".into());
    }
    Ok(a)
}
fn alias_valid(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().count() > 40 || value.chars().any(char::is_control)
    {
        Err("设备名称需为 1—40 字，不能含控制字符".into())
    } else {
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Beacon {
    version: u8,
    id: String,
    alias: String,
    port: u16,
}
struct Seen {
    beacon: Beacon,
    address: SocketAddr,
    at: Instant,
}
struct Invitation {
    secret: String,
    expires: Instant,
}
struct Runtime {
    stop: Arc<AtomicBool>,
    port: u16,
    handles: Vec<std::thread::JoinHandle<()>>,
}
pub struct Manager {
    store: Arc<Store>,
    identity: data::Identity,
    alias: Mutex<String>,
    runtime: Mutex<Option<Runtime>>,
    discovered: Mutex<HashMap<String, Seen>>,
    online: Mutex<HashMap<String, (Instant, String)>>,
    invitation: Mutex<Option<Invitation>>,
    pair_lock: Mutex<()>,
    transfer_lock: Mutex<()>,
    last_error: Mutex<String>,
}
impl Manager {
    pub fn new(store: Arc<Store>) -> Result<Arc<Self>, String> {
        data::schema(&store)?;
        let identity = data::identity(&store)?;
        let alias = store
            .db
            .lock()
            .map_err(fail)?
            .query_row(
                "SELECT value FROM settings WHERE key='lan_alias'",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap_or_else(|_| "嘎嘎安全助手".into());
        Ok(Arc::new(Self {
            store,
            identity,
            alias: Mutex::new(alias),
            runtime: Mutex::new(None),
            discovered: Mutex::new(HashMap::new()),
            online: Mutex::new(HashMap::new()),
            invitation: Mutex::new(None),
            pair_lock: Mutex::new(()),
            transfer_lock: Mutex::new(()),
            last_error: Mutex::new(String::new()),
        }))
    }
    fn enabled(&self) -> bool {
        self.runtime.lock().is_ok_and(|r| r.is_some())
    }
    fn port(&self) -> Result<u16, String> {
        self.runtime
            .lock()
            .map_err(fail)?
            .as_ref()
            .map(|r| r.port)
            .ok_or_else(|| "请先开启局域网协作".into())
    }
    fn mark_online(&self, id: &str, address: &str) {
        if let Ok(mut online) = self.online.lock() {
            online.insert(id.into(), (Instant::now(), address.into()));
        }
    }
    fn beacon(&self) -> Result<Beacon, String> {
        Ok(Beacon {
            version: 1,
            id: self.identity.id.clone(),
            alias: self.alias.lock().map_err(fail)?.clone(),
            port: self.port()?,
        })
    }
    pub fn start(self: &Arc<Self>, alias: &str, discover: bool) -> Result<(), String> {
        alias_valid(alias)?;
        let mut runtime = self.runtime.lock().map_err(fail)?;
        if runtime.is_some() {
            return Err("局域网协作已开启；修改名称请先关闭".into());
        }
        self.last_error.lock().map_err(fail)?.clear();
        *self.alias.lock().map_err(fail)? = alias.trim().into();
        self.store.db.lock().map_err(fail)?.execute("INSERT INTO settings(key,value) VALUES('lan_alias',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[alias.trim()]).map_err(fail)?;
        let listener = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
            .map_err(|e| format!("局域网监听失败：{e}"))?;
        let port = listener.local_addr().map_err(fail)?.port();
        listener.set_nonblocking(true).map_err(fail)?;
        let tls = net::server_tls(&self.identity)?;
        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = vec![net::server(self.clone(), listener, tls, stop.clone())];
        if discover {
            match net::discovery(self.clone(), stop.clone(), port, alias.trim()) {
                Ok(h) => handles.push(h),
                Err(e) => {
                    *self.last_error.lock().map_err(fail)? =
                        format!("自动发现不可用，可用邀请与手动地址连接：{e}")
                }
            }
        }
        handles.push(net::heartbeats(self.clone(), stop.clone()));
        *runtime = Some(Runtime {
            stop,
            port,
            handles,
        });
        Ok(())
    }
    pub fn stop(&self) -> Result<(), String> {
        let runtime = self.runtime.lock().map_err(fail)?.take();
        if let Some(runtime) = runtime {
            runtime.stop.store(true, Ordering::SeqCst);
            *self.invitation.lock().map_err(fail)? = None;
            self.online.lock().map_err(fail)?.clear();
            self.discovered.lock().map_err(fail)?.clear();
            for handle in runtime.handles {
                let _ = handle.join();
            }
        }
        Ok(())
    }
    pub fn invite(&self) -> Result<Value, String> {
        let port = self.port()?;
        let secret = random();
        *self.invitation.lock().map_err(fail)? = Some(Invitation {
            secret: secret.clone(),
            expires: Instant::now() + Duration::from_secs(300),
        });
        let addresses = net::addresses(port);
        let content = json!({"v":1,"id":self.identity.id,"secret":secret,"addresses":addresses});
        let code = format!(
            "GAGA-LAN-1.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&content).map_err(fail)?)
        );
        Ok(json!({"code":code,"expiresInSeconds":300,"addresses":addresses}))
    }
    pub fn pair(&self, address: &str, code: &str) -> Result<(), String> {
        let _lock = self.pair_lock.lock().map_err(fail)?;
        self.port()?;
        if code.len() > 4096 {
            return Err("邀请过长".into());
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                code.trim()
                    .strip_prefix("GAGA-LAN-1.")
                    .ok_or("邀请格式不正确")?,
            )
            .map_err(|_| "邀请编码无效")?;
        let invite: Value = serde_json::from_slice(&bytes).map_err(|_| "邀请内容无效")?;
        let id = invite["id"].as_str().ok_or("邀请缺少证书指纹")?;
        let secret = invite["secret"].as_str().ok_or("邀请缺少一次性凭据")?;
        if invite["v"] != 1
            || !id_valid(id)
            || id == self.identity.id
            || B64.decode(secret).map_or(true, |b| b.len() != 32)
        {
            return Err("邀请字段无效或属于本机".into());
        }
        let contacts = data::contacts(self)?;
        if contacts.iter().any(|c| c.id == id && c.secret.is_some()) {
            return Err("此设备已经配对".into());
        }
        if contacts.len() >= 64 && !contacts.iter().any(|c| c.id == id) {
            return Err("联系人已达 64 台上限".into());
        }
        let address = endpoint(address)?.to_string();
        let shared = random();
        let reply = net::request(
            self,
            &address,
            id,
            &net::Request {
                sender: self.identity.id.clone(),
                auth: secret.into(),
                action: net::Action::Pair {
                    identity: self.beacon()?,
                    shared: shared.clone(),
                },
            },
            None,
        )?;
        let peer: Beacon = serde_json::from_value(reply["identity"].clone()).map_err(fail)?;
        if peer.id != id {
            return Err("设备身份与邀请不符".into());
        }
        alias_valid(&peer.alias)?;
        data::save_contact(
            self,
            &data::Contact {
                id: id.into(),
                alias: peer.alias,
                endpoint: address.clone(),
                secret: Some(shared),
                created_at: now(),
            },
        )?;
        self.mark_online(id, &address);
        Ok(())
    }
    pub fn unpair(&self, id: &str) -> Result<(), String> {
        let _lock = self.pair_lock.lock().map_err(fail)?;
        let mut contact = data::contact(self, id)?;
        contact.secret = None;
        data::save_contact(self, &contact)?;
        self.online.lock().map_err(fail)?.remove(id);
        Ok(())
    }
    fn connection(&self, id: &str) -> Result<data::Contact, String> {
        self.port()?;
        let c = data::contact(self, id)?;
        if c.secret.is_none() {
            return Err("此设备已取消配对，请重新交换邀请".into());
        }
        Ok(c)
    }
    fn call(
        &self,
        c: &data::Contact,
        action: net::Action,
        file: Option<&mut Vec<u8>>,
    ) -> Result<Value, String> {
        let address = self
            .online
            .lock()
            .map_err(fail)?
            .get(&c.id)
            .filter(|(at, _)| at.elapsed() < Duration::from_secs(15))
            .map(|(_, address)| address.clone())
            .unwrap_or_else(|| c.endpoint.clone());
        let result = net::request(
            self,
            &address,
            &c.id,
            &net::Request {
                sender: self.identity.id.clone(),
                auth: c.secret.clone().ok_or("设备未配对")?,
                action,
            },
            file,
        );
        if result.is_ok() {
            self.mark_online(&c.id, &address)
        } else {
            self.online.lock().map_err(fail)?.remove(&c.id);
        }
        result
    }
    pub fn send_text(&self, peer: &str, text: &str) -> Result<(), String> {
        if text.trim().is_empty() || text.len() > 16384 {
            return Err("消息需为 1 字至 16 KiB".into());
        }
        let c = self.connection(peer)?;
        let id = uuid::Uuid::new_v4().to_string();
        data::insert(
            self,
            &id,
            peer,
            "out",
            "text",
            "sending",
            &data::Body::text(text.into()),
        )?;
        self.retry_with(&c, &id)
    }
    /// Pull one bounded page from a paired online peer. The operation is
    /// explicit, idempotent and append-only; it never deletes local history.
    pub fn recover_history(&self, peer: &str, before: Option<i64>) -> Result<Value, String> {
        let c = self.connection(peer)?;
        let mut cursor = before;
        let mut recovered = 0u64;
        let mut received = 0u64;
        let mut has_more = false;
        // Keep a single user action bounded. A second click continues from
        // the local history page; a malicious peer cannot force an unbounded
        // response or loop.
        for _ in 0..20 {
            let reply = self.call(
                &c,
                net::Action::HistoryPull {
                    before_seq: cursor,
                    limit: 100,
                },
                None,
            )?;
            let remote: Vec<data::Message> =
                serde_json::from_value(reply.get("messages").cloned().ok_or("伙伴未返回历史记录")?)
                    .map_err(|_| "伙伴历史记录格式无效")?;
            received += remote.len() as u64;
            for message in &remote {
                if message.peer_id != self.identity.id {
                    return Err("伙伴返回了不属于当前设备的历史记录".into());
                }
                validate_body(&message.kind, &message.body)?;
                let direction = if message.direction == "out" {
                    "in"
                } else {
                    "out"
                };
                let state = if message.kind == "text" {
                    "recovered"
                } else if direction == "in" {
                    "offered"
                } else {
                    "recovered_metadata"
                };
                if data::merge_recovered(self, message, peer, direction, state)? {
                    recovered += 1;
                }
            }
            has_more = reply["hasMore"].as_bool().unwrap_or(false);
            let next = remote.first().map(|m| m.seq);
            if !has_more {
                break;
            }
            let next = next.ok_or("伙伴历史分页缺少游标")?;
            if Some(next) == cursor {
                return Err("伙伴历史分页游标未前进".into());
            }
            cursor = Some(next);
        }
        Ok(json!({
            "recovered": recovered,
            "received": received,
            "hasMore": has_more,
            "nextBeforeSeq": if has_more { cursor } else { None },
        }))
    }
    pub fn create_group(
        &self,
        name: &str,
        group_type: &str,
        member_ids: Vec<String>,
    ) -> Result<data::Group, String> {
        if name.trim().is_empty() || name.chars().count() > 80 {
            return Err("群组名称需为 1—80 字".into());
        }
        let mut members = member_ids;
        if !members.iter().any(|id| id == &self.identity.id) {
            members.push(self.identity.id.clone());
        }
        let group = data::Group {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.trim().into(),
            group_type: if group_type.trim().is_empty() {
                "custom".into()
            } else {
                group_type.into()
            },
            role: "owner".into(),
            created_at: now(),
            member_ids: members,
        };
        data::save_group(self, &group)?;
        for peer in group
            .member_ids
            .iter()
            .filter(|id| *id != &self.identity.id)
        {
            if let Ok(c) = self.connection(peer) {
                let _ = self.call(
                    &c,
                    net::Action::GroupSync {
                        group_id: group.id.clone(),
                        group_name: group.name.clone(),
                        group_type: group.group_type.clone(),
                        member_ids: group.member_ids.clone(),
                    },
                    None,
                );
            }
        }
        Ok(group)
    }
    pub fn send_group_text(&self, group_id: &str, text: &str) -> Result<(), String> {
        if text.trim().is_empty() || text.len() > 16384 {
            return Err("群消息需为 1 字至 16 KiB".into());
        }
        let group = data::groups(self)?
            .into_iter()
            .find(|g| g.id == group_id)
            .ok_or("群组不存在")?;
        let id = uuid::Uuid::new_v4().to_string();
        let body = data::Body::text(text.into());
        data::group_message(
            self,
            &id,
            group_id,
            &self.identity.id,
            &self.alias.lock().map_err(fail)?.clone(),
            "text",
            &body,
        )?;
        let mut errors = Vec::new();
        for peer in group.member_ids {
            if let Ok(c) = self.connection(&peer) {
                if let Err(e) = self.call(
                    &c,
                    net::Action::GroupMessage {
                        group_id: group_id.into(),
                        message_id: id.clone(),
                        group_name: group.name.clone(),
                        sender_alias: self.alias.lock().map_err(fail)?.clone(),
                        kind: "text".into(),
                        body: body.clone(),
                    },
                    None,
                ) {
                    errors.push(format!("{peer}: {e}"));
                }
            } else {
                errors.push(format!("{peer}: 未配对"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "群消息已本地保存，但部分成员未送达：{}",
                errors.join("；")
            ))
        }
    }
    pub fn notify_group(
        &self,
        group_id: Option<&str>,
        kind: &str,
        title: &str,
        body: &str,
        case_id: Option<&str>,
        action_id: Option<&str>,
    ) -> Result<(), String> {
        let group = group_id
            .map(|id| {
                data::groups(self).and_then(|gs| {
                    gs.into_iter()
                        .find(|g| g.id == id)
                        .ok_or_else(|| "群组不存在".into())
                })
            })
            .transpose()?;
        data::notification(self, group_id, kind, title, body, case_id, action_id)?;
        if let Some(group) = group {
            let mut errors = Vec::new();
            for peer in group.member_ids {
                if let Ok(c) = self.connection(&peer) {
                    if let Err(e) = self.call(
                        &c,
                        net::Action::Notification {
                            id: uuid::Uuid::new_v4().to_string(),
                            group_id: group_id.map(str::to_owned),
                            kind: kind.into(),
                            title: title.into(),
                            body: body.into(),
                            case_id: case_id.map(str::to_owned),
                            action_id: action_id.map(str::to_owned),
                        },
                        None,
                    ) {
                        errors.push(e);
                    }
                }
            }
            if !errors.is_empty() {
                return Err(format!(
                    "通知已本地保存，部分成员未送达：{}",
                    errors.join("；")
                ));
            }
        }
        Ok(())
    }
    pub fn send_file(
        &self,
        peer: &str,
        path: Option<&str>,
        data_url: Option<&str>,
    ) -> Result<(), String> {
        let _transfer = self
            .transfer_lock
            .try_lock()
            .map_err(|_| "已有附件任务，请稍后再试")?;
        let c = self.connection(peer)?;
        let (name, bytes) = if let Some(url) = data_url {
            if url.len() > 12 * 1024 * 1024 {
                return Err("图片超过 8 MiB".into());
            }
            let (prefix, value) = url.split_once(',').ok_or("图片数据无效")?;
            if !matches!(
                prefix,
                "data:image/png;base64"
                    | "data:image/jpeg;base64"
                    | "data:image/webp;base64"
                    | "data:image/gif;base64"
            ) {
                return Err("不支持此图片类型".into());
            }
            let bytes = B64.decode(value).map_err(|_| "图片编码无效")?;
            let mime = image_mime(&bytes)?.ok_or("无法识别图片")?;
            (
                format!(
                    "截图-{}.{}",
                    chrono::Local::now().format("%H%M%S"),
                    mime.trim_start_matches("image/").replace("jpeg", "jpg")
                ),
                bytes,
            )
        } else {
            let path = Path::new(path.ok_or("请选择文件或粘贴图片")?);
            let meta = fs::symlink_metadata(path).map_err(fail)?;
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > FILE_LIMIT {
                return Err("仅支持不超过 32 MiB 的普通文件".into());
            }
            let name = path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or("文件名无效")?
                .to_string();
            let mut bytes = Vec::new();
            fs::File::open(path)
                .map_err(fail)?
                .take(FILE_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(fail)?;
            if bytes.len() as u64 > FILE_LIMIT {
                return Err("文件超过 32 MiB".into());
            }
            (name, bytes)
        };
        let mime = if bytes.len() as u64 <= IMAGE_LIMIT {
            image_mime(&bytes)?
        } else {
            None
        };
        let kind = if mime.is_some() { "image" } else { "file" };
        let body = data::Body {
            text: String::new(),
            name,
            size: bytes.len() as u64,
            sha256: hash(&bytes),
            mime: mime.unwrap_or_default(),
        };
        validate_body(kind, &body)?;
        let id = uuid::Uuid::new_v4().to_string();
        data::put_file(self, &id, &bytes)?;
        if let Err(e) = data::insert(self, &id, peer, "out", kind, "sending", &body) {
            let _ = fs::remove_file(self.store.root.join("lan-private/attachments").join(&id));
            return Err(e);
        }
        self.retry_with(&c, &id)
    }
    fn retry_with(&self, c: &data::Contact, id: &str) -> Result<(), String> {
        let msg = data::message(self, id)?;
        if msg.peer_id != c.id || msg.direction != "out" {
            return Err("消息不属于此联系人".into());
        }
        if matches!(msg.state.as_str(), "accepted" | "declined_by_peer") {
            return Ok(());
        }
        data::state(self, id, "sending")?;
        let action = net::Action::Message {
            id: id.into(),
            kind: msg.kind,
            body: msg.body,
        };
        match self.call(c, action, None) {
            Ok(reply) => data::finish_send(
                self,
                id,
                match reply["attachmentState"].as_str() {
                    Some("received") => "accepted",
                    Some("declined") => "declined_by_peer",
                    _ => "delivered",
                },
            ),
            Err(e) => {
                data::finish_send(self, id, "failed")?;
                Err(format!("发送未确认，可在消息旁重试：{e}"))
            }
        }
    }
    pub fn retry(&self, id: &str) -> Result<(), String> {
        let msg = data::message(self, id)?;
        let c = self.connection(&msg.peer_id)?;
        self.retry_with(&c, id)
    }
    pub fn receive(&self, id: &str) -> Result<(), String> {
        let _lock = self
            .transfer_lock
            .try_lock()
            .map_err(|_| "已有附件任务，请稍后再试")?;
        let msg = data::message(self, id)?;
        if msg.direction != "in" || !matches!(msg.state.as_str(), "offered" | "receiving") {
            return Err("附件不是待接收状态".into());
        }
        let c = self.connection(&msg.peer_id)?;
        let mut bytes = Vec::new();
        data::state(self, id, "receiving")?;
        let result = (|| {
            self.call(&c, net::Action::Fetch { id: id.into() }, Some(&mut bytes))?;
            if bytes.len() as u64 != msg.body.size || hash(&bytes) != msg.body.sha256 {
                return Err("附件完整性验证失败".into());
            }
            if msg.kind == "image" && image_mime(&bytes)?.as_deref() != Some(msg.body.mime.as_str())
            {
                return Err("图片类型与声明不符".into());
            }
            data::put_file(self, id, &bytes)?;
            data::state(self, id, "received")?;
            // 接收方持久保存并校验后才发回执；回执失败不撤销本地已接收文件。
            let _ = self.call(
                &c,
                net::Action::Receipt {
                    id: id.into(),
                    accepted: true,
                },
                None,
            );
            Ok(())
        })();
        if result.is_err() {
            let _ = data::state(self, id, "offered");
        }
        result
    }
    /// Fetch the body of an attachment whose metadata was recovered from a
    /// peer that had the receiver-side copy. This is deliberately explicit:
    /// a recovered metadata record never downloads or executes a file by
    /// itself.
    pub fn recover_attachment(&self, id: &str) -> Result<(), String> {
        let _lock = self
            .transfer_lock
            .try_lock()
            .map_err(|_| "已有附件任务，请稍后再试")?;
        let msg = data::message(self, id)?;
        if msg.direction != "out" || msg.state != "recovered_metadata" {
            return Err("附件没有可恢复的正文，或已完成恢复".into());
        }
        let c = self.connection(&msg.peer_id)?;
        let mut bytes = Vec::new();
        data::state(self, id, "recovering")?;
        let result = (|| {
            self.call(&c, net::Action::Fetch { id: id.into() }, Some(&mut bytes))?;
            if bytes.len() as u64 != msg.body.size || hash(&bytes) != msg.body.sha256 {
                return Err("附件完整性验证失败".into());
            }
            if msg.kind == "image" && image_mime(&bytes)?.as_deref() != Some(msg.body.mime.as_str())
            {
                return Err("图片类型与声明不符".into());
            }
            data::put_file(self, id, &bytes)?;
            data::state(self, id, "recovered")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = data::state(self, id, "recovered_metadata");
        }
        result
    }
    pub fn decline(&self, id: &str) -> Result<(), String> {
        let msg = data::message(self, id)?;
        if msg.direction != "in" || msg.state != "offered" {
            return Err("只能拒绝待接收附件".into());
        };
        data::state(self, id, "declined")?;
        if let Ok(c) = self.connection(&msg.peer_id) {
            let _ = self.call(
                &c,
                net::Action::Receipt {
                    id: id.into(),
                    accepted: false,
                },
                None,
            );
        }
        Ok(())
    }
    pub fn save_file(&self, id: &str, path: &Path) -> Result<(), String> {
        let msg = data::message(self, id)?;
        if msg.kind == "text" || !(msg.direction == "out" || msg.state == "received") {
            return Err("请先接收附件".into());
        }
        crate::report::validate_output(&self.store, path)?;
        let bytes = data::file(self, &msg)?;
        crate::file_commit::write_checked(path, |f| f.write_all(&bytes).map_err(fail), || Ok(()))
    }
    pub fn image(&self, id: &str) -> Result<String, String> {
        let msg = data::message(self, id)?;
        if msg.kind != "image" || !(msg.direction == "out" || msg.state == "received") {
            return Err("图片尚未接收".into());
        }
        let bytes = data::file(self, &msg)?;
        let mime = image_mime(&bytes)?.ok_or("图片无效")?;
        Ok(format!("data:{mime};base64,{}", B64.encode(bytes)))
    }
    pub fn snapshot(
        &self,
        peer: Option<&str>,
        before: Option<i64>,
        group_id: Option<&str>,
    ) -> Result<Value, String> {
        let enabled = self.enabled();
        let contacts = data::contacts(self)?;
        let online = self.online.lock().map_err(fail)?;
        let peers:Vec<Value>=contacts.iter().map(|c|json!({"id":c.id,"alias":c.alias,"endpoint":online.get(&c.id).map(|(_,a)|a).unwrap_or(&c.endpoint),"paired":c.secret.is_some(),"online":enabled&&c.secret.is_some()&&online.get(&c.id).is_some_and(|(at,_)|at.elapsed()<Duration::from_secs(15)),"createdAt":c.created_at})).collect();
        let discovered:Vec<Value>=self.discovered.lock().map_err(fail)?.values().filter(|s|s.at.elapsed()<Duration::from_secs(12)&&!contacts.iter().any(|c|c.id==s.beacon.id&&c.secret.is_some())).map(|s|json!({"id":s.beacon.id,"alias":s.beacon.alias,"endpoint":s.address.to_string()})).collect();
        let messages = peer
            .map(|p| data::history(self, p, before))
            .transpose()?
            .unwrap_or_default();
        let groups = data::groups(self)?;
        let group_messages = group_id
            .map(|g| data::group_history(self, g, before))
            .transpose()?
            .unwrap_or_default();
        let notifications = data::notifications(self)?;
        let port = self.runtime.lock().map_err(fail)?.as_ref().map(|r| r.port);
        Ok(
            json!({"enabled":enabled,"alias":self.alias.lock().map_err(fail)?.clone(),"id":self.identity.id,"addresses":port.map(net::addresses).unwrap_or_default(),"contacts":peers,"discovered":discovered,"messages":messages,"groups":groups,"groupMessages":group_messages,"notifications":notifications,"notice":self.last_error.lock().map_err(fail)?.clone(),"storage":"聊天正文、配对凭据和附件在本机加密保存；密钥受本机文件权限保护。事件证据库仍为明文。通用工作区备份不包含聊天与配对数据。"}),
        )
    }
}
fn image_mime(bytes: &[u8]) -> Result<Option<String>, String> {
    let format = match image::guess_format(bytes) {
        Ok(f)
            if matches!(
                f,
                image::ImageFormat::Png
                    | image::ImageFormat::Jpeg
                    | image::ImageFormat::WebP
                    | image::ImageFormat::Gif
            ) =>
        {
            f
        }
        _ => return Ok(None),
    };
    if bytes.len() as u64 > IMAGE_LIMIT {
        return Err("图片超过 8 MiB".into());
    }
    let mut reader = image::ImageReader::with_format(std::io::Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(32 * 1024 * 1024);
    limits.max_image_width = Some(4096);
    limits.max_image_height = Some(4096);
    reader.limits(limits);
    reader
        .decode()
        .map_err(|_| "图片损坏或尺寸超过 4096×4096")?;
    if format == image::ImageFormat::Gif {
        use image::{AnimationDecoder, ImageDecoder};
        let mut decoder =
            image::codecs::gif::GifDecoder::new(std::io::Cursor::new(bytes)).map_err(fail)?;
        let mut limits = image::Limits::default();
        limits.max_alloc = Some(32 * 1024 * 1024);
        limits.max_image_width = Some(4096);
        limits.max_image_height = Some(4096);
        decoder.set_limits(limits).map_err(fail)?;
        let mut pixels = 0u64;
        for (index, frame) in decoder.into_frames().enumerate() {
            let frame = frame.map_err(|_| "GIF 帧数据损坏")?;
            pixels += frame.buffer().width() as u64 * frame.buffer().height() as u64;
            if index >= 128 || pixels > 32 * 1024 * 1024 {
                return Err("GIF 超过 128 帧或累计像素限制，请缩小表情图片".into());
            }
        }
    }
    Ok(Some(format.to_mime_type().into()))
}
fn validate_body(kind: &str, b: &data::Body) -> Result<(), String> {
    if kind == "text" {
        if b.text.trim().is_empty()
            || b.text.len() > 16384
            || !b.name.is_empty()
            || b.size != 0
            || !b.sha256.is_empty()
            || !b.mime.is_empty()
        {
            return Err("消息字段无效".into());
        }
    } else if matches!(kind, "file" | "image") {
        if !b.text.is_empty()
            || b.name.trim().is_empty()
            || b.name.chars().count() > 240
            || b.name
                .chars()
                .any(|c| c.is_control() || c == '/' || c == '\\')
            || b.size > FILE_LIMIT
            || !id_valid(&b.sha256)
        {
            return Err("附件字段无效".into());
        }
        if kind == "image"
            && (b.size > IMAGE_LIMIT
                || !matches!(
                    b.mime.as_str(),
                    "image/png" | "image/jpeg" | "image/webp" | "image/gif"
                ))
        {
            return Err("图片声明无效".into());
        }
        if kind == "file" && !b.mime.is_empty() {
            return Err("文件类型无效".into());
        }
    } else {
        return Err("不支持的消息类型".into());
    }
    Ok(())
}
pub fn redact_backup(db: &rusqlite::Connection) -> Result<(), String> {
    data::redact(db)
}

/// 实际网络/文件工作放入阻塞线程，避免堵塞客户端界面。
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn lan_action(
    action: String,
    peer_id: Option<String>,
    text: Option<String>,
    path: Option<String>,
    data_url: Option<String>,
    message_id: Option<String>,
    group_id: Option<String>,
    group_name: Option<String>,
    group_type: Option<String>,
    member_ids: Option<Vec<String>>,
    notification_kind: Option<String>,
    notification_title: Option<String>,
    notification_body: Option<String>,
    case_id: Option<String>,
    action_id: Option<String>,
    before_seq: Option<i64>,
    lan: State<'_, Arc<Manager>>,
) -> Result<Value, String> {
    let m = lan.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let peer = || peer_id.as_deref().ok_or("请先选择设备");
        let id = || message_id.as_deref().ok_or("消息标识缺失");
        match action.as_str() {
            "start" => m.start(text.as_deref().unwrap_or("嘎嘎安全助手"), true)?,
            "stop" => m.stop()?,
            "invite" => return m.invite(),
            "pair" => m.pair(
                path.as_deref().ok_or("缺少设备地址")?,
                text.as_deref().ok_or("缺少邀请")?,
            )?,
            "unpair" => m.unpair(peer()?)?,
            "text" => m.send_text(peer()?, text.as_deref().unwrap_or(""))?,
            "recover_history" => return m.recover_history(peer()?, before_seq),
            "group_create" => return Ok(json!({"group":m.create_group(group_name.as_deref().unwrap_or("协作组"), group_type.as_deref().unwrap_or("custom"), member_ids.unwrap_or_default())?})),
            "group_text" => m.send_group_text(group_id.as_deref().ok_or("缺少群组")?, text.as_deref().unwrap_or(""))?,
            "notify" => m.notify_group(group_id.as_deref(), notification_kind.as_deref().unwrap_or("notice"), notification_title.as_deref().unwrap_or("协作通知"), notification_body.as_deref().unwrap_or(""), case_id.as_deref(), action_id.as_deref())?,
            "file" => m.send_file(peer()?, path.as_deref(), data_url.as_deref())?,
            "retry" => m.retry(id()?)?,
            "receive" => m.receive(id()?)?,
            "recover_attachment" => m.recover_attachment(id()?)?,
            "decline" => m.decline(id()?)?,
            "save" => m.save_file(id()?, Path::new(path.as_deref().ok_or("缺少保存位置")?))?,
            "image" => return Ok(json!({"url":m.image(id()?)?})),
            _ => return Err("不支持的协作操作".into()),
        }
        Ok(json!({"ok":true}))
    })
    .await
    .map_err(fail)?
}
#[tauri::command]
pub async fn lan_state(
    peer_id: Option<String>,
    before_seq: Option<i64>,
    group_id: Option<String>,
    lan: State<'_, Arc<Manager>>,
) -> Result<Value, String> {
    let m = lan.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        m.snapshot(peer_id.as_deref(), before_seq, group_id.as_deref())
    })
    .await
    .map_err(fail)?
}

#[derive(Default)]
pub struct UiCompanion(pub Arc<Mutex<Option<Arc<Manager>>>>);
/// 仅独立的原生验收模式可创建回环测试伙伴，正式界面无此入口。
#[tauri::command]
pub async fn lan_ui_companion(
    action: String,
    lan: State<'_, Arc<Manager>>,
    companion: State<'_, UiCompanion>,
    smoke: State<'_, crate::SmokeMode>,
) -> Result<Value, String> {
    if !cfg!(debug_assertions) || !smoke.0 {
        return Err("仅用于独立验收工作区".into());
    }
    let m = lan.inner().clone();
    let state = companion.0.clone();
    tauri::async_runtime::spawn_blocking(move||{
        let mut peer=state.lock().map_err(fail)?;
        if peer.is_none(){let other=Manager::new(Arc::new(Store::open(m.store.root.join("lan-ui-peer"))?))?;other.start("J4team 协作伙伴",true)?;*peer=Some(other);}
        let peer=peer.as_ref().ok_or("验收伙伴缺失")?;
        match action.as_str(){
            "prepare"=>return Ok(json!({"invite":peer.invite()?,"address":format!("127.0.0.1:{}",peer.port()?),"id":peer.identity.id})),
            "text"=>peer.send_text(&m.identity.id,"收到，我们继续核对证据 ✅")?,
            "file"=>{let path=peer.store.root.join("演练处置记录.txt");fs::write(&path,"仅为通信验收合成资料，不是真实客户数据。").map_err(fail)?;peer.send_file(&m.identity.id,Some(path.to_str().ok_or("路径无效")?),None)?;},
            "file_long"=>{let path=peer.store.root.join(format!("{}receipt.txt","synthetic-long-name-".repeat(10)));fs::write(&path,"synthetic long filename attachment").map_err(fail)?;peer.send_file(&m.identity.id,Some(path.to_str().ok_or("路径无效")?),None)?;},
            "gif"=>peer.send_file(&m.identity.id,None,Some("data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"))?,
            "receive"=>{for msg in data::history(peer,&m.identity.id,None)?{if msg.direction=="in"&&msg.state=="offered"{peer.receive(&msg.id)?;}}},
            "stop"=>peer.stop()?,
            "start"=>peer.start("J4team 协作伙伴",true)?,
            "snapshot"=>{},_=>return Err("无此验收操作".into())
        }peer.snapshot(Some(&m.identity.id),None,None)
    }).await.map_err(fail)?
}
