//! 有界 TLS 帧、证书固定、认证心跳和同网段组播发现。
//! UDP 广告只用于发现候选地址；它不能建立信任或把设备标为在线。
use super::*;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    DigitallySignedStruct, SignatureScheme,
};
use std::net::{TcpListener, TcpStream, UdpSocket};

const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 74, 74);
const DISCOVERY_PORT: u16 = 44974;
const FRAME_LIMIT: usize = 65536;

/// Reserve a bounded LAN worker slot without a load-then-increment race.
fn try_acquire_connection_slot(connections: &AtomicUsize, limit: usize) -> bool {
    let mut current = connections.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return false;
        }
        match connections.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}
#[derive(Serialize, Deserialize)]
pub(super) struct Request {
    pub sender: String,
    pub auth: String,
    pub action: Action,
}
/// 自签证书只证明持有私钥；邀请/配对凭据才决定是否可信。
/// 所有签名交由 rustls 验证，应用帧身份必须与握手证书指纹一致。
#[derive(Debug)]
struct Clients;
impl ClientCertVerifier for Clients {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if cert.is_empty() || cert.len() > 16384 {
            return Err(rustls::Error::General("设备证书大小无效".into()));
        }
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            msg,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            msg,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum Action {
    Pair {
        identity: Beacon,
        shared: String,
    },
    Ping {
        port: u16,
    },
    Message {
        id: String,
        kind: String,
        body: data::Body,
    },
    GroupMessage {
        group_id: String,
        message_id: String,
        group_name: String,
        sender_alias: String,
        kind: String,
        body: data::Body,
    },
    GroupSync {
        group_id: String,
        group_name: String,
        group_type: String,
        member_ids: Vec<String>,
    },
    Notification {
        id: String,
        group_id: Option<String>,
        kind: String,
        title: String,
        body: String,
        case_id: Option<String>,
        action_id: Option<String>,
    },
    /// Explicit history recovery. It returns bounded metadata/message bodies
    /// over the already authenticated TLS channel; it never runs automatically.
    HistoryPull {
        before_seq: Option<i64>,
        limit: u64,
    },
    Fetch {
        id: String,
    },
    Receipt {
        id: String,
        accepted: bool,
    },
}

#[derive(Debug)]
struct Pin(String);
impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if hash(end.as_ref()) == self.0 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "局域网设备证书与配对指纹不符".into(),
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            msg,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            msg,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
pub(super) fn server_tls(identity: &data::Identity) -> Result<Arc<rustls::ServerConfig>, String> {
    Ok(Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(fail)?
        .with_client_cert_verifier(Arc::new(Clients))
        .with_single_cert(
            vec![CertificateDer::from(identity.cert.clone())],
            PrivatePkcs8KeyDer::from(identity.private.clone()).into(),
        )
        .map_err(fail)?,
    ))
}
fn write_frame<T: Serialize>(s: &mut impl Write, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(fail)?;
    if bytes.len() > FRAME_LIMIT {
        return Err("通信帧过大".into());
    }
    s.write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| s.write_all(&bytes))
        .and_then(|_| s.flush())
        .map_err(fail)
}
fn read_frame<T: serde::de::DeserializeOwned>(s: &mut impl Read) -> Result<T, String> {
    let mut length = [0u8; 4];
    s.read_exact(&mut length)
        .map_err(|_| "对端连接中断或超时")?;
    let size = u32::from_be_bytes(length) as usize;
    if size == 0 || size > FRAME_LIMIT {
        return Err("对端通信帧超过限制".into());
    }
    let mut bytes = vec![0u8; size];
    s.read_exact(&mut bytes).map_err(|_| "对端通信数据不完整")?;
    serde_json::from_slice(&bytes).map_err(|_| "对端通信格式无效".into())
}
pub(super) fn request(
    m: &Manager,
    address: &str,
    pin: &str,
    request: &Request,
    file: Option<&mut Vec<u8>>,
) -> Result<Value, String> {
    let address = endpoint(address)?;
    let socket = TcpStream::connect_timeout(&address, Duration::from_millis(700))
        .map_err(|_| "无法连接设备；请确认对方开启协作、同网可达且防火墙允许")?;
    let socket = crate::connection::DeadlineSocket::new(
        socket,
        Duration::from_secs(60),
        Duration::from_secs(5),
    );
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(fail)?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(Pin(pin.into())))
    .with_client_auth_cert(
        vec![CertificateDer::from(m.identity.cert.clone())],
        PrivatePkcs8KeyDer::from(m.identity.private.clone()).into(),
    )
    .map_err(fail)?;
    let client = rustls::ClientConnection::new(
        Arc::new(cfg),
        ServerName::try_from("gaga.local").map_err(fail)?.to_owned(),
    )
    .map_err(fail)?;
    let mut stream = rustls::StreamOwned::new(client, socket);
    write_frame(&mut stream, request)?;
    let value: Value = read_frame(&mut stream)?;
    if value["ok"] != true {
        return Err(value["error"].as_str().unwrap_or("对端拒绝了请求").into());
    }
    if let Some(file) = file {
        let size = value["size"].as_u64().ok_or("对端未提供附件大小")?;
        if size > FILE_LIMIT {
            return Err("对端附件超过 32 MiB".into());
        }
        file.resize(size as usize, 0);
        stream
            .read_exact(file)
            .map_err(|_| "附件传输中断；请重新接收")?;
    }
    Ok(value)
}

fn handle(
    m: &Manager,
    source: SocketAddr,
    s: &mut (impl Read + Write),
    stop: &AtomicBool,
    certificate_id: &str,
) -> Result<(), String> {
    let req: Request = read_frame(s)?;
    if stop.load(Ordering::SeqCst) {
        return Err("局域网协作已关闭".into());
    }
    if !id_valid(&req.sender)
        || req.sender != certificate_id
        || req.sender == m.identity.id
        || req.auth.len() > 128
    {
        return Err("设备身份无效".into());
    }
    if let Action::Pair { identity, shared } = &req.action {
        let _guard = m.pair_lock.lock().map_err(fail)?;
        let mut invitation = m.invitation.lock().map_err(fail)?;
        let valid = invitation.as_ref().is_some_and(|i| {
            i.expires > Instant::now()
                && aws_lc_rs::constant_time::verify_slices_are_equal(
                    i.secret.as_bytes(),
                    req.auth.as_bytes(),
                )
                .is_ok()
        });
        if !valid {
            return Err("配对邀请已使用、已过期或不匹配".into());
        }
        if identity.version != 1
            || identity.id != req.sender
            || identity.port == 0
            || B64.decode(shared).map_or(true, |b| b.len() != 32)
        {
            return Err("配对字段无效".into());
        }
        alias_valid(&identity.alias)?;
        let contacts = data::contacts(m)?;
        if contacts
            .iter()
            .any(|c| c.id == req.sender && c.secret.is_some())
        {
            return Err("此设备已配对，请先取消旧配对".into());
        }
        if contacts.len() >= 64 && !contacts.iter().any(|c| c.id == req.sender) {
            return Err("联系人已达 64 台上限".into());
        }
        let address = SocketAddr::new(source.ip(), identity.port).to_string();
        data::save_contact(
            m,
            &data::Contact {
                id: req.sender.clone(),
                alias: identity.alias.clone(),
                endpoint: address.clone(),
                secret: Some(shared.clone()),
                created_at: now(),
            },
        )?;
        *invitation = None;
        m.mark_online(&req.sender, &address);
        return write_frame(s, &json!({"ok":true,"identity":m.beacon()?}));
    }
    let c = data::contact(m, &req.sender)?;
    let authenticated = c.secret.as_ref().is_some_and(|secret| {
        aws_lc_rs::constant_time::verify_slices_are_equal(secret.as_bytes(), req.auth.as_bytes())
            .is_ok()
    });
    if !authenticated {
        return Err("设备未配对或认证失败".into());
    }
    match req.action {
        Action::Ping { port } => {
            if port == 0 {
                return Err("设备端口无效".into());
            }
            let address = SocketAddr::new(source.ip(), port).to_string();
            if c.endpoint != address {
                let mut updated = c.clone();
                updated.endpoint = address.clone();
                data::save_contact(m, &updated)?;
            }
            m.mark_online(&req.sender, &address);
            write_frame(s, &json!({"ok":true}))
        }
        Action::Message { id, kind, body } => {
            validate_body(&kind, &body)?;
            data::insert(
                m,
                &id,
                &req.sender,
                "in",
                &kind,
                if kind == "text" {
                    "received"
                } else {
                    "offered"
                },
                &body,
            )?;
            // Retrying an offer also recovers a receipt lost during disconnect.
            // Report persisted state only; an offer ACK alone is not file receipt.
            let saved = data::message(m, &id)?;
            write_frame(
                s,
                &json!({"ok":true,"attachmentState":if kind == "text" { "" } else { saved.state.as_str() }}),
            )
        }
        Action::GroupMessage {
            group_id,
            message_id,
            group_name,
            sender_alias,
            kind,
            body,
        } => {
            uuid::Uuid::parse_str(&group_id).map_err(|_| "群组标识无效")?;
            uuid::Uuid::parse_str(&message_id).map_err(|_| "群消息标识无效")?;
            if group_name.is_empty() || group_name.chars().count() > 80 {
                return Err("群组名称无效".into());
            }
            alias_valid(&sender_alias)?;
            validate_body(&kind, &body)?;
            let allowed = data::groups(m)?
                .into_iter()
                .any(|g| g.id == group_id && g.member_ids.contains(&req.sender));
            if !allowed {
                return Err("发送方不在此群组，已拒绝群消息".into());
            }
            data::group_message(
                m,
                &message_id,
                &group_id,
                &req.sender,
                &sender_alias,
                &kind,
                &body,
            )?;
            write_frame(s, &json!({"ok":true}))
        }
        Action::GroupSync {
            group_id,
            group_name,
            group_type,
            member_ids,
        } => {
            if group_name.is_empty() || group_name.chars().count() > 80 || member_ids.len() > 64 {
                return Err("群组同步字段过长".into());
            }
            data::save_remote_group(
                m,
                &data::Group {
                    id: group_id,
                    name: group_name,
                    group_type,
                    role: "member".into(),
                    created_at: now(),
                    member_ids,
                },
                &req.sender,
            )?;
            write_frame(s, &json!({"ok":true}))
        }
        Action::Notification {
            id,
            group_id,
            kind,
            title,
            body,
            case_id,
            action_id,
        } => {
            uuid::Uuid::parse_str(&id).map_err(|_| "通知标识无效")?;
            if kind.chars().count() > 40
                || title.chars().count() > 160
                || body.chars().count() > 4000
            {
                return Err("通知字段过长".into());
            }
            let allowed = group_id
                .as_deref()
                .map(|gid| {
                    data::groups(m).map(|gs| {
                        gs.into_iter()
                            .any(|g| g.id == gid && g.member_ids.contains(&req.sender))
                    })
                })
                .transpose()?
                .unwrap_or(true);
            if !allowed {
                return Err("发送方不在此通知组，已拒绝通知".into());
            }
            data::notification(
                m,
                group_id.as_deref(),
                &kind,
                &title,
                &body,
                case_id.as_deref(),
                action_id.as_deref(),
            )?;
            write_frame(s, &json!({"ok":true}))
        }
        Action::HistoryPull { before_seq, limit } => {
            let limit = limit.clamp(1, 100) as usize;
            let available = data::history(m, &req.sender, before_seq)?;
            // A text message may be 16 KiB. Build the response incrementally
            // so the JSON payload remains below the bounded frame limit even
            // when a page contains long messages or attachment metadata.
            // `history` is ascending after its normal reverse. Take the
            // newest records that fit so the first sequence in this response
            // remains a valid cursor for the next request.
            let mut messages = Vec::new();
            for message in available.iter().rev().take(limit) {
                let mut candidate = messages.clone();
                candidate.push(message.clone());
                let probe = json!({"ok":true,"messages":candidate,"hasMore":true});
                let size = serde_json::to_vec(&probe).map_err(fail)?.len();
                if size > FRAME_LIMIT {
                    if messages.is_empty() {
                        return Err("单条历史消息超过通信帧限制".into());
                    }
                    break;
                }
                messages = candidate;
            }
            messages.reverse();
            let has_more = available.len() > messages.len();
            write_frame(
                s,
                &json!({"ok":true,"messages":messages,"hasMore":has_more}),
            )
        }
        Action::Fetch { id } => {
            let msg = data::message(m, &id)?;
            if msg.peer_id != req.sender || msg.kind == "text" {
                return Err("附件不属于此设备".into());
            }
            let bytes = data::file(m, &msg)?;
            write_frame(s, &json!({"ok":true,"size":bytes.len()}))?;
            for chunk in bytes.chunks(65536) {
                if stop.load(Ordering::SeqCst) {
                    return Err("协作已关闭，传输取消".into());
                }
                s.write_all(chunk).map_err(fail)?;
            }
            s.flush().map_err(fail)
        }
        Action::Receipt { id, accepted } => {
            let msg = data::message(m, &id)?;
            if msg.peer_id != req.sender || msg.direction != "out" || msg.kind == "text" {
                return Err("附件回执不属于此设备".into());
            }
            if msg.state != "accepted" {
                data::state(
                    m,
                    &id,
                    if accepted {
                        "accepted"
                    } else {
                        "declined_by_peer"
                    },
                )?;
            }
            write_frame(s, &json!({"ok":true}))
        }
        Action::Pair { .. } => unreachable!(),
    }
}
pub(super) fn server(
    m: Arc<Manager>,
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let connections = Arc::new(AtomicUsize::new(0));
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((socket, address)) => {
                    if !local(address.ip()) || !try_acquire_connection_slot(&connections, 4) {
                        continue;
                    }
                    if socket.set_nonblocking(false).is_err() {
                        continue;
                    }
                    let m = m.clone();
                    let tls = tls.clone();
                    let stop = stop.clone();
                    let count = connections.clone();
                    std::thread::spawn(move || {
                        let socket = crate::connection::DeadlineSocket::new(
                            socket,
                            Duration::from_secs(60),
                            Duration::from_secs(5),
                        );
                        if let Ok(session) = rustls::ServerConnection::new(tls) {
                            let mut stream = rustls::StreamOwned::new(session, socket);
                            if stream.conn.complete_io(&mut stream.sock).is_err() {
                                count.fetch_sub(1, Ordering::SeqCst);
                                return;
                            }
                            let certificate_id = stream
                                .conn
                                .peer_certificates()
                                .and_then(|c| c.first())
                                .map(|c| hash(c.as_ref()))
                                .unwrap_or_default();
                            if let Err(error) =
                                handle(&m, address, &mut stream, &stop, &certificate_id)
                            {
                                crate::runtime_log::event(
                                    "warn",
                                    "lan",
                                    "REQUEST_REJECTED",
                                    &error,
                                    None,
                                );
                                let _ =
                                    write_frame(&mut stream, &json!({"ok":false,"error":error}));
                            }
                        }
                        count.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(40))
                }
                Err(_) => break,
            }
        }
    })
}
pub(super) fn addresses(port: u16) -> Vec<String> {
    let mut ips = Vec::new();
    for route in ["192.168.1.1:9", "10.0.0.1:9", "172.16.0.1:9"] {
        if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
            if s.connect(route).is_ok() {
                if let Ok(a) = s.local_addr() {
                    if local(a.ip()) && !a.ip().is_loopback() {
                        ips.push(SocketAddr::new(a.ip(), port).to_string());
                    }
                }
            }
        }
    }
    ips.sort();
    ips.dedup();
    ips.push(format!("127.0.0.1:{port}"));
    ips
}
pub(super) fn discovery(
    m: Arc<Manager>,
    stop: Arc<AtomicBool>,
    port: u16,
    alias: &str,
) -> Result<std::thread::JoinHandle<()>, String> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(fail)?;
    socket.set_reuse_address(true).map_err(fail)?;
    #[cfg(unix)]
    socket.set_reuse_port(true).map_err(fail)?;
    socket
        .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT)).into())
        .map_err(fail)?;
    let socket: UdpSocket = socket.into();
    socket
        .join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)
        .map_err(fail)?;
    socket.set_multicast_ttl_v4(1).map_err(fail)?;
    socket.set_multicast_loop_v4(true).map_err(fail)?;
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(fail)?;
    let beacon = serde_json::to_vec(&Beacon {
        version: 1,
        id: m.identity.id.clone(),
        alias: alias.into(),
        port,
    })
    .map_err(fail)?;
    Ok(std::thread::spawn(move || {
        let mut last = Instant::now() - Duration::from_secs(3);
        let mut bytes = [0u8; 2048];
        while !stop.load(Ordering::SeqCst) {
            if last.elapsed() >= Duration::from_secs(3) {
                // App launches can have different local-network permissions from
                // terminal tests. A failed advertisement must remain visible.
                if let Err(error) = socket.send_to(&beacon, (GROUP, DISCOVERY_PORT)) {
                    if let Ok(mut notice) = m.last_error.lock() {
                        *notice = format!("自动发现发送失败，请检查局域网权限与网络；也可用邀请和手动地址连接：{error}");
                    }
                } else if let Ok(mut notice) = m.last_error.lock() {
                    if notice.starts_with("自动发现发送失败") {
                        notice.clear();
                    }
                }
                last = Instant::now();
            }
            match socket.recv_from(&mut bytes) {
                Ok((len, address)) => {
                    if !local(address.ip()) {
                        continue;
                    }
                    if let Ok(b) = serde_json::from_slice::<Beacon>(&bytes[..len]) {
                        if b.version != 1
                            || !id_valid(&b.id)
                            || b.id == m.identity.id
                            || b.port == 0
                            || alias_valid(&b.alias).is_err()
                        {
                            continue;
                        }
                        if let Ok(mut peers) = m.discovered.lock() {
                            peers.retain(|_, s| s.at.elapsed() < Duration::from_secs(12));
                            if peers.len() < 128 || peers.contains_key(&b.id) {
                                peers.insert(
                                    b.id.clone(),
                                    Seen {
                                        address: SocketAddr::new(address.ip(), b.port),
                                        beacon: b,
                                        at: Instant::now(),
                                    },
                                );
                            }
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => {
                    if let Ok(mut notice) = m.last_error.lock() {
                        *notice = format!("自动发现接收失败，请检查局域网权限与网络；也可用邀请和手动地址连接：{error}");
                    }
                    // Avoid spinning on a permanently failed socket.
                    break;
                }
            }
        }
    }))
}
pub(super) fn heartbeats(m: Arc<Manager>, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            if let Ok(contacts) = data::contacts(&m) {
                let active: Vec<_> = contacts
                    .into_iter()
                    .filter(|c| c.secret.is_some())
                    .collect();
                for batch in active.chunks(4) {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::scope(|scope| {
                        for c in batch {
                            let m = &m;
                            let stop = &stop;
                            scope.spawn(move || {
                                let Ok(port) = m.port() else { return };
                                let candidate = m.discovered.lock().ok().and_then(|d| {
                                    d.get(&c.id)
                                        .filter(|s| s.at.elapsed() < Duration::from_secs(12))
                                        .map(|s| s.address.to_string())
                                });
                                let address = candidate.unwrap_or_else(|| c.endpoint.clone());
                                let req = Request {
                                    sender: m.identity.id.clone(),
                                    auth: c.secret.clone().unwrap_or_default(),
                                    action: Action::Ping { port },
                                };
                                if request(m, &address, &c.id, &req, None).is_ok()
                                    && !stop.load(Ordering::SeqCst)
                                {
                                    m.mark_online(&c.id, &address);
                                }
                            });
                        }
                    });
                }
            }
            for _ in 0..25 {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    })
}

#[cfg(test)]
pub(super) fn rejected_unpaired(m: &Manager, address: &str, pin: &str) -> bool {
    request(
        m,
        address,
        pin,
        &Request {
            sender: hash(b"stranger"),
            auth: random(),
            action: Action::Ping { port: 1 },
        },
        None,
    )
    .is_err()
}

#[cfg(test)]
mod connection_limit_tests {
    use super::*;

    #[test]
    fn lan_connection_slots_remain_bounded_under_contention() {
        let slots = Arc::new(AtomicUsize::new(0));
        let acquired = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(33));
        let workers: Vec<_> = (0..32)
            .map(|_| {
                let slots = slots.clone();
                let acquired = acquired.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let owns_slot = try_acquire_connection_slot(&slots, 4);
                    if owns_slot {
                        acquired.fetch_add(1, Ordering::Relaxed);
                    }
                    barrier.wait();
                    if owns_slot {
                        slots.fetch_sub(1, Ordering::Release);
                    }
                })
            })
            .collect();
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(acquired.load(Ordering::Relaxed), 4);
        assert_eq!(slots.load(Ordering::Acquire), 0);
    }
}
