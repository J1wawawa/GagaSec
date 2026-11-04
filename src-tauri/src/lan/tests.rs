use super::*;
fn client() -> Arc<Manager> {
    let root = std::env::temp_dir().join(format!("gaga-lan-{}", uuid::Uuid::new_v4()));
    Manager::new(Arc::new(Store::open(root).unwrap())).unwrap()
}
fn cleanup(m: Arc<Manager>) {
    m.stop().unwrap();
    let root = m.store.root.clone();
    drop(m);
    let _ = fs::remove_dir_all(root);
}
fn pair(a: &Arc<Manager>, b: &Arc<Manager>) {
    a.start("甲的 Mac", false).unwrap();
    b.start("乙的 Mac", false).unwrap();
    let invite = b.invite().unwrap();
    a.pair(
        &format!("127.0.0.1:{}", b.port().unwrap()),
        invite["code"].as_str().unwrap(),
    )
    .unwrap();
}

#[test]
fn real_tls_chat_emoji_file_screenshot_restart_and_unpair() {
    let a = client();
    let b = client();
    pair(&a, &b);
    let peer = b.identity.id.clone();
    assert!(
        a.snapshot(Some(&peer), None, None).unwrap()["contacts"][0]["online"]
            .as_bool()
            .unwrap()
    );
    a.send_text(&peer, "收到，请复核截图 🦆✅").unwrap();
    let history = data::history(&b, &a.identity.id, None).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body.text, "收到，请复核截图 🦆✅");
    a.retry(&history[0].id).unwrap();
    assert_eq!(data::history(&b, &a.identity.id, None).unwrap().len(), 1);
    b.send_text(&a.identity.id, "双向回复 ✅").unwrap();
    assert_eq!(
        data::history(&a, &peer, None)
            .unwrap()
            .last()
            .unwrap()
            .body
            .text,
        "双向回复 ✅"
    );
    let bytes = b"synthetic case attachment, not executable";
    let input = a.store.root.join("har-notes.txt");
    fs::write(&input, bytes).unwrap();
    a.send_file(&peer, Some(input.to_str().unwrap()), None)
        .unwrap();
    let offer = data::history(&b, &a.identity.id, None)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(offer.state, "offered");
    assert!(!b
        .store
        .root
        .join("lan-private/attachments")
        .join(&offer.id)
        .exists());
    b.receive(&offer.id).unwrap();
    assert_eq!(
        data::file(&b, &data::message(&b, &offer.id).unwrap()).unwrap(),
        bytes
    );
    let out = b.store.root.join("export.txt");
    b.save_file(&offer.id, &out).unwrap();
    assert_eq!(fs::read(out).unwrap(), bytes);
    let mut png = std::io::Cursor::new(Vec::new());
    image::DynamicImage::new_rgba8(12, 8)
        .write_to(&mut png, image::ImageFormat::Png)
        .unwrap();
    let url = format!("data:image/png;base64,{}", B64.encode(png.get_ref()));
    a.send_file(&peer, None, Some(&url)).unwrap();
    let screenshot = data::history(&b, &a.identity.id, None)
        .unwrap()
        .pop()
        .unwrap();
    b.receive(&screenshot.id).unwrap();
    assert_eq!(b.image(&screenshot.id).unwrap(), url);
    let mut gif = Vec::new();
    {
        let mut encoder = image::codecs::gif::GifEncoder::new(&mut gif);
        for _ in 0..2 {
            encoder
                .encode_frame(image::Frame::new(image::RgbaImage::new(4, 4)))
                .unwrap();
        }
    }
    let gif_url = format!("data:image/gif;base64,{}", B64.encode(&gif));
    a.send_file(&peer, None, Some(&gif_url)).unwrap();
    let sticker = data::history(&b, &a.identity.id, None)
        .unwrap()
        .pop()
        .unwrap();
    b.receive(&sticker.id).unwrap();
    assert_eq!(b.image(&sticker.id).unwrap(), gif_url);
    assert_eq!(data::message(&a, &sticker.id).unwrap().state, "accepted");
    data::put_file(&b, &sticker.id, &gif).unwrap();
    // 配对和聊天记录重启保留，监听默认关闭；新身份不会静默覆盖旧密钥。
    b.stop().unwrap();
    let root = b.store.root.clone();
    let old_id = b.identity.id.clone();
    drop(b);
    std::thread::sleep(Duration::from_millis(100));
    let b = Manager::new(Arc::new(Store::open(root).unwrap())).unwrap();
    assert_eq!(b.identity.id, old_id);
    assert!(!b.enabled());
    assert_eq!(data::history(&b, &a.identity.id, None).unwrap().len(), 5);
    b.start("乙的 Mac", false).unwrap();
    a.mark_online(&peer, &format!("127.0.0.1:{}", b.port().unwrap()));
    b.unpair(&a.identity.id).unwrap();
    assert!(a
        .send_text(&peer, "应被拒绝")
        .unwrap_err()
        .contains("认证失败"));
    cleanup(a);
    cleanup(b);
}

#[test]
fn explicit_history_recovery_from_online_peer_is_idempotent() {
    let a = client();
    let b = client();
    pair(&a, &b);
    let b_id = b.identity.id.clone();
    a.send_text(&b_id, "恢复记录一").unwrap();
    a.send_text(&b_id, "恢复记录二").unwrap();
    assert_eq!(data::history(&b, &a.identity.id, None).unwrap().len(), 2);
    // Simulate a damaged local chat database while the paired peer remains
    // online and retains its encrypted outbox.
    b.store
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM lan_messages", [])
        .unwrap();
    let result = b.recover_history(&a.identity.id, None).unwrap();
    assert_eq!(result["recovered"], 2);
    let first_history = data::history(&b, &a.identity.id, None).unwrap();
    assert_eq!(first_history.len(), 2);
    let again = b.recover_history(&a.identity.id, None).unwrap();
    assert_eq!(again["recovered"], 0);
    let second_history = data::history(&b, &a.identity.id, None).unwrap();
    assert_eq!(second_history.len(), 2);
    assert_eq!(
        first_history
            .iter()
            .map(|message| (&message.id, &message.created_at))
            .collect::<Vec<_>>(),
        second_history
            .iter()
            .map(|message| (&message.id, &message.created_at))
            .collect::<Vec<_>>()
    );
    cleanup(a);
    cleanup(b);
}

#[test]
fn history_recovery_splits_long_messages_under_frame_limit() {
    let a = client();
    let b = client();
    pair(&a, &b);
    let peer = b.identity.id.clone();
    for index in 0..8 {
        data::insert(
            &a,
            &uuid::Uuid::new_v4().to_string(),
            &peer,
            "out",
            "text",
            "accepted",
            &data::Body::text(format!("长消息 {index} {}", "x".repeat(15_900))),
        )
        .unwrap();
    }
    let result = b.recover_history(&a.identity.id, None).unwrap();
    assert_eq!(result["recovered"], 8);
    assert_eq!(data::history(&b, &a.identity.id, None).unwrap().len(), 8);
    cleanup(a);
    cleanup(b);
}

#[test]
fn history_recovery_can_fetch_sender_attachment_from_receiver_copy() {
    let a = client();
    let b = client();
    pair(&a, &b);
    let bytes = b"recovery attachment body";
    let input = b.store.root.join("recover-me.txt");
    fs::write(&input, bytes).unwrap();
    b.send_file(&a.identity.id, Some(input.to_str().unwrap()), None)
        .unwrap();
    let offered = data::history(&a, &b.identity.id, None)
        .unwrap()
        .pop()
        .unwrap();
    a.receive(&offered.id).unwrap();

    // Lose the sender's local database row and attachment, while the paired
    // receiver still retains its verified copy.
    b.store
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM lan_messages", [])
        .unwrap();
    let _ = fs::remove_file(
        b.store
            .root
            .join("lan-private/attachments")
            .join(&offered.id),
    );
    let result = b.recover_history(&a.identity.id, None).unwrap();
    assert_eq!(result["recovered"], 1);
    let recovered = data::history(&b, &a.identity.id, None)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(recovered.direction, "out");
    assert_eq!(recovered.state, "recovered_metadata");
    b.recover_attachment(&recovered.id).unwrap();
    assert_eq!(data::message(&b, &recovered.id).unwrap().state, "recovered");
    assert_eq!(
        data::file(&b, &data::message(&b, &recovered.id).unwrap()).unwrap(),
        bytes
    );
    cleanup(a);
    cleanup(b);
}

#[test]
fn querying_duplicate_offer_recovers_a_lost_accept_or_decline_receipt() {
    let a = client();
    let b = client();
    pair(&a, &b);
    let input = a.store.root.join("receipt-recovery.txt");
    fs::write(&input, "synthetic attachment").unwrap();
    for accepted in [true, false] {
        a.send_file(&b.identity.id, Some(input.to_str().unwrap()), None)
            .unwrap();
        let offer = data::history(&b, &a.identity.id, None)
            .unwrap()
            .pop()
            .unwrap();
        if accepted {
            b.receive(&offer.id).unwrap();
        } else {
            b.decline(&offer.id).unwrap();
        }
        // Model a dropped final receipt: the receiver has persisted its decision,
        // while the sender still only knows its offer was delivered.
        data::state(&a, &offer.id, "delivered").unwrap();
        let before = data::history(&b, &a.identity.id, None).unwrap().len();
        a.retry(&offer.id).unwrap();
        assert_eq!(
            data::message(&a, &offer.id).unwrap().state,
            if accepted {
                "accepted"
            } else {
                "declined_by_peer"
            }
        );
        assert_eq!(
            data::history(&b, &a.identity.id, None).unwrap().len(),
            before
        );
    }
    cleanup(a);
    cleanup(b);
}

#[test]
fn rejects_untrusted_wrong_pin_expired_invitation_conflicting_ids_and_tampered_storage() {
    let a = client();
    let b = client();
    pair(&a, &b);
    let address = format!("127.0.0.1:{}", b.port().unwrap());
    assert!(net::rejected_unpaired(&a, &address, &b.identity.id));
    assert!(net::request(
        &a,
        &address,
        &hash(b"wrong certificate"),
        &net::Request {
            sender: a.identity.id.clone(),
            auth: random(),
            action: net::Action::Ping {
                port: a.port().unwrap()
            }
        },
        None
    )
    .is_err());
    a.send_text(&b.identity.id, "原始消息").unwrap();
    let msg = data::history(&b, &a.identity.id, None)
        .unwrap()
        .pop()
        .unwrap();
    assert!(data::insert(
        &b,
        &msg.id,
        &a.identity.id,
        "in",
        "text",
        "received",
        &data::Body::text("替换正文".into())
    )
    .is_err());
    let db_text: String = b
        .store
        .db
        .lock()
        .unwrap()
        .query_row("SELECT record FROM lan_messages LIMIT 1", [], |r| r.get(0))
        .unwrap();
    assert!(!db_text.contains("原始消息"));
    b.store
        .db
        .lock()
        .unwrap()
        .execute("UPDATE lan_messages SET record='AAAA'", [])
        .unwrap();
    assert!(data::history(&b, &a.identity.id, None).is_err());
    a.unpair(&b.identity.id).unwrap();
    b.unpair(&a.identity.id).unwrap();
    let invite = b.invite().unwrap();
    b.invitation.lock().unwrap().as_mut().unwrap().expires =
        Instant::now() - Duration::from_secs(1);
    assert!(a.pair(&address, invite["code"].as_str().unwrap()).is_err());
    assert!(endpoint("8.8.8.8:443").is_err());
    assert!(endpoint("127.0.0.1:0").is_err());
    assert!(validate_body(
        "file",
        &data::Body {
            text: String::new(),
            name: "../escape".into(),
            size: 1,
            sha256: hash(b"x"),
            mime: String::new()
        }
    )
    .is_err());
    cleanup(a);
    cleanup(b);
}

#[test]
fn shared_case_backup_excludes_lan_messages_and_credentials() {
    let a = client();
    let b = client();
    pair(&a, &b);
    a.send_text(&b.identity.id, "不能随案例共享的聊天").unwrap();
    let parent = std::env::temp_dir().join(format!("gaga-lan-backup-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&parent).unwrap();
    let backup = crate::maintenance::backup(&a.store, &parent).unwrap();
    let dir = Path::new(backup["path"].as_str().unwrap());
    assert!(!dir.join("lan-private").exists());
    let db = rusqlite::Connection::open(dir.join("workspace.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM lan_messages", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM lan_contacts", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    drop(db);
    cleanup(a);
    cleanup(b);
    let _ = fs::remove_dir_all(parent);
}

#[test]
fn multicast_discovery_uses_real_datagrams_without_pairing() {
    let a = client();
    let b = client();
    a.start("发现甲", true).unwrap();
    b.start("发现乙", true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if a.discovered.lock().unwrap().contains_key(&b.identity.id)
            && b.discovered.lock().unwrap().contains_key(&a.identity.id)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        a.discovered.lock().unwrap().contains_key(&b.identity.id),
        "真实组播发现未成功；检查本机局域网权限与网络环境"
    );
    assert!(data::contacts(&a).unwrap().is_empty());
    assert!(a.online.lock().unwrap().is_empty());
    cleanup(a);
    cleanup(b);
}

#[test]
fn restart_exposes_retry_for_interrupted_transfers_instead_of_leaving_them_running() {
    let m = client();
    let peer = hash(b"synthetic peer");
    let outgoing = uuid::Uuid::new_v4().to_string();
    let incoming = uuid::Uuid::new_v4().to_string();
    data::insert(
        &m,
        &outgoing,
        &peer,
        "out",
        "text",
        "sending",
        &data::Body::text("退出前发送未确认".into()),
    )
    .unwrap();
    data::insert(
        &m,
        &incoming,
        &peer,
        "in",
        "file",
        "receiving",
        &data::Body {
            text: String::new(),
            name: "receipt.txt".into(),
            size: 1,
            sha256: hash(b"x"),
            mime: String::new(),
        },
    )
    .unwrap();
    let root = m.store.root.clone();
    drop(m);
    let m = Manager::new(Arc::new(Store::open(root).unwrap())).unwrap();
    assert_eq!(data::message(&m, &outgoing).unwrap().state, "failed");
    assert_eq!(data::message(&m, &incoming).unwrap().state, "offered");
    assert!(!m.enabled());
    cleanup(m);
}
