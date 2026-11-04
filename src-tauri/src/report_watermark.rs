//! 加密的报告元数据标记。名称和时间通过本工作区的 AES-GCM 密钥解读，
//! 认证标签检测内容改动；这不是不可删除水印，也不是第三方身份认证。
use crate::{
    report_draft::ReportDraft,
    store::{open_regular_read, Store},
};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    sync::Arc,
};
use tauri::State;

const PREFIX: &str = "GAGA-WM-2.";
const MAX_FILE: u64 = 64 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    pub enabled: bool,
    pub name: String,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "J4team".into(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Watermark {
    pub format: String,
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub report_title: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inspection {
    pub present: bool,
    pub watermark: Option<Watermark>,
    pub notice: &'static str,
    pub verification: &'static str,
    pub pdf_pages: Option<usize>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    key_id: String,
    nonce: String,
    ciphertext: String,
}
// 密钥不进入报告或通用工作区备份；丢失密钥后，无法再解读已签发水印。
fn key(store: &Store, create: bool) -> Result<Option<[u8; 32]>, String> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().map_err(|e| e.to_string())?;
    let path = store.root.join("report-watermark.key");
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() != 32 {
            return Err("本工作区水印密钥文件异常，请检查数据目录或恢复密钥。".into());
        }
        return Ok(Some(
            fs::read(path)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "水印密钥长度异常")?,
        ));
    }
    if !create {
        return Ok(None);
    }
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    crate::file_commit::write_new(&path, |file| {
        file.write_all(&bytes).map_err(|e| e.to_string())
    })?;
    Ok(Some(bytes))
}
fn validate_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() || name.chars().count() > 120 || name.chars().any(char::is_control) {
        return Err("电子水印名称需为 1—120 字，不能含控制字符。".into());
    }
    Ok(())
}
pub fn validate(settings: &Settings) -> Result<(), String> {
    if settings.enabled {
        validate_name(&settings.name)?;
    }
    Ok(())
}
pub fn create(draft: &ReportDraft) -> Result<Option<Watermark>, String> {
    if !draft.watermark.enabled {
        return Ok(None);
    }
    validate(&draft.watermark)?;
    Ok(Some(Watermark {
        format: "gaga-report-watermark/1".into(),
        id: uuid::Uuid::new_v4().to_string(),
        name: draft.watermark.name.trim().into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        report_title: draft.title.clone(),
    }))
}
pub fn seal(store: &Store, mark: &Watermark) -> Result<String, String> {
    let key = key(store, true)?.ok_or("水印密钥不可用")?;
    let key_id = format!("{:x}", Sha256::digest(key));
    let mut nonce = [0; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "无法初始化水印加密")?;
    let plaintext = serde_json::to_vec(mark).map_err(|e| e.to_string())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: format!("{PREFIX}{key_id}").as_bytes(),
            },
        )
        .map_err(|_| "水印加密失败")?;
    let envelope = Envelope {
        key_id,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    Ok(format!(
        "{PREFIX}{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope).map_err(|e| e.to_string())?)
    ))
}
fn decode(store: &Store, token: &str) -> Result<Option<Watermark>, String> {
    if token.len() > 4096 {
        return Err("电子水印元数据过长。".into());
    }
    let raw = URL_SAFE_NO_PAD
        .decode(token.strip_prefix(PREFIX).ok_or("电子水印格式不受支持。")?)
        .map_err(|_| "电子水印编码损坏。")?;
    let envelope: Envelope = serde_json::from_slice(&raw).map_err(|_| "电子水印封装损坏。")?;
    let Some(key) = key(store, false)? else {
        return Ok(None);
    };
    if envelope.key_id != format!("{:x}", Sha256::digest(key)) {
        return Ok(None);
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(&envelope.nonce)
        .map_err(|_| "水印随机数编码损坏")?;
    if nonce.len() != 12 {
        return Err("电子水印随机数长度无效".into());
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&envelope.ciphertext)
        .map_err(|_| "水印密文编码损坏")?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "无法初始化水印解密")?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: format!("{PREFIX}{}", envelope.key_id).as_bytes(),
            },
        )
        .map_err(|_| "电子水印校验失败：内容被改动或损坏。")?;
    let mark: Watermark = serde_json::from_slice(&plaintext).map_err(|_| "电子水印内容损坏。")?;
    validate_name(&mark.name)?;
    if mark.format != "gaga-report-watermark/1"
        || uuid::Uuid::parse_str(&mark.id).is_err()
        || chrono::DateTime::parse_from_rfc3339(&mark.created_at).is_err()
        || mark.report_title.chars().count() > 200
    {
        return Err("电子水印字段无效。".into());
    }
    Ok(Some(mark))
}
fn checked_file(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("无法读取报告：{e}"))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_FILE {
        return Err("水印查询与 PDF 写入支持不超过 64 MiB 的报告文件。".into());
    }
    Ok(())
}
fn pdf(path: &Path) -> Result<lopdf::Document, String> {
    let mut bytes = Vec::new();
    open_regular_read(path)
        .map_err(|e| format!("无法读取 PDF：{e}"))?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("无法读取 PDF：{e}"))?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("水印查询与 PDF 写入支持不超过 64 MiB 的报告文件。".into());
    }
    let doc = lopdf::Document::load_mem(&bytes).map_err(|e| format!("无法读取 PDF：{e}"))?;
    if doc.is_encrypted() {
        return Err("请先在文档工具中解密 PDF 副本后重试。".into());
    }
    doc.catalog()
        .map_err(|_| "PDF 目录损坏，无法检查或流转此报告。")?;
    if doc.get_pages().is_empty() {
        return Err("PDF 没有可读取的页面，请重新导出报告。".into());
    }
    Ok(doc)
}
pub fn inspect(store: &Store, path: &Path) -> Result<Inspection, String> {
    checked_file(path)?;
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut pdf_pages = None;
    let token = match ext.as_str() {
        "html" | "htm" => {
            let mut text = String::new();
            open_regular_read(path)
                .map_err(|e| e.to_string())?
                .take(MAX_FILE + 1)
                .read_to_string(&mut text)
                .map_err(|e| e.to_string())?;
            if text.len() as u64 > MAX_FILE {
                return Err("水印查询与 PDF 写入支持不超过 64 MiB 的报告文件。".into());
            }
            let pattern = regex::Regex::new(
                r#"<meta name="gaga-report-watermark" content="(GAGA-WM-2\.[A-Za-z0-9_-]+)">"#,
            )
            .unwrap();
            pattern.captures(&text).map(|c| c[1].to_string())
        }
        "docx" => {
            let mut zip = zip::ZipArchive::new(open_regular_read(path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("无法读取 DOCX：{e}"))?;
            let result = match zip.by_name("docProps/custom.xml") {
                Ok(entry) => {
                    if entry.size() > 16384 {
                        return Err("DOCX 自定义元数据超出查询范围。".into());
                    }
                    let mut text = String::new();
                    entry
                        .take(16385)
                        .read_to_string(&mut text)
                        .map_err(|e| e.to_string())?;
                    if text.len() > 16384 {
                        return Err("DOCX 自定义元数据超出查询范围。".into());
                    }
                    let pattern = regex::Regex::new(r"GAGA-WM-2\.[A-Za-z0-9_-]+").unwrap();
                    pattern.find(&text).map(|m| m.as_str().to_string())
                }
                Err(zip::result::ZipError::FileNotFound) => None,
                Err(e) => return Err(format!("DOCX 元数据读取失败：{e}")),
            };
            result
        }
        "pdf" => {
            let doc = pdf(path)?;
            pdf_pages = Some(doc.get_pages().len());
            let info = doc
                .trailer
                .get(b"Info")
                .ok()
                .and_then(|o| doc.dereference(o).ok())
                .and_then(|(_, o)| o.as_dict().ok());
            info.and_then(|d| d.get(b"GagaWatermark").ok())
                .and_then(|o| o.as_str().ok())
                .map(|s| {
                    String::from_utf8(s.to_vec()).map_err(|_| "PDF 水印编码无效。".to_string())
                })
                .transpose()?
        }
        _ => return Err("请选择 HTML、DOCX 或 PDF 报告。".into()),
    };
    let watermark = token
        .as_deref()
        .map(|t| decode(store, t))
        .transpose()?
        .flatten();
    Ok(Inspection {
        pdf_pages,
        present: token.is_some(),
        verification:if watermark.is_some(){"verified_local"}else if token.is_some(){"foreign_or_changed"}else{"missing"},
        watermark,
        notice: "名称与时间由本工作区密钥解密，认证标签检测密文改动；不是第三方身份认证。标识可能被删除；未找到标识时无法判断是否曾有水印。密钥不随通用备份导出，需妥善保管原工作区。",
    })
}
/// 仅追加文档信息，原 PDF 字节完整保留，避免重新序列化浮点页面尺寸、字体等对象。
/// 增量写入会保留历史版本，因此不适合做文档脱敏或移除已有元数据。
pub fn stamp_pdf(source: &Path, dest: &Path, token: &str) -> Result<(), String> {
    checked_file(source)?;
    if source.canonicalize().map_err(|e| e.to_string())?
        == dest
            .parent()
            .ok_or("保存目录无效")?
            .canonicalize()
            .map_err(|e| e.to_string())?
            .join(dest.file_name().ok_or("文件名无效")?)
    {
        return Err("请选择新的 PDF 文件名，保留原报告。".into());
    }
    // 读取一次，再由同一份字节构建增量文档，避免文件变化导致旧对象与原字节不一致。
    let mut bytes = Vec::new();
    open_regular_read(source)
        .map_err(|e| e.to_string())?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("水印查询与 PDF 写入支持不超过 64 MiB 的报告文件。".into());
    }
    let doc = lopdf::Document::load_mem(&bytes).map_err(|e| format!("无法读取 PDF：{e}"))?;
    if doc.is_encrypted() {
        return Err("请先在文档工具中解密 PDF 副本后重试。".into());
    }
    doc.catalog().map_err(|_| "PDF 目录损坏，无法写入水印。")?;
    if doc.get_pages().is_empty() {
        return Err("PDF 没有可读取的页面，请重新导出报告。".into());
    }
    if doc.objects.values().any(|o| {
        o.as_dict().ok().is_some_and(|d| {
            // /Type 在签名字典里可省略；空签名域也留给签名软件处理。
            [b"Type".as_slice(), b"FT".as_slice()]
                .iter()
                .any(|key| d.get(key).ok().and_then(|o| o.as_name().ok()) == Some(b"Sig"))
                || (d.has(b"ByteRange") && d.has(b"Contents"))
        })
    }) {
        return Err("PDF 含数字签名，写入水印会影响签名；请使用未签名的原始导出副本。".into());
    }
    let mut info = doc
        .trailer
        .get(b"Info")
        .ok()
        .and_then(|o| doc.dereference(o).ok())
        .and_then(|(_, o)| o.as_dict().ok())
        .cloned()
        .unwrap_or_default();
    info.set("GagaWatermark", lopdf::Object::string_literal(token));
    let mut incremental = lopdf::IncrementalDocument::create_from(bytes, doc);
    let id = incremental.new_document.add_object(info);
    incremental.new_document.trailer.set("Info", id);
    crate::file_commit::write_checked(
        dest,
        |file| {
            incremental.save_to(file).map_err(|e| e.to_string())?;
            if file.metadata().map_err(|e| e.to_string())?.len() > MAX_FILE {
                return Err("写入后的 PDF 超过 64 MiB，请先缩小报告后重试。".into());
            }
            Ok(())
        },
        || Ok(()),
    )
}
#[tauri::command]
pub async fn inspect_report_watermark(
    path: String,
    store: State<'_, Arc<Store>>,
) -> Result<Inspection, String> {
    let store = store.inner().clone();
    let result = tauri::async_runtime::spawn_blocking(move || inspect(&store, Path::new(&path)))
        .await
        .map_err(|e| e.to_string())?;
    if let Err(error) = &result {
        crate::runtime_log::event("error", "report", "INSPECTION_FAILED", error, None);
    }
    result
}
#[tauri::command]
pub async fn stamp_report_pdf(
    source: String,
    destination: String,
    name: String,
    store: State<'_, Arc<Store>>,
) -> Result<Inspection, String> {
    let store = store.inner().clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        validate_name(&name)?;
        let destination = Path::new(&destination);
        if !destination
            .extension()
            .is_some_and(|s| s.eq_ignore_ascii_case("pdf"))
        {
            return Err("水印副本需保存为 .pdf 文件。".into());
        }
        crate::report::validate_output(&store, destination)?;
        let mark = Watermark {
            format: "gaga-report-watermark/1".into(),
            id: uuid::Uuid::new_v4().to_string(),
            name: name.trim().into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            report_title: Path::new(&source)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("调查报告")
                .chars()
                .take(200)
                .collect(),
        };
        stamp_pdf(Path::new(&source), destination, &seal(&store, &mark)?)?;
        inspect(&store, destination)
    })
    .await
    .map_err(|e| e.to_string())?;
    crate::runtime_log::event(
        if result.is_ok() { "info" } else { "error" },
        "report",
        if result.is_ok() {
            "PDF_STAMP_COMPLETED"
        } else {
            "PDF_STAMP_FAILED"
        },
        result
            .as_ref()
            .err()
            .map(String::as_str)
            .unwrap_or("PDF 水印副本写入并复读通过"),
        None,
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deeply_nested_pdf_is_rejected_without_crashing_or_replacing_output() {
        let root = std::env::temp_dir().join(format!("gaga-pdf-depth-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let source = root.join("nested.pdf");
        let destination = root.join("previous.pdf");
        // Valid xref to an over-deep Catalog: exercise the patched parser itself.
        let mut data = b"%PDF-1.4\n".to_vec();
        let offset = data.len();
        data.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /X ");
        data.extend(std::iter::repeat_n(b'[', 10380));
        data.extend(std::iter::repeat_n(b']', 10380));
        data.extend_from_slice(b" >>\nendobj\n");
        let xref = data.len();
        data.extend_from_slice(format!("xref\n0 2\n0000000000 65535 f \n{offset:010} 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
        fs::write(&source, &data).unwrap();
        fs::write(&destination, b"old report canary").unwrap();
        assert!(inspect(&store, &source).is_err());
        assert!(stamp_pdf(&source, &destination, "synthetic").is_err());
        assert_eq!(fs::read(&source).unwrap(), data);
        assert_eq!(fs::read(&destination).unwrap(), b"old report canary");
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn watermark_inspection_rejects_symlink_inputs() {
        let root =
            std::env::temp_dir().join(format!("gaga-watermark-link-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let outside = root.with_extension("outside.html");
        fs::write(&outside, "<html><head></head></html>").unwrap();
        let link = root.join("report.html");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(inspect(&store, &link).is_err());
        drop(store);
        fs::remove_file(link).unwrap();
        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn metadata_roundtrip_is_unicode_bounded_and_versioned() {
        let d = ReportDraft {
            title: "报告 <现场>".into(),
            watermark: Settings {
                enabled: true,
                name: "J4team / 复核人甲".into(),
            },
            ..Default::default()
        };
        let mark = create(&d).unwrap().unwrap();
        let root = std::env::temp_dir().join(format!("gaga-sealed-mark-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let token = seal(&store, &mark).unwrap();
        let read = decode(&store, &token).unwrap().unwrap();
        assert!(!token.contains(&d.watermark.name));
        let outer = URL_SAFE_NO_PAD
            .decode(token.strip_prefix(PREFIX).unwrap())
            .unwrap();
        assert!(!String::from_utf8_lossy(&outer).contains(&d.watermark.name));
        let mut envelope: Envelope = serde_json::from_slice(&outer).unwrap();
        let mut changed = URL_SAFE_NO_PAD.decode(&envelope.ciphertext).unwrap();
        changed[0] ^= 1;
        envelope.ciphertext = URL_SAFE_NO_PAD.encode(changed);
        let changed = format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope).unwrap())
        );
        assert!(decode(&store, &changed).unwrap_err().contains("校验失败"));
        let other_root =
            std::env::temp_dir().join(format!("gaga-foreign-mark-{}", uuid::Uuid::new_v4()));
        let other = Store::open(other_root.clone()).unwrap();
        assert!(decode(&other, &token).unwrap().is_none());
        drop(other);
        fs::remove_dir_all(other_root).unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
        assert_eq!(read.name, d.watermark.name);
        assert_eq!(read.id, mark.id);
        assert_eq!(read.created_at, mark.created_at);
        assert_eq!(read.report_title, d.title);

        assert!(validate_name("\n").is_err());
        assert!(validate_name(&"a".repeat(121)).is_err());
        let disabled = ReportDraft {
            watermark: Settings {
                enabled: false,
                name: String::new(),
            },
            ..Default::default()
        };
        assert!(create(&disabled).unwrap().is_none());
    }
    #[test]
    fn report_exports_embed_metadata_outside_the_body_and_allow_disabling() {
        let root = std::env::temp_dir().join(format!("gaga-watermark-{}", uuid::Uuid::new_v4()));
        let store = Store::open(root.clone()).unwrap();
        let case = store.active().unwrap();
        store
            .add_node(
                "水印输出验收".into(),
                "正文可编辑".into(),
                "2026-10-29T10:21:00+08:00".into(),
                "复核人员".into(),
                None,
                None,
            )
            .unwrap();
        let mut draft = crate::report_draft::load(&store, &case).unwrap();
        draft.watermark.name = "交付甲 · 中文 <标识>".into();
        crate::report_draft::save(&store, &case, &mut draft).unwrap();
        for (file, export) in [
            (
                "report.html",
                crate::report::export_html as fn(&Store, &Path) -> Result<(), String>,
            ),
            ("report.docx", crate::report::export_docx),
        ] {
            let path = root.join(file);
            export(&store, &path).unwrap();
            let mark = inspect(&store, &path).unwrap().watermark.unwrap();
            assert_eq!(mark.name, draft.watermark.name);
            if file.ends_with("html") {
                assert!(!fs::read_to_string(&path)
                    .unwrap()
                    .split("<body>")
                    .nth(1)
                    .unwrap()
                    .contains(PREFIX));
            } else {
                let mut z = zip::ZipArchive::new(fs::File::open(&path).unwrap()).unwrap();
                let mut body = String::new();
                z.by_name("word/document.xml")
                    .unwrap()
                    .read_to_string(&mut body)
                    .unwrap();
                assert!(!body.contains(PREFIX));
            }
        }
        draft.watermark.enabled = false;
        crate::report_draft::save(&store, &case, &mut draft).unwrap();
        for (file, export) in [
            (
                "report.html",
                crate::report::export_html as fn(&Store, &Path) -> Result<(), String>,
            ),
            ("report.docx", crate::report::export_docx),
        ] {
            let path = root.join(file);
            export(&store, &path).unwrap();
            assert!(!inspect(&store, &path).unwrap().present);
        }
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn pdf_copy_keeps_pages_and_content_and_roundtrips_metadata() {
        use lopdf::{dictionary, Document, Object, Stream};
        let root = std::env::temp_dir().join(format!("gaga-pdf-mark-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let source = root.join("before.pdf");
        let dest = root.join("after.pdf");
        let mut doc = Document::with_version("1.5");
        let pages = doc.new_object_id();
        let stream = doc.add_object(Stream::new(
            dictionary! {},
            b"q 0 0 0 rg 100 100 200 100 re f Q".to_vec(),
        ));
        let page=doc.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"Contents"=>stream,"MediaBox"=>vec![0.into(),0.into(),595.into(),842.into()]});
        doc.objects.insert(
            pages,
            Object::Dictionary(dictionary! {"Type"=>"Pages","Kids"=>vec![page.into()],"Count"=>1}),
        );
        let catalog = doc.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
        doc.trailer.set("Root", catalog);
        doc.save(&source).unwrap();
        let store = Store::open(root.join("workspace")).unwrap();
        let original = fs::read(&source).unwrap();
        let mark = create(&ReportDraft::default()).unwrap().unwrap();
        stamp_pdf(&source, &dest, &seal(&store, &mark).unwrap()).unwrap();
        assert_eq!(fs::read(&source).unwrap(), original);
        // 页尺寸在部分生成器中具有超出 f32 的精度，不能经过整份文档重写。
        // 保留完整前缀也保护原字体、正文流和页面对象的精确表示。
        assert!(fs::read(&dest).unwrap().starts_with(&original));
        let reopened = pdf(&dest).unwrap();
        assert_eq!(reopened.get_pages().len(), 1);
        assert_eq!(
            reopened.get_page_content(page).unwrap(),
            doc.get_page_content(page).unwrap()
        );
        let read = inspect(&store, &dest).unwrap().watermark.unwrap();
        assert_eq!(read.name, mark.name);
        assert_eq!(read.created_at, mark.created_at);
        assert_eq!(read.id, mark.id);
        assert!(stamp_pdf(&source, &source, &seal(&store, &mark).unwrap()).is_err());
        // 签名字典的 /Type 可缺省，仍必须拒绝写入。
        doc.add_object(dictionary! {"ByteRange"=>vec![0.into(),1.into(),2.into(),3.into()],"Contents"=>Object::string_literal("signature")});
        doc.save(&source).unwrap();
        let previous_copy = fs::read(&dest).unwrap();
        assert!(stamp_pdf(&source, &dest, &seal(&store, &mark).unwrap())
            .unwrap_err()
            .contains("签名"));
        assert_eq!(fs::read(&dest).unwrap(), previous_copy);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
