//! WebView 只展示随安装包交付的页面。报告/消息中的链接不能把有本地
//! 文件与凭据访问能力的主窗口导航到外部页面；CSP 是另一层独立限制。
pub fn trusted_document(url: &tauri::Url, development: bool) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let bundled = matches!(
        (url.scheme(), url.host_str(), url.port()),
        ("tauri", Some("localhost"), None) | ("http" | "https", Some("tauri.localhost"), None)
    );
    bundled
        || (development
            && url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port() == Some(1420))
}

pub fn navigation_policy() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("local-document-policy")
        .on_navigation(|webview, url| {
            let allowed =
                webview.label() == "main" && trusted_document(url, cfg!(debug_assertions));
            if !allowed {
                crate::runtime_log::event(
                    "warn",
                    "webview",
                    "NAVIGATION_BLOCKED",
                    "主窗口已拒绝导航到外部页面",
                    None,
                );
            }
            allowed
        })
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packaged_documents_have_an_exact_origin_allowlist() {
        for origin in [
            "tauri://localhost/index.html",
            "http://tauri.localhost/",
            "https://tauri.localhost/#reports",
        ] {
            assert!(
                trusted_document(&origin.parse().unwrap(), false),
                "{origin}"
            );
        }
        for origin in [
            "https://example.test/",
            "https://tauri.localhost.example.test/",
            "tauri://localhost.example.test/",
            "https://user@tauri.localhost/",
            "http://tauri.localhost:1420/",
            "file:///etc/passwd",
            "data:text/html,hello",
            "javascript:alert(1)",
            "http://127.0.0.1:1420/",
        ] {
            assert!(
                !trusted_document(&origin.parse().unwrap(), false),
                "{origin}"
            );
        }
        assert!(trusted_document(
            &"http://127.0.0.1:1420/".parse().unwrap(),
            true
        ));
        assert!(!trusted_document(
            &"http://127.0.0.1:1421/".parse().unwrap(),
            true
        ));
    }
}
