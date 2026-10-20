//! UI-only language preference. It never replaces remote names or protocol values.
use leptos::prelude::*;

thread_local! {
    static ENGLISH: ArcRwSignal<bool> = ArcRwSignal::new(false);
    static MESSAGES: std::cell::RefCell<std::collections::BTreeMap<String, (String, String)>> = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

pub fn english() -> bool {
    ENGLISH.with(Get::get)
}

pub fn text(chinese: &'static str, english_text: &'static str) -> &'static str {
    MESSAGES.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() < 4096 {
            let pair = (chinese.to_owned(), english_text.to_owned());
            cache.insert(chinese.into(), pair.clone());
            cache.insert(english_text.into(), pair);
        }
    });
    if english() { english_text } else { chinese }
}

pub fn feedback_pair(value: &str) -> (String, String) {
    MESSAGES.with(|cache| {
        cache
            .borrow()
            .get(value)
            .cloned()
            .unwrap_or_else(|| (value.to_owned(), value.to_owned()))
    })
}

pub fn feedback_text(value: &str) -> String {
    let pair = feedback_pair(value);
    if english() { pair.1 } else { pair.0 }
}

pub fn join_feedback(values: &[String], separator: &str) -> String {
    let pairs: Vec<_> = values
        .iter()
        .filter(|value| !value.is_empty())
        .map(|value| feedback_pair(value))
        .collect();
    formatted(
        pairs
            .iter()
            .map(|pair| pair.0.as_str())
            .collect::<Vec<_>>()
            .join(separator),
        pairs
            .iter()
            .map(|pair| pair.1.as_str())
            .collect::<Vec<_>>()
            .join(separator),
    )
}

pub fn formatted(chinese: String, english_text: String) -> String {
    let selected = if english() {
        english_text.clone()
    } else {
        chinese.clone()
    };
    if chinese.len() <= 4096 && english_text.len() <= 4096 {
        MESSAGES.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache.len() >= 4094 {
                cache.clear();
            }
            let pair = (chinese, english_text);
            cache.insert(pair.0.clone(), pair.clone());
            cache.insert(pair.1.clone(), pair);
        });
    }
    selected
}

/// Explain typed management failures without displaying tokens or remote bodies.
pub fn sdk_error(error: &nestlink_sdk::SdkError) -> &'static str {
    use nestlink_sdk::SdkError;
    match error {
        SdkError::SignIn => text("请先登录。", "Sign in first."),
        SdkError::Timeout => text(
            "请求超时，请检查网络后重试。",
            "The request timed out. Check your connection and retry.",
        ),
        SdkError::Transport(_) | SdkError::BrowserTransport => text(
            "无法连接服务器，请检查网络和服务器地址。",
            "Cannot reach the server. Check your connection and the server address.",
        ),
        SdkError::Trust | SdkError::Proof(_) => text(
            "服务器或设备身份核验失败，请核对部署信息。",
            "Server or device identity verification failed. Check the deployment details.",
        ),
        SdkError::Invalid | SdkError::Json(_) => text(
            "服务器响应不符合协议，请检查客户端与服务器版本。",
            "The server response is invalid. Check client and server versions.",
        ),
        SdkError::Api(_, code) => api_error(*code),
        #[cfg(not(target_arch = "wasm32"))]
        _ => text(
            "操作未完成，请检查连接和当前授权。",
            "The operation did not complete. Check the connection and current authorization.",
        ),
    }
}

fn api_error(code: nestlink_protocol::ErrorCode) -> &'static str {
    use nestlink_protocol::ErrorCode;
    match code {
        ErrorCode::AuthRequired => text(
            "登录已失效，请重新登录。",
            "Your sign-in expired. Sign in again.",
        ),
        ErrorCode::PermissionRequired => text(
            "当前账号或设备未获准执行这项操作。",
            "This account or device is not authorized for this operation.",
        ),
        ErrorCode::ProtocolMismatch | ErrorCode::InvalidMessage => text(
            "请求不符合协议，请检查输入和客户端版本。",
            "The request is invalid. Check the input and client version.",
        ),
        ErrorCode::DirectUnavailable => text(
            "未能建立直连，请检查双方网络或选择获准的中继。",
            "A direct connection could not be established. Check both networks or choose an authorized relay.",
        ),
        ErrorCode::RelayDisabled => text(
            "当前策略不允许中继。",
            "The current policy does not allow relays.",
        ),
        ErrorCode::RelayUnavailable | ErrorCode::TurnUnreachable => text(
            "获准的中继暂时不可用，请检查节点状态。",
            "The authorized relay is unavailable. Check the node status.",
        ),
        ErrorCode::PublicIngressDisabled => text(
            "当前策略未启用公网服务入口。",
            "Public service ingress is disabled by the current policy.",
        ),
        ErrorCode::PolicyRevoked => text(
            "授权已撤销，请重新申请访问。",
            "Access was revoked. Request access again.",
        ),
        ErrorCode::LeaseExpired => text(
            "授权已到期，请重新申请访问。",
            "Authorization expired. Request access again.",
        ),
        ErrorCode::SetupBudgetExhausted => text(
            "授权剩余时间不足以完成连接准备，请重新申请访问。",
            "Too little authorization time remains to prepare the connection. Request access again.",
        ),
        ErrorCode::CapacityExceeded => text(
            "已达到容量或流量上限，请稍后重试。",
            "A capacity or traffic limit was reached. Retry later.",
        ),
        ErrorCode::CodecUnsupported => text(
            "此设备无法使用所需的 VP8/Opus 媒体格式。",
            "This device cannot use the required VP8/Opus media formats.",
        ),
        ErrorCode::PlatformUnsupported => text(
            "当前系统不支持这项操作。",
            "This operation is unavailable on this platform.",
        ),
        ErrorCode::OsPermissionDenied => text(
            "系统权限未批准，请在设备本机检查授权。",
            "System permission was denied. Check permissions locally on the device.",
        ),
        ErrorCode::IdentityMismatch => text(
            "设备身份与当前授权不一致，连接已拒绝。",
            "Device identity does not match the authorization. The connection was rejected.",
        ),
        ErrorCode::ReplayRejected => text(
            "此操作已过期或重复，请刷新后重试。",
            "This operation is stale or duplicated. Refresh before retrying.",
        ),
        _ => text(
            "服务器未能完成请求，请稍后重试。",
            "The server could not complete the request. Retry later.",
        ),
    }
}

pub fn peer_error(error: &crate::browser_peer::PeerError) -> String {
    use crate::browser_peer::PeerError;
    let chinese = match error {
        PeerError::InvalidIceConfiguration => "部署的连接发现配置无效。",
        PeerError::InvalidPathMode => "所选连接方式无效。",
        PeerError::InvalidPermit => "会话许可无效或已到期。",
        PeerError::EndpointMismatch => "本页临时设备身份与获准的控制端不一致。",
        PeerError::EndpointLeaseExpired => "本页临时设备授权已到期，请重新连接。",
        PeerError::UnauthorizedTrack => "被控设备发送了未经批准的媒体，连接已停止。",
        PeerError::CodecUnavailable => "浏览器无法使用所需的 VP8/Opus 媒体格式。",
        PeerError::PathNotPermitted => "当前授权不允许使用所需的连接路径。",
        PeerError::RelayUnavailable => "此连接获准的 TURN 中继暂不可用。",
        PeerError::NoSelectedPath => "浏览器未报告可用的连接路径。",
        PeerError::SelectedPathRejected => "浏览器选择的路径不符合当前连接方式。",
        PeerError::OfferRequired
        | PeerError::AnswerRequired
        | PeerError::UnsupportedTrickleSignal => "设备的连接协商信息不符合要求。",
        PeerError::Cancelled => "连接已取消。",
        PeerError::Expired => "会话或临时设备授权已到期。",
        PeerError::TimedOut => "连接操作超时，请检查网络后重试。",
        PeerError::BrowserUnavailable => "此浏览器不支持 WebRTC。",
        PeerError::BrowserOperation => "浏览器未能完成媒体连接操作。",
        PeerError::SignalRejected => "设备签名信令核验失败，连接已拒绝。",
    };
    formatted(chinese.into(), error.to_string())
}

pub fn peer_connection_error(
    error: &crate::browser_peer::PeerError,
    mode: crate::browser_peer::PeerPathMode,
) -> String {
    use crate::browser_peer::{PeerError, PeerPathMode};
    if !matches!(
        error,
        PeerError::TimedOut
            | PeerError::Expired
            | PeerError::InvalidPermit
            | PeerError::NoSelectedPath
            | PeerError::BrowserOperation
    ) {
        return peer_error(error);
    }
    let help = if mode == PeerPathMode::DirectOnly {
        (
            "未建立可达的直连路径。请检查 STUN 和 UDP 网络；跨网受限时，请管理员允许并配置 TURN 中继，再使用自动连接。",
            "No reachable direct path was established. Check STUN and UDP reachability. For restrictive networks, ask your administrator to configure and allow TURN, then use Automatic.",
        )
    } else {
        (
            "未建立可达的远控路径。请检查部署的 STUN、TURN 中继和双方的中继权限后重试。服务器上的 WebSocket 中继不能替代浏览器所需的 TURN。",
            "No reachable remote path was established. Check deployment STUN, TURN and both devices' relay permissions, then retry. Browser connections require TURN; the native WebSocket relay does not provide it.",
        )
    };
    let detail = peer_error(error);
    let (chinese, english_text) = feedback_pair(&detail);
    formatted(
        format!("{chinese} {}", help.0),
        format!("{english_text} {}", help.1),
    )
}

pub fn set_english(value: bool) {
    ENGLISH.with(|language| language.set(value));
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        if let Ok(Some(storage)) = window.local_storage() {
            let _ = storage.set_item("nestlink.ui.language", if value { "en" } else { "zh" });
        }
        if let Some(document) = window.document() {
            document.set_title(if value {
                "NestLink Management"
            } else {
                "NestLink 管理"
            });
            if let Some(root) = document.document_element() {
                let _ = root.set_attribute("lang", if value { "en" } else { "zh-CN" });
            }
        }
    }
}

pub fn initialize() {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        let saved = window
            .local_storage()
            .ok()
            .flatten()
            .and_then(|storage| storage.get_item("nestlink.ui.language").ok().flatten());
        let english = match saved.as_deref() {
            Some("en") => true,
            Some("zh") => false,
            _ => window
                .navigator()
                .language()
                .is_some_and(|language| language.starts_with("en")),
        };
        set_english(english);
    }
}

/// Both format strings remain compile-time checked, including captured values.
#[macro_export]
macro_rules! localized_format {
    ($chinese:literal, $english:literal $(,)?) => {
        $crate::i18n::formatted(format!($chinese), format!($english))
    };
    ($chinese:literal, $english:literal, $a:expr $(,)?) => {{
        let a = &$a;
        $crate::i18n::formatted(format!($chinese, a), format!($english, a))
    }};
    ($chinese:literal, $english:literal, $a:expr, $b:expr $(,)?) => {{
        let (a, b) = (&$a, &$b);
        $crate::i18n::formatted(format!($chinese, a, b), format!($english, a, b))
    }};
    ($chinese:literal, $english:literal, $a:expr, $b:expr, $c:expr $(,)?) => {{
        let (a, b, c) = (&$a, &$b, &$c);
        $crate::i18n::formatted(format!($chinese, a, b, c), format!($english, a, b, c))
    }};
}

/// Only explicit local UI feedback is translated; names and protocol values stay raw.
#[macro_export]
macro_rules! localized_detail {
    ($chinese:literal, $english:literal, $detail:expr $(,)?) => {{
        let detail = $detail.to_string();
        let (chinese, english_text) = $crate::i18n::feedback_pair(&detail);
        $crate::i18n::formatted(format!($chinese, chinese), format!($english, english_text))
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_changes_only_explicit_ui_copy_and_formats_values_once() {
        set_english(false);
        assert_eq!(text("设备", "Devices"), "设备");
        let value = "direct_only";
        let message = crate::localized_format!("模式 {value}", "Mode {value}");
        assert_eq!(message, "模式 direct_only");
        set_english(true);
        assert_eq!(feedback_text(&message), "Mode direct_only");
        assert_eq!(text("设备", "Devices"), "Devices");
        assert_eq!(
            crate::localized_format!("模式 {value}", "Mode {value}"),
            "Mode direct_only"
        );
        assert_eq!(value, "direct_only");
        let problem = sdk_error(&nestlink_sdk::SdkError::Timeout);
        let detail = crate::localized_detail!("保存失败：{}", "Save failed: {}", problem);
        assert!(detail.starts_with("Save failed: The request timed out."));
        set_english(false);
        assert!(feedback_text(&detail).starts_with("保存失败：请求超时"));
        let peer = peer_connection_error(
            &crate::browser_peer::PeerError::TimedOut,
            crate::browser_peer::PeerPathMode::DirectOnly,
        );
        let joined = join_feedback(&[detail.clone(), peer], " ");
        set_english(true);
        let english_joined = feedback_text(&joined);
        assert!(english_joined.contains("Save failed: The request timed out."));
        assert!(english_joined.contains("No reachable direct path"));
        assert!(!english_joined.contains("请求"));
        // A remote name equal to local UI copy remains an ordinary format value.
        let name = "设备";
        let named = crate::localized_format!("名称 {}", "Name {}", name);
        assert_eq!(named, "Name 设备");
        set_english(false);
    }
}
