//! UI-only language preference. It never replaces remote names or protocol values.
use leptos::prelude::*;

thread_local! {
    static ENGLISH: ArcRwSignal<bool> = ArcRwSignal::new(false);
}

pub fn english() -> bool {
    ENGLISH.with(Get::get)
}

pub fn text(chinese: &'static str, english_text: &'static str) -> &'static str {
    if english() { english_text } else { chinese }
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
    if english() {
        return error.to_string();
    }
    match error {
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
    }
    .into()
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
        text(
            "未建立可达的直连路径。请检查 STUN 和 UDP 网络；跨网受限时，请管理员允许并配置 TURN 中继，再使用自动连接。",
            "No reachable direct path was established. Check STUN and UDP reachability. For restrictive networks, ask your administrator to configure and allow TURN, then use Automatic.",
        )
    } else {
        text(
            "未建立可达的远控路径。请检查部署的 STUN、TURN 中继和双方的中继权限后重试。服务器上的 WebSocket 中继不能替代浏览器所需的 TURN。",
            "No reachable remote path was established. Check deployment STUN, TURN and both devices' relay permissions, then retry. Browser connections require TURN; the native WebSocket relay does not provide it.",
        )
    };
    format!("{} {help}", peer_error(error))
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
    ($chinese:literal, $english:literal $(, $($arguments:tt)*)?) => {
        if $crate::i18n::english() {
            format!($english $(, $($arguments)*)?)
        } else {
            format!($chinese $(, $($arguments)*)?)
        }
    };
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
        assert_eq!(text("设备", "Devices"), "Devices");
        assert_eq!(
            crate::localized_format!("模式 {value}", "Mode {value}"),
            "Mode direct_only"
        );
        assert_eq!(value, "direct_only");
        set_english(false);
    }
}
