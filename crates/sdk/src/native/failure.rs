//! Preserve security failures through real carrier errors without inspecting
//! human-readable messages. Reachability failures retain normal path fallback.
use crate::SdkError;
use nestlink_protocol::{ContractError, ErrorCode};
use nestlink_transport_wss::{
    WebSocketError, WebSocketProtocolError, WebSocketTlsError, WebSocketUrlError,
};
use std::{error::Error, io};

pub(super) fn classify(error: &(dyn Error + 'static), unavailable: ErrorCode) -> ErrorCode {
    classify_inner(error, unavailable, 0)
}

fn classify_inner(
    error: &(dyn Error + 'static),
    unavailable: ErrorCode,
    depth: u8,
) -> ErrorCode {
    // The bound also prevents a faulty third-party source chain from looping.
    if depth >= 16 {
        return ErrorCode::ProtocolMismatch;
    }
    if let Some(error) = error.downcast_ref::<rustls::Error>() {
        return match error {
            rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented => {
                ErrorCode::IdentityMismatch
            }
            _ => ErrorCode::ProtocolMismatch,
        };
    }
    if let Some(error) = error.downcast_ref::<quinn::ConnectionError>() {
        return match error {
            quinn::ConnectionError::TransportError(error) => {
                quic_code(error.code, unavailable)
            }
            quinn::ConnectionError::ConnectionClosed(close) => {
                quic_code(close.error_code, unavailable)
            }
            quinn::ConnectionError::VersionMismatch => ErrorCode::ProtocolMismatch,
            // A generic application close can be a peer restart or a losing
            // carrier being torn down. Only an explicit typed admission error
            // establishes an authorization rejection.
            quinn::ConnectionError::ApplicationClosed(_) => unavailable,
            _ => unavailable,
        };
    }
    if let Some(error) = error.downcast_ref::<ContractError>() {
        return error.code;
    }
    if let Some(error) = error.downcast_ref::<SdkError>() {
        match error {
            SdkError::Trust => return ErrorCode::IdentityMismatch,
            SdkError::SignIn => return ErrorCode::AuthRequired,
            SdkError::Invalid | SdkError::Json(_) => return ErrorCode::InvalidMessage,
            SdkError::Api(_, code) => return *code,
            _ => {}
        }
    }
    if let Some(error) = error.downcast_ref::<nestlink_transport_wss::Error>() {
        match error {
            nestlink_transport_wss::Error::Invalid => return ErrorCode::PermissionRequired,
            nestlink_transport_wss::Error::TlsSetup(source) => {
                let code = classify_inner(source.as_ref(), unavailable, depth + 1);
                return if code == unavailable { ErrorCode::ProtocolMismatch } else { code };
            }
            _ => {}
        }
    }
    if let Some(error) = error.downcast_ref::<WebSocketError>() {
        return match error {
            WebSocketError::Io(source) => classify_inner(source, unavailable, depth + 1),
            WebSocketError::Tls(source) => classify_inner(source, unavailable, depth + 1),
            WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed => unavailable,
            WebSocketError::Protocol(
                WebSocketProtocolError::ResetWithoutClosingHandshake
                | WebSocketProtocolError::HandshakeIncomplete,
            ) => unavailable,
            WebSocketError::Url(WebSocketUrlError::UnableToConnect(_)) => unavailable,
            WebSocketError::Http(response) => match response.status().as_u16() {
                401 => ErrorCode::AuthRequired,
                403 => ErrorCode::PermissionRequired,
                408 | 429 | 500..=599 => unavailable,
                _ => ErrorCode::ProtocolMismatch,
            },
            _ => ErrorCode::ProtocolMismatch,
        };
    }
    if let Some(error) = error.downcast_ref::<WebSocketTlsError>() {
        return match error {
            WebSocketTlsError::Rustls(source) => {
                classify_inner(source.as_ref(), unavailable, depth + 1)
            }
            _ => ErrorCode::ProtocolMismatch,
        };
    }
    if let Some(error) = error.downcast_ref::<io::Error>() {
        if let Some(inner) = error.get_ref() {
            let code = classify_inner(inner, unavailable, depth + 1);
            if code != unavailable {
                return code;
            }
        }
        return match error.kind() {
            io::ErrorKind::InvalidData => ErrorCode::ProtocolMismatch,
            io::ErrorKind::PermissionDenied => ErrorCode::PermissionRequired,
            _ => unavailable,
        };
    }
    match error.source() {
        Some(source) => classify_inner(source, unavailable, depth + 1),
        None => unavailable,
    }
}

fn quic_code(code: quinn::TransportErrorCode, unavailable: ErrorCode) -> ErrorCode {
    if matches!(
        code,
        quinn::TransportErrorCode::NO_ERROR
            | quinn::TransportErrorCode::CONNECTION_REFUSED
            | quinn::TransportErrorCode::NO_VIABLE_PATH
    ) {
        return unavailable;
    }
    let code = u64::from(code);
    if (0x100..0x200).contains(&code) && code != 0x178 {
        // RFC 9000 CRYPTO_ERROR carries the TLS alert. no_application_protocol
        // (120) is a protocol mismatch; every crypto failure remains terminal.
        ErrorCode::IdentityMismatch
    } else {
        ErrorCode::ProtocolMismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_tls_and_protocol_failures_remain_terminal() {
        let tls = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure),
        );
        assert_eq!(classify(&tls, ErrorCode::DirectUnavailable), ErrorCode::IdentityMismatch);
        assert_eq!(
            classify(&io::Error::new(io::ErrorKind::InvalidData, "ALPN"), ErrorCode::DirectUnavailable),
            ErrorCode::ProtocolMismatch
        );
        let quic = quinn::ConnectionError::TransportError(quinn::TransportError {
            code: quinn::TransportErrorCode::crypto(42),
            frame: None,
            reason: String::new(),
        });
        assert_eq!(classify(&quic, ErrorCode::DirectUnavailable), ErrorCode::IdentityMismatch);
        assert_eq!(
            classify(&SdkError::Trust, ErrorCode::RelayUnavailable),
            ErrorCode::IdentityMismatch
        );
        assert_eq!(
            classify(&ContractError::new(ErrorCode::PolicyRevoked, "revoked"), ErrorCode::RelayUnavailable),
            ErrorCode::PolicyRevoked
        );
    }

    #[test]
    fn genuine_network_failure_remains_retryable() {
        for kind in [io::ErrorKind::TimedOut, io::ErrorKind::ConnectionRefused, io::ErrorKind::ConnectionReset] {
            assert_eq!(classify(&io::Error::from(kind), ErrorCode::DirectUnavailable), ErrorCode::DirectUnavailable);
        }
        assert_eq!(
            classify(&quinn::ConnectionError::TimedOut, ErrorCode::RelayUnavailable),
            ErrorCode::RelayUnavailable
        );
        let closed = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(0),
            reason: bytes::Bytes::new(),
        });
        assert_eq!(
            classify(&closed, ErrorCode::RelayUnavailable),
            ErrorCode::RelayUnavailable
        );
        assert_eq!(
            classify(&SdkError::Relay(WebSocketError::ConnectionClosed.into()), ErrorCode::RelayUnavailable),
            ErrorCode::RelayUnavailable
        );
    }

    #[test]
    fn outer_websocket_preserves_tls_protocol_and_http_authority_failures()
    -> Result<(), Box<dyn std::error::Error>> {
        let tls = WebSocketError::Tls(WebSocketTlsError::Rustls(Box::new(
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        )));
        assert_eq!(
            classify(&SdkError::Relay(tls.into()), ErrorCode::RelayUnavailable),
            ErrorCode::IdentityMismatch
        );
        let protocol = WebSocketError::Protocol(WebSocketProtocolError::SecWebSocketAcceptKeyMismatch);
        assert_eq!(
            classify(&SdkError::Relay(protocol.into()), ErrorCode::RelayUnavailable),
            ErrorCode::ProtocolMismatch
        );
        for (status, expected) in [
            (401, ErrorCode::AuthRequired),
            (403, ErrorCode::PermissionRequired),
            (503, ErrorCode::RelayUnavailable),
        ] {
            let response = tokio_tungstenite::tungstenite::http::Response::builder()
                .status(status)
                .body(None)?;
            let error = SdkError::Relay(WebSocketError::Http(Box::new(response)).into());
            assert_eq!(classify(&error, ErrorCode::RelayUnavailable), expected);
        }
        for kind in [io::ErrorKind::ConnectionRefused, io::ErrorKind::ConnectionReset, io::ErrorKind::TimedOut] {
            let outer = SdkError::Relay(WebSocketError::Io(io::Error::from(kind)).into());
            let inner = SdkError::Relay(nestlink_transport_wss::Error::Tls(io::Error::from(kind)));
            assert_eq!(classify(&outer, ErrorCode::RelayUnavailable), ErrorCode::RelayUnavailable);
            assert_eq!(classify(&inner, ErrorCode::RelayUnavailable), ErrorCode::RelayUnavailable);
        }
        Ok(())
    }
}
