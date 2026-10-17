//! Optional relay availability never grants authority to use a relay path.
use super::{SdkError, VerifiedPermit, WebRtcHostError, ensure_live, io, remaining};
use nestlink_protocol::{ErrorCode, Path};
use std::{future::Future, time::Duration};

const OPTIONAL_TURN_OPERATION_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) async fn bounded_turn_operation<T>(
    permit: &VerifiedPermit,
    optional: bool,
    operation: impl Future<Output = Result<T, WebRtcHostError>>,
) -> Result<T, WebRtcHostError> {
    ensure_live(permit)?;
    let result = if optional {
        tokio::time::timeout(
            remaining(permit)?.min(OPTIONAL_TURN_OPERATION_TIMEOUT),
            operation,
        )
        .await
        .map_err(|_| WebRtcHostError::Sdk(SdkError::Timeout))?
    } else {
        operation.await
    };
    ensure_live(permit)?;
    result
}

/// `None` means that the caller must withdraw TURN and retain only the direct
/// path already granted by this permit. Invalid trust or authority is fatal.
pub(super) fn optional_turn_result<T>(
    permit: &VerifiedPermit,
    optional: bool,
    result: Result<T, WebRtcHostError>,
) -> Result<Option<T>, WebRtcHostError> {
    ensure_live(permit)?;
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if optional
                && permit.claims().paths.contains(&(Path::Direct as i32))
                && is_turn_availability_error(&error) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn is_turn_availability_error(error: &WebRtcHostError) -> bool {
    match error {
        WebRtcHostError::RelayUnavailable | WebRtcHostError::Sdk(SdkError::Timeout) => true,
        WebRtcHostError::Sdk(SdkError::Api(status, code)) => {
            (*status == reqwest::StatusCode::TOO_MANY_REQUESTS
                && *code == ErrorCode::CapacityExceeded)
                || (status.is_server_error()
                    && matches!(
                        code,
                        ErrorCode::RelayUnavailable | ErrorCode::TurnUnreachable
                    ))
                || (*status == reqwest::StatusCode::FORBIDDEN && *code == ErrorCode::RelayDisabled)
        }
        WebRtcHostError::Sdk(SdkError::Transport(error)) => transport_unavailable(error),
        _ => false,
    }
}

fn transport_unavailable(error: &reqwest::Error) -> bool {
    if error.is_timeout() {
        return true;
    }
    if !error.is_connect() {
        return false;
    }
    let mut source = std::error::Error::source(error);
    let mut unavailable = false;
    while let Some(error) = source {
        // TLS certificate/protocol failures must never be reduced to an
        // optional relay outage merely because reqwest marks them "connect".
        if error.downcast_ref::<rustls::Error>().is_some() {
            return false;
        }
        if let Some(error) = error.downcast_ref::<io::Error>() {
            unavailable |= matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::AddrNotAvailable
                    | io::ErrorKind::NetworkDown
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::HostUnreachable
            );
        }
        source = error.source();
    }
    unavailable
}
