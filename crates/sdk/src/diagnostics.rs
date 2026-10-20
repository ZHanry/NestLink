//! Fixed diagnostic labels; never stringify a transport or protocol error.
use crate::SdkError;
use nestlink_protocol::{ErrorCode, diagnostics::ConnectionFailure as Failure};

fn contract_failure(code: ErrorCode) -> Failure {
    match code {
        ErrorCode::AuthRequired => Failure::SignInRequired,
        ErrorCode::PermissionRequired | ErrorCode::ReplayRejected => Failure::InvalidAuthorization,
        ErrorCode::PolicyRevoked => Failure::AuthorizationRevoked,
        ErrorCode::LeaseExpired => Failure::AuthorizationExpired,
        ErrorCode::SetupBudgetExhausted => Failure::StartupAuthorizationExpired,
        ErrorCode::IdentityMismatch => Failure::EndpointMismatch,
        ErrorCode::CodecUnsupported => Failure::CodecUnavailable,
        ErrorCode::DirectUnavailable
        | ErrorCode::RelayDisabled
        | ErrorCode::PublicIngressDisabled => Failure::PathNotPermitted,
        ErrorCode::TurnUnreachable | ErrorCode::RelayUnavailable => Failure::RelayUnavailable,
        _ => Failure::ManagementRejected,
    }
}

impl SdkError {
    pub fn diagnostic_failure(&self) -> Failure {
        match self {
            Self::Api(_, code) => contract_failure(*code),
            Self::Proof(error) => contract_failure(error.code),
            Self::SignIn => Failure::SignInRequired,
            Self::Trust => Failure::EndpointMismatch,
            Self::Timeout => Failure::OperationTimeout,
            Self::Transport(error) if error.is_timeout() => Failure::OperationTimeout,
            Self::Transport(_) | Self::BrowserTransport => Failure::ManagementTransport,
            Self::Invalid | Self::Json(_) => Failure::InvalidResponse,
            #[cfg(not(target_arch = "wasm32"))]
            _ => Failure::Unclassified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn management_failures_keep_login_revocation_and_setup_expiry_distinct() {
        for (code, expected) in [
            (ErrorCode::AuthRequired, Failure::SignInRequired),
            (ErrorCode::PolicyRevoked, Failure::AuthorizationRevoked),
            (ErrorCode::LeaseExpired, Failure::AuthorizationExpired),
            (
                ErrorCode::SetupBudgetExhausted,
                Failure::StartupAuthorizationExpired,
            ),
            (ErrorCode::IdentityMismatch, Failure::EndpointMismatch),
            (ErrorCode::RelayUnavailable, Failure::RelayUnavailable),
        ] {
            assert_eq!(
                SdkError::Api(reqwest::StatusCode::FORBIDDEN, code).diagnostic_failure(),
                expected
            );
            assert_eq!(
                SdkError::Proof(nestlink_protocol::ContractError::new(
                    code,
                    "private reason must not enter diagnostics"
                ))
                .diagnostic_failure(),
                expected
            );
        }
        assert_eq!(
            SdkError::SignIn.diagnostic_failure(),
            Failure::SignInRequired
        );
        assert_eq!(
            SdkError::BrowserTransport.diagnostic_failure(),
            Failure::ManagementTransport
        );
        assert_eq!(
            SdkError::Invalid.diagnostic_failure(),
            Failure::InvalidResponse
        );
    }
}
