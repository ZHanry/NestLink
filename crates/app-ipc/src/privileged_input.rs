//! Explicit local input-broker lifecycle; it cannot authorize a remote session.
use nestlink_app_core::CoreHandle;
use std::{future::Future, pin::Pin};

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol-spec/application-privileged-input.rs"
));

pub type PrivilegedInputResult = Result<PrivilegedInputStatus, PrivilegedInputError>;
pub type PrivilegedInputFuture<'a> =
    Pin<Box<dyn Future<Output = PrivilegedInputResult> + Send + 'a>>;

pub trait LocalPrivilegedInputHandler: Send + Sync {
    fn handle(
        &self,
        core: CoreHandle,
        generation: u64,
        action: PrivilegedInputAction,
    ) -> PrivilegedInputFuture<'_>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Command;

    #[test]
    fn status_is_read_only_and_start_stop_require_generation_fences() {
        assert!(
            !Command::PrivilegedInput {
                action: PrivilegedInputAction::Status
            }
            .mutates()
        );
        assert!(
            Command::PrivilegedInput {
                action: PrivilegedInputAction::Start
            }
            .mutates()
        );
        assert!(
            Command::PrivilegedInput {
                action: PrivilegedInputAction::Stop
            }
            .mutates()
        );
    }
    #[test]
    fn local_consent_command_cannot_supply_issuer_permit_or_executable() {
        for field in ["issuer", "signed_permit", "executable"] {
            let value = serde_json::json!({"command":"privileged_input","action":"start",field:"untrusted"});
            assert!(serde_json::from_value::<Command>(value).is_err());
        }
    }
}
