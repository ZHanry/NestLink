//! Transport-independent, bounded NestLink v15 wire contract.
pub mod api;
pub mod browse;
pub mod clipboard;
pub mod diagnostics;
pub mod file_recovery;
pub mod file_roots;
pub mod files;
pub mod ice;
pub mod input;
pub mod internal_software_media_candidate;
pub use input::valid_scroll;
pub mod media;
pub mod media_authority;
pub mod media_format;
pub mod native_displays;
pub mod native_media_format;
pub mod native_renewal;
pub mod network;
pub mod network_datagram;
pub mod node_discovery;
pub mod node_resources;
pub mod nodes;
pub mod relay;
pub mod relay_close;
pub mod relay_datagram;
pub mod service_plane;
pub mod service_quota_recovery;
pub mod services;
pub mod signaling;
pub mod spaces;
pub mod turn;
pub mod upload;
pub mod webrtc;
pub mod webrtc_data;
include!(concat!(env!("OUT_DIR"), "/nestlink.v1.rs"));
include!(concat!(env!("OUT_DIR"), "/contract.rs"));

use prost::Message;
use uuid::Uuid;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{code:?}: {reason}")]
pub struct ContractError {
    pub code: ErrorCode,
    pub reason: &'static str,
}

impl ContractError {
    pub fn new(code: ErrorCode, reason: &'static str) -> Self {
        Self { code, reason }
    }
}

pub fn decode_bounded<M: Message + Default>(bytes: &[u8], budget: u64) -> Result<M, ContractError> {
    if bytes.len() as u64 > budget {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "message budget exceeded",
        ));
    }
    M::decode(bytes)
        .map_err(|_| ContractError::new(ErrorCode::InvalidMessage, "malformed protobuf"))
}

pub fn valid_id(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.hyphenated().to_string() == value)
}

impl PermitClaims {
    pub fn is_setup(&self) -> bool {
        self.lease_sequence == 1
            && self
                .required_capabilities
                .iter()
                .any(|value| value == ice::SETUP_CAPABILITY)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        media_authority::permit_formats(self)?;
        let invalid = |reason| ContractError::new(ErrorCode::InvalidMessage, reason);
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "unsupported permit schema",
            ));
        }
        if [
            &self.deployment_id,
            &self.session_id,
            &self.account_id,
            &self.controller_device_id,
            &self.host_device_id,
            &self.resource_id,
        ]
        .iter()
        .any(|id| !valid_id(id))
        {
            return Err(invalid("invalid resource or identity UUID"));
        }
        if self.controller_device_id == self.host_device_id {
            return Err(invalid(
                "controller and host must be different installations",
            ));
        }
        if [
            &self.controller_key_sha256,
            &self.host_key_sha256,
            &self.capability_sha256,
        ]
        .iter()
        .any(|digest| digest.len() != 32)
        {
            return Err(invalid("invalid key or capability digest"));
        }
        if self.controller_key_sha256 == self.host_key_sha256 {
            return Err(invalid("endpoint installations must have distinct keys"));
        }
        if [
            self.security_epoch,
            self.policy_revision,
            self.connection_generation,
            self.lease_sequence,
        ]
        .contains(&0)
        {
            return Err(invalid("zero security generation"));
        }
        let lifetime = self
            .expires_at_unix_ms
            .checked_sub(self.issued_at_unix_ms)
            .ok_or_else(|| invalid("invalid lease interval"))?;
        let maximum = if self.lease_sequence == 1
            && self
                .required_capabilities
                .iter()
                .any(|capability| capability == ice::SETUP_CAPABILITY)
        {
            ice::SETUP_BUDGET_MS
        } else {
            SESSION_LEASE_MS
        };
        if lifetime == 0 || lifetime > maximum {
            return Err(invalid("lease lifetime out of bounds"));
        }
        if self.paths.is_empty()
            || self.paths.len() > 2
            || self
                .paths
                .iter()
                .any(|v| !matches!(Path::try_from(*v), Ok(Path::Direct | Path::Relay)))
            || has_duplicates(&self.paths)
        {
            return Err(invalid("invalid path set"));
        }
        if self.permissions.is_empty()
            || self.permissions.len() > 7
            || self
                .permissions
                .iter()
                .any(|v| !matches!(Permission::try_from(*v), Ok(p) if p != Permission::Unspecified))
            || has_duplicates(&self.permissions)
        {
            return Err(invalid("invalid permissions"));
        }
        if self.required_capabilities.len() > 32
            || self.required_capabilities.iter().any(|s| {
                s.is_empty()
                    || s.len() > 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            })
            || has_duplicates(&self.required_capabilities)
        {
            return Err(invalid("invalid required capabilities"));
        }
        Ok(())
    }
}

fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(i, value)| values[..i].contains(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_decode_rejects_oversized_and_malformed_messages() {
        assert_eq!(
            decode_bounded::<SignedPermit>(&[0; 5], 4)
                .err()
                .map(|e| e.code),
            Some(ErrorCode::CapacityExceeded)
        );
        assert!(decode_bounded::<SignedPermit>(&[0xff], 4).is_err());
    }
    #[test]
    fn identities_require_canonical_non_nil_uuid() {
        assert!(valid_id("11111111-1111-4111-8111-111111111111"));
        assert!(!valid_id("00000000-0000-0000-0000-000000000000"));
        assert!(!valid_id("11111111111141118111111111111111"));
    }
}
