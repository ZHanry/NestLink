//! Independent finite offline authority. No online grant is lengthened or
//! accepted by decoding this bundle. Every section is mandatory.
use crate::{ContractError, ErrorCode, valid_id};
use serde::{Deserialize, Serialize};
pub mod channel;
pub mod management;

pub const OFFLINE_BUNDLE_VERSION: u16 = 1;
pub const MAX_OFFLINE_MS: u64 = 30 * 60 * 1000;
pub const OFFLINE_BUNDLE_BYTES: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineMember {
    pub installation_id: String,
    pub account_id: String,
    pub public_key: [u8; 32],
    pub membership_epoch: u64,
    /// Random ephemeral process public key supplied during online approval.
    /// Its matching private key remains only in the original process memory.
    pub process_nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineDirectTransport {
    Quic,
    Tls,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineConnection {
    pub connection_id: String,
    pub path_id: String,
    /// A canonical, nonempty subset of the two supported direct carriers.
    pub direct_transports: Vec<OfflineDirectTransport>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineRemoteOperation {
    View,
    Audio,
    Input,
    ClipboardRead,
    ClipboardWrite,
    FileRead,
    FileWrite,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub enum OfflineBusiness {
    RemoteControl {
        resource_id: String,
        /// Each high-privilege operation needs its own explicit approval.
        operations: Vec<OfflineRemoteOperation>,
        capability_digest: [u8; 32],
    },
    PrivateService {
        service_id: String,
        service_revision: u64,
        definition_digest: [u8; 32],
        target_digest: [u8; 32],
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineResourceReservation {
    pub reservation_id: String,
    /// Entire promise is committed online before issuance, never refunded by
    /// untrusted client usage or by changing this bundle's entry point.
    pub byte_limit: u64,
    pub file_write_limit: u64,
    /// Total connection attempts across the original owner, including retries.
    pub connection_limit: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineGrantBundleClaims {
    pub bundle_version: u16,
    pub deployment_id: String,
    pub space_id: String,
    pub bundle_id: String,
    pub policy_epoch: u64,
    pub security_epoch: u64,
    pub highest_revocation_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// Source/target order is significant and signed.
    pub members: [OfflineMember; 2],
    pub connection: OfflineConnection,
    pub business: OfflineBusiness,
    pub resources: OfflineResourceReservation,
}

impl OfflineGrantBundleClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.bundle_version != OFFLINE_BUNDLE_VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "unsupported offline bundle",
            ));
        }
        if [
            &self.deployment_id,
            &self.space_id,
            &self.bundle_id,
            &self.connection.connection_id,
            &self.connection.path_id,
            &self.resources.reservation_id,
        ]
        .iter()
        .any(|id| !valid_id(id))
            || self.policy_epoch == 0
            || self.security_epoch == 0
            || self.highest_revocation_epoch == 0
            || self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_OFFLINE_MS
            || self.expires_at_ms > i64::MAX as u64
            || self.resources.byte_limit == 0
            || self.resources.byte_limit > i64::MAX as u64
            || self.resources.file_write_limit > self.resources.byte_limit
            || self.resources.connection_limit == 0
            || self.resources.connection_limit > 1024
        {
            return Err(invalid(
                "invalid offline scope, finite deadline or reservation",
            ));
        }
        let ids = [
            &self.bundle_id,
            &self.connection.connection_id,
            &self.connection.path_id,
            &self.resources.reservation_id,
        ];
        if ids.iter().enumerate().any(|(i, id)| ids[..i].contains(id)) {
            return Err(invalid(
                "offline chain purposes require distinct identities",
            ));
        }
        for member in &self.members {
            if !valid_id(&member.installation_id)
                || !valid_id(&member.account_id)
                || member.public_key == [0; 32]
                || member.process_nonce == [0; 32]
                || member.membership_epoch == 0
            {
                return Err(invalid(
                    "offline membership needs a fixed installation and live process",
                ));
            }
        }
        if self.members[0].installation_id == self.members[1].installation_id
            || self.members[0].public_key == self.members[1].public_key
            || self.members[0].process_nonce == self.members[1].process_nonce
            || self.connection.direct_transports.is_empty()
            || self.connection.direct_transports.len() > 2
            || self
                .connection
                .direct_transports
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(
                "offline endpoints or direct carrier set is ambiguous",
            ));
        }
        match &self.business {
            OfflineBusiness::RemoteControl {
                resource_id,
                operations,
                capability_digest,
            } => {
                if !valid_id(resource_id)
                    || *capability_digest == [0; 32]
                    || operations.is_empty()
                    || operations.len() > 7
                    || operations.windows(2).any(|pair| pair[0] >= pair[1])
                    || (self.resources.file_write_limit > 0
                        && !operations.contains(&OfflineRemoteOperation::FileWrite))
                {
                    return Err(invalid(
                        "offline remote operations or file reservation differ",
                    ));
                }
            }
            OfflineBusiness::PrivateService {
                service_id,
                service_revision,
                definition_digest,
                target_digest,
            } => {
                if !valid_id(service_id)
                    || *service_revision == 0
                    || *definition_digest == [0; 32]
                    || *target_digest == [0; 32]
                    || self.resources.file_write_limit != 0
                {
                    return Err(invalid(
                        "offline private service must fix one approved target",
                    ));
                }
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| invalid("offline bundle encoding failed"))?;
        if bytes.len() > OFFLINE_BUNDLE_BYTES {
            return Err(invalid("offline bundle byte limit exceeded"));
        }
        Ok(bytes)
    }
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > OFFLINE_BUNDLE_BYTES {
            return Err(invalid("offline bundle byte limit exceeded"));
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid complete offline bundle"))?;
        if value.canonical_bytes()? != bytes {
            return Err(invalid("noncanonical offline bundle"));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOfflineGrantBundle {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}
impl SignedOfflineGrantBundle {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.claims.is_empty()
            || self.claims.len() > OFFLINE_BUNDLE_BYTES
            || self.signature.len() != 64
        {
            return Err(invalid("invalid offline signed envelope"));
        }
        Ok(())
    }
}
fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}

/// Device consent to the exact complete draft, separate from the authority
/// signature and from an account's management session. Both endpoints approve.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineEndpointApproval {
    pub endpoint: u8,
    pub draft_digest: [u8; 32],
    pub signature: Vec<u8>,
}
