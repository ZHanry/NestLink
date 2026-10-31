//! Online review and durable consumption; these envelopes never authorize I/O.
use super::*;
use schemars::JsonSchema;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfflineEnableUpdate {
    pub expected_revision: u64,
    pub enabled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfflinePolicyView {
    pub revision: u64,
    pub enabled: bool,
    pub highest_revocation_epoch: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfflinePrivateDraftRequest {
    pub consumer_device_id: String,
    pub service_id: String,
    pub process_nonces: [[u8; 32]; 2],
    pub expected_policy_revision: u64,
    pub expected_service_revision: u64,
    pub expected_exposure_revision: u64,
    pub direct_transports: Vec<OfflineDirectTransport>,
    pub maximum_bytes: u64,
    pub maximum_connections: u32,
    pub expires_at_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfflineBundleView {
    pub claims: OfflineGrantBundleClaims,
    pub draft_digest: [u8; 32],
    pub authority_public_key: [u8; 32],
    pub approved: [bool; 2],
    pub consumed: [bool; 2],
    pub signed: Option<SignedOfflineGrantBundle>,
    /// False requires stopping the original owner before any further I/O.
    pub live: bool,
    pub policy_epoch: u64,
    pub security_epoch: u64,
    pub highest_revocation_epoch: u64,
    pub observed_at_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfflineConsumeChallenge {
    pub bundle_id: String,
    pub endpoint: u8,
    pub draft_digest: [u8; 32],
    pub process_nonce: [u8; 32],
    pub challenge: [u8; 32],
    pub expires_at_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfflineConsumeRequest {
    pub endpoint: u8,
    pub draft_digest: [u8; 32],
    pub process_nonce: [u8; 32],
    pub signature: Vec<u8>,
}
