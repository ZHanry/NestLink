//! Public local intent; signed authority remains in the account actor.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRemotePreparationSettings {
    pub request_id: String,
    pub connection_generation: u64,
    pub permit_sha256: [u8; 32],
    pub space_revision: u64,
    pub policy_epoch: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSpaceMode {
    Direct,
    Relays,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSpacePreviewRequest {
    pub runtime_id: String,
    pub context: String,
    pub space_id: String,
    pub request_id: String,
    pub expected_connection_generation: u64,
    pub expected_space_revision: u64,
    pub expected_policy_epoch: u64,
    pub expected_network_revision: u64,
    /// Entered independently by the local user, never filled from the directory.
    pub trusted_authority_key: [u8; 32],
    pub mode: NativeSpaceMode,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSpaceConfirmation {
    pub runtime_id: String,
    pub context: String,
    pub nonce: String,
    pub node_ids: Option<[String; 2]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeSpaceRelayChoice {
    pub node_id: String,
    pub runtime_generation: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeSpacePreview {
    pub nonce: String,
    pub context: String,
    pub space_id: String,
    pub deployment_id: String,
    pub authority_key: [u8; 32],
    pub request_id: String,
    pub connection_generation: u64,
    pub permit_sha256: [u8; 32],
    pub membership_epochs: [u64; 2],
    pub installation_ids: [String; 2],
    pub roles: [nestlink_protocol::network::SpaceRole; 2],
    pub expected_network_revision: u64,
    pub expires_at_unix_ms: u64,
    pub mode: NativeSpaceMode,
    pub relay_choices: Vec<NativeSpaceRelayChoice>,
}
