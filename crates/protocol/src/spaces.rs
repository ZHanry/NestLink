//! Account delegation and one-use enrollment; these types grant no business access.
use crate::network::SpaceRole;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub mod service_publication;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceCreateRequest {
    pub name: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceRevisionRequest {
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceMemberUpdate {
    pub expected_revision: u64,
    pub expected_member_epoch: u64,
    pub role: SpaceRole,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceMemberRemoval {
    pub expected_revision: u64,
    pub expected_member_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceDeviceJoin {
    pub expected_revision: u64,
    pub expected_membership_epoch: u64,
    pub installation_id: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceDeviceRemoval {
    pub expected_revision: u64,
    pub expected_membership_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceInvitationRequest {
    pub expected_revision: u64,
    pub role: SpaceRole,
    pub target_account_id: Option<String>,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceInvitationAcceptance {
    pub token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpaceView {
    pub space_id: String,
    pub deployment_id: String,
    pub authority_public_key: String,
    pub name: String,
    pub archived: bool,
    pub revision: u64,
    pub policy_epoch: u64,
    pub observed_at_unix_ms: u64,
    pub role: SpaceRole,
    pub member_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpaceMemberView {
    pub account_id: String,
    pub name: String,
    pub role: SpaceRole,
    pub member_epoch: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpaceDeviceView {
    pub installation_id: String,
    pub account_id: String,
    pub name: String,
    pub role: SpaceRole,
    pub membership_epoch: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpaceInvitationView {
    pub invitation_id: String,
    pub role: SpaceRole,
    pub target_account_id: Option<String>,
    pub expires_at_unix_ms: u64,
    pub revoked: bool,
    pub consumed: bool,
}

/// The secret is returned exactly once and must be cleared when the UI closes.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct SpaceInvitationIssued {
    pub invitation: SpaceInvitationView,
    pub token: String,
    pub space: SpaceView,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpaceDetails {
    pub space: SpaceView,
    pub members: Vec<SpaceMemberView>,
    pub devices: Vec<SpaceDeviceView>,
    pub invitations: Vec<SpaceInvitationView>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpaceAuditEntry {
    pub sequence: u64,
    pub action: String,
    pub target_id: String,
    pub actor_account_id: String,
    pub at_unix_ms: u64,
}
