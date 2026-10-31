// Management directory only: addresses and names confer no traffic authority.
use super::SpaceView;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceAddressIssue {
    pub expected_revision: u64,
    pub expected_address_epoch: u64,
    pub expected_membership_epoch: u64,
    pub installation_id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceAddressReservation {
    pub expected_revision: u64,
    pub expected_address_epoch: u64,
    pub ipv4: String,
    pub ipv6: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceAddressRename {
    pub expected_revision: u64,
    pub expected_address_epoch: u64,
    pub name: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpaceAddressRevocation {
    pub expected_revision: u64,
    pub expected_address_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpaceAddressView {
    pub installation_id: String,
    pub account_id: String,
    pub public_key: String,
    pub account_member_epoch: u64,
    pub membership_epoch: u64,
    pub address_epoch: u64,
    pub name: String,
    pub fqdn: String,
    pub ipv4: String,
    pub ipv6: String,
    pub reserved: bool,
    pub revoked: bool,
    /// A fresh server observation, never an authorization or an offline lease.
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SpaceAddressDirectory {
    pub space: SpaceView,
    /// Independent from the network authority revision and policy epoch.
    pub revision: u64,
    pub suffix: String,
    pub ipv4_pool: String,
    pub ipv6_pool: String,
    /// Consumers must revalidate; this slice installs no resolver or OS routes.
    pub cache_max_age_seconds: u32,
    /// Members see their own active records; managers also see stale tombstones.
    pub addresses: Vec<SpaceAddressView>,
}
