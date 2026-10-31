//! Fresh mutual endpoint proof on the existing mutually pinned direct carrier.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineChannelBinding {
    pub bundle_id: String,
    pub draft_digest: [u8; 32],
    pub source_nonce: [u8; 32],
    pub host_nonce: [u8; 32],
}
