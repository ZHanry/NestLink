//! Independently versioned topology statements. Parsing is never publication,
//! forwarding, prefix access or business authorization.
use crate::{
    ContractError, ErrorCode, valid_id,
    network::{GrantScope, IpPrefix, PeerId},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeSet;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_REPORT_BYTES: usize = 16_384;
pub const MAX_NEIGHBORS: usize = 16;
pub const MAX_PREFIXES: usize = crate::network::MAX_PREFIXES;
pub const MAX_TTL_MS: u64 = 10_000;
pub const MAX_ADVERTISEMENTS: usize = 4096;
pub const MAX_DELTA: usize = 256;
pub const MAX_ADVERTISEMENT_BYTES: usize = MAX_REPORT_BYTES + 1024;
pub const MAX_UPDATE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootIncarnation {
    pub runtime_generation: u64,
    pub runtime_id: String,
}
impl BootIncarnation {
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_id(&self.runtime_id)
            || self.runtime_generation == 0
            || self.runtime_generation > i64::MAX as u64
        {
            return Err(invalid("invalid topology boot incarnation"));
        }
        Ok(())
    }
}

/// Only the authority may grant publication. A registered global relay role
/// alone does not confer publication or forwarding in any space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyPublisherClaims {
    pub scope: GrantScope,
    pub node_id: String,
    pub public_key: [u8; 32],
    pub peer: PeerId,
    pub incarnation: BootIncarnation,
    pub allowed_neighbors: Vec<PeerId>,
    pub route_export_digests: Vec<[u8; 32]>,
    pub allowed_prefixes: Vec<IpPrefix>,
}
impl TopologyPublisherClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.scope.validate()?;
        self.incarnation.validate()?;
        self.peer.validate()?;
        validate_prefixes(&self.allowed_prefixes)?;
        if !valid_id(&self.node_id)
            || self.public_key == [0; 32]
            || self.peer != PeerId::from_public_key(&self.public_key)
            || self.allowed_neighbors.len() > MAX_NEIGHBORS
            || self.allowed_neighbors.windows(2).any(|p| p[0] >= p[1])
            || self.allowed_neighbors.contains(&self.peer)
            || self.route_export_digests.len() > MAX_PREFIXES
            || self.route_export_digests.contains(&[0; 32])
            || self.route_export_digests.windows(2).any(|p| p[0] >= p[1])
            || (self.route_export_digests.is_empty() != self.allowed_prefixes.is_empty())
        {
            return Err(invalid("invalid topology publisher authority"));
        }
        for peer in &self.allowed_neighbors {
            peer.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyNeighbor {
    pub local: PeerId,
    pub remote: PeerId,
    pub local_endpoint_revision: u64,
    pub remote_endpoint_revision: u64,
    pub up: bool,
}
impl TopologyNeighbor {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.local.validate()?;
        self.remote.validate()?;
        if self.local == self.remote
            || self.local_endpoint_revision == 0
            || self.remote_endpoint_revision == 0
            || self.local_endpoint_revision > i64::MAX as u64
            || self.remote_endpoint_revision > i64::MAX as u64
        {
            return Err(invalid("invalid topology neighbor"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyReport {
    pub schema_version: u32,
    pub deployment_id: String,
    pub space_id: String,
    pub policy_epoch: u64,
    pub node_id: String,
    pub peer: PeerId,
    pub publisher_digest: [u8; 32],
    pub incarnation: BootIncarnation,
    pub sequence: u64,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub neighbors: Vec<TopologyNeighbor>,
    pub prefixes: Vec<IpPrefix>,
}
impl TopologyReport {
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(self.schema_version)?;
        self.incarnation.validate()?;
        self.peer.validate()?;
        validate_prefixes(&self.prefixes)?;
        lifetime(self.not_before_ms, self.expires_at_ms)?;
        if !valid_id(&self.deployment_id)
            || !valid_id(&self.space_id)
            || !valid_id(&self.node_id)
            || self.policy_epoch == 0
            || self.policy_epoch > i64::MAX as u64
            || self.publisher_digest == [0; 32]
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.neighbors.len() > MAX_NEIGHBORS
            || self.neighbors.windows(2).any(|p| p[0].remote >= p[1].remote)
        {
            return Err(invalid("invalid topology report"));
        }
        for neighbor in &self.neighbors {
            neighbor.validate()?;
            if neighbor.local != self.peer {
                return Err(invalid("topology report has another publisher's edge"));
            }
        }
        Ok(())
    }
}

/// The authority carries the exact node report and its node signature. Its own
/// signature narrows the observation lifetime, never grants network access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyAdvertisement {
    pub schema_version: u32,
    pub report: TopologyReport,
    pub report_signature: Vec<u8>,
    pub report_digest: [u8; 32],
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
}
impl TopologyAdvertisement {
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(self.schema_version)?;
        self.report.validate()?;
        lifetime(self.not_before_ms, self.expires_at_ms)?;
        if self.report_signature.len() != 64
            || self.report_digest == [0; 32]
            || self.not_before_ms < self.report.not_before_ms
            || self.expires_at_ms > self.report.expires_at_ms
        {
            return Err(invalid("invalid topology advertisement"));
        }
        Ok(())
    }
}

macro_rules! signed {
    ($name:ident, $claim:ty, $maximum:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub claims: Vec<u8>,
            pub signature: Vec<u8>,
        }
        impl $name {
            pub fn validate(&self) -> Result<(), ContractError> {
                if self.signature.len() != 64 || self.claims.len() > $maximum {
                    return Err(invalid("invalid signed topology envelope"));
                }
                <$claim>::decode_canonical(&self.claims)?;
                Ok(())
            }
            pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
                self.validate()?;
                canonical(self, $maximum * 4 + 512)
            }
            pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ContractError> {
                let value: Self = decode(bytes, $maximum * 4 + 512)?;
                if value.canonical_bytes()? != bytes {
                    return Err(invalid("noncanonical signed topology envelope"));
                }
                Ok(value)
            }
        }
    };
}

signed!(SignedTopologyPublisher, TopologyPublisherClaims, MAX_REPORT_BYTES);
signed!(SignedTopologyReport, TopologyReport, MAX_REPORT_BYTES);
signed!(SignedTopologyAdvertisement, TopologyAdvertisement, MAX_ADVERTISEMENT_BYTES);

/// A withdrawal is sufficient on its own. Its authority-signed update must not
/// require the old publisher/report to remain valid before removing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyWithdrawal {
    pub node_id: String,
    pub peer: PeerId,
    pub publisher_digest: [u8; 32],
    pub incarnation: BootIncarnation,
    pub sequence: u64,
}
impl TopologyWithdrawal {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.peer.validate()?;
        self.incarnation.validate()?;
        if !valid_id(&self.node_id)
            || self.publisher_digest == [0; 32]
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
        {
            return Err(invalid("invalid topology withdrawal"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case", deny_unknown_fields)]
pub enum TopologyChange {
    Upsert(SignedTopologyAdvertisement),
    Withdraw(TopologyWithdrawal),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyDeltaEntry {
    pub cursor: u64,
    pub change: TopologyChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TopologySync {
    Full {
        cursor: u64,
        advertisements: Vec<SignedTopologyAdvertisement>,
    },
    Delta {
        after_cursor: u64,
        cursor: u64,
        has_more: bool,
        changes: Vec<TopologyDeltaEntry>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyUpdate {
    pub schema_version: u32,
    pub deployment_id: String,
    pub space_id: String,
    pub policy_epoch: u64,
    pub query_nonce: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub sync: TopologySync,
}
impl TopologyUpdate {
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(self.schema_version)?;
        lifetime(self.issued_at_ms, self.expires_at_ms)?;
        if !valid_id(&self.deployment_id)
            || !valid_id(&self.space_id)
            || self.policy_epoch == 0
            || self.policy_epoch > i64::MAX as u64
            || self.query_nonce == [0; 32]
        {
            return Err(invalid("invalid topology update scope"));
        }
        match &self.sync {
            TopologySync::Full { cursor, advertisements } => {
                if *cursor > i64::MAX as u64 || advertisements.len() > MAX_ADVERTISEMENTS {
                    return Err(invalid("topology snapshot exceeds its budget"));
                }
                let mut nodes = BTreeSet::new();
                let mut peers = BTreeSet::new();
                for signed in advertisements {
                    signed.validate()?;
                    let ad = TopologyAdvertisement::decode_canonical(&signed.claims)?;
                    self.check_report_scope(&ad.report)?;
                    if !nodes.insert(ad.report.node_id) || !peers.insert(ad.report.peer) {
                        return Err(invalid("duplicate topology snapshot publisher"));
                    }
                }
            }
            TopologySync::Delta { after_cursor, cursor, has_more, changes } => {
                if *cursor > i64::MAX as u64
                    || after_cursor > cursor
                    || changes.len() > MAX_DELTA
                    || (changes.is_empty() && (*cursor != *after_cursor || *has_more))
                {
                    return Err(invalid("invalid topology delta cursor or budget"));
                }
                let mut previous = *after_cursor;
                for entry in changes {
                    if entry.cursor <= previous || entry.cursor > *cursor {
                        return Err(invalid("out-of-order topology delta"));
                    }
                    match &entry.change {
                        TopologyChange::Upsert(signed) => {
                            signed.validate()?;
                            let ad = TopologyAdvertisement::decode_canonical(&signed.claims)?;
                            self.check_report_scope(&ad.report)?;
                        }
                        TopologyChange::Withdraw(withdrawal) => withdrawal.validate()?,
                    }
                    previous = entry.cursor;
                }
                if previous != *cursor {
                    return Err(invalid("topology delta cursor skips its last entry"));
                }
            }
        }
        Ok(())
    }
    fn check_report_scope(&self, report: &TopologyReport) -> Result<(), ContractError> {
        if report.deployment_id != self.deployment_id
            || report.space_id != self.space_id
            || report.policy_epoch != self.policy_epoch
        {
            return Err(invalid("topology update contains another scope"));
        }
        Ok(())
    }
}
signed!(SignedTopologyUpdate, TopologyUpdate, MAX_UPDATE_BYTES);

macro_rules! codec {
    ($name:ty, $maximum:expr) => {
        impl $name {
            pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
                self.validate()?;
                canonical(self, $maximum)
            }
            pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ContractError> {
                let value: Self = decode(bytes, $maximum)?;
                if value.canonical_bytes()? != bytes {
                    return Err(invalid("noncanonical topology claims"));
                }
                Ok(value)
            }
        }
    };
}
codec!(TopologyPublisherClaims, MAX_REPORT_BYTES);
codec!(TopologyReport, MAX_REPORT_BYTES);
codec!(TopologyAdvertisement, MAX_ADVERTISEMENT_BYTES);
codec!(TopologyUpdate, MAX_UPDATE_BYTES);

fn canonical<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, ContractError> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid("topology serialization failed"))?;
    if bytes.len() > maximum {
        return Err(ContractError::new(ErrorCode::CapacityExceeded, "topology byte budget exceeded"));
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned>(bytes: &[u8], maximum: usize) -> Result<T, ContractError> {
    if bytes.len() > maximum {
        return Err(ContractError::new(ErrorCode::CapacityExceeded, "topology byte budget exceeded"));
    }
    serde_json::from_slice(bytes).map_err(|_| invalid("malformed topology claims"))
}
fn validate_prefixes(prefixes: &[IpPrefix]) -> Result<(), ContractError> {
    if prefixes.len() > MAX_PREFIXES
        || prefixes.windows(2).any(|p| {
            (p[0].network, p[0].prefix_len) >= (p[1].network, p[1].prefix_len)
        })
    {
        return Err(invalid("invalid topology prefix set"));
    }
    for prefix in prefixes {
        prefix.validate()?;
    }
    Ok(())
}
fn schema(version: u32) -> Result<(), ContractError> {
    if version != SCHEMA_VERSION {
        return Err(ContractError::new(ErrorCode::ProtocolMismatch, "unsupported topology schema"));
    }
    Ok(())
}
fn lifetime(start: u64, end: u64) -> Result<(), ContractError> {
    if start == 0
        || end > i64::MAX as u64
        || end.checked_sub(start).is_none_or(|ttl| ttl == 0 || ttl > MAX_TTL_MS)
    {
        return Err(invalid("invalid topology lifetime"));
    }
    Ok(())
}
fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}
