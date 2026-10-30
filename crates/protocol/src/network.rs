//! Independently versioned network grants. These never reinterpret v15 permits.
//!
//! Parsing a claim does not authenticate it or authorize any business channel.
//! Signature verification and live policy/epoch checks belong to identity/policy.
use crate::{ContractError, ErrorCode, valid_id};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

pub const SCHEMA_VERSION: u32 = 1;
pub const CLAIM_BYTES: usize = 16_384;
pub const MAX_RELAYS: usize = 16;
pub const MAX_HOPS: u8 = 2;
pub const MAX_PREFIXES: usize = 32;
pub const MAX_RULES: usize = 64;
pub const CORE_CAPABILITY: &str = "network-core-v1";
pub const MIGRATION_CAPABILITY: &str = "path-migration-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityOffer {
    pub schema_version: u32,
    pub supported: Vec<String>,
    pub required: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiatedProtocol {
    LegacyV15,
    NetworkV1 { path_migration: bool },
}

impl CapabilityOffer {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "unsupported network capability schema",
            ));
        }
        for list in [&self.supported, &self.required] {
            if list.len() > 32
                || list.windows(2).any(|names| names[0] >= names[1])
                || list.iter().any(|name| {
                    name.is_empty()
                        || name.len() > 64
                        || !name.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                })
            {
                return Err(invalid(
                    "capability names must be bounded, unique and sorted",
                ));
            }
        }
        if self
            .required
            .iter()
            .any(|name| self.supported.binary_search(name).is_err())
            || (self
                .supported
                .iter()
                .any(|name| name == MIGRATION_CAPABILITY)
                && !self.supported.iter().any(|name| name == CORE_CAPABILITY))
        {
            return Err(invalid(
                "required capability is not supported or migration lacks a network contract",
            ));
        }
        Ok(())
    }
}

/// Call on authenticated offers. An unavailable required capability is an error,
/// never permission to fall back after a failed new-protocol handshake.
pub fn negotiate(
    local: &CapabilityOffer,
    remote: &CapabilityOffer,
) -> Result<NegotiatedProtocol, ContractError> {
    local.validate()?;
    remote.validate()?;
    for required in local.required.iter().chain(&remote.required) {
        if !matches!(required.as_str(), CORE_CAPABILITY | MIGRATION_CAPABILITY)
            || local.supported.binary_search(required).is_err()
            || remote.supported.binary_search(required).is_err()
        {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "required network capability is unavailable",
            ));
        }
    }
    let both = |name| {
        local.supported.iter().any(|value| value == name)
            && remote.supported.iter().any(|value| value == name)
    };
    if both(CORE_CAPABILITY) {
        Ok(NegotiatedProtocol::NetworkV1 {
            path_migration: both(MIGRATION_CAPABILITY),
        })
    } else {
        Ok(NegotiatedProtocol::LegacyV15)
    }
}

fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        Self(Sha256::digest(public_key).into())
    }

    pub fn validate(self) -> Result<(), ContractError> {
        if self.0 == [0; 32] {
            return Err(invalid("empty peer identity"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPair {
    pub first: PeerId,
    pub second: PeerId,
}

impl PeerPair {
    pub fn new(a: PeerId, b: PeerId) -> Result<Self, ContractError> {
        let pair = Self {
            first: a.min(b),
            second: a.max(b),
        };
        pair.validate()?;
        Ok(pair)
    }

    pub fn validate(self) -> Result<(), ContractError> {
        self.first.validate()?;
        self.second.validate()?;
        if self.first >= self.second {
            return Err(invalid("peer pair must be distinct and canonical"));
        }
        Ok(())
    }

    pub fn contains(self, peer: PeerId) -> bool {
        peer == self.first || peer == self.second
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantScope {
    pub schema_version: u32,
    pub deployment_id: String,
    pub space_id: String,
    pub grant_id: String,
    pub policy_epoch: u64,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
}

impl GrantScope {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "unknown network grant schema",
            ));
        }
        if [&self.deployment_id, &self.space_id, &self.grant_id]
            .iter()
            .any(|id| !valid_id(id))
            || self.policy_epoch == 0
            || self.not_before_ms == 0
            || self.expires_at_ms <= self.not_before_ms
        {
            return Err(invalid("invalid network grant scope or lifetime"));
        }
        Ok(())
    }

    pub fn valid_at(&self, now_ms: u64) -> bool {
        self.not_before_ms <= now_ms && now_ms < self.expires_at_ms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceRole {
    Owner,
    Admin,
    Member,
    Guest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    RemoteControl,
    PrivateService,
    PublicService,
    NetworkPacket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipClaims {
    pub scope: GrantScope,
    pub installation_id: String,
    pub peer: PeerId,
    pub public_key: [u8; 32],
    pub membership_epoch: u64,
    pub role: SpaceRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectivityClaims {
    pub scope: GrantScope,
    pub peers: PeerPair,
    pub purpose: Purpose,
    /// Membership digests follow the canonical first/second peer order.
    pub membership_digests: [[u8; 32]; 2],
    /// SessionPermit, ServiceLease or NetworkAccessGrant, according to purpose.
    pub business_grant_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathPolicy {
    pub allow_direct: bool,
    /// Strictly increasing authenticated relay identities; never arbitrary URLs.
    pub relays: Vec<PeerId>,
    pub max_hops: u8,
}

impl PathPolicy {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.relays.len() > MAX_RELAYS
            || self.max_hops > MAX_HOPS
            || (self.relays.is_empty() != (self.max_hops == 0))
            || (!self.allow_direct && self.relays.is_empty())
            || self.relays.windows(2).any(|peers| peers[0] >= peers[1])
        {
            return Err(invalid("invalid or noncanonical path policy"));
        }
        for relay in &self.relays {
            relay.validate()?;
        }
        Ok(())
    }

    pub fn allows(&self, peers: PeerPair, route: &[PeerId]) -> bool {
        self.validate().is_ok()
            && peers.validate().is_ok()
            && if route.is_empty() {
                self.allow_direct
            } else {
                route.len() <= usize::from(self.max_hops)
                    && route.iter().enumerate().all(|(i, relay)| {
                        !peers.contains(*relay)
                            && self.relays.binary_search(relay).is_ok()
                            && !route[..i].contains(relay)
                    })
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathClaims {
    pub scope: GrantScope,
    pub peers: PeerPair,
    pub purpose: Purpose,
    pub connectivity_grant_digest: [u8; 32],
    pub policy: PathPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitClaims {
    pub scope: GrantScope,
    pub peers: PeerPair,
    pub transport_group: [u8; 32],
    pub route_id: String,
    pub relay: PeerId,
    pub previous: PeerId,
    pub next: PeerId,
    pub remaining_hops: u8,
    pub byte_limit: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpPrefix {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl IpPrefix {
    pub fn validate(self) -> Result<(), ContractError> {
        crate::api::ServiceSourceNetwork {
            address: self.network.to_string(),
            prefix: self.prefix_len,
        }
        .validate()?;
        if self.prefix_len == 0
            || self.network.is_unspecified()
            || self.network.is_loopback()
            || self.network.is_multicast()
        {
            return Err(invalid(
                "prefix must be canonical and cannot export a default route",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteExportClaims {
    pub scope: GrantScope,
    pub gateway: PeerId,
    pub prefixes: Vec<IpPrefix>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpProtocol {
    Tcp,
    Udp,
    IcmpV4,
    IcmpV6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    pub protocol: IpProtocol,
    pub direction: Direction,
    pub ports: Option<[u16; 2]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAccessClaims {
    pub scope: GrantScope,
    pub source: PeerId,
    pub destination: PeerId,
    pub source_prefixes: Vec<IpPrefix>,
    pub destination_prefixes: Vec<IpPrefix>,
    pub rules: Vec<NetworkRule>,
    pub byte_limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "claims",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum GrantClaims {
    Membership(MembershipClaims),
    Connectivity(ConnectivityClaims),
    Path(PathClaims),
    Transit(TransitClaims),
    RouteExport(RouteExportClaims),
    NetworkAccess(NetworkAccessClaims),
}

fn require_digest(digest: &[u8; 32]) -> Result<(), ContractError> {
    if *digest == [0; 32] {
        return Err(invalid("empty authorization digest"));
    }
    Ok(())
}

fn prefixes(values: &[IpPrefix]) -> Result<(), ContractError> {
    if values.is_empty() || values.len() > MAX_PREFIXES {
        return Err(invalid("invalid prefix count"));
    }
    for (i, value) in values.iter().enumerate() {
        value.validate()?;
        if values[..i].contains(value) {
            return Err(invalid("duplicate prefix"));
        }
    }
    Ok(())
}

impl GrantClaims {
    pub fn scope(&self) -> &GrantScope {
        match self {
            Self::Membership(c) => &c.scope,
            Self::Connectivity(c) => &c.scope,
            Self::Path(c) => &c.scope,
            Self::Transit(c) => &c.scope,
            Self::RouteExport(c) => &c.scope,
            Self::NetworkAccess(c) => &c.scope,
        }
    }

    pub fn domain(&self) -> &'static [u8] {
        match self {
            Self::Membership(_) => b"NestLink/network/v1/membership\0",
            Self::Connectivity(_) => b"NestLink/network/v1/connectivity\0",
            Self::Path(_) => b"NestLink/network/v1/path\0",
            Self::Transit(_) => b"NestLink/network/v1/transit\0",
            Self::RouteExport(_) => b"NestLink/network/v1/route-export\0",
            Self::NetworkAccess(_) => b"NestLink/network/v1/network-access\0",
        }
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        self.scope().validate()?;
        match self {
            Self::Membership(c) => {
                if !valid_id(&c.installation_id)
                    || c.membership_epoch == 0
                    || c.public_key == [0; 32]
                    || c.peer != PeerId::from_public_key(&c.public_key)
                {
                    return Err(invalid(
                        "membership must bind the installation and device key",
                    ));
                }
                c.peer.validate()?;
            }
            Self::Connectivity(c) => {
                c.peers.validate()?;
                for digest in &c.membership_digests {
                    require_digest(digest)?;
                }
                require_digest(&c.business_grant_digest)?;
            }
            Self::Path(c) => {
                c.peers.validate()?;
                require_digest(&c.connectivity_grant_digest)?;
                c.policy.validate()?;
                if c.policy.relays.iter().any(|relay| c.peers.contains(*relay)) {
                    return Err(invalid("an endpoint cannot be its own relay"));
                }
            }
            Self::Transit(c) => {
                c.peers.validate()?;
                require_digest(&c.transport_group)?;
                for peer in [c.relay, c.previous, c.next] {
                    peer.validate()?;
                }
                if !valid_id(&c.route_id)
                    || c.peers.contains(c.relay)
                    || c.relay == c.previous
                    || c.relay == c.next
                    || c.previous == c.next
                    || c.remaining_hops == 0
                    || c.remaining_hops > MAX_HOPS
                    || c.byte_limit == 0
                {
                    return Err(invalid("invalid authenticated transit adjacency"));
                }
            }
            Self::RouteExport(c) => {
                c.gateway.validate()?;
                prefixes(&c.prefixes)?;
            }
            Self::NetworkAccess(c) => {
                PeerPair::new(c.source, c.destination)?;
                prefixes(&c.source_prefixes)?;
                prefixes(&c.destination_prefixes)?;
                if c.rules.is_empty() || c.rules.len() > MAX_RULES || c.byte_limit == 0 {
                    return Err(invalid(
                        "network access needs bounded explicit rules and quota",
                    ));
                }
                for (i, rule) in c.rules.iter().enumerate() {
                    let valid = match (rule.protocol, rule.ports) {
                        (IpProtocol::Tcp | IpProtocol::Udp, Some([first, last])) => {
                            first != 0 && first <= last
                        }
                        (IpProtocol::IcmpV4 | IpProtocol::IcmpV6, None) => true,
                        _ => false,
                    };
                    if !valid || c.rules[..i].contains(rule) {
                        return Err(invalid("invalid network protocol/port rule"));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| invalid("network grant serialization failed"))?;
        if bytes.len() > CLAIM_BYTES {
            return Err(invalid("network grant exceeds its byte budget"));
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > CLAIM_BYTES {
            return Err(invalid("network grant exceeds its byte budget"));
        }
        let claims: Self =
            serde_json::from_slice(bytes).map_err(|_| invalid("malformed network grant"))?;
        if claims.canonical_bytes()? != bytes {
            return Err(invalid("noncanonical network grant"));
        }
        Ok(claims)
    }

    pub fn signing_message(&self) -> Result<Vec<u8>, ContractError> {
        let bytes = self.canonical_bytes()?;
        let length = u32::try_from(bytes.len())
            .map_err(|_| invalid("network grant exceeds its byte budget"))?;
        let mut message = self.domain().to_vec();
        message.extend_from_slice(&length.to_be_bytes());
        message.extend_from_slice(&bytes);
        Ok(message)
    }

    /// Exact signed PathGrant identity, scope, purpose and peers isolate groups.
    /// This helper does not authenticate the grant. Only verified callers may use it.
    pub fn unverified_transport_group_digest(&self) -> Result<[u8; 32], ContractError> {
        if !matches!(self, Self::Path(_)) {
            return Err(invalid("transport groups require a PathGrant"));
        }
        let mut transcript = b"NestLink/network/v1/transport-group\0".to_vec();
        transcript.extend_from_slice(&self.signing_message()?);
        Ok(Sha256::digest(transcript).into())
    }
}
