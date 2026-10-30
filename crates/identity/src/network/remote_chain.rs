//! Complete ordered two-relay authorization. No hop can replace its neighbor.
use super::*;
use crate::VerifiedPermit;
use nestlink_protocol::network_datagram_v2::{Direction, PATH_EPOCH};

fn chain_admission_transcript(
    allocation: &str, binding: &[u8;32], relay: PeerId,
    public_key: &[u8;32], nonce: &[u8;32],
) -> Result<Vec<u8>,ContractError> {
    relay.validate()?;
    if !nestlink_protocol::valid_id(allocation) || *binding == [0;32]
        || *nonce == [0;32] || relay == PeerId::from_public_key(public_key)
    { return Err(denied()); }
    let mut bytes = b"NestLink/network-datagram/v2/neighbor-admission\0".to_vec();
    bytes.extend_from_slice(&(allocation.len() as u32).to_be_bytes());
    bytes.extend_from_slice(allocation.as_bytes());
    bytes.extend_from_slice(binding);
    bytes.extend_from_slice(&relay.0);
    bytes.extend_from_slice(public_key);
    bytes.extend_from_slice(nonce);
    Ok(bytes)
}
impl crate::InstallationIdentity {
    pub fn sign_network_chain_admission(
        &self, allocation: &str, binding: &[u8;32], relay: PeerId, nonce: &[u8;32],
    ) -> Result<[u8;64],ContractError> {
        Ok(self.key.sign(&chain_admission_transcript(allocation,binding,relay,&self.public_key(),nonce)?).to_bytes())
    }
}
impl crate::nodes::NodeIdentity {
    pub fn sign_network_chain_admission(
        &self, allocation: &str, binding: &[u8;32], relay: PeerId, nonce: &[u8;32],
    ) -> Result<[u8;64],ContractError> {
        Ok(self.key.sign(&chain_admission_transcript(allocation,binding,relay,&self.public_key(),nonce)?).to_bytes())
    }
}
pub fn verify_network_chain_admission(
    allocation: &str, binding: &[u8;32], relay: PeerId,
    public_key: &[u8;32], nonce: &[u8;32], signature: &[u8],
) -> Result<(),ContractError> {
    VerifyingKey::from_bytes(public_key).map_err(|_| denied())?
        .verify_strict(&chain_admission_transcript(allocation,binding,relay,public_key,nonce)?,
            &Signature::from_slice(signature).map_err(|_| denied())?)
        .map_err(|_|denied())
}

/// Domain-separated endpoint consent for a complete ordered reservation. The
/// signature field is excluded; every other request field is bound, including
/// both topology references and the exact member/path identifiers and expiry.
pub fn remote_chain_reservation_transcript(
    business: &nestlink_protocol::PermitClaims,
    account: &str,
    space: &str,
    request: &nestlink_protocol::api::NetworkRemoteRelayChainRequest,
) -> Result<nestlink_protocol::DeviceActionClaims, ContractError> {
    business.validate()?;
    let path = &request.path;
    let ids = [
        account, space, request.route_id.as_str(), request.device_id.as_str(),
        path.connectivity_grant_id.as_str(), path.path_grant_id.as_str(),
        path.controller_membership_grant_id.as_str(), path.host_membership_grant_id.as_str(),
        request.node_ids[0].as_str(), request.node_ids[1].as_str(),
        request.transit_grant_ids[0].as_str(), request.transit_grant_ids[1].as_str(),
    ];
    if ids.iter().any(|id| !nestlink_protocol::valid_id(id))
        || request.node_ids[0] == request.node_ids[1]
        || request.transit_grant_ids[0] == request.transit_grant_ids[1]
        || request.topology_digests.contains(&[0; 32])
        || path.expected_policy_epoch == 0
        || path.expires_at_unix_ms <= business.issued_at_unix_ms
        || path.expires_at_unix_ms > business.expires_at_unix_ms
        || (request.device_id != business.controller_device_id
            && request.device_id != business.host_device_id)
    {
        return Err(denied());
    }
    use prost::Message;
    let mut transcript = b"NestLink/network-datagram/v2/chain-reservation\0".to_vec();
    transcript.extend_from_slice(&digest(&business.encode_to_vec()));
    for id in ids {
        transcript.extend_from_slice(&(id.len() as u32).to_be_bytes());
        transcript.extend_from_slice(id.as_bytes());
    }
    transcript.extend_from_slice(&path.expected_policy_epoch.to_be_bytes());
    transcript.extend_from_slice(&path.expires_at_unix_ms.to_be_bytes());
    for reference in request.topology_digests {
        transcript.extend_from_slice(&reference);
    }
    let mut claims = crate::relay_transcript(business, account, &request.device_id, &digest(&business.encode_to_vec()))?;
    claims.action = nestlink_protocol::DeviceAction::RelayAllocate as i32;
    claims.payload_sha256 = digest(&transcript).to_vec();
    Ok(claims)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RemoteChainBinding {
    pub digest: [u8; 32],
    pub peers: PeerPair,
    /// Ordered from the canonical first business peer to the second.
    pub relays: [PeerId; 2],
    pub byte_limit: u64,
    pub expires_at_ms: u64,
}
impl RemoteChainBinding {
    pub fn adjacency(&self, relay: PeerId) -> Option<(PeerId, PeerId)> {
        if relay == self.relays[0] {
            Some((self.peers.first, self.relays[1]))
        } else if relay == self.relays[1] {
            Some((self.relays[0], self.peers.second))
        } else {
            None
        }
    }
    pub fn remaining_hops(&self, relay: PeerId, direction: Direction) -> Option<u8> {
        let index = self.relays.iter().position(|peer| *peer == relay)?;
        Some(match direction {
            Direction::FirstToSecond => (2 - index) as u8,
            Direction::SecondToFirst => (index + 1) as u8,
        })
    }
}

/// Every participant verifies the same full ordered grant set, in addition to
/// the current business/member/path chain. Individual TransitGrants alone are
/// insufficient. Binding includes both digests, business generation and epoch.
pub fn remote_chain_binding(
    context: &NetworkVerification<'_>,
    path: &VerifiedNetworkPath,
    connectivity: &VerifiedNetworkGrant,
    transits: &[VerifiedNetworkGrant],
    permit: &VerifiedPermit,
) -> Result<RemoteChainBinding, ContractError> {
    let [first, second] = transits else {
        return Err(denied());
    };
    let peers = super::remote::remote_path_peers(context, path, connectivity, permit)?;
    first.check_current(context)?;
    second.check_current(context)?;
    let (GrantClaims::Transit(a), GrantClaims::Transit(b)) = (first.claims(), second.claims()) else {
        return Err(denied());
    };
    path.check_route(context, &[a.relay, b.relay])?;
    if a.scope.grant_id == b.scope.grant_id
        || a.route_id != b.route_id
        || a.previous != peers.first
        || a.next != b.relay
        || b.previous != a.relay
        || b.next != peers.second
        || a.remaining_hops != 2
        || b.remaining_hops != 1
    {
        return Err(denied());
    }
    for grant in [a, b] {
        if grant.peers != peers
            || grant.transport_group != path.transport_group_id()
            || grant.scope.not_before_ms < path.claims().scope.not_before_ms
            || grant.scope.expires_at_ms > path.claims().scope.expires_at_ms
            || grant.scope.grant_id == path.claims().scope.grant_id
            || grant.scope.grant_id == connectivity.claims().scope().grant_id
        {
            return Err(denied());
        }
    }
    let mut transcript = b"NestLink/network-datagram/v2/route-binding\0".to_vec();
    transcript.extend_from_slice(&path.transport_group_id());
    transcript.extend_from_slice(&connectivity.digest());
    transcript.extend_from_slice(&2u32.to_be_bytes());
    for grant in transits {
        transcript.extend_from_slice(&grant.digest());
    }
    transcript.extend_from_slice(&permit.digest());
    transcript.extend_from_slice(&permit.claims().connection_generation.to_be_bytes());
    transcript.extend_from_slice(&PATH_EPOCH.to_be_bytes());
    Ok(RemoteChainBinding {
        digest: digest(&transcript), peers, relays: [a.relay, b.relay],
        byte_limit: a.byte_limit.min(b.byte_limit),
        expires_at_ms: a.scope.expires_at_ms.min(b.scope.expires_at_ms),
    })
}
fn denied() -> ContractError {
    ContractError::new(ErrorCode::PermissionRequired, "network remote chain refused")
}

/// Verified only after the enclosing exact-query node-policy snapshot. Its
/// original allocation stays bound to the business endpoints; adjacency slots
/// belong to the two fixed neighboring peers, including the other relay.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeRemoteChainBinding {
    pub chain: RemoteChainBinding,
    pub relay: PeerId,
}
impl NodeRemoteChainBinding {
    pub fn neighbors(&self) -> [PeerId; 2] {
        // Construction below admits only one of the two ordered relays.
        if self.relay == self.chain.relays[0] {
            [self.chain.peers.first, self.chain.relays[1]]
        } else {
            [self.chain.relays[0], self.chain.peers.second]
        }
    }
}

pub fn verify_node_network_chain_resource(
    resource: &nestlink_protocol::NodeNetworkRelayResource,
    allocation_issuer: &[u8; 32],
    now_ms: u64,
) -> Result<NodeRemoteChainBinding, ContractError> {
    use nestlink_protocol::api::NetworkRemoteRelayChainView;
    use crate::{relay::session_binding, verify_permit};
    if resource.network_schema_version != 2
        || !resource.relay_bundle_json.is_empty()
        || resource.chain_bundle_json.is_empty()
        || resource.chain_bundle_json.len() > 49_152
    {
        return Err(denied());
    }
    let allocation = resource.allocation.as_ref().ok_or_else(denied)?;
    allocation.validate()?;
    let authority: [u8; 32] = resource.network_authority_key.as_slice().try_into().map_err(|_| denied())?;
    let view: NetworkRemoteRelayChainView = serde_json::from_slice(&resource.chain_bundle_json).map_err(|_| denied())?;
    for node in &view.nodes { node.endpoints.validate()?; }
    if view.nodes[0].node_id == view.nodes[1].node_id || view.topology_digests.contains(&[0; 32]) {
        return Err(denied());
    }
    let permit = verify_permit(&resource.business_permit, allocation_issuer)?;
    let business = permit.claims();
    let path_signed = super::remote::signed(&view.path.path)?;
    let path_claims = GrantClaims::decode_canonical(&path_signed.claims)?;
    let scope = path_claims.scope();
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &authority, deployment_id: &allocation.deployment_id,
        space_id: &scope.space_id, policy_epoch: scope.policy_epoch,
        now_ms, revoked_grant_ids: &revoked,
    };
    let (path, connectivity) = super::remote::resource_path(&view.path, &context, &permit)?;
    let transits = [
        verify_network_grant(&super::remote::signed(&view.transits[0])?, &context)?,
        verify_network_grant(&super::remote::signed(&view.transits[1])?, &context)?,
    ];
    let chain = remote_chain_binding(&context, &path, &connectivity, &transits, &permit)?;
    let index = view.nodes.iter().position(|node| node.node_id == allocation.node_id).ok_or_else(denied)?;
    let GrantClaims::Transit(transit) = transits[index].claims() else { return Err(denied()); };
    if allocation.allocation_id != transit.scope.grant_id
        || view.route_id != transit.route_id
        || view.path.request_id != business.session_id
        || allocation.session_id != business.session_id
        || view.nodes[index].revision != allocation.node_endpoint_revision
        || chain.relays[index].0.as_slice() != allocation.node_key_sha256.as_slice()
        || transit.byte_limit != allocation.bytes_per_allocation
        || allocation.security_epoch != business.security_epoch
        || allocation.policy_revision != business.policy_revision
        || allocation.connection_generation != business.connection_generation
        || allocation.controller_device_id != business.controller_device_id
        || allocation.host_device_id != business.host_device_id
        || allocation.controller_key_sha256 != business.controller_key_sha256
        || allocation.host_key_sha256 != business.host_key_sha256
        || allocation.controller_account_id != business.account_id
        || allocation.session_binding_sha256 != session_binding(business)?
        || allocation.issued_at_unix_ms != transit.scope.not_before_ms
        || allocation.expires_at_unix_ms != chain.expires_at_ms
        || allocation.transports != [nestlink_protocol::RelayTransport::QuicDatagram as i32]
        || allocation.grant_sequence != 1
    {
        return Err(denied());
    }
    Ok(NodeRemoteChainBinding { chain, relay: chain.relays[index] })
}
