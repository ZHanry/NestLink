//! Complete ordered two-relay authorization. No hop can replace its neighbor.
use super::*;
use crate::VerifiedPermit;
use nestlink_protocol::network_datagram_v2::{Direction, PATH_EPOCH};

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
