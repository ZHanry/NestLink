//! Private service network authority stays separate from remote-control permits.
use super::*;
use crate::services::private::VerifiedPrivateServiceLease;
use nestlink_protocol::{
    network_datagram,
    service_plane::{SERVICE_USAGE_BYTES, ServiceUsageBudgetGrantClaims, decode_service_message},
};

fn denied() -> ContractError {
    ContractError::new(
        ErrorCode::PermissionRequired,
        "private service network path refused",
    )
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateServiceRouteBinding {
    pub digest: [u8; 32],
    pub peers: PeerPair,
    pub relay: PeerId,
    pub byte_limit: u64,
    pub expires_at_ms: u64,
}
/// Purpose-specific verification constructs the original common NRD2 geometry;
/// relay forwarding and physical ownership keep using that mature chain type.
pub type PrivateServiceChainBinding = RelayChainBinding;

pub fn private_service_path_peers(
    context: &NetworkVerification<'_>,
    path: &VerifiedNetworkPath,
    connectivity: &VerifiedNetworkGrant,
    business: &VerifiedPrivateServiceLease,
) -> Result<PeerPair, ContractError> {
    business.check_time(context.now_ms)?;
    path.check_current(context)?;
    connectivity.check_current(context)?;
    let GrantClaims::Connectivity(connection) = connectivity.claims() else {
        return Err(denied());
    };
    let c = business.claims();
    let base = business.lease().claims();
    let peers = PeerPair::new(
        PeerId::from_public_key(&c.consumer_public_key),
        PeerId::from_public_key(&c.host_public_key),
    )?;
    if context.authority_key != &c.network_authority_key
        || context.space_id != c.space_id
        || context.policy_epoch != c.space_policy_epoch
        || context.deployment_id != base.deployment_id
        || path.purpose() != Purpose::PrivateService
        || connection.purpose != Purpose::PrivateService
        || path.peers() != peers
        || connection.peers != peers
        || path.claims().connectivity_grant_digest != connectivity.digest()
        || connection.business_grant_digest != business.digest()
        || path.claims().scope.not_before_ms < base.issued_at_unix_ms
        || path.claims().scope.expires_at_ms > base.expires_at_unix_ms
    {
        return Err(denied());
    }
    for member in &path.memberships {
        let member = member.claims();
        let expected = if member.installation_id == c.consumer_device_id {
            (c.consumer_public_key, c.consumer_membership_epoch)
        } else if member.installation_id == base.definition.host_device_id {
            (c.host_public_key, c.host_membership_epoch)
        } else {
            return Err(denied());
        };
        if member.public_key != expected.0 || member.membership_epoch != expected.1 {
            return Err(denied());
        }
    }
    Ok(peers)
}
pub fn private_service_route_binding(
    context: &NetworkVerification<'_>,
    path: &VerifiedNetworkPath,
    connectivity: &VerifiedNetworkGrant,
    transit: &VerifiedNetworkGrant,
    business: &VerifiedPrivateServiceLease,
) -> Result<PrivateServiceRouteBinding, ContractError> {
    let peers = private_service_path_peers(context, path, connectivity, business)?;
    transit.check_current(context)?;
    let GrantClaims::Transit(forward) = transit.claims() else {
        return Err(denied());
    };
    path.check_route(context, &[forward.relay])?;
    let usage: ServiceUsageBudgetGrantClaims = decode_service_message(
        &business.lease().claims().usage_grant.claims,
        SERVICE_USAGE_BYTES,
    )?;
    if forward.peers != peers
        || forward.transport_group != path.transport_group_id()
        || forward.previous != peers.first
        || forward.next != peers.second
        || forward.remaining_hops != 1
        || forward.scope.not_before_ms < path.claims().scope.not_before_ms
        || forward.scope.expires_at_ms > path.claims().scope.expires_at_ms
        || forward.byte_limit > usage.byte_ceiling
    {
        return Err(denied());
    }
    let mut message = b"NestLink/private-service/v1/network-route\0".to_vec();
    for value in [
        path.transport_group_id(),
        connectivity.digest(),
        transit.digest(),
        business.digest(),
    ] {
        message.extend_from_slice(&value);
    }
    message.extend_from_slice(&network_datagram::PATH_EPOCH.to_be_bytes());
    Ok(PrivateServiceRouteBinding {
        digest: digest(&message),
        peers,
        relay: forward.relay,
        byte_limit: forward.byte_limit,
        expires_at_ms: forward.scope.expires_at_ms,
    })
}

/// The full ordered TransitGrant set is bound to this private business grant,
/// its independent network signer and the original shared service allowance.
/// A single hop, a reordered set or a remote-control permit grants no route.
pub fn private_service_chain_binding(
    context: &NetworkVerification<'_>,
    path: &VerifiedNetworkPath,
    connectivity: &VerifiedNetworkGrant,
    transits: &[VerifiedNetworkGrant],
    business: &VerifiedPrivateServiceLease,
) -> Result<PrivateServiceChainBinding, ContractError> {
    let [first, second] = transits else {
        return Err(denied());
    };
    let peers = private_service_path_peers(context, path, connectivity, business)?;
    first.check_current(context)?;
    second.check_current(context)?;
    let (GrantClaims::Transit(a), GrantClaims::Transit(b)) = (first.claims(), second.claims())
    else {
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
    let usage: ServiceUsageBudgetGrantClaims = decode_service_message(
        &business.lease().claims().usage_grant.claims,
        SERVICE_USAGE_BYTES,
    )?;
    for grant in [a, b] {
        if grant.peers != peers
            || grant.transport_group != path.transport_group_id()
            || grant.scope.not_before_ms < path.claims().scope.not_before_ms
            || grant.scope.expires_at_ms > path.claims().scope.expires_at_ms
            || grant.scope.grant_id == path.claims().scope.grant_id
            || grant.scope.grant_id == connectivity.claims().scope().grant_id
            || grant.byte_limit > usage.byte_ceiling
        {
            return Err(denied());
        }
    }
    let mut message = b"NestLink/private-service/v2/network-chain\0".to_vec();
    message.extend_from_slice(&path.transport_group_id());
    message.extend_from_slice(&connectivity.digest());
    message.extend_from_slice(&2u32.to_be_bytes());
    for grant in transits {
        message.extend_from_slice(&grant.digest());
    }
    message.extend_from_slice(&business.digest());
    message.extend_from_slice(&network_datagram::PATH_EPOCH.to_be_bytes());
    Ok(PrivateServiceChainBinding {
        digest: digest(&message),
        peers,
        relays: [a.relay, b.relay],
        byte_limit: a.byte_limit.min(b.byte_limit),
        expires_at_ms: a.scope.expires_at_ms.min(b.scope.expires_at_ms),
    })
}
