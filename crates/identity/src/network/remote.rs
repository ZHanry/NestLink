//! Shared remote route chain verification for endpoints and resource consumers.
use super::*;
use crate::{VerifiedPermit, relay::session_binding, verify_permit};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_protocol::{
    NodeNetworkRelayResource, Path,
    api::{NetworkGrantView, NetworkRemoteRelayView},
    network::SCHEMA_VERSION,
    network_datagram,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RemoteRouteBinding {
    pub digest: [u8; 32],
    pub peers: PeerPair,
    pub relay: PeerId,
    pub byte_limit: u64,
    pub expires_at_ms: u64,
}
fn denied() -> ContractError {
    ContractError::new(
        ErrorCode::PermissionRequired,
        "network remote route refused",
    )
}

pub fn remote_route_binding(
    context: &NetworkVerification<'_>,
    path: &VerifiedNetworkPath,
    connectivity: &VerifiedNetworkGrant,
    transit: &VerifiedNetworkGrant,
    permit: &VerifiedPermit,
) -> Result<RemoteRouteBinding, ContractError> {
    let peers = remote_path_peers(context, path, connectivity, permit)?;
    transit.check_current(context)?;
    let GrantClaims::Transit(forward) = transit.claims() else {
        return Err(denied());
    };
    path.check_route(context, &[forward.relay])?;
    if forward.peers != peers
        || forward.transport_group != path.transport_group_id()
        || forward.previous != peers.first
        || forward.next != peers.second
        || forward.remaining_hops != 1
        || forward.scope.not_before_ms < path.claims().scope.not_before_ms
        || forward.scope.expires_at_ms > path.claims().scope.expires_at_ms
    {
        return Err(denied());
    }
    Ok(RemoteRouteBinding {
        digest: remote_route_binding_digest(
            path.transport_group_id(),
            connectivity.digest(),
            transit.digest(),
            permit.digest(),
            permit.claims().connection_generation,
        ),
        peers,
        relay: forward.relay,
        byte_limit: forward.byte_limit,
        expires_at_ms: forward.scope.expires_at_ms,
    })
}
/// Canonical binding projection shared by endpoint and management validation.
/// These digests are metadata; callers must separately verify all authorities.
pub fn remote_route_binding_digest(
    transport_group: [u8; 32],
    connectivity: [u8; 32],
    transit: [u8; 32],
    permit: [u8; 32],
    generation: u64,
) -> [u8; 32] {
    let mut transcript = b"NestLink/network-datagram/v1/route-binding\0".to_vec();
    transcript.extend_from_slice(&transport_group);
    transcript.extend_from_slice(&connectivity);
    transcript.extend_from_slice(&transit);
    transcript.extend_from_slice(&permit);
    transcript.extend_from_slice(&generation.to_be_bytes());
    transcript.extend_from_slice(&network_datagram::PATH_EPOCH.to_be_bytes());
    digest(&transcript)
}

pub(super) fn remote_path_peers(
    context: &NetworkVerification<'_>,
    path: &VerifiedNetworkPath,
    connectivity: &VerifiedNetworkGrant,
    permit: &VerifiedPermit,
) -> Result<PeerPair, ContractError> {
    path.check_current(context)?;
    connectivity.check_current(context)?;
    let GrantClaims::Connectivity(connection) = connectivity.claims() else {
        return Err(denied());
    };
    let business = permit.claims();
    let peers = PeerPair::new(
        PeerId(
            business
                .controller_key_sha256
                .as_slice()
                .try_into()
                .map_err(|_| denied())?,
        ),
        PeerId(
            business
                .host_key_sha256
                .as_slice()
                .try_into()
                .map_err(|_| denied())?,
        ),
    )?;
    if path.purpose() != Purpose::RemoteControl
        || connection.purpose != Purpose::RemoteControl
        || connection.peers != peers
        || path.peers() != peers
        || connectivity.digest() != path.claims().connectivity_grant_digest
        || connection.business_grant_digest != permit.digest()
        || business.deployment_id != context.deployment_id
        || !business.paths.contains(&(Path::Relay as i32))
        || business.issued_at_unix_ms > context.now_ms
        || business.expires_at_unix_ms <= context.now_ms
        || path.claims().scope.not_before_ms < business.issued_at_unix_ms
        || path.claims().scope.expires_at_ms > business.expires_at_unix_ms
    {
        return Err(denied());
    }
    Ok(peers)
}

pub(super) fn signed(view: &NetworkGrantView) -> Result<SignedNetworkGrant, ContractError> {
    let decode = |s: &str| -> Result<Vec<u8>, ContractError> {
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| denied())?;
        if URL_SAFE_NO_PAD.encode(&bytes) != s {
            return Err(denied());
        }
        Ok(bytes)
    };
    let signed = SignedNetworkGrant {
        claims: decode(&view.claims)?,
        signature: decode(&view.signature)?,
    };
    let claims = GrantClaims::decode_canonical(&signed.claims)?;
    if view.schema_version != SCHEMA_VERSION || view.grant_id != claims.scope().grant_id {
        return Err(denied());
    }
    Ok(signed)
}

/// The resource MUST already have passed the exact-query node-policy signature
/// verifier. That fresh signed snapshot supplies the authority pin and current
/// member/runtime facts; no credential supplied by a socket is a trust anchor.
pub fn verify_node_network_resource(
    resource: &NodeNetworkRelayResource,
    allocation_issuer: &[u8; 32],
    now_ms: u64,
) -> Result<RemoteRouteBinding, ContractError> {
    if resource.network_schema_version != 1
        || !resource.chain_bundle_json.is_empty()
        || !resource.private_service_bundle_json.is_empty()
    {
        return Err(denied());
    }
    let allocation = resource.allocation.as_ref().ok_or_else(denied)?;
    allocation.validate()?;
    let authority: [u8; 32] = resource
        .network_authority_key
        .as_slice()
        .try_into()
        .map_err(|_| denied())?;
    let view: NetworkRemoteRelayView =
        serde_json::from_slice(&resource.relay_bundle_json).map_err(|_| denied())?;
    view.node.endpoints.validate()?;
    let permit = verify_permit(&resource.business_permit, allocation_issuer)?;
    let c = permit.claims();
    let path_signed = signed(&view.path.path)?;
    let path_claims = GrantClaims::decode_canonical(&path_signed.claims)?;
    let scope = path_claims.scope();
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &authority,
        deployment_id: &allocation.deployment_id,
        space_id: &scope.space_id,
        policy_epoch: scope.policy_epoch,
        now_ms,
        revoked_grant_ids: &revoked,
    };
    let (path, connectivity) = resource_path(&view.path, &context, &permit)?;
    let transit = verify_network_grant(&signed(&view.transit)?, &context)?;
    let binding = remote_route_binding(&context, &path, &connectivity, &transit, &permit)?;
    let GrantClaims::Transit(forward) = transit.claims() else {
        return Err(denied());
    };
    if view.allocation_id != allocation.allocation_id
        || forward.route_id != allocation.allocation_id
        || view.path.request_id != c.session_id
        || allocation.session_id != c.session_id
        || view.node.node_id != allocation.node_id
        || view.node.revision != allocation.node_endpoint_revision
        || binding.relay.0.as_slice() != allocation.node_key_sha256.as_slice()
        || binding.byte_limit != allocation.bytes_per_allocation
        || allocation.security_epoch != c.security_epoch
        || allocation.policy_revision != c.policy_revision
        || allocation.connection_generation != c.connection_generation
        || allocation.controller_device_id != c.controller_device_id
        || allocation.host_device_id != c.host_device_id
        || allocation.controller_key_sha256 != c.controller_key_sha256
        || allocation.host_key_sha256 != c.host_key_sha256
        || allocation.controller_account_id != c.account_id
        || allocation.session_binding_sha256 != session_binding(c)?
        || allocation.issued_at_unix_ms != forward.scope.not_before_ms
        || allocation.expires_at_unix_ms != binding.expires_at_ms
        || allocation.transports != [nestlink_protocol::RelayTransport::QuicDatagram as i32]
        || allocation.grant_sequence != 1
    {
        return Err(denied());
    }
    Ok(binding)
}

/// Reuse the identical full membership/connectivity/business verification for
/// both wire versions. The fresh snapshot, not socket input, pins the context.
pub(super) fn resource_path(
    view: &nestlink_protocol::api::NetworkRemotePathView,
    context: &NetworkVerification<'_>,
    permit: &VerifiedPermit,
) -> Result<(VerifiedNetworkPath, VerifiedNetworkGrant), ContractError> {
    let c = permit.claims();
    let member = |view: &NetworkGrantView,
                  device: &str,
                  key: &[u8]|
     -> Result<VerifiedMembership, ContractError> {
        let grant = verify_network_grant(&signed(view)?, context)?;
        let GrantClaims::Membership(claims) = grant.claims() else {
            return Err(denied());
        };
        if digest(&claims.public_key).as_slice() != key {
            return Err(denied());
        }
        let public_key = claims.public_key;
        let epoch = claims.membership_epoch;
        VerifiedMembership::from_grant(grant, context, device, &public_key, epoch)
    };
    let members = [
        member(
            &view.controller_membership,
            &c.controller_device_id,
            &c.controller_key_sha256,
        )?,
        member(&view.host_membership, &c.host_device_id, &c.host_key_sha256)?,
    ];
    let connectivity = verify_network_grant(&signed(&view.connectivity)?, context)?;
    let path = VerifiedNetworkPath::from_grants(
        context,
        members,
        connectivity.clone(),
        verify_network_grant(&signed(&view.path)?, context)?,
        permit.digest(),
    )?;
    Ok((path, connectivity))
}
