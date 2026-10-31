//! Device consent binds the complete atomic set, not two unrelated allocations.
use super::*;
use nestlink_protocol::{
    DeviceAction, DeviceActionClaims, PermitClaims, api::NetworkRemoteRouteSetRequest,
};
use prost::Message;

/// Cryptographic verification only. The caller supplies a current trusted
/// management context; a peer response cannot supply its own authority pin.
pub struct VerifiedRemoteRouteSetGrants {
    pub path: VerifiedNetworkPath,
    pub connectivity: VerifiedNetworkGrant,
    pub transits: [VerifiedNetworkGrant; 2],
    pub bindings: [RemoteRouteBinding; 2],
}

pub fn verify_remote_route_set_grants(
    context: &NetworkVerification<'_>,
    view: &nestlink_protocol::api::NetworkRemoteRouteSetView,
    permit: &crate::VerifiedPermit,
) -> Result<VerifiedRemoteRouteSetGrants, ContractError> {
    let denied = || ContractError::new(ErrorCode::PermissionRequired, "network route set refused");
    if !nestlink_protocol::valid_id(&view.set_id)
        || view.path.request_id != permit.claims().session_id
        || view.members[0].allocation_id >= view.members[1].allocation_id
        || view.members[0].node.node_id == view.members[1].node.node_id
    {
        return Err(denied());
    }
    let (path, connectivity) = super::remote::resource_path(&view.path, context, permit)?;
    let transits = [
        verify_network_grant(&super::remote::signed(&view.members[0].transit)?, context)?,
        verify_network_grant(&super::remote::signed(&view.members[1].transit)?, context)?,
    ];
    if transits[0].digest() == transits[1].digest() {
        return Err(denied());
    }
    let mut relays = Vec::with_capacity(2);
    let mut bindings = Vec::with_capacity(2);
    for (member, transit) in view.members.iter().zip(&transits) {
        if !nestlink_protocol::valid_id(&member.allocation_id)
            || member.allocation_id == view.set_id
            || !nestlink_protocol::valid_id(&member.node.node_id)
            || member.node.revision == 0
            || member.node.endpoints.quic_uri.is_none()
        {
            return Err(denied());
        }
        member.node.endpoints.validate()?;
        let GrantClaims::Transit(claims) = transit.claims() else {
            return Err(denied());
        };
        if claims.route_id != member.allocation_id
            || claims.scope
                != (GrantScope {
                    grant_id: member.transit.grant_id.clone(),
                    ..path.claims().scope.clone()
                })
        {
            return Err(denied());
        }
        relays.push(claims.relay);
        bindings.push(remote_route_binding(
            context,
            &path,
            &connectivity,
            transit,
            permit,
        )?);
    }
    relays.sort();
    if relays[0] == relays[1]
        || path.claims().policy.allow_direct
        || path.claims().policy.max_hops != 1
        || path.claims().policy.relays != relays
    {
        return Err(denied());
    }
    Ok(VerifiedRemoteRouteSetGrants {
        path,
        connectivity,
        transits,
        bindings: bindings.try_into().map_err(|_| denied())?,
    })
}

pub fn remote_route_set_reservation_transcript(
    business: &PermitClaims,
    account: &str,
    space: &str,
    request: &NetworkRemoteRouteSetRequest,
) -> Result<DeviceActionClaims, ContractError> {
    business.validate()?;
    let path = &request.path;
    let ids = [
        account,
        space,
        request.set_id.as_str(),
        request.device_id.as_str(),
        path.connectivity_grant_id.as_str(),
        path.path_grant_id.as_str(),
        path.controller_membership_grant_id.as_str(),
        path.host_membership_grant_id.as_str(),
        request.members[0].allocation_id.as_str(),
        request.members[0].transit_grant_id.as_str(),
        request.members[0].node_id.as_str(),
        request.members[1].allocation_id.as_str(),
        request.members[1].transit_grant_id.as_str(),
        request.members[1].node_id.as_str(),
    ];
    let grants = [
        &path.connectivity_grant_id,
        &path.path_grant_id,
        &request.members[0].transit_grant_id,
        &request.members[1].transit_grant_id,
    ];
    if ids.iter().any(|id| !nestlink_protocol::valid_id(id))
        || request.members[0].allocation_id >= request.members[1].allocation_id
        || request
            .members
            .iter()
            .any(|member| member.allocation_id == request.set_id)
        || request.members[0].node_id == request.members[1].node_id
        || grants.into_iter().collect::<BTreeSet<_>>().len() != 4
        || path.expected_policy_epoch == 0
        || path.expires_at_unix_ms <= business.issued_at_unix_ms
        || path.expires_at_unix_ms > business.expires_at_unix_ms
        || (request.device_id != business.controller_device_id
            && request.device_id != business.host_device_id)
    {
        return Err(ContractError::new(
            ErrorCode::PermissionRequired,
            "network route set consent refused",
        ));
    }
    let business_digest = digest(&business.encode_to_vec());
    let mut transcript = b"NestLink/network-datagram/v1/route-set-reservation\0".to_vec();
    transcript.extend_from_slice(&business_digest);
    for id in ids {
        transcript.extend_from_slice(&(id.len() as u32).to_be_bytes());
        transcript.extend_from_slice(id.as_bytes());
    }
    transcript.extend_from_slice(&path.expected_policy_epoch.to_be_bytes());
    transcript.extend_from_slice(&path.expires_at_unix_ms.to_be_bytes());
    let mut claims =
        crate::relay_transcript(business, account, &request.device_id, &business_digest)?;
    claims.action = DeviceAction::RelayAllocate as i32;
    claims.payload_sha256 = digest(&transcript).to_vec();
    Ok(claims)
}
