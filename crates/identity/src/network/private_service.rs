//! Private service network authority stays separate from remote-control permits.
use super::*;
use crate::services::private::VerifiedPrivateServiceLease;
use nestlink_protocol::{network_datagram,service_plane::{ServiceUsageBudgetGrantClaims,
    SERVICE_USAGE_BYTES,decode_service_message}};

fn denied()->ContractError{ContractError::new(ErrorCode::PermissionRequired,"private service network path refused")}
#[derive(Clone,Copy,PartialEq,Eq)]
pub struct PrivateServiceRouteBinding{
    pub digest:[u8;32],pub peers:PeerPair,pub relay:PeerId,pub byte_limit:u64,pub expires_at_ms:u64,
}

pub fn private_service_path_peers(context:&NetworkVerification<'_>,path:&VerifiedNetworkPath,
    connectivity:&VerifiedNetworkGrant,business:&VerifiedPrivateServiceLease)->Result<PeerPair,ContractError>{
    business.check_time(context.now_ms)?;path.check_current(context)?;connectivity.check_current(context)?;
    let GrantClaims::Connectivity(connection)=connectivity.claims()else{return Err(denied());};
    let c=business.claims();let base=business.lease().claims();
    let peers=PeerPair::new(PeerId::from_public_key(&c.consumer_public_key),PeerId::from_public_key(&c.host_public_key))?;
    if context.authority_key!=&c.network_authority_key || context.space_id!=c.space_id
        || context.policy_epoch!=c.space_policy_epoch || context.deployment_id!=base.deployment_id
        || path.purpose()!=Purpose::PrivateService || connection.purpose!=Purpose::PrivateService
        || path.peers()!=peers || connection.peers!=peers
        || path.claims().connectivity_grant_digest!=connectivity.digest()
        || connection.business_grant_digest!=business.digest()
        || path.claims().scope.not_before_ms<base.issued_at_unix_ms
        || path.claims().scope.expires_at_ms>base.expires_at_unix_ms{return Err(denied());}
    for member in &path.memberships{
        let member=member.claims();
        let expected=if member.installation_id==c.consumer_device_id{
            (c.consumer_public_key,c.consumer_membership_epoch)
        }else if member.installation_id==base.definition.host_device_id{
            (c.host_public_key,c.host_membership_epoch)
        }else{return Err(denied());};
        if member.public_key!=expected.0 || member.membership_epoch!=expected.1{return Err(denied());}
    }
    Ok(peers)
}
pub fn private_service_route_binding(context:&NetworkVerification<'_>,path:&VerifiedNetworkPath,
    connectivity:&VerifiedNetworkGrant,transit:&VerifiedNetworkGrant,business:&VerifiedPrivateServiceLease)
    ->Result<PrivateServiceRouteBinding,ContractError>{
    let peers=private_service_path_peers(context,path,connectivity,business)?;
    transit.check_current(context)?;
    let GrantClaims::Transit(forward)=transit.claims()else{return Err(denied());};
    path.check_route(context,&[forward.relay])?;
    let usage:ServiceUsageBudgetGrantClaims=decode_service_message(&business.lease().claims().usage_grant.claims,SERVICE_USAGE_BYTES)?;
    if forward.peers!=peers || forward.transport_group!=path.transport_group_id()
        || forward.previous!=peers.first || forward.next!=peers.second || forward.remaining_hops!=1
        || forward.scope.not_before_ms<path.claims().scope.not_before_ms
        || forward.scope.expires_at_ms>path.claims().scope.expires_at_ms
        || forward.byte_limit>usage.byte_ceiling{return Err(denied());}
    let mut message=b"NestLink/private-service/v1/network-route\0".to_vec();
    for value in [path.transport_group_id(),connectivity.digest(),transit.digest(),business.digest()]{message.extend_from_slice(&value);}
    message.extend_from_slice(&network_datagram::PATH_EPOCH.to_be_bytes());
    Ok(PrivateServiceRouteBinding{digest:digest(&message),peers,relay:forward.relay,
        byte_limit:forward.byte_limit,expires_at_ms:forward.scope.expires_at_ms})
}
