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

pub enum PrivateServiceNodeBinding {
    Single(PrivateServiceRouteBinding),
    Chain(NodeRemoteChainBinding),
}

impl crate::InstallationIdentity {
    pub fn sign_private_service_route(&self, service: &str, request: &nestlink_protocol::services::private::PrivateServiceAccessRequest) -> Result<[u8;64],ContractError> {
        Ok(self.key.sign(&request.route_transcript(service)?).to_bytes())
    }
}
impl crate::service_plane::ServiceLeaseSigner {
    pub fn sign_private_service_relay(&self,business_digest:&[u8;32],route:&nestlink_protocol::services::private::PrivateServiceRelayRoute)->Result<[u8;64],ContractError>{
        Ok(self.key.sign(&route.transcript(business_digest)?).to_bytes())
    }
}

fn verify_private_service_transcript(
    transcript: &[u8],
    public_key: &[u8; 32],
    signature: &[u8],
) -> Result<(), ContractError> {
    VerifyingKey::from_bytes(public_key)
        .map_err(|_| denied())?
        .verify_strict(
            transcript,
            &Signature::from_slice(signature).map_err(|_| denied())?,
        )
        .map_err(|_| denied())
}

/// Verifies the exact independently domain-separated request signed by the
/// consumer installation, without the framing of a device action claim.
pub fn verify_private_service_route_request(
    service: &str,
    request: &nestlink_protocol::services::private::PrivateServiceAccessRequest,
    public_key: &[u8; 32],
    signature: &[u8],
) -> Result<(), ContractError> {
    verify_private_service_transcript(&request.route_transcript(service)?, public_key, signature)
}

/// A complete private grant is rooted in the pinned deployment node policy
/// signer, independently of the remote-control allocation issuer.
pub type VerifiedPrivateServiceGrant = (VerifiedPrivateServiceLease, VerifiedNetworkPath, VerifiedNetworkGrant, Vec<VerifiedNetworkGrant>);
pub fn verify_private_service_grant(
    grant: &nestlink_protocol::services::private::PrivateServiceGrant,
    policy_issuer: &[u8;32],
    deployment: &str,
    now: u64,
) -> Result<VerifiedPrivateServiceGrant,ContractError> {
    let delegation = crate::service_plane::publication::verify_service_issuer_delegation(&grant.issuer,policy_issuer,deployment,now)?;
    delegation.verify_lease(&grant.lease.service_lease,now)?;
    let business = crate::services::private::verify_private_service_lease(&grant.lease,&delegation.claims().service_issuer)?;
    let binding = business.claims();
    let revoked = BTreeSet::new();
    let context = NetworkVerification {authority_key:&binding.network_authority_key,deployment_id:deployment,space_id:&binding.space_id,policy_epoch:binding.space_policy_epoch,now_ms:now,revoked_grant_ids:&revoked};
    let decode = |view: &nestlink_protocol::api::NetworkGrantView| verify_network_grant(&remote::signed(view)?, &context);
    let member = |view: &nestlink_protocol::api::NetworkGrantView, installation: &str, key: &[u8;32], epoch| {
        VerifiedMembership::from_grant(decode(view)?,&context,installation,key,epoch)
    };
    let view=&grant.network;
    let usage: ServiceUsageBudgetGrantClaims=decode_service_message(&business.lease().claims().usage_grant.claims,SERVICE_USAGE_BYTES)?;
    if view.grant_id != usage.grant_id {return Err(denied());}
    let members=[member(&view.consumer_membership,&binding.consumer_device_id,&binding.consumer_public_key,binding.consumer_membership_epoch)?,member(&view.host_membership,&business.lease().claims().definition.host_device_id,&binding.host_public_key,binding.host_membership_epoch)?];
    let connectivity=decode(&view.connectivity)?;
    let path=VerifiedNetworkPath::from_grants(&context,members,connectivity.clone(),decode(&view.path)?,business.digest())?;
    private_service_path_peers(&context,&path,&connectivity,&business)?;
    let transits=match &view.relay {
        None=>{path.check_route(&context,&[])?;Vec::new()},
        Some(route)=>{
            verify_private_service_transcript(&route.transcript(&business.digest())?,&delegation.claims().service_issuer,&route.signature)?;
            if !nestlink_protocol::valid_id(&route.route_id) || route.nodes.len()!=route.transits.len() || route.nodes.len()!=route.node_public_keys.len() || !(1..=2).contains(&route.nodes.len()) || route.topology_digests.len()!=if route.nodes.len()==2 {2}else{0} || route.nodes.len()==2 && (route.nodes[0].node_id==route.nodes[1].node_id || route.node_public_keys[0]==route.node_public_keys[1]) {return Err(denied());}
            let transits=route.transits.iter().map(decode).collect::<Result<Vec<_>,_>>()?;
            for (index,grant) in transits.iter().enumerate() {
                route.nodes[index].endpoints.validate()?;
                let GrantClaims::Transit(transit)=grant.claims() else {return Err(denied());};
                if !nestlink_protocol::valid_id(&route.nodes[index].node_id) || route.nodes[index].revision==0 || transit.route_id!=route.route_id || transit.relay!=PeerId::from_public_key(&route.node_public_keys[index]) {return Err(denied());}
            }
            if transits.len()==1 {private_service_route_binding(&context,&path,&connectivity,&transits[0],&business)?;} else {private_service_chain_binding(&context,&path,&connectivity,&transits,&business)?;}
            transits
        }
    };
    Ok((business,path,connectivity,transits))
}

pub fn private_service_allocation_binding(business:&VerifiedPrivateServiceLease)->[u8;32] {
    let mut bytes=b"NestLink/private-service/v1/relay-allocation\0".to_vec();
    bytes.extend_from_slice(&business.digest());
    digest(&bytes)
}

/// Call only after the fresh, exact-query snapshot signature was verified.
pub fn verify_node_private_service_resource(resource:&nestlink_protocol::NodeNetworkRelayResource,policy_issuer:&[u8;32],now:u64)->Result<PrivateServiceNodeBinding,ContractError> {
    if !resource.business_permit.is_empty() || !resource.relay_bundle_json.is_empty() || !resource.chain_bundle_json.is_empty() || resource.private_service_bundle_json.is_empty() || resource.private_service_bundle_json.len()>65_536 {return Err(denied());}
    let allocation=resource.allocation.as_ref().ok_or_else(denied)?;
    allocation.validate()?;
    let grant:nestlink_protocol::services::private::PrivateServiceGrant=serde_json::from_slice(&resource.private_service_bundle_json).map_err(|_|denied())?;
    let (business,path,connectivity,transits)=verify_private_service_grant(&grant,policy_issuer,&allocation.deployment_id,now)?;
    let binding=business.claims();
    let base=business.lease().claims();
    let route=grant.network.relay.as_ref().ok_or_else(denied)?;
    let index=route.nodes.iter().position(|node|node.node_id==allocation.node_id).ok_or_else(denied)?;
    let GrantClaims::Transit(transit)=transits[index].claims() else{return Err(denied());};
    if resource.network_schema_version as usize!=transits.len() || resource.network_authority_key!=binding.network_authority_key || allocation.allocation_id!=transit.scope.grant_id || allocation.session_id!=grant.network.grant_id || allocation.security_epoch!=base.security_epoch || allocation.policy_revision!=base.policy_revision || allocation.connection_generation!=1 || allocation.controller_device_id!=binding.consumer_device_id || allocation.host_device_id!=base.definition.host_device_id || allocation.controller_key_sha256!=digest(&binding.consumer_public_key) || allocation.host_key_sha256!=digest(&binding.host_public_key) || allocation.controller_account_id!=binding.consumer_account_id || allocation.host_account_id!=base.account_id || allocation.session_binding_sha256!=private_service_allocation_binding(&business) || allocation.node_key_sha256!=transit.relay.0 || allocation.node_endpoint_revision!=route.nodes[index].revision || allocation.bytes_per_allocation!=transit.byte_limit || allocation.issued_at_unix_ms!=transit.scope.not_before_ms || allocation.expires_at_unix_ms!=transit.scope.expires_at_ms || allocation.transports!=[nestlink_protocol::RelayTransport::QuicDatagram as i32] || allocation.grant_sequence!=1 {return Err(denied());}
    let revoked=BTreeSet::new();
    let context=NetworkVerification{authority_key:&binding.network_authority_key,deployment_id:&base.deployment_id,space_id:&binding.space_id,policy_epoch:binding.space_policy_epoch,now_ms:now,revoked_grant_ids:&revoked};
    if transits.len()==1 {Ok(PrivateServiceNodeBinding::Single(private_service_route_binding(&context,&path,&connectivity,&transits[0],&business)?))} else {Ok(PrivateServiceNodeBinding::Chain(NodeRemoteChainBinding{chain:private_service_chain_binding(&context,&path,&connectivity,&transits,&business)?,relay:transit.relay}))}
}

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
        || forward.byte_limit == 0
        || forward.byte_limit > nestlink_protocol::services::private::private_service_wire_allowance(usage.byte_ceiling)?
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
            || grant.byte_limit == 0
            || grant.byte_limit > nestlink_protocol::services::private::private_service_wire_allowance(usage.byte_ceiling)?
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
