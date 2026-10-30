use super::*;
use nestlink_identity::nodes::NodeIdentity;
use nestlink_protocol::api::NetworkRemoteRelayChainView;
use crate::control::NetworkChainNeighborProof;

fn chain_resource(
    issued:u64, node_key:Vec<u8>,
) -> TestResult<(NodeNetworkRelayResource,InstallationIdentity,NodeIdentity,NodeRemoteChainBinding)> {
    let (mut resource,endpoint) = resource_at(issued,node_key)?;
    let one:NetworkRemoteRelayView = serde_json::from_slice(&resource.relay_bundle_json)?;
    let authority = NetworkAuthoritySigner::from_master_seed(&[64;32])?;
    let decode = |view:&NetworkGrantView| -> TestResult<GrantClaims> {
        Ok(GrantClaims::decode_canonical(&URL_SAFE_NO_PAD.decode(&view.claims)?)?)
    };
    let encode = |claims:GrantClaims| -> TestResult<NetworkGrantView> {
        let signed = authority.sign(&claims)?;
        Ok(NetworkGrantView {schema_version:1,grant_id:claims.scope().grant_id.clone(),
            claims:URL_SAFE_NO_PAD.encode(signed.claims),signature:URL_SAFE_NO_PAD.encode(signed.signature)})
    };
    let GrantClaims::Path(mut path) = decode(&one.path.path)? else {return Err("path".into());};
    let GrantClaims::Transit(mut transit) = decode(&one.transit)? else {return Err("transit".into());};
    let other = NodeIdentity::generate();
    let local = transit.relay;
    let relay = PeerId::from_public_key(&other.public_key());
    let index = usize::from(PeerId(endpoint.fingerprint()) != path.peers.first);
    let relays = if index==0 {[local,relay]} else {[relay,local]};
    path.policy.relays = relays.to_vec(); path.policy.relays.sort(); path.policy.max_hops=2;
    let mut path_view = one.path;
    path_view.path=encode(GrantClaims::Path(path.clone()))?;
    let context = NetworkVerification {
        authority_key:&authority.public_key(),deployment_id:&path.scope.deployment_id,space_id:&path.scope.space_id,
        policy_epoch:path.scope.policy_epoch,now_ms:issued,revoked_grant_ids:&std::collections::BTreeSet::new(),
    };
    let permit = verify_permit(&resource.business_permit,&PermitSigner::from_seed([1;32]).public_key())?;
    let verify=|view:&NetworkGrantView| -> TestResult<VerifiedNetworkGrant> {
        Ok(verify_network_grant(&SignedNetworkGrant {
            claims:URL_SAFE_NO_PAD.decode(&view.claims)?,signature:URL_SAFE_NO_PAD.decode(&view.signature)?,
        },&context)?)
    };
    let member=|view:&NetworkGrantView,device:&str| -> TestResult<VerifiedMembership> {
        let grant=verify(view)?;
        let GrantClaims::Membership(claims)=grant.claims() else {return Err("membership".into());};
        let (key,epoch)=(claims.public_key,claims.membership_epoch);
        Ok(VerifiedMembership::from_grant(grant,&context,device,&key,epoch)?)
    };
    let verified=VerifiedNetworkPath::from_grants(&context,[
        member(&path_view.controller_membership,&permit.claims().controller_device_id)?,
        member(&path_view.host_membership,&permit.claims().host_device_id)?,
    ],verify(&path_view.connectivity)?,verify(&path_view.path)?,permit.digest())?;
    transit.transport_group=verified.transport_group_id();
    let mut first=transit.clone(); first.scope.grant_id=id(31); first.relay=relays[0];
    first.previous=path.peers.first;first.next=relays[1];first.remaining_hops=2;
    let mut second=transit;second.scope.grant_id=id(32);second.relay=relays[1];
    second.previous=relays[0];second.next=path.peers.second;second.remaining_hops=1;
    let original_node=one.node;
    let other_node=NodeEndpointsView {node_id:id(50),revision:1,endpoints:original_node.endpoints.clone()};
    let nodes=if index==0 {[original_node,other_node]} else {[other_node,original_node]};
    resource.allocation.as_mut().ok_or("allocation")?.allocation_id=if index==0 {id(31)} else {id(32)};
    resource.network_schema_version=2;
    resource.relay_bundle_json.clear();
    resource.chain_bundle_json=serde_json::to_vec(&NetworkRemoteRelayChainView {
        route_id:one.allocation_id,path:path_view,transits:[encode(GrantClaims::Transit(first))?,encode(GrantClaims::Transit(second))?],
        nodes,topology_digests:[[7;32],[8;32]],
    })?;
    let binding=verify_node_network_chain_resource(&resource,&PermitSigner::from_seed([1;32]).public_key(),issued)?;
    Ok((resource,endpoint,other,binding))
}

#[tokio::test]
async fn chain_neighbors_reuse_shared_slots_meters_and_original_snapshot_continuity() -> TestResult {
    use nestlink_transport_stream::tls::CurrentClientPins;
    let mut base=CandidateFixture::with_node_ttl(10000,10000)?;
    let now=sample(base.control.started)?;
    let (resource,endpoint,other,binding)=chain_resource(now.unix_ms,base.lease.node_key_sha256.clone())?;
    base.claims=resource.allocation.as_ref().ok_or("allocation")?.clone();
    let make_snapshot=|sequence,now:ClockSample,included| {
        let mut value=snapshot(sequence,now,Vec::new());
        value.allocation_issuer=PermitSigner::from_seed([1;32]).public_key().to_vec();
        if included {value.network_routes.push(resource.clone());}
        value
    };
    base.control.state.lock().map_err(|_|"state")?.resources.accept(make_snapshot(3,now,true),&base.lease,now.monotonic_ms,now)?;
    assert!(base.control.contains(&endpoint.fingerprint()));
    assert!(base.control.contains(&digest(&other.public_key())));
    let stranger=InstallationIdentity::generate();
    assert!(!base.control.contains(&stranger.fingerprint()));
    let challenge=[71;32];
    let endpoint_signature=endpoint.sign_network_chain_admission(&base.claims.allocation_id,&binding.chain.digest,binding.relay,&challenge)?;
    let other_signature=other.sign_network_chain_admission(&base.claims.allocation_id,&binding.chain.digest,binding.relay,&challenge)?;
    let prepare=|key:&[u8;32],signature:&[u8],nonce:&[u8;32]| base.control.prepare_network_chain_neighbor(
        &base.claims.allocation_id,&binding.chain.digest,&digest(key),
        NetworkChainNeighborProof {public_key:key,signature},nonce,
    );
    assert!(prepare(&endpoint.public_key(),&endpoint_signature,&[72;32]).is_err());
    assert!(prepare(&stranger.public_key(),&endpoint_signature,&challenge).is_err());
    let pending=prepare(&endpoint.public_key(),&endpoint_signature,&challenge)?;
    assert_eq!(pending.network_chain(),Some(binding));
    assert!(pending.network_direction().is_none());
    let first=prepare(&endpoint.public_key(),&endpoint_signature,&challenge)?.reserve()?;
    assert!(prepare(&endpoint.public_key(),&endpoint_signature,&challenge).is_err());
    let second=prepare(&other.public_key(),&other_signature,&challenge)?.reserve()?;
    assert_eq!(first.is_controller(),!second.is_controller());
    assert_eq!(base.control.counters()?.opened_connections,2);
    first.admit(5000,||Ok(()))?;
    second.admit(5000,||Ok(()))?;
    assert!(first.admit(1,||Ok(())).is_err());
    let now=sample(base.control.started)?;
    base.control.state.lock().map_err(|_|"state")?.resources.accept(make_snapshot(4,now,false),&base.lease,now.monotonic_ms,now)?;
    assert!(first.check_live().is_err());
    assert!(second.check_live().is_err());
    drop(first);drop(second);
    assert!(!base.control.contains(&digest(&other.public_key())));
    let now=sample(base.control.started)?;
    base.control.state.lock().map_err(|_|"state")?.resources.accept(make_snapshot(5,now,true),&base.lease,now.monotonic_ms,now)?;
    assert!(pending.reserve().is_err());
    assert!(prepare(&other.public_key(),&other_signature,&challenge).is_err());
    Ok(())
}
