//! Real HTTP/SQLite association and ordinary one-use packet admission. Kernel
//! forwarding qualification remains the privileged Linux owner's separate job.
use super::*;
use base64::{Engine,engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{network::NetworkVerification,nodes::NodeIdentity,subnet::{SubnetGatewayState,verify_subnet_mapping}};
use nestlink_protocol::{NodeRole,api::{NodeRegistration,NodeEndpoints,NodeEndpointsUpdate,NetworkRouteExportRequest},network_topology::BootIncarnation,subnet::management::*};
use nestlink_sdk::network::{packet_access::OnlinePacketAccess,routed::PinnedNetworkSpace,subnet::{SubnetLocalConsent,SubnetInterfaces,SubnetInterface}};
use std::collections::BTreeSet;

struct Gateway { node: String, identity: NodeIdentity, mapping: SubnetMappingView, reference: SubnetMappingReference }
async fn gateway(f:&Fixture,seed:u8,alias:&str) -> Result<Gateway> {
    let identity=NodeIdentity::from_seed(&[seed;32]);
    let node=random_id();
    let mut store=f.store()?;
    let actor=f.manager.principal().ok_or("manager missing")?;
    store.register_node(actor,NodeRegistration{id:node.clone(),name:"explicit subnet node".into(),public_key:URL_SAFE_NO_PAD.encode(identity.public_key()),roles:vec![NodeRole::NodeRelay as i32],max_connections:16,bytes_per_second:1_048_576})?;
    store.set_node_endpoints(actor,&node,NodeEndpointsUpdate{expected_revision:0,endpoints:NodeEndpoints{quic_uri:Some("quic://127.0.0.1:31982".into()),allow_loopback:true,..NodeEndpoints::default()}},now()?)?;
    let runtime_id=random_id();
    let challenge=store.node_challenge(&node,now()?)?;
    let lease=store.issue_node_lease(&identity.prove(&challenge,&runtime_id)?,now()?)?;
    drop(store);
    let original=IpPrefix{network:"192.168.1.0".parse()?,prefix_len:24};
    let alias=IpPrefix{network:alias.parse()?,prefix_len:24};
    let policy=f.manager.network_policy(&f.space).await?;
    let export=f.manager.issue_network_route_export(&f.space,&node,NetworkRouteExportRequest{grant_id:random_id(),expected_revision:policy.revision,expected_policy_epoch:policy.policy_epoch,prefixes:vec![original,alias],expires_at_ms:now()?+60_000}).await?;
    let policy=f.manager.network_policy(&f.space).await?;
    let mapping=f.manager.issue_subnet_mapping(&f.space,&SubnetMappingRequest{mapping_version:1,grant_id:random_id(),gateway_node_id:node.clone(),route_export_grant_id:export.grant_id,
        expected_revision:policy.revision,expected_policy_epoch:policy.policy_epoch,expected_gateway_incarnation:BootIncarnation{runtime_id,runtime_generation:lease.runtime_generation},original,alias,expires_at_ms:now()?+60_000}).await?;
    let revoked=BTreeSet::new();
    let context=NetworkVerification{authority_key:&f.authority,deployment_id:&f.deployment,space_id:&f.space,policy_epoch:policy.policy_epoch,now_ms:now()?,revoked_grant_ids:&revoked};
    let export=verify_network_grant(&decode_network_grant(&mapping.route_export)?,&context)?;
    let state=SubnetGatewayState{node_id:&mapping.gateway.node_id,public_key:&mapping.gateway.public_key,incarnation:&mapping.gateway.incarnation,mapping_revision:mapping.gateway.mapping_revision,lease_expires_at_ms:mapping.gateway.lease_expires_at_ms};
    let verified=verify_subnet_mapping(&mapping.mapping,&context,export,&state)?;
    let reference=SubnetMappingReference{mapping_id:verified.claims().scope.grant_id.clone(),mapping_digest:verified.digest(),expected_mapping_revision:1};
    Ok(Gateway{node,identity,mapping,reference})
}
async fn bind_request(f:&Fixture,gateway:&Gateway,endpoint:usize) -> Result<SubnetGatewayInstallationRequest> {
    Ok(SubnetGatewayInstallationRequest{mapping:gateway.reference.clone(),installation_id:if endpoint==0 {f.source_device.device_id.clone()} else {f.target_device.device_id.clone()},
        membership_grant_id:if endpoint==0 {f.request.source_membership_grant_id.clone()} else {f.request.destination_membership_grant_id.clone()},expected_revision:f.manager.network_policy(&f.space).await?.revision})
}
async fn bind(f:&Fixture,gateway:&Gateway,endpoint:usize) -> Result {
    let owner=if endpoint==0 {&f.source} else {&f.target};
    owner.bind_subnet_gateway_installation(&f.space,&gateway.reference.mapping_id,&bind_request(f,gateway,endpoint).await?).await?;
    Ok(())
}
async fn request(f:&Fixture,source:Option<&Gateway>,destination:Option<&Gateway>) -> Result<SubnetNetworkAccessRequest> {
    let mut packet=f.fresh_request().await?;
    packet.expected_revision=f.manager.network_policy(&f.space).await?.revision;
    for (gateway,prefixes) in [(source,&mut packet.source_prefixes),(destination,&mut packet.destination_prefixes)] {
        if let Some(gateway)=gateway { *prefixes=vec![nestlink_protocol::subnet::SubnetMappingClaims::decode_canonical(&gateway.mapping.mapping.claims)?.alias]; }
    }
    Ok(SubnetNetworkAccessRequest{packet,source_mapping:source.map(|gateway|gateway.reference.clone()),destination_mapping:destination.map(|gateway|gateway.reference.clone())})
}
fn digest(f:&Fixture,view:&NetworkAccessView) -> Result<[u8;32]> {
    let revoked=BTreeSet::new();
    Ok(verify_network_grant(&decode_network_grant(&view.access)?,&NetworkVerification{authority_key:&f.authority,deployment_id:&f.deployment,space_id:&f.space,
        policy_epoch:view.address_directory.space.policy_epoch,now_ms:now()?,revoked_grant_ids:&revoked})?.digest())
}
fn udp(source:[u8;4],destination:[u8;4],port:u16) -> Result<Vec<u8>> {
    let builder=etherparse::PacketBuilder::ipv4(source,destination,64).udp(41000,port);
    let mut bytes=Vec::new();
    builder.write(&mut bytes,&[8;64])?;
    Ok(bytes)
}
fn cascade(f:&Fixture,view:&NetworkAccessView) -> Result {
    let snapshot=f.store()?.network_policy_snapshot(&f.space,now()?)?;
    for id in [&view.access.grant_id,&view.connectivity.grant_id,&view.path.grant_id] {assert!(snapshot.verification().revoked_grant_ids.contains(id),"all original graph IDs must close together");}
    Ok(())
}

#[tokio::test]
async fn same_key_requires_explicit_owner_binding_and_mapping_revoke_stops_original_online_budget() -> Result {
    let f=Fixture::new().await?;
    let gateway=gateway(&f,62,"10.210.2.0").await?;
    let unapproved=request(&f,None,Some(&gateway)).await?;
    status(f.target.issue_subnet_network_access(&f.space,&unapproved).await,403);
    status(f.target.issue_network_access(&f.space,unapproved.packet).await,403);
    let approval=bind_request(&f,&gateway,1).await?;
    status(f.manager.bind_subnet_gateway_installation(&f.space,&gateway.reference.mapping_id,&approval).await,403);
    status(f.source.bind_subnet_gateway_installation(&f.space,&gateway.reference.mapping_id,&approval).await,403);
    let wrong_endpoint=bind_request(&f,&gateway,0).await?;
    status(f.source.bind_subnet_gateway_installation(&f.space,&gateway.reference.mapping_id,&wrong_endpoint).await,403);
    bind(&f,&gateway,1).await?;
    let packet=request(&f,None,Some(&gateway)).await?;
    status(f.source.issue_subnet_network_access(&f.space,&packet).await,403);
    let mut wrong=packet.clone(); wrong.destination_mapping.as_mut().ok_or("mapping missing")?.mapping_digest[0]^=1;
    status(f.target.issue_subnet_network_access(&f.space,&wrong).await,403);
    let issued=f.target.issue_subnet_network_access(&f.space,&packet).await?;
    assert_eq!(issued.subnet_mappings.len(),1);
    assert_eq!(issued.subnet_mappings[0].mapping,gateway.mapping.mapping);
    let business=digest(&f,&issued)?;
    let pin=PinnedNetworkSpace::new(f.space.clone(),f.authority)?;
    let mut source=OnlinePacketAccess::start(&f.source,&pin,&f.source_device,&issued.access.grant_id,business,random_id()).await?;
    let target_owner=random_id();
    let mut target=OnlinePacketAccess::start(&f.target,&pin,&f.target_device,&issued.access.grant_id,business,target_owner.clone()).await?;
    let source_ip:std::net::Ipv4Addr=issued.address_directory.addresses[0].ipv4.parse()?;
    let bytes=udp(source_ip.octets(),[10,210,2,42],53)?;
    source.admit_local(&bytes)?; target.admit_remote(&bytes)?;
    assert!(target.admit_remote(&udp(source_ip.octets(),[192,168,1,42],53)?).is_err());
    assert!(source.admit_local(&udp(source_ip.octets(),[10,210,2,42],54)?).is_err());
    let spent=source.spent_bytes();
    source.refresh(&f.source).await?;
    assert_eq!(source.spent_bytes(),spent,"refresh cannot refill the original budget");
    let plan=target.subnet_plan(SubnetLocalConsent::approve(target_owner,gateway.reference.mapping_digest,business)?,SubnetInterfaces{tun:SubnetInterface{index:12,name:"nltfixture".into()},lan:SubnetInterface{index:13,name:"ethfixture".into()}},&["127.0.0.1".parse()?])?;
    assert_eq!(plan.view().mapping_digest,gateway.reference.mapping_digest);
    let mut reopened=f.store()?;
    let read=reopened.network_access(f.source.principal().ok_or("source missing")?,&f.space,&issued.access.grant_id,now()?)?;
    assert_eq!(read.subnet_mappings[0].mapping,gateway.mapping.mapping);
    drop(reopened);
    f.manager.revoke_subnet_mapping(&f.space,&gateway.reference.mapping_id,&SubnetMappingRevoke{expected_revision:f.manager.network_policy(&f.space).await?.revision,expected_mapping_revision:1}).await?;
    cascade(&f,&issued)?;
    assert!(source.refresh(&f.source).await.is_err());
    assert!(target.refresh(&f.target).await.is_err());
    assert!(source.admit_local(&bytes).is_err());
    assert_eq!(source.spent_bytes(),spent);
    f.finish().await
}

#[tokio::test]
async fn independently_bound_overlapping_sites_admit_only_alias_packets_and_node_restart_closes_graph() -> Result {
    let f=Fixture::new().await?;
    let source_gateway=gateway(&f,61,"10.210.1.0").await?;
    let target_gateway=gateway(&f,62,"10.210.2.0").await?;
    bind(&f,&source_gateway,0).await?; bind(&f,&target_gateway,1).await?;
    let issued=f.target.issue_subnet_network_access(&f.space,&request(&f,Some(&source_gateway),Some(&target_gateway)).await?).await?;
    assert_eq!(issued.subnet_mappings.len(),2);
    let business=digest(&f,&issued)?;
    let pin=PinnedNetworkSpace::new(f.space.clone(),f.authority)?;
    let mut source=OnlinePacketAccess::start(&f.source,&pin,&f.source_device,&issued.access.grant_id,business,random_id()).await?;
    let mut target=OnlinePacketAccess::start(&f.target,&pin,&f.target_device,&issued.access.grant_id,business,random_id()).await?;
    let bytes=udp([10,210,1,42],[10,210,2,42],53)?;
    source.admit_local(&bytes)?; target.admit_remote(&bytes)?;
    assert!(source.admit_local(&udp([192,168,1,42],[10,210,2,42],53)?).is_err());
    assert!(target.admit_remote(&udp([10,210,2,42],[10,210,1,42],53)?).is_err());
    let mut store=f.store()?;
    let challenge=store.node_challenge(&source_gateway.node,now()?)?;
    store.issue_node_lease(&source_gateway.identity.prove(&challenge,&random_id())?,now()?)?;
    drop(store);
    cascade(&f,&issued)?;
    assert!(source.refresh(&f.source).await.is_err());
    assert!(target.refresh(&f.target).await.is_err());
    status(f.target.network_access(&f.space,&issued.access.grant_id).await,403);
    assert_eq!(f.manager.subnet_mapping(&f.space,&target_gateway.reference.mapping_id).await?.mapping,target_gateway.mapping.mapping);
    f.finish().await
}

#[tokio::test]
async fn original_export_revoke_and_observed_mapping_expiry_cannot_revive_a_bound_packet_graph() -> Result {
    for expired in [false,true] {
        let f=Fixture::new().await?;
        let gateway=gateway(&f,62,"10.210.2.0").await?;
        bind(&f,&gateway,1).await?;
        let issued=f.target.issue_subnet_network_access(&f.space,&request(&f,None,Some(&gateway)).await?).await?;
        if expired {
            let claims=nestlink_protocol::subnet::SubnetMappingClaims::decode_canonical(&gateway.mapping.mapping.claims)?;
            let mut store=f.store()?;
            assert!(store.network_access(f.source.principal().ok_or("source missing")?,&f.space,&issued.access.grant_id,claims.scope.expires_at_ms).is_err());
            assert!(matches!(store.network_access(f.source.principal().ok_or("source missing")?,&f.space,&issued.access.grant_id,now()?),Err(StorageError::Conflict)),"clock rollback cannot revive a terminal graph");
            drop(store);
        } else {
            f.manager.revoke_network_route_export(&f.space,&gateway.mapping.route_export.grant_id,f.manager.network_policy(&f.space).await?.revision).await?;
            cascade(&f,&issued)?;
            status(f.source.network_access(&f.space,&issued.access.grant_id).await,403);
            status(f.target.start_network_access(&f.space,&issued.access.grant_id,NetworkAccessStart{installation_id:f.target_device.device_id.clone(),owner_id:random_id()}).await,403);
        }
        f.finish().await?;
    }
    Ok(())
}
