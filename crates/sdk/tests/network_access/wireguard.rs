//! Production HTTP/SQLite key binding plus the original noncloneable packet
//! admission owner. Kernel WireGuard handshake/cleanup is qualified separately.
use super::*;
use nestlink_identity::{network::NetworkVerification,wireguard::{WireGuardPortalState,verify_wireguard_client_binding},subnet::{SubnetGatewayState,verify_subnet_mapping}};
use nestlink_protocol::{api::NetworkRouteExportRequest,subnet::{SubnetMappingClaims,management::*},wireguard::{WireGuardClientBindingClaims,management::*}};
use nestlink_sdk::network::{packet_access::OnlinePacketAccess,routed::PinnedNetworkSpace,wireguard::OnlineWireGuardClient};
use std::{collections::BTreeSet,net::Ipv4Addr};

fn prefix(address:Ipv4Addr)->IpPrefix {IpPrefix{network:address.into(),prefix_len:32}}
async fn portal(f:&Fixture)->Result<subnet::Gateway> {
    let prefix=prefix("10.210.7.2".parse()?);
    let portal=subnet::gateway_prefix(f,61,prefix,prefix).await?;
    subnet::bind(f,&portal,0).await?;
    Ok(portal)
}
async fn second_mapping(f:&Fixture,portal:&subnet::Gateway,address:Ipv4Addr)->Result<subnet::Gateway> {
    let policy=f.manager.network_policy(&f.space).await?;
    let export=f.manager.issue_network_route_export(&f.space,&portal.node,NetworkRouteExportRequest{grant_id:random_id(),expected_revision:policy.revision,expected_policy_epoch:policy.policy_epoch,prefixes:vec![prefix(address)],expires_at_ms:now()?+60_000}).await?;
    let policy=f.manager.network_policy(&f.space).await?;
    let mapping=f.manager.issue_subnet_mapping(&f.space,&SubnetMappingRequest{mapping_version:1,grant_id:random_id(),gateway_node_id:portal.node.clone(),route_export_grant_id:export.grant_id,expected_revision:policy.revision,expected_policy_epoch:policy.policy_epoch,expected_gateway_incarnation:portal.mapping.gateway.incarnation.clone(),original:prefix(address),alias:prefix(address),expires_at_ms:now()?+60_000}).await?;
    let revoked=BTreeSet::new();
    let context=NetworkVerification{authority_key:&f.authority,deployment_id:&f.deployment,space_id:&f.space,policy_epoch:policy.policy_epoch,now_ms:now()?,revoked_grant_ids:&revoked};
    let verified=verify_subnet_mapping(&mapping.mapping,&context,verify_network_grant(&decode_network_grant(&mapping.route_export)?,&context)?,&SubnetGatewayState{node_id:&mapping.gateway.node_id,public_key:&mapping.gateway.public_key,incarnation:&mapping.gateway.incarnation,mapping_revision:1,lease_expires_at_ms:mapping.gateway.lease_expires_at_ms})?;
    let reference=SubnetMappingReference{mapping_id:verified.claims().scope.grant_id.clone(),mapping_digest:verified.digest(),expected_mapping_revision:1};
    let result=subnet::Gateway{node:portal.node.clone(),identity:nestlink_identity::nodes::NodeIdentity::from_seed(&[61;32]),mapping,reference};
    subnet::bind(f,&result,0).await?;
    Ok(result)
}
async fn access(f:&Fixture,portal:&subnet::Gateway)->Result<NetworkAccessView> {
    let mut packet=f.fresh_request().await?;
    packet.expected_revision=f.manager.network_policy(&f.space).await?.revision;
    packet.source_prefixes=vec![SubnetMappingClaims::decode_canonical(&portal.mapping.mapping.claims)?.alias];
    Ok(f.target.issue_subnet_network_access(&f.space,&SubnetNetworkAccessRequest{packet,source_mapping:Some(portal.reference.clone()),destination_mapping:None}).await?)
}
async fn request(f:&Fixture,portal:&subnet::Gateway,access:&NetworkAccessView)->Result<WireGuardClientBindingRequest> {
    let policy=f.manager.network_policy(&f.space).await?;
    let original=GrantClaims::decode_canonical(&decode_network_grant(&access.access)?.claims)?;
    let GrantClaims::NetworkAccess(original)=original else {return Err("expected packet business".into());};
    Ok(WireGuardClientBindingRequest{binding_version:1,grant_id:random_id(),client_id:random_id(),expected_client_revision:0,expected_revision:policy.revision,expected_policy_epoch:policy.policy_epoch,installation_id:f.source_device.device_id.clone(),portal_node_id:portal.node.clone(),expected_portal_incarnation:portal.mapping.gateway.incarnation.clone(),access_grant_id:access.access.grant_id.clone(),client_public_key:[21;32],client_address:SubnetMappingClaims::decode_canonical(&portal.mapping.mapping.claims)?.alias.network.to_string().parse()?,total_byte_ceiling:original.byte_limit*2,expires_at_ms:original.scope.expires_at_ms})
}
fn digest(f:&Fixture,view:&WireGuardClientBindingView)->Result<[u8;32]> {
    let revoked=BTreeSet::new();
    let context=NetworkVerification{authority_key:&f.authority,deployment_id:&f.deployment,space_id:&f.space,policy_epoch:view.policy.policy_epoch,now_ms:now()?,revoked_grant_ids:&revoked};
    let claims=WireGuardClientBindingClaims::decode_canonical(&view.binding.claims)?;
    let gateway=&view.packet_access.subnet_mappings[0].gateway;
    Ok(verify_wireguard_client_binding(&view.binding,&context,verify_network_grant(&decode_network_grant(&view.packet_access.access)?,&context)?,&WireGuardPortalState{node_id:&gateway.node_id,public_key:&gateway.public_key,incarnation:&gateway.incarnation,lease_expires_at_ms:gateway.lease_expires_at_ms,client_revision:claims.client_revision})?.digest())
}
fn assert_graph_closed(f:&Fixture,access:&NetworkAccessView)->Result {
    let snapshot=f.store()?.network_policy_snapshot(&f.space,now()?)?;
    for id in [&access.access.grant_id,&access.connectivity.grant_id,&access.path.grant_id] {assert!(snapshot.verification().revoked_grant_ids.contains(id));}
    Ok(())
}

#[tokio::test]
async fn independent_client_key_requires_exact_original_source_authority_and_revoke_stops_both_packet_owners()->Result {
    let f=Fixture::new().await?;
    let portal=portal(&f).await?;
    let access=access(&f,&portal).await?;
    let request=request(&f,&portal,&access).await?;
    for actor in [&f.manager,&f.target,&f.stranger] {status(actor.issue_wireguard_client_binding(&f.space,&request).await,403);}
    let mut wrong=request.clone();wrong.installation_id=f.target_device.device_id.clone();status(f.source.issue_wireguard_client_binding(&f.space,&wrong).await,403);
    wrong=request.clone();wrong.client_address="10.210.7.3".parse()?;status(f.source.issue_wireguard_client_binding(&f.space,&wrong).await,403);
    wrong=request.clone();wrong.expected_portal_incarnation.runtime_generation+=1;status(f.source.issue_wireguard_client_binding(&f.space,&wrong).await,409);
    let issued=f.source.issue_wireguard_client_binding(&f.space,&request).await?;
    assert_eq!(issued.committed_bytes,f.request.byte_limit);
    assert_eq!(issued.total_byte_ceiling,f.request.byte_limit*2);
    for actor in [&f.manager,&f.target,&f.stranger] {status(actor.wireguard_client_binding(&f.space,&request.grant_id).await,403);}
    let reopened=f.store()?.wireguard_client_binding(f.source.principal().ok_or("source missing")?,&f.space,&request.grant_id,now()?)?;
    assert_eq!(reopened.binding,issued.binding);
    let pin=PinnedNetworkSpace::new(f.space.clone(),f.authority)?;
    let binding=digest(&f,&issued)?;
    let business=subnet::digest(&f,&access)?;
    assert!(OnlineWireGuardClient::start(&f.source,&pin,&f.source_device,&request.grant_id,[45;32],business,random_id()).await.is_err());
    assert!(OnlineWireGuardClient::start(&f.source,&pin,&f.target_device,&request.grant_id,binding,business,random_id()).await.is_err());
    let mut owner=OnlineWireGuardClient::start(&f.source,&pin,&f.source_device,&request.grant_id,binding,business,random_id()).await?;
    let mut target=OnlinePacketAccess::start(&f.target,&pin,&f.target_device,&access.access.grant_id,business,random_id()).await?;
    assert!(OnlineWireGuardClient::start(&f.source,&pin,&f.source_device,&request.grant_id,binding,business,random_id()).await.is_err());
    let target_ip:Ipv4Addr=access.address_directory.addresses[1].ipv4.parse()?;
    let bytes=subnet::udp(request.client_address.octets(),target_ip.octets(),53)?;
    owner.admit_local(&bytes)?;target.admit_remote(&bytes)?;
    assert!(owner.admit_local(&subnet::udp([10,210,7,3],target_ip.octets(),53)?).is_err());
    assert!(owner.admit_local(&subnet::udp(request.client_address.octets(),target_ip.octets(),54)?).is_err());
    let spent=owner.spent_bytes();owner.refresh(&f.source,&f.source_device).await?;assert_eq!(owner.spent_bytes(),spent);
    let revoke=WireGuardClientRevoke{expected_revision:f.source.network_policy(&f.space).await?.revision,expected_client_revision:1};
    status(f.manager.revoke_wireguard_client(&f.space,&request.grant_id,&revoke).await,403);
    f.source.revoke_wireguard_client(&f.space,&request.grant_id,&revoke).await?;
    assert_graph_closed(&f,&access)?;
    assert!(owner.refresh(&f.source,&f.source_device).await.is_err());assert!(target.refresh(&f.target).await.is_err());
    assert!(owner.admit_local(&bytes).is_err());assert_eq!(owner.spent_bytes(),spent);
    status(f.source.network_access(&f.space,&access.access.grant_id).await,403);
    status(f.source.wireguard_client_binding(&f.space,&request.grant_id).await,403);
    f.finish().await
}

#[tokio::test]
async fn key_rotation_retains_old_names_and_cumulative_client_ceiling_across_database_reopen()->Result {
    let f=Fixture::new().await?;
    let portal=portal(&f).await?;
    let first=access(&f,&portal).await?;
    let original=request(&f,&portal,&first).await?;
    f.source.issue_wireguard_client_binding(&f.space,&original).await?;
    let next=second_mapping(&f,&portal,"10.210.7.3".parse()?).await?;
    let second=access(&f,&next).await?;
    let mut rotated=request(&f,&next,&second).await?;
    rotated.client_id=original.client_id.clone();rotated.expected_client_revision=1;rotated.client_public_key=[22;32];
    let mut larger=rotated.clone();larger.total_byte_ceiling+=1;status(f.source.issue_wireguard_client_binding(&f.space,&larger).await,409);
    let issued=f.source.issue_wireguard_client_binding(&f.space,&rotated).await?;
    assert_eq!(issued.committed_bytes,f.request.byte_limit*2);
    assert_graph_closed(&f,&first)?;
    status(f.source.wireguard_client_binding(&f.space,&original.grant_id).await,403);
    let repeated=access(&f,&portal).await?;
    let mut collision=request(&f,&portal,&repeated).await?;collision.client_public_key=[23;32];
    status(f.source.issue_wireguard_client_binding(&f.space,&collision).await,409);
    let third_mapping=second_mapping(&f,&portal,"10.210.7.4".parse()?).await?;
    let third=access(&f,&third_mapping).await?;
    let mut exhausted=request(&f,&third_mapping,&third).await?;
    exhausted.client_id=original.client_id.clone();exhausted.expected_client_revision=2;exhausted.client_public_key=[24;32];
    status(f.source.issue_wireguard_client_binding(&f.space,&exhausted).await,429);
    let mut reopened=f.store()?;
    let restored=reopened.wireguard_client_binding(f.source.principal().ok_or("source missing")?,&f.space,&rotated.grant_id,now()?)?;
    assert_eq!(restored.committed_bytes,f.request.byte_limit*2);assert_eq!(restored.binding,issued.binding);
    drop(reopened);
    status(f.source.issue_wireguard_client_binding(&f.space,&exhausted).await,429);
    status(f.source.issue_wireguard_client_binding(&f.space,&collision).await,409);
    f.finish().await
}

#[tokio::test]
async fn portal_restart_and_observed_binding_expiry_close_the_original_graph_without_clock_rollback_revival()->Result {
    for expiry in [false,true] {
        let f=Fixture::new().await?;
        let portal=portal(&f).await?;
        let access=access(&f,&portal).await?;
        let mut request=request(&f,&portal,&access).await?;
        if expiry {request.expires_at_ms=now()?+5000;}
        let issued=f.source.issue_wireguard_client_binding(&f.space,&request).await?;
        let mut store=f.store()?;
        let actor=f.source.principal().ok_or("source missing")?;
        let observation=if expiry {request.expires_at_ms+1} else {
            let challenge=store.node_challenge(&portal.node,now()?)?;
            store.issue_node_lease(&portal.identity.prove(&challenge,&random_id())?,now()?)?;
            now()?
        };
        assert!(store.wireguard_client_binding(actor,&f.space,&request.grant_id,observation).is_err());
        assert!(store.wireguard_client_binding(actor,&f.space,&request.grant_id,observation).is_err());
        assert!(store.wireguard_client_binding(actor,&f.space,&request.grant_id,observation.saturating_sub(10_000)).is_err());
        let connection=rusqlite::Connection::open(&f.database)?;
        let closed:bool=connection.query_row("SELECT revoked FROM network_wireguard_bindings WHERE grant_id=?1",[&request.grant_id],|row|row.get(0))?;
        assert!(closed);assert!(!issued.binding.claims.is_empty());
        let original_closed:bool=connection.query_row("SELECT revoked FROM network_packet_access WHERE access_grant_id=?1",[&request.access_grant_id],|row|row.get(0))?;assert!(original_closed);
        drop(connection);drop(store);f.finish().await?;
    }
    Ok(())
}
