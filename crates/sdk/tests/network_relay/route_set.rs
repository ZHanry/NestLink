//! Actual HTTP, two real NodeControl owners and one original group's admission.
//! This proves healthy-member isolation, not selection or an in-place switch.
use super::*;
use nestlink_protocol::{api::{NetworkRemoteRouteSetRequest, NetworkRemoteRouteSetMemberRequest},network::GrantClaims};

#[tokio::test]
async fn original_route_set_keeps_b_admissible_after_a_stops_and_rejects_role_replay() -> Result {
    let mut f=Fixture::new().await?;
    let mut second=super::chain::ChainNode::new(&f).await?;
    let original=f.sdk.network_remote_relay(f.pin.space_id(),&f.allocation).await?;
    let path=GrantClaims::decode_canonical(&URL_SAFE_NO_PAD.decode(&original.path.path.claims)?)?;
    let policy=f.sdk.network_policy(f.pin.space_id()).await?;
    let a=f.control.current_lease()?;
    let b=second.control.current_lease()?;
    let expires=path.scope().expires_at_ms.min(a.expires_at_unix_ms).min(b.expires_at_unix_ms);
    let mut ids=[random_id(),random_id()]; ids.sort();
    let nodes=[&f.node_id,&second.id];
    let request=NetworkRemoteRouteSetRequest {set_id:random_id(),path:NetworkRemotePathRequest {
        connectivity_grant_id:random_id(),path_grant_id:random_id(),controller_membership_grant_id:original.path.controller_membership.grant_id,
        host_membership_grant_id:original.path.host_membership.grant_id,expected_policy_epoch:policy.policy_epoch,expires_at_unix_ms:expires},
        members:[0,1].map(|index|NetworkRemoteRouteSetMemberRequest {allocation_id:ids[index].clone(),transit_grant_id:random_id(),node_id:nodes[index].clone()}),
        device_id:f.controller.device_id.clone(),signature:String::new()};
    let set=request.set_id.clone();
    let initial=f.sdk.reserve_verified_network_remote_route_set(&f.pin,&f.controller,&f.permit,&f.host.identity.public_key(),request).await?;
    assert!(initial.candidates().iter().all(|candidate|candidate.available()));
    let group=initial.transport_group(); let path_id=initial.path_grant_id().to_owned(); let deadline=initial.deadline();
    let bindings=initial.candidates().map(|candidate|candidate.route_binding());
    tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            if [&f.control,&second.control].into_iter().enumerate().all(|(index,control)|control.resource_snapshot().is_ok_and(|snapshot|snapshot.network_routes.iter().any(|resource|resource.allocation.as_ref().is_some_and(|allocation|allocation.allocation_id==ids[index])))) {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await?;
    f.control.stop(); f.shutdown.send_replace(true);
    f.sdk.revoke_node(&f.node_id).await?;
    let refreshed=initial.refresh_current(&f.sdk,&f.controller,&f.permit,&f.host.identity.public_key()).await?;
    assert_eq!(refreshed.transport_group(),group); assert_eq!(refreshed.path_grant_id(),path_id);
    assert!(refreshed.deadline()<=deadline);
    assert_eq!(refreshed.candidates().map(|candidate|candidate.route_binding()),bindings);
    assert!(!refreshed.candidates()[0].available()); assert!(refreshed.candidates()[1].available());
    assert!(refreshed.candidate_for_admission(&f.sdk,&f.controller,&f.permit,&f.host.identity.public_key(),0).is_none());
    if let Some(task)=f.node_task.as_mut(){tokio::time::timeout(Duration::from_secs(3),task).await???;}
    f.node_task=None;
    f.node.close_and_wait(Instant::now()+Duration::from_secs(3)).await?;
    let current=f.sdk.verified_network_remote_route_set(&f.pin,&f.controller,&f.permit,&f.host.identity.public_key(),&set).await?;
    assert_eq!(current.transport_group(),group);
    let candidate=current.candidate_for_admission(&f.sdk,&f.controller,&f.permit,&f.host.identity.public_key(),1).ok_or("healthy candidate unavailable")?;
    let uri=url::Url::parse(candidate.node().endpoints.quic_uri.as_deref().ok_or("node URI")?)?;
    let address:SocketAddr=format!("{}:{}",uri.host_str().ok_or("host")?,uri.port().ok_or("port")?).parse()?;
    let mut endpoint=routed::AdjacencyEndpoint::bind_node("127.0.0.1:0".parse()?,&f.controller.identity,candidate.relay())?;
    let bound=endpoint.local_addr()?;
    let connect_deadline=Instant::now()+Duration::from_secs(3);
    let mut adjacency=endpoint.connect_node(address,&f.controller.identity,&f.controller.device_id,candidate.allocation_id(),candidate.route_binding(),connect_deadline).await?;
    let mut replay=routed::AdjacencyEndpoint::bind_node("127.0.0.1:0".parse()?,&f.controller.identity,candidate.relay())?;
    assert!(replay.connect_node(address,&f.controller.identity,&f.controller.device_id,candidate.allocation_id(),candidate.route_binding(),connect_deadline).await.is_err());
    replay.close_and_wait(Instant::now()+Duration::from_secs(3)).await?;
    f.sdk.revoke_network_remote_route_set(f.pin.space_id(),&set).await?;
    tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            if second.control.resource_snapshot().is_ok_and(|snapshot|!snapshot.network_routes.iter().any(|resource|resource.allocation.as_ref().is_some_and(|allocation|allocation.allocation_id==ids[1]))) {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await?;
    adjacency.close_and_wait(Instant::now()+Duration::from_secs(3)).await?;
    let _socket=UdpSocket::bind(bound)?;
    assert!(f.sdk.verified_network_remote_route_set(&f.pin,&f.controller,&f.permit,&f.host.identity.public_key(),&set).await.is_err());
    second.finish().await?; f.finish().await?;
    Ok(())
}
