//! Real authenticated HTTP route-set issuance and current availability readback.
use super::*;
use nestlink_identity::network::remote_route_set_reservation_transcript;
use nestlink_protocol::api::{NetworkRemotePathRequest, NetworkRemoteRouteSetRequest, NetworkRemoteRouteSetMemberRequest, RelayQuotaUpdate};

fn request(f:&Fixture,remote:&RemoteSetup,nodes:&[String;2]) -> Result<NetworkRemoteRouteSetRequest> {
    let store=Store::open_existing(&f.database,&f.deployment)?;
    let now=current_ms()?;
    let actor=store.authenticate(&f.admin_token,now/1000)?;
    let business=store.current_permit(&actor,&remote.request,now/1000)?;
    let mut ids=[random_id(),random_id()]; ids.sort();
    let mut request=NetworkRemoteRouteSetRequest {set_id:random_id(),path:NetworkRemotePathRequest {
        connectivity_grant_id:random_id(),path_grant_id:random_id(),controller_membership_grant_id:remote.controller_membership.clone(),host_membership_grant_id:remote.host_membership.clone(),expected_policy_epoch:3,expires_at_unix_ms:(now+6000).min(remote.expires_at_ms)},
        members:[0,1].map(|index| NetworkRemoteRouteSetMemberRequest {allocation_id:ids[index].clone(),transit_grant_id:random_id(),node_id:nodes[index].clone()}),
        device_id:business.controller_device_id.clone(),signature:String::new()};
    request.signature=URL_SAFE_NO_PAD.encode(remote.controller_key.sign_action(&remote_route_set_reservation_transcript(&business,&actor.account_id,&f.space,&request)?)?);
    Ok(request)
}

#[tokio::test]
async fn route_set_http_binds_atomic_consent_and_keeps_healthy_member_after_other_node_revocation() -> Result {
    let f=Fixture::new(false).await?;
    let remote=setup_remote_with_path(&f,true,false)?;
    let nodes=[topology::registered_node(&f)?.0,topology::registered_node(&f)?.0];
    let request=request(&f,&remote,&nodes)?;
    let issue=format!("{}/remote/{}/route-sets",f.base(),remote.request);
    let endpoint=format!("{}/route-sets/{}",f.base(),request.set_id);
    let body=serde_json::to_value(&request)?;
    assert_eq!(f.call("POST",&issue,body.clone(),None).await?.0,StatusCode::UNAUTHORIZED);
    let mut changed=request.clone(); changed.members[0].transit_grant_id=random_id();
    assert!(f.call("POST",&issue,serde_json::to_value(changed)?,Some(&f.admin_token)).await?.0.is_client_error());
    let (status,issued)=f.call("POST",&issue,body.clone(),Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::CREATED,"{issued}");
    assert_eq!(issued["set_id"],request.set_id);
    for index in 0..2 { assert_eq!(issued["members"][index]["available"],true); assert_eq!(issued["members"][index]["allocation_id"],request.members[index].allocation_id); }
    for token in [&f.admin_token,&f.member_token] {
        let (status,read)=f.call("GET",&endpoint,Value::Null,Some(token)).await?;
        assert_eq!(status,StatusCode::OK,"{read}"); assert_eq!(read,issued);
    }
    assert_eq!(f.call("POST",&issue,body,Some(&f.admin_token)).await?.0,StatusCode::CONFLICT);
    let mut store=Store::open_existing(&f.database,&f.deployment)?;
    let actor=store.authenticate(&f.admin_token,current_ms()?/1000)?;
    store.revoke_node(&actor,&nodes[0])?;
    drop(store);
    let (status,read)=f.call("GET",&endpoint,Value::Null,Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::OK,"{read}");
    assert_eq!(read["members"][0]["available"],false); assert_eq!(read["members"][1]["available"],true);
    assert_eq!(read["path"],issued["path"]);
    for index in 0..2 { assert_eq!(read["members"][index]["transit"],issued["members"][index]["transit"]); assert_eq!(read["members"][index]["node"],issued["members"][index]["node"]); }
    let legacy=format!("{}/relays/{}",f.base(),request.members[1].allocation_id);
    assert_eq!(f.call("GET",&legacy,Value::Null,Some(&f.admin_token)).await?.0,StatusCode::FORBIDDEN);
    for _ in 0..2 { assert_eq!(f.call("DELETE",&endpoint,Value::Null,Some(&f.member_token)).await?.0,StatusCode::NO_CONTENT); }
    assert_eq!(f.call("GET",&endpoint,Value::Null,Some(&f.admin_token)).await?.0,StatusCode::FORBIDDEN);
    let db=Connection::open(&f.database)?;
    assert_eq!(db.query_row("SELECT count(*) FROM network_remote_route_set_members WHERE set_id=?1 AND closed=1 AND promised_until>?2",params![request.set_id,current_ms()?],|row|row.get::<_,u64>(0))?,2);
    Ok(())
}

#[tokio::test]
async fn route_set_http_second_global_capacity_rejection_leaves_no_partial_path_or_allocation() -> Result {
    let f=Fixture::new(false).await?;
    let remote=setup_remote_with_path(&f,true,false)?;
    let nodes=[topology::registered_node(&f)?.0,topology::registered_node(&f)?.0];
    let mut store=Store::open_existing(&f.database,&f.deployment)?;
    let now=current_ms()?; let actor=store.authenticate(&f.admin_token,now/1000)?;
    let quota=store.relay_quota_current()?; let mut limits=quota.limits; limits.max_allocations=1;
    store.set_relay_quota(&actor,RelayQuotaUpdate {expected_revision:quota.revision,limits},now/1000)?;
    drop(store);
    let request=request(&f,&remote,&nodes)?;
    let issue=format!("{}/remote/{}/route-sets",f.base(),remote.request);
    let (status,body)=f.call("POST",&issue,serde_json::to_value(&request)?,Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::TOO_MANY_REQUESTS,"{body}");
    let db=Connection::open(&f.database)?;
    assert_eq!(db.query_row("SELECT count(*) FROM network_remote_route_sets WHERE set_id=?1",[&request.set_id],|row|row.get::<_,u64>(0))?,0);
    assert_eq!(db.query_row("SELECT count(*) FROM network_remote_route_set_members WHERE set_id=?1",[&request.set_id],|row|row.get::<_,u64>(0))?,0);
    assert_eq!(db.query_row("SELECT count(*) FROM network_remote_paths WHERE space_id=?1 AND path_grant_id=?2",params![f.space,request.path.path_grant_id],|row|row.get::<_,u64>(0))?,0);
    Ok(())
}
