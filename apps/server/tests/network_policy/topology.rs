use super::*;
use nestlink_identity::{nodes::NodeIdentity,network_topology::*};
use nestlink_protocol::{
    NodeRole,
    api::{NodeRegistration,NodeEndpoints,NodeEndpointsUpdate},
    network_topology::{BootIncarnation,TopologyPublisherClaims,TopologyReport,TopologySync,TopologyChange},
};

fn registered_node(f:&Fixture) -> Result<(String,NodeIdentity,BootIncarnation)> {
    let now = current_ms()?;
    let mut store = Store::open_existing(&f.database,&f.deployment)?;
    let actor = store.authenticate(&f.admin_token,now/1000)?;
    let node = NodeIdentity::generate();
    let id = random_id();
    store.register_node(&actor,NodeRegistration {id:id.clone(),name:"topology HTTP node".into(),public_key:URL_SAFE_NO_PAD.encode(node.public_key()),roles:vec![NodeRole::NodeRelay as i32],max_connections:16,bytes_per_second:1024*1024})?;
    store.set_node_endpoints(&actor,&id,NodeEndpointsUpdate {expected_revision:0,endpoints:NodeEndpoints {quic_uri:Some("quic://127.0.0.1:31001".into()),wss_origin:None,allow_loopback:true}},now)?;
    let runtime_id = random_id();
    let challenge = store.node_challenge(&id,now)?;
    let lease = store.issue_node_lease(&node.prove(&challenge,&runtime_id)?,now)?;
    Ok((id,node,BootIncarnation {runtime_id,runtime_generation:lease.runtime_generation}))
}

#[tokio::test]
async fn topology_http_authenticates_node_reports_and_signs_query_bound_withdrawals() -> Result {
    let f = Fixture::new(false).await?;
    f.setup_space().await?;
    let (node_id,node,incarnation) = registered_node(&f)?;
    let publishers = format!("{}/topology/publishers/{node_id}",f.base());
    let request = json!({"publisher_id":random_id(),"expected_policy_epoch":2,"allowed_node_ids":[],"expires_at_ms":current_ms()?+60_000});
    assert_eq!(f.call("POST",&publishers,request.clone(),None).await?.0,StatusCode::UNAUTHORIZED);
    assert_eq!(f.call("POST",&publishers,request.clone(),Some(&f.member_token)).await?.0,StatusCode::FORBIDDEN);
    let (status,body) = f.call("POST",&publishers,request,Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::CREATED,"{body}");
    let signed_publisher: SignedTopologyPublisher = serde_json::from_value(body.clone())?;
    assert_eq!(f.call("GET",&publishers,Value::Null,Some(&f.admin_token)).await?.1,body);
    let claims = TopologyPublisherClaims::decode_canonical(&signed_publisher.claims)?;
    assert_eq!(claims.incarnation,incarnation);
    let revoked = BTreeSet::new();
    let now = current_ms()?;
    let context = NetworkVerification {authority_key:&f.issuer,deployment_id:&f.deployment,space_id:&f.space,policy_epoch:2,now_ms:now,revoked_grant_ids:&revoked};
    let publisher = verify_topology_publisher(&signed_publisher,&context,&node_id,&node.public_key(),&incarnation,&[])?;
    let report = node.sign_topology_report(&TopologyReport {schema_version:1,deployment_id:f.deployment.clone(),space_id:f.space.clone(),policy_epoch:2,node_id:node_id.clone(),peer:publisher.claims().peer,publisher_digest:publisher.digest(),incarnation:incarnation.clone(),sequence:1,not_before_ms:now,expires_at_ms:now+5000,neighbors:Vec::new(),prefixes:Vec::new()})?;
    let reports = format!("{}/topology/reports/{node_id}",f.base());
    let mut invalid = report.clone(); invalid.signature[0] ^= 1;
    assert_eq!(f.call("POST",&reports,serde_json::to_value(invalid)?,None).await?.0,StatusCode::FORBIDDEN);
    let (status,ad) = f.call("POST",&reports,serde_json::to_value(&report)?,None).await?;
    assert_eq!(status,StatusCode::OK,"{ad}");
    let signed_ad: SignedTopologyAdvertisement = serde_json::from_value(ad.clone())?;
    let mut context = context;
    context.now_ms = current_ms()?;
    let verified = verify_topology_advertisement(&signed_ad,&publisher,&context,&incarnation,0)?;
    assert_eq!(verified.claims().report.sequence,1);
    let (status,retry) = f.call("POST",&reports,serde_json::to_value(&report)?,None).await?;
    assert_eq!(status,StatusCode::OK,"{retry}");
    assert_eq!(retry,ad,"exact HTTP retry extended or changed the observation");
    let query = format!("{}/topology/query",f.base());
    let nonce = [83u8;32];
    let (status,full) = f.call("POST",&query,json!({"nonce":nonce,"after_cursor":null}),Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::OK,"{full}");
    let full: SignedTopologyUpdate = serde_json::from_value(full)?;
    context.now_ms = current_ms()?;
    let full = verify_topology_update(&full,&context,&nonce)?;
    assert!(matches!(&full.claims().sync,TopologySync::Full {cursor:1,advertisements} if advertisements.len()==1));
    assert_eq!(f.call("DELETE",&publishers,Value::Null,Some(&f.admin_token)).await?.0,StatusCode::NO_CONTENT);
    let nonce = [84u8;32];
    let (status,delta) = f.call("POST",&query,json!({"nonce":nonce,"after_cursor":1}),Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::OK,"{delta}");
    let delta: SignedTopologyUpdate = serde_json::from_value(delta)?;
    context.now_ms = current_ms()?;
    let delta = verify_topology_update(&delta,&context,&nonce)?;
    assert!(matches!(&delta.claims().sync,TopologySync::Delta {after_cursor:1,cursor:2,changes,..} if changes.len()==1 && matches!(&changes[0].change,TopologyChange::Withdraw(w) if w.sequence==1)));
    assert_eq!(f.call("POST",&reports,serde_json::to_value(report)?,None).await?.0,StatusCode::FORBIDDEN);
    assert_eq!(f.call("POST",&query,json!({"nonce":vec![0u8;32],"after_cursor":2}),Some(&f.admin_token)).await?.0,StatusCode::BAD_REQUEST);
    Ok(())
}
