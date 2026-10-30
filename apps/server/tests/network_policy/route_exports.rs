use super::*;
use nestlink_identity::network_topology::{verify_topology_publisher,verify_topology_update,SignedTopologyPublisher,SignedTopologyUpdate};
use nestlink_protocol::{api::NetworkGrantView,network::{IpPrefix,PeerId},network_topology::{TopologyChange,TopologyReport,TopologySync}};

fn signed(view: NetworkGrantView) -> Result<SignedNetworkGrant> {
    Ok(SignedNetworkGrant {claims:URL_SAFE_NO_PAD.decode(view.claims)?,signature:URL_SAFE_NO_PAD.decode(view.signature)?})
}

#[tokio::test]
async fn route_export_http_keeps_node_prefix_authority_separate_and_revokes_the_real_journal() -> Result {
    let f = Fixture::new(false).await?;
    f.setup_space().await?;
    let (node_id,node,incarnation) = topology::registered_node(&f)?;
    let now = current_ms()?;
    let mut store = Store::open_existing(&f.database,&f.deployment)?;
    let before = store.network_policy_snapshot(&f.space,now)?;
    let id = random_id();
    let endpoint = format!("{}/route-exports/{node_id}",f.base());
    let request = json!({"grant_id":id,"expected_revision":before.revision(),"expected_policy_epoch":2,"prefixes":[{"network":"10.40.0.0","prefix_len":24}],"expires_at_ms":now+60_000});
    assert_eq!(f.call("POST",&endpoint,request.clone(),None).await?.0,StatusCode::UNAUTHORIZED);
    assert_eq!(f.call("POST",&endpoint,request.clone(),Some(&f.member_token)).await?.0,StatusCode::FORBIDDEN);
    let (status,issued) = f.call("POST",&endpoint,request.clone(),Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::CREATED,"{issued}");
    let export = signed(serde_json::from_value(issued.clone())?)?;
    let read = format!("{}/route-export-grants/{id}",f.base());
    assert_eq!(f.call("GET",&read,Value::Null,Some(&f.admin_token)).await?.1,issued);
    assert_eq!(f.call("GET",&read,Value::Null,Some(&f.member_token)).await?.0,StatusCode::FORBIDDEN);
    assert_eq!(f.call("POST",&endpoint,request,Some(&f.admin_token)).await?.0,StatusCode::CONFLICT);
    let snapshot = store.network_policy_snapshot(&f.space,current_ms()?)?;
    let export = verify_network_grant(&export,&snapshot.verification())?;
    let GrantClaims::RouteExport(claims) = export.claims() else { return Err("unexpected grant kind".into()); };
    assert_eq!(claims.gateway,PeerId::from_public_key(&node.public_key()));
    let publishers = format!("{}/topology/publishers/{node_id}",f.base());
    let (status,body) = f.call("POST",&publishers,json!({"publisher_id":random_id(),"expected_policy_epoch":2,"allowed_node_ids":[],"route_export_grant_ids":[id],"expires_at_ms":now+50_000}),Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::CREATED,"{body}");
    let publisher: SignedTopologyPublisher = serde_json::from_value(body)?;
    let snapshot = store.network_policy_snapshot(&f.space,current_ms()?)?;
    let publisher = verify_topology_publisher(&publisher,&snapshot.verification(),&node_id,&node.public_key(),&incarnation,std::slice::from_ref(&export))?;
    let issued_at = current_ms()?;
    let report = node.sign_topology_report(&TopologyReport {
        schema_version:1,deployment_id:f.deployment.clone(),space_id:f.space.clone(),policy_epoch:2,node_id:node_id.clone(),
        peer:publisher.claims().peer,publisher_digest:publisher.digest(),incarnation,sequence:1,not_before_ms:issued_at,expires_at_ms:issued_at+5000,
        neighbors:vec![],prefixes:vec![IpPrefix {network:"10.40.0.0".parse()?,prefix_len:24}],
    })?;
    let reports = format!("{}/topology/reports/{node_id}",f.base());
    let (status,body) = f.call("POST",&reports,serde_json::to_value(&report)?,None).await?;
    assert_eq!(status,StatusCode::OK,"{body}");
    let snapshot = store.network_policy_snapshot(&f.space,current_ms()?)?;
    let revision = snapshot.revision();
    assert_eq!(f.call("DELETE",&read,json!({"expected_revision":revision}),Some(&f.member_token)).await?.0,StatusCode::FORBIDDEN);
    let (status,body) = f.call("DELETE",&read,json!({"expected_revision":revision}),Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::OK,"{body}");
    assert_eq!(f.call("GET",&read,Value::Null,Some(&f.admin_token)).await?.0,StatusCode::FORBIDDEN);
    assert_eq!(f.call("GET",&publishers,Value::Null,Some(&f.admin_token)).await?.0,StatusCode::FORBIDDEN);
    assert_eq!(f.call("POST",&reports,serde_json::to_value(&report)?,None).await?.0,StatusCode::FORBIDDEN);
    let nonce = [91u8;32];
    let (status,body) = f.call("POST",&format!("{}/topology/query",f.base()),json!({"nonce":nonce,"after_cursor":1}),Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::OK,"{body}");
    let update: SignedTopologyUpdate = serde_json::from_value(body)?;
    let snapshot = store.network_policy_snapshot(&f.space,current_ms()?)?;
    let update = verify_topology_update(&update,&snapshot.verification(),&nonce)?;
    assert!(matches!(&update.claims().sync,TopologySync::Delta {after_cursor:1,cursor:2,changes,..} if changes.len()==1 && matches!(&changes[0].change,TopologyChange::Withdraw(w) if w.node_id==node_id && w.sequence==1)));
    Ok(())
}
