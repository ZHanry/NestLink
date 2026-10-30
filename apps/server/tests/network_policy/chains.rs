use super::*;
use nestlink_identity::{network::remote_chain_reservation_transcript,network_topology::*};
use nestlink_protocol::{
    api::{NetworkRemotePathRequest,NetworkRemoteRelayChainRequest},
    network::PeerId,
    network_topology::{TopologyReport,TopologyNeighbor},
};
use nestlink_storage::network_policy::topology::TopologyPublisherRequest;

#[tokio::test]
async fn chain_http_authenticates_atomic_reservation_exact_readback_and_held_revocation() -> Result {
    let f = Fixture::new(false).await?;
    let remote = setup_remote_with_path(&f,true,false)?;
    let nodes = [topology::registered_node(&f)?,topology::registered_node(&f)?];
    let mut store = Store::open_existing(&f.database,&f.deployment)?;
    let now = current_ms()?;
    let actor = store.authenticate(&f.admin_token,now/1000)?;
    let signer = PermitSigner::from_seed([44;32]).network_authority_signer()?;
    let mut publishers = Vec::new();
    for index in 0..2 {
        publishers.push(store.issue_topology_publisher(&actor,&signer,&f.space,&nodes[index].0,TopologyPublisherRequest {
            publisher_id:random_id(),expected_policy_epoch:3,allowed_node_ids:vec![nodes[1-index].0.clone()],expires_at_ms:now+30_000,
        },now)?);
    }
    let snapshot = store.network_policy_snapshot(&f.space,now)?;
    let mut digests = Vec::new();
    for index in 0..2 {
        let (id,node,incarnation) = &nodes[index];
        let publisher = verify_topology_publisher(&publishers[index],&snapshot.verification(),id,&node.public_key(),incarnation,&[])?;
        let report = node.sign_topology_report(&TopologyReport {
            schema_version:1,deployment_id:f.deployment.clone(),space_id:f.space.clone(),policy_epoch:3,
            node_id:id.clone(),peer:PeerId::from_public_key(&node.public_key()),publisher_digest:publisher.digest(),
            incarnation:incarnation.clone(),sequence:1,not_before_ms:now,expires_at_ms:now+6000,
            neighbors:vec![TopologyNeighbor {
                local:PeerId::from_public_key(&node.public_key()),remote:PeerId::from_public_key(&nodes[1-index].1.public_key()),
                local_endpoint_revision:1,remote_endpoint_revision:1,up:true,
            }],prefixes:Vec::new(),
        })?;
        let signed = store.accept_topology_report(&signer,&f.space,id,&report,now)?;
        digests.push(verify_topology_advertisement(&signed,&publisher,&snapshot.verification(),incarnation,0)?.digest());
    }
    let business = store.current_permit(&actor,&remote.request,now/1000)?;
    let mut request = NetworkRemoteRelayChainRequest {
        route_id:random_id(),path:NetworkRemotePathRequest {
            connectivity_grant_id:random_id(),path_grant_id:random_id(),
            controller_membership_grant_id:remote.controller_membership.clone(),host_membership_grant_id:remote.host_membership.clone(),
            expected_policy_epoch:3,expires_at_unix_ms:(now+4000).min(remote.expires_at_ms),
        },
        node_ids:nodes.each_ref().map(|node|node.0.clone()),transit_grant_ids:[random_id(),random_id()],
        topology_digests:digests.try_into().map_err(|_|"digests")?,device_id:business.controller_device_id.clone(),signature:String::new(),
    };
    request.signature = URL_SAFE_NO_PAD.encode(remote.controller_key.sign_action(&remote_chain_reservation_transcript(&business,&actor.account_id,&f.space,&request)?)?);
    drop(store);
    let issue = format!("{}/remote/{}/relay-chains",f.base(),remote.request);
    let endpoint = format!("{}/relay-chains/{}",f.base(),request.route_id);
    let body = serde_json::to_value(&request)?;
    assert_eq!(f.call("POST",&issue,body.clone(),None).await?.0,StatusCode::UNAUTHORIZED);
    let mut tampered = request.clone();
    tampered.node_ids.swap(0,1);
    assert!(f.call("POST",&issue,serde_json::to_value(tampered)?,Some(&f.admin_token)).await?.0.is_client_error());
    let (status,issued) = f.call("POST",&issue,body.clone(),Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::CREATED,"{issued}");
    assert_eq!(issued["route_id"],request.route_id);
    assert_eq!(issued["nodes"][0]["node_id"],nodes[0].0);
    assert_eq!(issued["nodes"][1]["node_id"],nodes[1].0);
    for token in [&f.admin_token,&f.member_token] {
        let (status,read) = f.call("GET",&endpoint,Value::Null,Some(token)).await?;
        assert_eq!(status,StatusCode::OK,"{read}");
        assert_eq!(read,issued);
    }
    assert_eq!(f.call("POST",&issue,body,Some(&f.admin_token)).await?.0,StatusCode::CONFLICT);
    assert_eq!(f.call("DELETE",&endpoint,Value::Null,Some(&f.member_token)).await?.0,StatusCode::NO_CONTENT);
    assert_eq!(f.call("GET",&endpoint,Value::Null,Some(&f.admin_token)).await?.0,StatusCode::FORBIDDEN);
    let db = Connection::open(&f.database)?;
    assert_eq!(db.query_row("SELECT count(*) FROM network_remote_chain_hops WHERE route_id=?1 AND closed=1 AND promised_until>?2",params![request.route_id,current_ms()?],|r|r.get::<_,u64>(0))?,2);
    Ok(())
}
