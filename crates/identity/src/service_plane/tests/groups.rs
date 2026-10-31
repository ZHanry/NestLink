use super::*;
use nestlink_protocol::service_plane::group::*;

fn grouped()->Result<Fixture,ContractError>{
    let mut fixture=Fixture::new()?;
    let limits=ServiceLimits{maximum_connections:1,bytes_per_second:2048,maximum_bytes:32768,idle_timeout_seconds:5};
    let group=ServiceEdgeGroupView{group_version:1,group_id:id(20),revision:2,service_id:fixture.claims.service_id.clone(),service_revision:fixture.claims.service_revision,definition_sha256:fixture.claims.definition_sha256,target_sha256:fixture.claims.target_sha256,public_ips:vec!["1.1.1.1".parse().map_err(|_|invalid())?],members:vec![ServiceEdgeGroupMember{node_id:id(8),namespace_revision:1,ingress_ip:"192.168.40.2".parse().map_err(|_|invalid())?,limits},ServiceEdgeGroupMember{node_id:id(13),namespace_revision:1,ingress_ip:"192.168.40.3".parse().map_err(|_|invalid())?,limits}]};
    let hash=super::super::group::service_edge_group_digest(&group)?;
    let mut claims=fixture.claims.clone();
    claims.edge_group=Some(ServiceEdgeGroupBinding{group,member_node_id:id(13),allocation:limits,aggregate_sha256:hash});
    fixture.resign_usage_grant(&mut claims)?;fixture.claims=claims;Ok(fixture)
}
#[test]
fn group_signature_cannot_be_read_as_legacy_single_edge_authority()->Result<(),ContractError>{
    let legacy=Fixture::new()?;
    assert!(serde_json::to_value(&legacy.claims).map_err(|_|invalid())?.get("edge_group").is_none());
    let fixture=grouped()?;let signed=fixture.service.sign(&fixture.claims)?;
    let lease=verify_service_lease(&signed,&fixture.service.public_key())?;
    assert_eq!(lease.claims().definition.edge_node_id,id(8));assert_eq!(lease.claims().edge_node_id(),id(13));
    assert_eq!(lease.claims().effective_limits().maximum_connections,1);
    assert!(verify_signature(&fixture.service.public_key(),LEASE,&signed.claims,&signed.signature).is_err());
    Ok(())
}
#[test]
fn group_digest_member_target_and_aggregate_capacity_are_all_bound()->Result<(),ContractError>{
    let fixture=grouped()?;
    for change in 0..6 {
        let mut claims=fixture.claims.clone();let binding=claims.edge_group.as_mut().ok_or_else(invalid)?;
        match change {
            0=>binding.aggregate_sha256[0]^=1,
            1=>binding.group.target_sha256[0]^=1,
            2=>binding.group.members[1].limits.maximum_bytes+=1,
            3=>binding.group.members[1].limits.maximum_connections+=1,
            4=>binding.group.members[1].limits.bytes_per_second+=1,
            _=>binding.member_node_id=id(14),
        }
        assert!(fixture.service.sign(&claims).is_err());
    }
    Ok(())
}
#[test]
fn snapshot_uses_actual_group_member_and_refuses_original_definition_edge()->Result<(),ContractError>{
    let fixture=grouped()?;let mut query=fixture.query();query.node_id=id(13);
    let request=fixture.edge.sign_service_query(&query)?;
    let snapshot=ServiceResourceSnapshot{query:query.clone(),query_sha256:digest(&request.claims),service_lease_issuer:fixture.service.public_key(),issued_at_unix_ms:10000,expires_at_unix_ms:11000,leases:vec![fixture.service.sign(&fixture.claims)?]};
    let signed=fixture.policy.sign_service_snapshot(&snapshot)?;
    verify_service_snapshot(&signed,&fixture.policy.public_key(),&request,&fixture.edge.public_key())?;
    query.node_id=id(8);let request=fixture.edge.sign_service_query(&query)?;
    let snapshot=ServiceResourceSnapshot{query,query_sha256:digest(&request.claims),..snapshot};
    let signed=fixture.policy.sign_service_snapshot(&snapshot)?;
    assert!(verify_service_snapshot(&signed,&fixture.policy.public_key(),&request,&fixture.edge.public_key()).is_err());Ok(())
}
