//! Observation authority is independent of transit and retains original expiry.
use super::*;
use nestlink_identity::{network::{NetworkAuthoritySigner, NetworkVerification}, network_topology::verify_topology_publisher};
use nestlink_protocol::{api::{NetworkNodeTopologyAuthority, NetworkNodeTopologyNeighbor, NodeEndpoints, NodeEndpointsView},network::{GrantScope,PeerId},network_topology::{BootIncarnation,TopologyPublisherClaims}};
use std::collections::BTreeSet;
type TestResult<T=()> = Result<T,Box<dyn std::error::Error>>;

fn authority(expires:u64)->TestResult<(NodeLeaseClaims,NetworkNodeTopologyAuthority)> {
    let local=NodeIdentity::from_seed(&[71;32]);
    let remote=NodeIdentity::from_seed(&[72;32]);
    let signer=NetworkAuthoritySigner::from_master_seed(&[73;32])?;
    let mut lease=lease();lease.node_key_sha256=digest(&local.public_key()).to_vec();
    let claims=TopologyPublisherClaims {
        scope:GrantScope {schema_version:1,deployment_id:lease.deployment_id.clone(),space_id:id(31),grant_id:id(32),policy_epoch:1,not_before_ms:10000,expires_at_ms:expires},
        node_id:lease.node_id.clone(),public_key:local.public_key(),peer:PeerId::from_public_key(&local.public_key()),
        incarnation:BootIncarnation {runtime_id:lease.runtime_id.clone(),runtime_generation:lease.runtime_generation},
        allowed_neighbors:vec![PeerId::from_public_key(&remote.public_key())],route_export_digests:vec![],allowed_prefixes:vec![],
    };
    let signed=signer.sign_topology_publisher(&claims)?;
    let key=signer.public_key();let revoked=BTreeSet::new();
    let context=NetworkVerification {authority_key:&key,deployment_id:&claims.scope.deployment_id,space_id:&claims.scope.space_id,policy_epoch:1,now_ms:10000,revoked_grant_ids:&revoked};
    let verified=verify_topology_publisher(&signed,&context,&lease.node_id,&local.public_key(),&claims.incarnation,&[])?;
    let endpoint=|node,port|NodeEndpointsView {node_id:node,revision:1,endpoints:NodeEndpoints {quic_uri:Some(format!("quic://127.0.0.1:{port}")),allow_loopback:true,..Default::default()}};
    Ok((lease.clone(),NetworkNodeTopologyAuthority {
        authority_key:key,publisher:signed,publisher_digest:verified.digest(),route_exports:vec![],local:endpoint(lease.node_id,31001),
        neighbors:vec![NetworkNodeTopologyNeighbor {public_key:remote.public_key(),publisher_digest:[31;32],incarnation:BootIncarnation {runtime_id:id(33),runtime_generation:1},expires_at_ms:expires,node:endpoint(id(34),31002)}],
    }))
}
fn publication_snapshot(sequence:u64,now:ClockSample,publications:&[NetworkNodeTopologyAuthority])->TestResult<NodeResourceSnapshotClaims> {
    let mut value=snapshot(sequence,now,vec![]);
    value.topology_publications_json=serde_json::to_vec(publications)?;
    Ok(value)
}

#[test]
fn observation_metadata_grants_no_forwarding_and_omission_removes_its_current_owner()->TestResult {
    let (lease,authority)=authority(15000)?;
    let mut resources=Resources::default();
    resources.accept(publication_snapshot(1,clock(0,10000),&[authority.clone()])?,&lease,0,clock(0,10000))?;
    let current=resources.snapshot.as_ref().ok_or("snapshot missing")?;
    assert_eq!(current.topology,vec![authority]);assert!(current.entries.is_empty());assert!(resources.pairs.is_empty());
    assert!(resources.reserve(&grant(),0,clock(0,10000)).is_err());
    resources.accept(publication_snapshot(2,clock(100,10100),&[])?,&lease,100,clock(100,10100))?;
    assert!(resources.snapshot.as_ref().ok_or("snapshot missing")?.topology.is_empty());
    Ok(())
}

#[test]
fn forged_publisher_wrong_runtime_and_unapproved_probe_targets_are_rejected()->TestResult {
    let (lease,original)=authority(15000)?;
    let mut cases=Vec::new();
    let mut altered=original.clone();altered.publisher.signature[0]^=1;cases.push(altered);
    let mut altered=original.clone();altered.authority_key[0]^=1;cases.push(altered);
    let mut altered=original.clone();altered.local.node_id=id(40);cases.push(altered);
    let mut altered=original.clone();altered.publisher_digest[0]^=1;cases.push(altered);
    let mut altered=original.clone();altered.neighbors[0].public_key=NodeIdentity::from_seed(&[74;32]).public_key();cases.push(altered);
    let mut altered=original.clone();altered.neighbors.push(altered.neighbors[0].clone());cases.push(altered);
    let mut altered=original.clone();altered.neighbors[0].node.endpoints.quic_uri=Some("quic://127.0.0.1:31002".into());altered.neighbors[0].node.endpoints.allow_loopback=false;cases.push(altered);
    for altered in cases {
        assert!(Resources::default().accept(publication_snapshot(1,clock(0,10000),&[altered])?,&lease,0,clock(0,10000)).is_err());
    }
    let mut wrong_runtime=lease.clone();wrong_runtime.runtime_generation+=1;
    let mut value=publication_snapshot(1,clock(0,10000),&[original.clone()])?;
    value.query.as_mut().ok_or("query missing")?.runtime_generation=wrong_runtime.runtime_generation;
    assert!(Resources::default().accept(value,&wrong_runtime,0,clock(0,10000)).is_err());
    assert!(Resources::default().accept(publication_snapshot(1,clock(0,10000),&[original.clone(),original])?,&lease,0,clock(0,10000)).is_err());
    Ok(())
}

#[test]
fn refreshed_observations_stop_and_wall_rollback_never_move_original_publisher_deadline()->TestResult {
    let (lease,authority)=authority(10500)?;
    let mut resources=Resources::default();
    resources.accept(publication_snapshot(1,clock(0,10000),&[authority.clone()])?,&lease,0,clock(0,10000))?;
    assert_eq!(resources.topology_deadlines[&authority.publisher_digest],500);
    resources.accept(publication_snapshot(2,clock(100,10010),&[authority.clone()])?,&lease,100,clock(100,10010))?;
    assert_eq!(resources.topology_deadlines[&authority.publisher_digest],500);
    resources.stop();
    resources.accept(publication_snapshot(3,clock(400,10020),&[authority.clone()])?,&lease,400,clock(400,10020))?;
    assert_eq!(resources.topology_deadlines[&authority.publisher_digest],500);
    Ok(())
}
