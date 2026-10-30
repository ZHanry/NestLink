use super::*;
use crate::{
    InstallationIdentity, PermitSigner, relay::node_relay_transcript, verify_device_action,
};
use nestlink_protocol::{RelayAllocationClaims, RelayTransport, SCHEMA_VERSION};
fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn query() -> NodeResourceQueryClaims {
    NodeResourceQueryClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 1,
        node_id: id(2),
        runtime_id: id(3),
        runtime_generation: 2,
        policy_revision: 3,
        lease_sequence: 4,
        request_id: id(4),
        request_sequence: 5,
        issued_at_unix_ms: 10000,
        expires_at_unix_ms: 11000,
    }
}
fn allocation() -> RelayAllocationClaims {
    RelayAllocationClaims {
        node_endpoint_revision: 0,
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 1,
        allocation_id: id(5),
        session_id: id(6),
        node_id: id(2),
        runtime_id: id(3),
        runtime_generation: 2,
        node_key_sha256: vec![1; 32],
        controller_device_id: id(7),
        host_device_id: id(8),
        controller_key_sha256: vec![2; 32],
        host_key_sha256: vec![3; 32],
        controller_account_id: id(9),
        host_account_id: id(10),
        connection_generation: 1,
        policy_revision: 3,
        quota_revision: 6,
        session_binding_sha256: vec![4; 32],
        transports: vec![
            RelayTransport::QuicDatagram as i32,
            RelayTransport::WssStream as i32,
        ],
        grant_sequence: 1,
        issued_at_unix_ms: 9500,
        expires_at_unix_ms: 19500,
        bytes_per_second: 1000,
        bytes_per_allocation: 10000,
    }
}
fn snapshot(signed: &SignedNodeResourceQuery) -> Result<NodeResourceSnapshotClaims, ContractError> {
    Ok(NodeResourceSnapshotClaims {
        topology_publications_json: Vec::new(),
        network_routes: Vec::new(),
        query: Some(query()),
        query_sha256: digest(&signed.claims).to_vec(),
        allocation_issuer: PermitSigner::generate().public_key().to_vec(),
        quota_revision: 6,
        issued_at_unix_ms: 10000,
        expires_at_unix_ms: 11000,
        allocations: vec![allocation()],
    })
}
#[test]
fn signed_resource_queries_snapshots_and_allocations_have_distinct_domains()
-> Result<(), ContractError> {
    let node = NodeIdentity::generate();
    let master = PermitSigner::generate();
    let policy = master.node_policy_signer()?;
    let request = node.sign_resource_query(&query())?;
    assert_eq!(
        verify_resource_query(&request, &node.public_key())?,
        query()
    );
    assert!(verify_resource_query(&request, &NodeIdentity::generate().public_key()).is_err());
    let c = snapshot(&request)?;
    let response = policy.sign_resource_snapshot(&c)?;
    assert_eq!(
        verify_resource_snapshot(&response, &policy.public_key(), &request)?,
        c
    );
    assert!(verify_resource_snapshot(&response, &master.public_key(), &request).is_err());
    // Even with the same signing seed, a signature is only valid for its purpose.
    let same_key = NodeIdentity::from_seed(&policy.key.to_bytes());
    let swapped_query = SignedNodeResourceQuery {
        claims: response.claims.clone(),
        signature: response.signature.clone(),
    };
    assert!(verify_resource_query(&swapped_query, &same_key.public_key()).is_err());
    let allocation = master.sign_relay_allocation(&allocation())?;
    let swapped_response = SignedNodeResourceSnapshot {
        claims: allocation.claims,
        signature: allocation.signature,
    };
    assert!(verify_resource_snapshot(&swapped_response, &master.public_key(), &request).is_err());
    let mut changed = response.clone();
    changed.claims[0] ^= 1;
    assert!(verify_resource_snapshot(&changed, &policy.public_key(), &request).is_err());
    let mut other = query();
    other.request_id = id(11);
    assert!(
        verify_resource_snapshot(
            &response,
            &policy.public_key(),
            &node.sign_resource_query(&other)?
        )
        .is_err()
    );
    let mut digest_mismatch = c;
    digest_mismatch.query_sha256[0] ^= 1;
    assert!(
        verify_resource_snapshot(
            &policy.sign_resource_snapshot(&digest_mismatch)?,
            &policy.public_key(),
            &request
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn resource_metadata_is_bounded_ordered_and_tied_to_the_node_query() -> Result<(), ContractError> {
    let node = NodeIdentity::generate();
    let request = node.sign_resource_query(&query())?;
    let c = snapshot(&request)?;
    for mutation in 0..12 {
        let mut changed = c.clone();
        match mutation {
            0 => changed.expires_at_unix_ms += 1,
            1 => changed.expires_at_unix_ms = changed.issued_at_unix_ms,
            2 => changed.allocation_issuer.truncate(31),
            3 => changed.query_sha256.clear(),
            4 => changed.allocations.push(changed.allocations[0].clone()),
            5 => changed.allocations[0].runtime_id = id(11),
            6 => changed.allocations[0].runtime_generation += 1,
            7 => changed.allocations[0].security_epoch += 1,
            8 => changed.allocations[0].quota_revision += 1,
            9 => changed.allocations[0].issued_at_unix_ms = changed.issued_at_unix_ms + 1,
            10 => changed.allocations[0].expires_at_unix_ms = changed.issued_at_unix_ms,
            _ => changed
                .allocations
                .resize(129, changed.allocations[0].clone()),
        }
        assert!(changed.validate().is_err(), "mutation {mutation}");
    }
    for mutation in 0..5 {
        let mut changed = query();
        match mutation {
            0 => changed.request_id = "invalid".into(),
            1 => changed.request_sequence = 0,
            2 => changed.lease_sequence = i64::MAX as u64 + 1,
            3 => changed.expires_at_unix_ms += 1,
            _ => changed.expires_at_unix_ms = changed.issued_at_unix_ms,
        }
        assert!(node.sign_resource_query(&changed).is_err());
    }
    let oversized = SignedNodeResourceSnapshot {
        claims: vec![0; NODE_RESOURCE_MESSAGE_BYTES as usize + 1],
        signature: vec![0; 64],
    };
    assert_eq!(
        verify_resource_snapshot(&oversized, &node.public_key(), &request)
            .err()
            .map(|e| e.code),
        Some(ErrorCode::CapacityExceeded)
    );
    Ok(())
}
#[test]
fn endpoint_signatures_bind_transport_challenge_grant_and_endpoint() -> Result<(), ContractError> {
    let key = InstallationIdentity::generate();
    let c = allocation();
    let proof = node_relay_transcript(
        &c,
        &c.controller_device_id,
        RelayTransport::WssStream,
        &[1; 32],
    )?;
    let signature = key.sign_action(&proof)?;
    verify_device_action(&proof, &key.public_key(), &signature)?;
    let mut renewed = c.clone();
    renewed.grant_sequence += 1;
    for altered in [
        node_relay_transcript(
            &c,
            &c.controller_device_id,
            RelayTransport::QuicDatagram,
            &[1; 32],
        )?,
        node_relay_transcript(
            &c,
            &c.controller_device_id,
            RelayTransport::WssStream,
            &[2; 32],
        )?,
        node_relay_transcript(&c, &c.host_device_id, RelayTransport::WssStream, &[1; 32])?,
        node_relay_transcript(
            &renewed,
            &c.controller_device_id,
            RelayTransport::WssStream,
            &[1; 32],
        )?,
    ] {
        assert!(verify_device_action(&altered, &key.public_key(), &signature).is_err());
    }
    assert!(node_relay_transcript(&c, &id(11), RelayTransport::WssStream, &[1; 32]).is_err());
    Ok(())
}
