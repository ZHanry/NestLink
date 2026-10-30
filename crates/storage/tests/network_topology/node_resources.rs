//! Real signed resource queries bootstrap observation rights, never transit.
use super::*;
use nestlink_identity::{
    PermitSigner,
    network::{SignedNetworkGrant, verify_network_grant},
    node_resources::verify_resource_snapshot,
};
use nestlink_protocol::{
    NodeResourceQueryClaims,
    api::{NetworkNodeTopologyAuthority, NetworkRouteExportRequest},
    network::IpPrefix,
};
use nestlink_storage::relay_reservations::RelayLifecycle;

fn snapshot(
    f: &mut Fixture,
    lifecycle: &RelayLifecycle,
    index: usize,
    sequence: u64,
    now: u64,
) -> Result<Vec<NetworkNodeTopologyAuthority>> {
    let lease = &f.leases[index];
    let query = f.nodes[index]
        .1
        .sign_resource_query(&NodeResourceQueryClaims {
            schema_version: nestlink_protocol::SCHEMA_VERSION,
            deployment_id: lease.deployment_id.clone(),
            security_epoch: lease.security_epoch,
            node_id: lease.node_id.clone(),
            runtime_id: lease.runtime_id.clone(),
            runtime_generation: lease.runtime_generation,
            policy_revision: lease.policy_revision,
            lease_sequence: lease.lease_sequence,
            request_id: random_id(),
            request_sequence: sequence,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + 1000,
        })?;
    let root = PermitSigner::from_seed([61; 32]);
    let claims = f
        .store
        .node_resource_snapshot_with_network(lifecycle, &query, &root, now)?;
    // Publication/probe authority never creates or spends a business resource.
    assert!(claims.allocations.is_empty());
    assert!(claims.network_routes.is_empty());
    let policy = root.node_policy_signer()?;
    let mut signed = policy.sign_resource_snapshot(&claims)?;
    let verified = verify_resource_snapshot(&signed, &policy.public_key(), &query)?;
    let publications = if verified.topology_publications_json.is_empty() {
        Vec::new()
    } else {
        serde_json::from_slice(&verified.topology_publications_json)?
    };
    signed.claims.push(0);
    assert!(verify_resource_snapshot(&signed, &policy.public_key(), &query).is_err());
    Ok(publications)
}

fn replace_publisher(f: &mut Fixture, index: usize, allowed: bool, now: u64) -> Result {
    f.publishers[index] = f.store.issue_topology_publisher(
        &f.actor,
        &f.signer,
        &f.space,
        &f.nodes[index].0,
        TopologyPublisherRequest {
            publisher_id: random_id(),
            expected_policy_epoch: 1,
            allowed_node_ids: if allowed {
                vec![f.nodes[1 - index].0.clone()]
            } else {
                Vec::new()
            },
            route_export_grant_ids: Vec::new(),
            expires_at_ms: NOW + 60_000,
        },
        now,
    )?;
    Ok(())
}

#[test]
fn bootstrap_uses_current_mutually_allowed_publishers_and_exact_registered_endpoints() -> Result {
    let mut f = Fixture::new()?;
    let lifecycle = f.store.relay_lifecycle(NOW + 2)?;
    for index in 0..2 {
        let publications = snapshot(&mut f, &lifecycle, index, 1, NOW + 3)?;
        assert_eq!(publications.len(), 1);
        let publication = &publications[0];
        assert_eq!(publication.publisher.claims, f.publishers[index].claims);
        assert_eq!(
            publication.publisher.signature,
            f.publishers[index].signature
        );
        assert_eq!(publication.authority_key, f.signer.public_key());
        assert_eq!(publication.local.node_id, f.nodes[index].0);
        assert_eq!(publication.local.revision, 1);
        assert!(publication.route_exports.is_empty());
        assert_eq!(publication.neighbors.len(), 1);
        let neighbor = &publication.neighbors[0];
        assert_eq!(neighbor.public_key, f.nodes[1 - index].1.public_key());
        assert_eq!(neighbor.incarnation, f.nodes[1 - index].2);
        assert_eq!(neighbor.node.node_id, f.nodes[1 - index].0);
        assert_eq!(neighbor.node.revision, 1);
        assert_eq!(
            neighbor.expires_at_ms,
            f.leases[1 - index].expires_at_unix_ms
        );
    }
    replace_publisher(&mut f, 1, false, NOW + 10)?;
    assert!(
        snapshot(&mut f, &lifecycle, 0, 2, NOW + 10)?[0]
            .neighbors
            .is_empty()
    );
    assert!(
        snapshot(&mut f, &lifecycle, 1, 2, NOW + 10)?[0]
            .neighbors
            .is_empty()
    );
    replace_publisher(&mut f, 1, true, NOW + 20)?;
    assert_eq!(
        snapshot(&mut f, &lifecycle, 0, 3, NOW + 20)?[0]
            .neighbors
            .len(),
        1
    );
    Ok(())
}

#[test]
fn publisher_revocation_omits_local_authority_and_remote_bootstrap_without_granting_transit()
-> Result {
    let mut f = Fixture::new()?;
    let lifecycle = f.store.relay_lifecycle(NOW + 2)?;
    f.store
        .revoke_topology_publisher(&f.actor, &f.space, &f.nodes[1].0, NOW + 10)?;
    assert!(snapshot(&mut f, &lifecycle, 1, 1, NOW + 10)?.is_empty());
    assert!(
        snapshot(&mut f, &lifecycle, 0, 1, NOW + 10)?[0]
            .neighbors
            .is_empty()
    );
    f.restart()?;
    assert!(snapshot(&mut f, &lifecycle, 1, 2, NOW + 20)?.is_empty());
    Ok(())
}

#[test]
fn publisher_deadline_removes_bootstrap_even_while_both_registered_node_leases_are_live() -> Result
{
    let mut f = Fixture::new()?;
    let lifecycle = f.store.relay_lifecycle(NOW + 2)?;
    f.publishers[1] = f.store.issue_topology_publisher(
        &f.actor,
        &f.signer,
        &f.space,
        &f.nodes[1].0,
        TopologyPublisherRequest {
            publisher_id: random_id(),
            expected_policy_epoch: 1,
            allowed_node_ids: vec![f.nodes[0].0.clone()],
            route_export_grant_ids: Vec::new(),
            expires_at_ms: NOW + 200,
        },
        NOW + 10,
    )?;
    assert_eq!(
        snapshot(&mut f, &lifecycle, 0, 1, NOW + 199)?[0]
            .neighbors
            .len(),
        1
    );
    assert!(
        snapshot(&mut f, &lifecycle, 0, 2, NOW + 200)?[0]
            .neighbors
            .is_empty()
    );
    assert!(snapshot(&mut f, &lifecycle, 1, 1, NOW + 200)?.is_empty());
    Ok(())
}

#[test]
fn exact_route_export_envelopes_are_delegated_and_revocation_removes_dependent_authority() -> Result
{
    let mut f = Fixture::new()?;
    let lifecycle = f.store.relay_lifecycle(NOW + 2)?;
    let current = f.store.network_policy_snapshot(&f.space, NOW + 10)?;
    let id = random_id();
    let export = f.store.issue_network_route_export(
        &f.actor,
        &f.signer,
        &f.space,
        &f.nodes[0].0,
        NetworkRouteExportRequest {
            grant_id: id.clone(),
            expected_revision: current.revision(),
            expected_policy_epoch: current.policy_epoch(),
            prefixes: vec![IpPrefix {
                network: "10.60.0.0".parse()?,
                prefix_len: 24,
            }],
            expires_at_ms: NOW + 5000,
        },
        NOW + 10,
    )?;
    f.publishers[0] = f.store.issue_topology_publisher(
        &f.actor,
        &f.signer,
        &f.space,
        &f.nodes[0].0,
        TopologyPublisherRequest {
            publisher_id: random_id(),
            expected_policy_epoch: 1,
            allowed_node_ids: vec![f.nodes[1].0.clone()],
            route_export_grant_ids: vec![id.clone()],
            expires_at_ms: NOW + 5000,
        },
        NOW + 10,
    )?;
    let publications = snapshot(&mut f, &lifecycle, 0, 1, NOW + 10)?;
    let publication = &publications[0];
    assert_eq!(publication.route_exports.len(), 1);
    let delegated = &publication.route_exports[0];
    assert_eq!(delegated.claims, export.claims);
    assert_eq!(delegated.signature, export.signature);
    let current = f.store.network_policy_snapshot(&f.space, NOW + 10)?;
    let proof = verify_network_grant(
        &SignedNetworkGrant {
            claims: delegated.claims.clone(),
            signature: delegated.signature.clone(),
        },
        &current.verification(),
    )?;
    let verified = verify_topology_publisher(
        &publication.publisher,
        &current.verification(),
        &f.nodes[0].0,
        &f.nodes[0].1.public_key(),
        &f.nodes[0].2,
        &[proof],
    )?;
    assert_eq!(verified.digest(), publication.publisher_digest);
    f.store
        .revoke_network_route_export(&f.actor, &f.space, &id, current.revision(), NOW + 20)?;
    assert!(snapshot(&mut f, &lifecycle, 0, 2, NOW + 20)?.is_empty());
    assert!(
        snapshot(&mut f, &lifecycle, 1, 1, NOW + 20)?[0]
            .neighbors
            .is_empty()
    );
    Ok(())
}

#[test]
fn expired_neighbor_lease_is_removed_while_independently_renewed_local_node_remains_current()
-> Result {
    let mut f = Fixture::new()?;
    let renew_at = NOW + 9500;
    let challenge = f.store.node_challenge(&f.nodes[0].0, renew_at)?;
    f.leases[0] = f.store.issue_node_lease(
        &f.nodes[0].1.prove(&challenge, &f.nodes[0].2.runtime_id)?,
        renew_at,
    )?;
    let now = f.leases[1].expires_at_unix_ms;
    let lifecycle = f.store.relay_lifecycle(now)?;
    let publications = snapshot(&mut f, &lifecycle, 0, 1, now)?;
    assert_eq!(publications.len(), 1);
    assert!(publications[0].neighbors.is_empty());
    assert!(snapshot(&mut f, &lifecycle, 1, 1, now).is_err());
    Ok(())
}
