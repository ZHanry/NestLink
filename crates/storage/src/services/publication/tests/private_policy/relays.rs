//! Actual registered relay leases and signed topology reports exercise the
//! private transaction and the retained topology journal, without RemotePermit.
use super::*;
use crate::{
    network_policy::topology::TopologyPublisherRequest,
    relay_reservations::RelayLifecycle,
};
use nestlink_identity::{
    PermitSigner,
    network::verify_private_service_grant,
    network_topology::{
        SignedTopologyPublisher, verify_topology_advertisement, verify_topology_publisher,
    },
};
use nestlink_protocol::{
    NodeResourceQueryClaims,
    api::{RelayQuotaLimits, RelayQuotaUpdate},
    network::PeerId,
    network_topology::{BootIncarnation, TopologyNeighbor, TopologyReport},
};

struct PrivateChain {
    f: Fixture,
    access: PrivateAccess,
    lifecycle: RelayLifecycle,
    node_signer: NodePolicySigner,
    nodes: [(String, NodeIdentity, BootIncarnation); 2],
    leases: [NodeLeaseClaims; 2],
    publishers: [SignedTopologyPublisher; 2],
    reports: [TopologyReport; 2],
    digests: [[u8; 32]; 2],
    at: u64,
}

impl PrivateChain {
    fn new() -> Result<Self> {
        let mut f = Fixture::with_paths(PeerPathMode::DirectPreferred)?;
        let access = configure(&mut f)?;
        let mut nodes = Vec::new();
        let mut leases = Vec::new();
        for index in 0..2 {
            let identity = NodeIdentity::generate();
            let id = random_id();
            f.store.register_node(
                &f.creator,
                NodeRegistration {
                    id: id.clone(),
                    name: format!("private-chain-{index}"),
                    public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
                    roles: vec![NodeRole::NodeRelay as i32],
                    max_connections: 16,
                    bytes_per_second: 1_048_576,
                },
            )?;
            f.store.set_node_endpoints(
                &f.creator,
                &id,
                NodeEndpointsUpdate {
                    expected_revision: 0,
                    endpoints: NodeEndpoints {
                        quic_uri: Some(format!("quic://127.0.0.1:{}", 30100 + index)),
                        allow_loopback: true,
                        ..NodeEndpoints::default()
                    },
                },
                now()?,
            )?;
            let challenge = f.store.node_challenge(&id, now()?)?;
            let lease = f.store.issue_node_lease(
                &identity.prove(&challenge, &random_id())?,
                now()?,
            )?;
            nodes.push((
                id,
                identity,
                BootIncarnation {
                    runtime_id: lease.runtime_id.clone(),
                    runtime_generation: lease.runtime_generation,
                },
            ));
            leases.push(lease);
        }
        let nodes: [_; 2] = nodes.try_into().map_err(|_| "private relay count")?;
        let at = now()?;
        let snapshot = f.store.network_policy_snapshot(&access.exposure.space_id, at)?;
        let epoch = snapshot.verification().policy_epoch;
        let mut publishers = Vec::new();
        for index in 0..2 {
            publishers.push(f.store.issue_topology_publisher(
                &f.creator,
                &access.network,
                &access.exposure.space_id,
                &nodes[index].0,
                TopologyPublisherRequest {
                    publisher_id: random_id(),
                    expected_policy_epoch: epoch,
                    allowed_node_ids: vec![nodes[1 - index].0.clone()],
                    route_export_grant_ids: Vec::new(),
                    expires_at_ms: at + 60_000,
                },
                at,
            )?);
        }
        let publishers: [_; 2] = publishers.try_into().map_err(|_| "publisher count")?;
        let mut reports = Vec::new();
        let mut digests = Vec::new();
        for index in 0..2 {
            let (id, identity, incarnation) = &nodes[index];
            let publisher = verify_topology_publisher(
                &publishers[index],
                &snapshot.verification(),
                id,
                &identity.public_key(),
                incarnation,
                &[],
            )?;
            let report = TopologyReport {
                schema_version: 1,
                deployment_id: f.store.deployment_id()?,
                space_id: access.exposure.space_id.clone(),
                policy_epoch: epoch,
                node_id: id.clone(),
                peer: PeerId::from_public_key(&identity.public_key()),
                publisher_digest: publisher.digest(),
                incarnation: incarnation.clone(),
                sequence: 1,
                not_before_ms: at,
                expires_at_ms: at + 5000,
                neighbors: vec![TopologyNeighbor {
                    local: PeerId::from_public_key(&identity.public_key()),
                    remote: PeerId::from_public_key(&nodes[1 - index].1.public_key()),
                    local_endpoint_revision: 1,
                    remote_endpoint_revision: 1,
                    up: true,
                }],
                prefixes: Vec::new(),
            };
            let signed = f.store.accept_topology_report(
                &access.network,
                &access.exposure.space_id,
                id,
                &identity.sign_topology_report(&report)?,
                at,
            )?;
            let advertisement = verify_topology_advertisement(
                &signed,
                &publisher,
                &snapshot.verification(),
                incarnation,
                0,
            )?;
            digests.push(advertisement.digest());
            reports.push(report);
        }
        let lifecycle = f.store.relay_lifecycle(at)?;
        Ok(Self {
            f,
            access,
            lifecycle,
            node_signer: NodePolicySigner::from_master_seed(&[222; 32])?,
            nodes,
            leases: leases.try_into().map_err(|_| "lease count")?,
            publishers,
            reports: reports.try_into().map_err(|_| "report count")?,
            digests: digests.try_into().map_err(|_| "digest count")?,
            at,
        })
    }

    fn sign(&self, body: &mut PrivateServiceAccessRequest) -> Result {
        let signature = URL_SAFE_NO_PAD.encode(
            self.access.consumer_identity.sign_private_service_route(&self.f.view.id, body)?,
        );
        let PrivateServiceRouteRequest::Relay { signature: value, .. } = &mut body.route else {
            return Err("private relay selection missing".into());
        };
        *value = signature;
        Ok(())
    }

    fn request(&self) -> Result<PrivateServiceAccessRequest> {
        let mut body = request(&self.f, &self.access);
        body.maximum_bytes = 4096;
        body.route = PrivateServiceRouteRequest::Relay {
            node_ids: self.nodes.iter().map(|node| node.0.clone()).collect(),
            topology_digests: self.digests.to_vec(),
            signature: String::new(),
        };
        self.sign(&mut body)?;
        Ok(body)
    }

    fn issue(&mut self, body: PrivateServiceAccessRequest, at: u64) -> std::result::Result<PrivateServiceGrant, StorageError> {
        self.f.store.issue_private_service_grant(
            &self.lifecycle, &self.f.creator, &self.f.view.id, body,
            &self.f.service_signer, &self.access.network, &self.node_signer, at,
        )
    }

    fn quota(&mut self, allocations: u16) -> Result {
        let old = self.f.store.relay_quota_current()?;
        self.f.store.set_relay_quota(
            &self.f.creator,
            RelayQuotaUpdate {
                expected_revision: old.revision,
                limits: RelayQuotaLimits {
                    max_allocations: allocations,
                    max_account_endpoints: 4,
                    ..old.limits
                },
            },
            self.at / 1000,
        )?;
        Ok(())
    }

    fn report(&mut self, index: usize, sequence: u64, up: bool, at: u64) -> Result {
        let mut report = self.reports[index].clone();
        report.sequence = sequence;
        report.not_before_ms = at;
        report.expires_at_ms = at + 5000;
        report.neighbors[0].up = up;
        let (id, identity, incarnation) = &self.nodes[index];
        let snapshot = self.f.store.network_policy_snapshot(&self.access.exposure.space_id, at)?;
        let publisher = verify_topology_publisher(
            &self.publishers[index], &snapshot.verification(), id,
            &identity.public_key(), incarnation, &[],
        )?;
        let signed = self.f.store.accept_topology_report(
            &self.access.network, &self.access.exposure.space_id, id,
            &identity.sign_topology_report(&report)?, at,
        )?;
        self.digests[index] = verify_topology_advertisement(
            &signed, &publisher, &snapshot.verification(), incarnation, sequence - 1,
        )?.digest();
        self.reports[index] = report;
        Ok(())
    }

    fn held(&self, at: u64) -> Result<u64> {
        Ok(self.f.store.connection.query_row(
            "SELECT count(*) FROM all_relay_capacity WHERE promised_until>?1", [at], |r| r.get(0),
        )?)
    }
}

#[test]
fn private_two_hop_second_capacity_failure_rolls_back_service_and_both_hop_promises() -> Result {
    let mut f = PrivateChain::new()?;
    f.quota(1)?;
    let body = f.request()?;
    let before = f.f.store.audit_count()?;
    assert!(matches!(f.issue(body.clone(), f.at), Err(StorageError::RateLimited)));
    assert_eq!(f.f.store.audit_count()?, before);
    let count: u64 = f.f.store.connection.query_row(
        "SELECT (SELECT count(*) FROM private_service_leases)+(SELECT count(*) FROM private_service_relay_hops)+(SELECT count(*) FROM service_usage_grants)", [], |r| r.get(0),
    )?;
    assert_eq!(count, 0);
    assert_eq!(f.held(f.at)?, 0);
    ledgers(&mut f.f, 0, 0)?;
    // The exact request may succeed after capacity becomes available because
    // the first failed transaction retained no lease, audit or budget debit.
    f.quota(2)?;
    let grant = f.issue(body.clone(), f.at)?;
    let repeated = f.issue(body, f.at)?;
    assert_eq!(serde_json::to_vec(&grant)?, serde_json::to_vec(&repeated)?);
    let (_, _, _, transits) = verify_private_service_grant(
        &grant, &f.node_signer.public_key(), &f.f.store.deployment_id()?, f.at,
    )?;
    assert_eq!(transits.len(), 2);
    assert_eq!(f.held(f.at)?, 2);
    ledgers(&mut f.f, 0, 4096)?;
    Ok(())
}

#[test]
fn private_two_hop_refresh_preserves_exact_grants_and_down_up_cannot_revive_them() -> Result {
    let mut f = PrivateChain::new()?;
    let body = f.request()?;
    let grant = f.issue(body.clone(), f.at)?;
    let grant_id = grant.network.grant_id.clone();
    let original = serde_json::to_vec(&grant.network)?;
    let promised: u64 = f.f.store.connection.query_row(
        "SELECT sum(promised_until) FROM private_service_relay_hops WHERE grant_id=?1",
        [&grant_id], |r| r.get(0),
    )?;
    f.report(0, 2, true, f.at + 101)?;
    f.report(1, 2, true, f.at + 101)?;
    let current = f.f.store.private_service_network_path(
        &f.f.creator, &f.f.view.id, &grant_id, &f.f.service_signer, f.at + 101,
    )?;
    assert_eq!(serde_json::to_vec(&current)?, original);
    let retained: u64 = f.f.store.connection.query_row(
        "SELECT sum(promised_until) FROM private_service_relay_hops WHERE grant_id=?1",
        [&grant_id], |r| r.get(0),
    )?;
    assert_eq!(retained, promised);
    // No consumer, host inbox or resource poll observes the intermediate down.
    // The authenticated acceptance transaction itself must fence both hops.
    f.report(0, 3, false, f.at + 202)?;
    f.report(0, 4, true, f.at + 303)?;
    assert!(matches!(f.f.store.private_service_network_path(
        &f.f.creator, &f.f.view.id, &grant_id, &f.f.service_signer, f.at + 303,
    ), Err(StorageError::Forbidden)));
    assert!(matches!(f.issue(body, f.at + 303), Err(StorageError::Forbidden)));
    let closed: u64 = f.f.store.connection.query_row(
        "SELECT count(*) FROM private_service_relay_hops WHERE grant_id=?1 AND closed=1",
        [&grant_id], |r| r.get(0),
    )?;
    assert_eq!(closed, 2);
    assert_eq!(f.held(f.at + 303)?, 2);
    ledgers(&mut f.f, 0, 4096)?;
    let page = f.f.store.private_service_host_access(
        &f.f.creator, &f.f.view.id, &f.access.runtime,
        ServiceQuery { security_epoch: f.f.store.security_epoch()?, after_id: None, limit: 10 },
        &f.f.service_signer, &f.node_signer, f.at + 303,
    )?;
    assert!(page.grants.is_empty());
    let root = PermitSigner::from_seed([223; 32]);
    for index in 0..2 {
        let lease = &f.leases[index];
        let query = f.nodes[index].1.sign_resource_query(&NodeResourceQueryClaims {
            schema_version: SCHEMA_VERSION, deployment_id: lease.deployment_id.clone(),
            security_epoch: lease.security_epoch, node_id: lease.node_id.clone(),
            runtime_id: lease.runtime_id.clone(), runtime_generation: lease.runtime_generation,
            policy_revision: lease.policy_revision, lease_sequence: lease.lease_sequence,
            request_id: random_id(), request_sequence: 1, issued_at_unix_ms: f.at + 303,
            expires_at_unix_ms: f.at + 303 + NODE_RESOURCE_TTL_MS,
        })?;
        let snapshot = f.f.store.node_resource_snapshot_with_private_services(
            &f.lifecycle, &query, &root, &f.f.service_signer, &f.node_signer, f.at + 303,
        )?;
        assert!(snapshot.allocations.is_empty());
        assert!(snapshot.network_routes.is_empty());
    }
    assert_eq!(f.held(f.at + 303)?, 2);
    Ok(())
}

#[test]
fn expired_private_grant_is_omitted_after_same_runtime_presence_refresh() -> Result {
    let mut f = PrivateChain::new()?;
    let request = f.request()?;
    let grant = f.issue(request, f.at)?;
    let (business, _, _, _) = verify_private_service_grant(
        &grant, &f.node_signer.public_key(), &f.f.store.deployment_id()?, f.at,
    )?;
    let base = business.lease().claims();
    let expires = base.expires_at_unix_ms;
    let presence = PrivateServiceHostClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: base.deployment_id.clone(),
        security_epoch: base.security_epoch,
        policy_revision: base.policy_revision,
        service_id: base.service_id.clone(),
        service_revision: base.service_revision,
        exposure_revision: business.claims().exposure_revision,
        target_sha256: base.target_sha256,
        host_device_id: base.definition.host_device_id.clone(),
        runtime_id: f.access.runtime.clone(),
        request_sequence: 2,
        address: base.edge_service_address.clone(),
        issued_at_unix_ms: expires - 1,
        expires_at_unix_ms: expires + 5000,
    };
    f.f.store.register_private_service_host(
        &f.f.creator, &f.f.host.sign_private_service_host(&presence)?, expires - 1,
    )?;
    let page = f.f.store.private_service_host_access(
        &f.f.creator, &f.f.view.id, &f.access.runtime,
        ServiceQuery { security_epoch: f.f.store.security_epoch()?, after_id: None, limit: 10 },
        &f.f.service_signer, &f.node_signer, expires + 1,
    )?;
    assert!(page.grants.is_empty());
    let terminal: bool = f.f.store.connection.query_row(
        "SELECT terminal FROM service_usage_grants WHERE grant_id=?1",
        [&grant.network.grant_id], |r| r.get(0),
    )?;
    assert!(!terminal);
    // Discovery omission does not manufacture a usage seal or an early relay
    // close receipt. Both original promises still occupy their hold margin.
    assert_eq!(f.held(expires + 1)?, 2);
    ledgers(&mut f.f, 0, 4096)?;
    Ok(())
}
