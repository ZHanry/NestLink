use super::*;
use crate::{
    control::{Runtime, resources},
    gate::NodeGate,
    meter::Meter,
    service_plane::{
        IngressNamespace, IngressOwnership, ServiceResourceSet, ServiceTcpIngress, test_support::*,
    },
};
use nestlink_identity::{
    digest,
    nodes::NodePolicySigner,
    service_plane::{VerifiedServiceSnapshot, verify_service_snapshot},
};
use nestlink_protocol::{
    NODE_RESOURCE_TTL_MS, NodeChallenge, NodeResourceQueryClaims, SCHEMA_VERSION,
    api::ServiceIngress,
    service_plane::{
        ServiceResourceSnapshot, SignedServiceResourceQuery, SignedServiceResourceSnapshot,
    },
};
use nestlink_session::ClockSample;
use nestlink_traversal::turn::TurnAuthorization;
use prost::Message;
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
};

fn control(fixture: &Fixture, public: bool) -> TestResult<(NodeControl, NodePolicySigner)> {
    control_with_runtime(
        fixture,
        public,
        fixture.claims.edge_runtime_id.clone(),
        fixture.claims.edge_runtime_generation,
    )
}
fn control_with_runtime(
    fixture: &Fixture,
    public: bool,
    runtime_id: String,
    runtime_generation: u64,
) -> TestResult<(NodeControl, NodePolicySigner)> {
    let policy = NodePolicySigner::from_master_seed(&[61; 32])?;
    let started = Instant::now();
    let now = wall()?;
    let c = &fixture.claims;
    let challenge = NodeChallenge {
        schema_version: SCHEMA_VERSION,
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        node_id: c.definition.edge_node_id.clone(),
        node_key_sha256: c.edge_key_sha256.to_vec(),
        request_id: id(21),
        nonce: vec![2; 32],
        expires_at_unix_ms: now + 2000,
    };
    let node_lease = NodeLeaseClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        node_id: c.definition.edge_node_id.clone(),
        runtime_id: runtime_id.clone(),
        runtime_generation,
        node_key_sha256: c.edge_key_sha256.to_vec(),
        request_id: challenge.request_id.clone(),
        nonce: challenge.nonce.clone(),
        roles: vec![NodeRole::NodeEdge as i32],
        policy_revision: c.policy_revision,
        lease_sequence: 1,
        issued_at_unix_ms: now,
        expires_at_unix_ms: now + 10000,
        server_forwarding_allowed: true,
        public_ingress_allowed: public,
        max_connections: 4,
        bytes_per_second: 1_048_576,
    };
    let mut gate = NodeGate::new(
        c.deployment_id.clone(),
        c.definition.edge_node_id.clone(),
        runtime_id.clone(),
        fixture.edge.public_key(),
        policy.public_key(),
        vec![NodeRole::NodeEdge],
    )?;
    gate.accept(
        &policy.sign(&node_lease)?.encode_to_vec(),
        &challenge,
        0,
        ClockSample {
            monotonic_ms: 0,
            unix_ms: now,
        },
    )?;
    let state = Arc::new(Mutex::new(Runtime {
        gate,
        meter: Meter::default(),
        ready: true,
        service_shutdown: false,
        resources: resources::Resources::default(),
        service_resource_owner: None,
        service_usage: Arc::new(crate::service_usage::ServiceUsageStore::for_test()?),
        topology: Default::default(),
    }));
    let (stop_signal, stopped) = watch::channel(false);
    let control = NodeControl {
        state,
        started,
        stopped,
        stop_signal,
        turn_authorization: Arc::new(TurnAuthorization::new(64)?),
        pump: tokio::spawn(std::future::pending::<Result<(), Error>>()),
        _usage_pump: tokio::spawn(async { Ok(()) }),
        runtime_id: runtime_id.clone(),
    };
    Ok((control, policy))
}
fn snapshot(
    fixture: &Fixture,
    policy: &NodePolicySigner,
    sequence: u64,
    ttl: u64,
    present: bool,
) -> TestResult<VerifiedServiceSnapshot> {
    let (signed, request) = signed_snapshot(fixture, policy, sequence, ttl, present)?;
    Ok(verify_service_snapshot(
        &signed,
        &policy.public_key(),
        &request,
        &fixture.edge.public_key(),
    )?)
}
fn signed_snapshot(
    fixture: &Fixture,
    policy: &NodePolicySigner,
    sequence: u64,
    ttl: u64,
    present: bool,
) -> TestResult<(SignedServiceResourceSnapshot, SignedServiceResourceQuery)> {
    let now = wall()?;
    let query = NodeResourceQueryClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: fixture.claims.deployment_id.clone(),
        security_epoch: fixture.claims.security_epoch,
        node_id: fixture.claims.definition.edge_node_id.clone(),
        runtime_id: fixture.claims.edge_runtime_id.clone(),
        runtime_generation: fixture.claims.edge_runtime_generation,
        policy_revision: fixture.claims.policy_revision,
        lease_sequence: 1,
        request_id: uuid::Uuid::new_v4().to_string(),
        request_sequence: sequence,
        issued_at_unix_ms: now,
        expires_at_unix_ms: now + ttl,
    };
    let request = fixture.edge.sign_service_query(&query)?;
    let snapshot = ServiceResourceSnapshot {
        query,
        query_sha256: digest(&request.claims),
        service_lease_issuer: fixture.signer.public_key(),
        issued_at_unix_ms: now,
        expires_at_unix_ms: now + ttl,
        leases: if present {
            vec![fixture.signer.sign(&fixture.claims)?]
        } else {
            Vec::new()
        },
    };
    Ok((policy.sign_service_snapshot(&snapshot)?, request))
}
#[tokio::test]
async fn publication_does_not_replace_independent_node_public_ingress_authority() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let publication = fixture.publication()?;
    let (node, _) = control(&fixture, false)?;
    assert!(
        publication
            .handle()
            .reserve_edge(&node, "127.0.0.1".parse()?)
            .is_err()
    );
    assert_eq!(node.counters()?.opened_connections, 0);
    Ok(())
}
#[tokio::test]
async fn node_reservations_share_aggregate_admission_with_publication_quota() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let publication = fixture.publication()?;
    let (node, _) = control(&fixture, true)?;
    let first = publication
        .handle()
        .reserve_edge(&node, "127.0.0.1".parse()?)?;
    let second = publication
        .handle()
        .reserve_edge(&node, "127.0.0.2".parse()?)?;
    first.try_charge(600)?;
    second.try_charge(400)?;
    assert_eq!(node.counters()?.admitted_bytes, 1000);
    assert_eq!(publication.handle().counters()?.admitted_bytes, 1000);
    assert!(
        publication
            .handle()
            .reserve_edge(&node, "127.0.0.3".parse()?)
            .is_err()
    );
    drop(first);
    drop(second);
    let c = node.counters()?;
    assert_eq!(c.opened_connections, c.closed_connections);
    Ok(())
}
#[tokio::test]
async fn snapshot_omission_revokes_existing_io_and_id_cannot_reappear() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let (node, policy) = control(&fixture, true)?;
    let mut set = ServiceResourceSet::new();
    let started = Instant::now();
    set.accept(snapshot(&fixture, &policy, 1, 1000, true)?, &node, started)?;
    let old = set.publication(&fixture.claims.publication_id)?;
    let flow = old.reserve_edge(&node, "127.0.0.1".parse()?)?;
    let started = Instant::now();
    set.accept(snapshot(&fixture, &policy, 2, 1000, false)?, &node, started)?;
    assert!(flow.check_live().is_err());
    assert!(old.lease().is_err());
    let started = Instant::now();
    assert!(
        set.accept(snapshot(&fixture, &policy, 3, 1000, true)?, &node, started)
            .is_err()
    );
    assert!(set.active_ids().is_empty());
    Ok(())
}

#[tokio::test]
async fn rebuilding_service_resource_set_cannot_reset_runtime_replay_state() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let (node, policy) = control(&fixture, true)?;
    let mut first = ServiceResourceSet::new();
    let original_request_started = Instant::now();
    let (signed, request) = signed_snapshot(&fixture, &policy, 1, NODE_RESOURCE_TTL_MS, true)?;
    let first_snapshot = verify_service_snapshot(
        &signed,
        &policy.public_key(),
        &request,
        &fixture.edge.public_key(),
    )?;
    let replay_snapshot = verify_service_snapshot(
        &signed,
        &policy.public_key(),
        &request,
        &fixture.edge.public_key(),
    )?;
    first.accept(first_snapshot, &node, original_request_started)?;
    first.accept(
        snapshot(&fixture, &policy, 2, NODE_RESOURCE_TTL_MS, false)?,
        &node,
        Instant::now(),
    )?;
    assert!(first.active_ids().is_empty());
    drop(first);

    let mut rebuilt = ServiceResourceSet::new();
    assert!(
        rebuilt
            .accept(replay_snapshot, &node, original_request_started,)
            .is_err()
    );
    assert!(rebuilt.active_ids().is_empty());
    Ok(())
}
#[tokio::test]
async fn new_node_runtime_rejects_previous_runtime_service_grant() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let (node, policy) = control_with_runtime(&fixture, true, id(13), 2)?;
    let mut set = ServiceResourceSet::new();

    // The old runtime's grant and snapshot are cryptographically valid, but the
    // current NodeControl gate is bound to the next runtime generation.
    let previous_runtime_snapshot = snapshot(&fixture, &policy, 1, NODE_RESOURCE_TTL_MS, true)?;
    assert!(
        set.accept(previous_runtime_snapshot, &node, Instant::now())
            .is_err()
    );
    assert!(set.active_ids().is_empty());
    assert!(node.service_publication_ids()?.is_empty());
    Ok(())
}
#[tokio::test]
async fn expired_resource_snapshot_never_resurrects_the_same_publication() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let (node, policy) = control(&fixture, true)?;
    let mut set = ServiceResourceSet::new();
    let started = Instant::now();
    set.accept(snapshot(&fixture, &policy, 1, 1000, true)?, &node, started)?;
    let old = set.publication(&fixture.claims.publication_id)?;
    tokio::time::sleep_until(old.deadline()?.into()).await;
    assert!(old.lease().is_err());
    let started = Instant::now();
    assert!(
        set.accept(snapshot(&fixture, &policy, 2, 1000, true)?, &node, started)
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn snapshot_verified_by_a_foreign_issuer_is_rejected_by_actual_node_gate() -> TestResult {
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let (node, _policy) = control(&fixture, true)?;
    let foreign = NodePolicySigner::from_master_seed(&[99; 32])?;
    let mut set = ServiceResourceSet::new();
    let started = Instant::now();
    assert!(
        set.accept(snapshot(&fixture, &foreign, 1, 1000, true)?, &node, started)
            .is_err()
    );
    assert!(set.active_ids().is_empty());
    Ok(())
}
#[tokio::test]
async fn namespace_excludes_management_reserved_ports_and_duplicate_http_https_owners() -> TestResult
{
    assert!(
        IngressNamespace::new(
            id(8),
            "svc.example.test".into(),
            "manage.example.test".into(),
            vec![28743]
        )
        .is_err()
    );
    assert!(
        IngressNamespace::new(
            id(8),
            "svc.example.test".into(),
            "manage.example.test".into(),
            vec![443]
        )
        .is_err()
    );
    let fixture = Fixture::new(
        ServiceIngress::Http {
            hostname: "app.svc.example.test".into(),
        },
        "http",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    let (node, _) = control(&fixture, true)?;
    let ownership = IngressOwnership::new(IngressNamespace::new(
        id(8),
        "svc.example.test".into(),
        "manage.example.test".into(),
        vec![29100],
    )?);
    let first = fixture.publication()?;
    let reserved = ownership.reserve(&first.handle(), &node)?;
    let mut second = Fixture::new(
        ServiceIngress::Https {
            hostname: "app.svc.example.test".into(),
        },
        "http",
        "127.0.0.1:8081".parse()?,
        5000,
    )?;
    second.claims.publication_id = id(91);
    second.claims.ingress_claim_id = id(92);
    second.claims.edge_key_sha256 = fixture.claims.edge_key_sha256;
    second.refresh_usage_binding()?;
    let second = second.publication()?;
    assert!(ownership.reserve(&second.handle(), &node).is_err());
    drop(reserved);
    let _new_owner = ownership.reserve(&second.handle(), &node)?;
    let mut foreign = Fixture::new(
        ServiceIngress::Http {
            hostname: "manage.example.test".into(),
        },
        "http",
        "127.0.0.1:8082".parse()?,
        5000,
    )?;
    foreign.claims.edge_key_sha256 = fixture.claims.edge_key_sha256;
    assert!(
        ownership
            .reserve(&foreign.publication()?.handle(), &node)
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn actual_tcp_ingress_binds_peer_target_proof_half_close_and_node_stop() -> TestResult {
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let temporary = TcpListener::bind("127.0.0.1:0").await?;
    let public_address = temporary.local_addr()?;
    drop(temporary);
    let fixture = Fixture::new(
        ServiceIngress::Tcp {
            port: public_address.port(),
        },
        "tcp",
        backend.local_addr()?,
        5000,
    )?;
    let (node, _) = control(&fixture, true)?;
    let edge_publication = fixture.publication()?;
    let host_publication = fixture.publication()?;
    let target_owner = fixture.owner()?;
    let ownership = IngressOwnership::new(IngressNamespace::new(
        id(8),
        "svc.example.test".into(),
        "manage.example.test".into(),
        vec![public_address.port()],
    )?);
    let reservation = ownership.reserve(&edge_publication.handle(), &node)?;
    let mut ingress = ServiceTcpIngress::bind(reservation, &node, public_address.ip()).await?;
    let mut visitor = TcpStream::connect(public_address).await?;
    let accepted = tokio::time::timeout(Duration::from_secs(1), ingress.accept(&node)).await??;
    assert_eq!(accepted.peer(), visitor.local_addr()?);
    let pending = accepted.challenge(&fixture.edge)?;
    let prepared = target_owner.prepare(
        &host_publication.handle(),
        pending.challenge(),
        &fixture.edge.public_key(),
        &fixture.host,
    )?;
    let authorized = pending.accept_proof(&fixture.host.public_key(), prepared.proof())?;
    // An in-memory carrier exercises the kernel only. Production must supply
    // a pinned, encrypted WSS/QUIC carrier at these same two boundaries.
    let (left, right) = tokio::io::duplex(64);
    let edge_task = tokio::spawn(authorized.forward(left));
    let host_task = tokio::spawn(prepared.forward_stream(right));
    let backend_task = tokio::spawn(async move {
        let (mut target, _) = backend.accept().await?;
        let mut request = Vec::new();
        target.read_to_end(&mut request).await?;
        if request != b"public request" {
            return Err(std::io::Error::other("wrong target request"));
        }
        target.write_all(b"target response").await?;
        target.shutdown().await
    });
    visitor.write_all(b"public request").await?;
    visitor.shutdown().await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), visitor.read_to_end(&mut response)).await??;
    assert_eq!(response, b"target response");
    tokio::time::timeout(Duration::from_secs(1), edge_task).await???;
    tokio::time::timeout(Duration::from_secs(1), host_task).await???;
    backend_task.await??;
    assert_eq!(
        node.counters()?.admitted_bytes,
        (b"public request".len() + b"target response".len()) as u64
    );
    node.stop();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), ingress.accept(&node))
            .await?
            .is_err()
    );
    let _rebound = TcpListener::bind(public_address).await?;
    Ok(())
}

struct TcpIngressFixture {
    _fixture: Fixture,
    node: NodeControl,
    publication: crate::service_plane::ServicePublication,
    ingress: ServiceTcpIngress,
    address: std::net::SocketAddr,
}
async fn tcp_ingress_fixture(publication_maximum: u16) -> TestResult<TcpIngressFixture> {
    let temporary = TcpListener::bind("127.0.0.1:0").await?;
    let address = temporary.local_addr()?;
    drop(temporary);
    let mut fixture = Fixture::new(
        ServiceIngress::Tcp {
            port: address.port(),
        },
        "tcp",
        "127.0.0.1:8080".parse()?,
        5000,
    )?;
    fixture.claims.definition.allowed_sources[0].address = "127.0.0.1".into();
    fixture.claims.definition.allowed_sources[0].prefix = 32;
    fixture.claims.definition.limits.maximum_connections = publication_maximum;
    fixture.claims.definition_sha256 =
        nestlink_identity::services::definition_digest(&fixture.claims.definition)?;
    fixture.refresh_usage_binding()?;
    let (node, _) = control(&fixture, true)?;
    let publication = fixture.publication()?;
    let ownership = IngressOwnership::new(IngressNamespace::new(
        id(8),
        "svc.example.test".into(),
        "manage.example.test".into(),
        vec![address.port()],
    )?);
    let reservation = ownership.reserve(&publication.handle(), &node)?;
    let ingress = ServiceTcpIngress::bind(reservation, &node, address.ip()).await?;
    Ok(TcpIngressFixture {
        _fixture: fixture,
        node,
        publication,
        ingress,
        address,
    })
}

async fn assert_rejected_visitor_closed(visitor: &mut TcpStream) -> TestResult {
    let mut byte = [0];
    match tokio::time::timeout(Duration::from_secs(1), visitor.read(&mut byte)).await? {
        Ok(0) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
        _ => Err("rejected visitor socket remained open or received data".into()),
    }
}

#[tokio::test]
async fn tcp_source_denial_does_not_stop_listener_or_publication() -> TestResult {
    let TcpIngressFixture {
        _fixture,
        node,
        publication,
        mut ingress,
        address,
    } = tcp_ingress_fixture(2).await?;
    let socket = TcpSocket::new_v4()?;
    socket.bind("127.0.0.2:0".parse()?)?;
    let mut denied = socket.connect(address).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), ingress.accept(&node))
            .await
            .is_err()
    );
    assert_rejected_visitor_closed(&mut denied).await?;
    assert_eq!(publication.handle().counters()?.opened_connections, 0);
    let visitor = TcpStream::connect(address).await?;
    let accepted = tokio::time::timeout(Duration::from_secs(1), ingress.accept(&node)).await??;
    assert_eq!(accepted.peer(), visitor.local_addr()?);
    drop(accepted);
    assert!(publication.handle().lease().is_ok());
    node.stop();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), ingress.accept(&node))
            .await?
            .is_err()
    );
    let _rebound = TcpListener::bind(address).await?;
    Ok(())
}

async fn tcp_capacity_denial_recovers(publication_maximum: u16, held: usize) -> TestResult {
    let TcpIngressFixture {
        _fixture,
        node,
        publication,
        mut ingress,
        address,
    } = tcp_ingress_fixture(publication_maximum).await?;
    let mut permits = Vec::new();
    for _ in 0..held {
        permits.push(publication.handle().reserve_edge(&node, address.ip())?);
    }
    let mut refused = TcpStream::connect(address).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), ingress.accept(&node))
            .await
            .is_err()
    );
    assert_rejected_visitor_closed(&mut refused).await?;
    drop(permits);
    let visitor = TcpStream::connect(address).await?;
    let accepted = tokio::time::timeout(Duration::from_secs(1), ingress.accept(&node)).await??;
    assert_eq!(accepted.peer(), visitor.local_addr()?);
    drop(accepted);
    let counters = publication.handle().counters()?;
    assert_eq!(counters.opened_connections, counters.closed_connections);
    let counters = node.counters()?;
    assert_eq!(counters.opened_connections, counters.closed_connections);
    Ok(())
}

#[tokio::test]
async fn tcp_publication_capacity_denial_preserves_listener_and_recovers() -> TestResult {
    tcp_capacity_denial_recovers(2, 2).await
}

#[tokio::test]
async fn tcp_node_capacity_denial_preserves_listener_and_recovers() -> TestResult {
    tcp_capacity_denial_recovers(8, 4).await
}
