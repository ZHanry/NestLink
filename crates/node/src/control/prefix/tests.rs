use super::*;
use crate::{
    control::{NodeConfig, Runtime, TopologyReporter},
    gate::NodeGate,
    meter::Meter,
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{
    digest,
    network::{NetworkAuthoritySigner, NetworkVerification, verify_network_grant},
    network_topology::{
        VerifiedTopologyPublisher, verify_topology_publisher, verify_topology_report,
    },
    nodes::{NodeIdentity, NodePolicySigner},
};
use nestlink_protocol::{
    NodeChallenge, NodeResourceQueryClaims, NodeResourceSnapshotClaims, NodeRole,
    api::{NetworkTopologyEnvelope, NodeEndpoints, NodeEndpointsView},
    network::{GrantClaims, GrantScope, PeerId, RouteExportClaims},
    network_topology::{BootIncarnation, SignedTopologyAdvertisement, SignedTopologyReport},
};
use nestlink_traversal::turn::TurnAuthorization;
use prost::Message;
use std::{
    collections::BTreeSet,
    future::Future,
    net::IpAddr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::{io::AsyncReadExt, net::TcpListener, sync::Notify};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const NODE_SEED: [u8; 32] = [141; 32];

fn id(value: u16) -> String {
    format!("{value:08x}-1111-4111-8111-111111111111")
}

// Ask the OS for this runner's real nonloopback source address. No packet is
// sent and no privileged interface/route mutation is needed on hosted runners.
fn host_ip() -> TestResult<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("192.0.2.1:9")?;
    let ip = socket.local_addr()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        return Err("hosted fixture requires a real nonloopback address".into());
    }
    Ok(ip)
}

struct Fixture {
    control: Arc<NodeControl>,
    config: NodeConfig,
    authority: NetworkNodeTopologyAuthority,
    signer: Arc<NetworkAuthoritySigner>,
    publisher: VerifiedTopologyPublisher,
    policy: NodePolicySigner,
    sequence: AtomicU64,
    prefix: IpPrefix,
    target: SocketAddr,
}

impl Fixture {
    fn new(origin: String, target: SocketAddr, lease_ms: u64) -> TestResult<Self> {
        let started = std::time::Instant::now();
        let now = sample(started)?;
        let identity = NodeIdentity::from_seed(&NODE_SEED);
        let policy = NodePolicySigner::from_master_seed(&[142; 32])?;
        let signer = Arc::new(NetworkAuthoritySigner::from_master_seed(&[143; 32])?);
        let lease = NodeLeaseClaims {
            schema_version: 1,
            deployment_id: id(1),
            security_epoch: 1,
            node_id: id(2),
            runtime_id: id(3),
            runtime_generation: 1,
            node_key_sha256: digest(&identity.public_key()).to_vec(),
            request_id: id(4),
            nonce: vec![1; 32],
            roles: vec![NodeRole::NodeRelay as i32],
            policy_revision: 1,
            lease_sequence: 1,
            issued_at_unix_ms: now.unix_ms,
            expires_at_unix_ms: now.unix_ms + lease_ms,
            server_forwarding_allowed: true,
            public_ingress_allowed: false,
            max_connections: 8,
            bytes_per_second: 1024,
        };
        let challenge = challenge(&lease);
        let mut gate = NodeGate::new(
            id(1),
            id(2),
            id(3),
            identity.public_key(),
            policy.public_key(),
            vec![NodeRole::NodeRelay],
        )?;
        gate.accept(&policy.sign(&lease)?.encode_to_vec(), &challenge, 0, now)?;
        let (stop_signal, stopped) = watch::channel(false);
        let control = Arc::new(NodeControl {
            state: Arc::new(Mutex::new(Runtime {
                gate,
                meter: Meter::default(),
                ready: true,
                service_shutdown: false,
                resources: super::super::resources::Resources::default(),
                service_resource_owner: None,
                service_usage: Arc::new(crate::service_usage::ServiceUsageStore::for_test()?),
                topology: Default::default(),
            })),
            started,
            stopped,
            stop_signal,
            runtime_id: id(3),
            turn_authorization: Arc::new(TurnAuthorization::new(8)?),
            pump: tokio::spawn(std::future::pending::<Result<(), Error>>()),
            _usage_pump: tokio::spawn(async { Ok(()) }),
        });
        let config = NodeConfig {
            deployment_id: id(1),
            node_id: id(2),
            control_origin: origin,
            trusted_policy_issuer: URL_SAFE_NO_PAD.encode(policy.public_key()),
            identity_key_file: std::env::temp_dir().join("unused-prefix-test-key"),
            service_usage_directory: None,
            roles: vec![NodeRole::NodeRelay as i32],
            allow_loopback_http: true,
        };
        let prefix = IpPrefix {
            network: target.ip(),
            prefix_len: if target.is_ipv4() { 32 } else { 128 },
        };
        let scope = |grant| GrantScope {
            schema_version: 1,
            deployment_id: id(1),
            space_id: id(5),
            grant_id: id(grant),
            policy_epoch: 1,
            not_before_ms: now.unix_ms,
            expires_at_ms: now.unix_ms + 5000,
        };
        let export = signer.sign(&GrantClaims::RouteExport(RouteExportClaims {
            scope: scope(6),
            gateway: PeerId::from_public_key(&identity.public_key()),
            prefixes: vec![prefix],
        }))?;
        let key = signer.public_key();
        let revoked = BTreeSet::new();
        let context = NetworkVerification {
            authority_key: &key,
            deployment_id: &id(1),
            space_id: &id(5),
            policy_epoch: 1,
            now_ms: now.unix_ms,
            revoked_grant_ids: &revoked,
        };
        let verified_export = verify_network_grant(&export, &context)?;
        let claims = TopologyPublisherClaims {
            scope: scope(7),
            node_id: id(2),
            public_key: identity.public_key(),
            peer: PeerId::from_public_key(&identity.public_key()),
            incarnation: BootIncarnation {
                runtime_id: id(3),
                runtime_generation: 1,
            },
            allowed_neighbors: vec![],
            route_export_digests: vec![verified_export.digest()],
            allowed_prefixes: vec![prefix],
        };
        let signed = signer.sign_topology_publisher(&claims)?;
        let publisher = verify_topology_publisher(
            &signed,
            &context,
            &id(2),
            &identity.public_key(),
            &claims.incarnation,
            &[verified_export],
        )?;
        let authority = NetworkNodeTopologyAuthority {
            authority_key: key,
            publisher: signed,
            publisher_digest: publisher.digest(),
            route_exports: vec![NetworkTopologyEnvelope {
                claims: export.claims,
                signature: export.signature,
            }],
            local: NodeEndpointsView {
                node_id: id(2),
                revision: 1,
                endpoints: NodeEndpoints {
                    quic_uri: Some("quic://127.0.0.1:31001".into()),
                    allow_loopback: true,
                    ..Default::default()
                },
            },
            neighbors: vec![],
        };
        let fixture = Self {
            control,
            config,
            authority,
            signer,
            publisher,
            policy,
            sequence: AtomicU64::new(0),
            prefix,
            target,
        };
        fixture.refresh(std::slice::from_ref(&fixture.authority))?;
        Ok(fixture)
    }

    fn refresh(&self, authorities: &[NetworkNodeTopologyAuthority]) -> TestResult {
        let now = sample(self.control.started)?;
        let lease = self.control.current_lease()?;
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        self.control
            .install_topology_fixture(NodeResourceSnapshotClaims {
                query: Some(NodeResourceQueryClaims {
                    schema_version: 1,
                    deployment_id: lease.deployment_id,
                    security_epoch: lease.security_epoch,
                    node_id: lease.node_id,
                    runtime_id: lease.runtime_id,
                    runtime_generation: lease.runtime_generation,
                    policy_revision: lease.policy_revision,
                    lease_sequence: lease.lease_sequence,
                    request_id: id(100 + sequence as u16),
                    request_sequence: sequence,
                    issued_at_unix_ms: now.unix_ms,
                    expires_at_unix_ms: now.unix_ms + 1000,
                }),
                query_sha256: vec![1; 32],
                allocation_issuer: vec![2; 32],
                quota_revision: 1,
                issued_at_unix_ms: now.unix_ms,
                expires_at_unix_ms: now.unix_ms + 1000,
                allocations: vec![],
                network_routes: vec![],
                topology_publications_json: serde_json::to_vec(authorities)?,
            })?;
        Ok(())
    }

    fn owner(&self) -> TestResult<LocalPrefixOwner> {
        Ok(LocalPrefixOwner::start(
            self.control.clone(),
            &self.authority,
            LocalPrefixChoice::approve(self.prefix, self.target)?,
        )?)
    }

    fn reporter(&self) -> TestResult<TopologyReporter> {
        Ok(TopologyReporter::new(
            self.config.clone(),
            NodeIdentity::from_seed(&NODE_SEED),
        )?)
    }

    fn renew_lease(&self) -> TestResult {
        let mut state = self
            .control
            .state
            .lock()
            .map_err(|_| "poisoned fixture runtime")?;
        let now = sample(self.control.started)?;
        let mut lease = state.gate.current(now)?.clone();
        lease.lease_sequence += 1;
        lease.issued_at_unix_ms = now.unix_ms;
        lease.expires_at_unix_ms = now.unix_ms + 10_000;
        lease.request_id = id(80);
        lease.nonce = vec![2; 32];
        state.gate.accept(
            &self.policy.sign(&lease)?.encode_to_vec(),
            &challenge(&lease),
            now.monotonic_ms,
            now,
        )?;
        Ok(())
    }
}

fn challenge(lease: &NodeLeaseClaims) -> NodeChallenge {
    NodeChallenge {
        schema_version: 1,
        deployment_id: lease.deployment_id.clone(),
        security_epoch: lease.security_epoch,
        node_id: lease.node_id.clone(),
        node_key_sha256: lease.node_key_sha256.clone(),
        request_id: lease.request_id.clone(),
        nonce: lease.nonce.clone(),
        expires_at_unix_ms: lease.issued_at_unix_ms + 2000,
    }
}

async fn reachable(owner: &LocalPrefixOwner) -> TestResult<PrefixEvidence> {
    Ok(tokio::time::timeout(Duration::from_millis(900), async {
        loop {
            if let Ok(evidence) = owner.evidence(&owner.binding.control, &owner.binding.authority) {
                return evidence;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?)
}

#[test]
fn local_approval_is_exact_host_and_port_without_mapped_or_default_routes() -> TestResult {
    let target: SocketAddr = "192.0.2.10:8080".parse()?;
    let prefix = IpPrefix {
        network: target.ip(),
        prefix_len: 32,
    };
    assert!(LocalPrefixChoice::approve(prefix, target).is_ok());
    for (address, bits, socket) in [
        ("192.0.2.0", 24, "192.0.2.0:8080"),
        ("0.0.0.0", 0, "0.0.0.0:8080"),
        ("127.0.0.1", 32, "127.0.0.1:8080"),
        ("192.0.2.10", 32, "192.0.2.11:8080"),
        ("192.0.2.10", 32, "192.0.2.10:0"),
        ("::ffff:127.0.0.1", 128, "[::ffff:127.0.0.1]:8080"),
    ] {
        assert!(
            LocalPrefixChoice::approve(
                IpPrefix {
                    network: address.parse()?,
                    prefix_len: bits
                },
                socket.parse()?
            )
            .is_err()
        );
    }
    assert!(
        LocalPrefixChoice::approve(
            IpPrefix {
                network: "fd00::1".parse()?,
                prefix_len: 128
            },
            "[fd00::1]:8080".parse()?
        )
        .is_ok()
    );
    Ok(())
}

struct HttpState {
    signer: Arc<NetworkAuthoritySigner>,
    publisher: VerifiedTopologyPublisher,
    paused: AtomicBool,
    seen: Notify,
    resume: Notify,
}

async fn report(
    State(state): State<Arc<HttpState>>,
    Json(signed): Json<SignedTopologyReport>,
) -> Result<Json<SignedTopologyAdvertisement>, StatusCode> {
    state.seen.notify_one();
    if state.paused.load(Ordering::SeqCst) {
        state.resume.notified().await;
    }
    let key = state.signer.public_key();
    let claims = state.publisher.claims();
    let revoked = BTreeSet::new();
    let now = sample(std::time::Instant::now())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unix_ms;
    let context = NetworkVerification {
        authority_key: &key,
        deployment_id: &claims.scope.deployment_id,
        space_id: &claims.scope.space_id,
        policy_epoch: claims.scope.policy_epoch,
        now_ms: now,
        revoked_grant_ids: &revoked,
    };
    let verified =
        verify_topology_report(&signed, &state.publisher, &context, &claims.incarnation, 0)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(
        state
            .signer
            .sign_topology_advertisement(&verified, now, verified.claims().expires_at_ms)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ))
}

#[tokio::test]
async fn actual_tcp_measurement_reaches_signed_http_through_the_original_sequence_owner()
-> TestResult {
    let target = TcpListener::bind((host_ip()?, 0)).await?;
    let http = TcpListener::bind("127.0.0.1:0").await?;
    let fixture = Fixture::new(
        format!("http://{}", http.local_addr()?),
        target.local_addr()?,
        10_000,
    )?;
    let state = Arc::new(HttpState {
        signer: fixture.signer.clone(),
        publisher: fixture.publisher.clone(),
        paused: AtomicBool::new(false),
        seen: Notify::new(),
        resume: Notify::new(),
    });
    let router = Router::new()
        .route(
            "/api/v3/network/spaces/{space}/topology/reports/{node}",
            post(report),
        )
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(http, router).await });
    let mut owner = fixture.owner()?;
    let (mut stream, _) =
        tokio::time::timeout(Duration::from_millis(900), target.accept()).await??;
    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), stream.read(&mut byte)).await??,
        0,
        "probe must close without sending application data"
    );
    drop(stream);
    let evidence = reachable(&owner).await?;
    let reporter = fixture.reporter()?;
    assert!(
        reporter
            .publish_authority_with_prefixes(
                &fixture.control,
                &fixture.authority,
                vec![],
                &[&owner, &owner]
            )
            .await
            .is_err()
    );
    let reply = reporter
        .publish_authority_with_prefixes(&fixture.control, &fixture.authority, vec![], &[&owner])
        .await?;
    assert_eq!(reply.claims().report.prefixes, vec![fixture.prefix]);
    assert_eq!(reply.claims().report.sequence, 1);
    assert!(reply.claims().report.expires_at_ms <= evidence.expires_at_ms);
    state.paused.store(true, Ordering::SeqCst);
    // Consume the first request's retained notification before starting this one.
    state.seen.notified().await;
    let owners = [&owner];
    let mut pending = Box::pin(reporter.publish_authority_with_prefixes(
        &fixture.control,
        &fixture.authority,
        vec![],
        &owners,
    ));
    tokio::select! {
        result = &mut pending => return Err(format!("publication completed before revocation: {}", result.is_ok()).into()),
        _ = state.seen.notified() => {}
    }
    owner.revoke();
    state.resume.notify_one();
    assert!(pending.await.is_err());
    state.paused.store(false, Ordering::SeqCst);
    let withdrawn = reporter
        .publish_authority(&fixture.control, &fixture.authority, vec![])
        .await?;
    assert!(withdrawn.claims().report.prefixes.is_empty());
    assert_eq!(withdrawn.claims().report.sequence, 3);
    owner.close(Duration::from_secs(1)).await?;
    assert!(owner.task.is_none());
    assert!(!owner.is_reachable());
    server.abort();
    assert!(server.await.is_err_and(|error| error.is_cancelled()));
    Ok(())
}

#[tokio::test]
async fn original_export_runtime_revision_omission_and_stop_revoke_measured_targets() -> TestResult
{
    for change in 0..5 {
        let listener = TcpListener::bind((host_ip()?, 0)).await?;
        let fixture = Fixture::new("http://127.0.0.1:9".into(), listener.local_addr()?, 10_000)?;
        let mut owner = fixture.owner()?;
        reachable(&owner).await?;
        match change {
            0 => fixture.refresh(&[])?,
            1 => {
                let mut changed = fixture.authority.clone();
                changed.local.revision += 1;
                fixture.refresh(&[changed])?;
            }
            2 => fixture.control.stop(),
            3 => owner.revoke(),
            _ => {
                let mut changed = fixture.authority.clone();
                changed.publisher.signature[0] ^= 1;
                assert!(
                    LocalPrefixOwner::start(
                        fixture.control.clone(),
                        &changed,
                        LocalPrefixChoice::approve(fixture.prefix, fixture.target)?
                    )
                    .is_err()
                );
                let other = Fixture::new("http://127.0.0.1:9".into(), fixture.target, 10_000)?;
                assert!(owner.evidence(&other.control, &other.authority).is_err());
                assert!(
                    owner.is_reachable(),
                    "wrong caller cannot revoke an unrelated local owner"
                );
                let other_prefix = IpPrefix {
                    network: "192.0.2.33".parse()?,
                    prefix_len: 32,
                };
                assert!(
                    LocalPrefixOwner::start(
                        fixture.control.clone(),
                        &fixture.authority,
                        LocalPrefixChoice::approve(other_prefix, "192.0.2.33:8080".parse()?)?
                    )
                    .is_err()
                );
                owner.revoke();
            }
        }
        assert!(!owner.is_reachable());
        if change == 0 {
            fixture.refresh(std::slice::from_ref(&fixture.authority))?;
            assert!(
                !owner.is_reachable(),
                "omitted original owner cannot revive from a detached envelope"
            );
        }
        owner.close(Duration::from_secs(1)).await?;
        assert!(owner.task.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn actual_probe_failure_withdraws_and_recovery_cannot_acknowledge_old_evidence() -> TestResult
{
    let listener = TcpListener::bind((host_ip()?, 0)).await?;
    let address = listener.local_addr()?;
    let fixture = Fixture::new("http://127.0.0.1:9".into(), address, 10_000)?;
    let mut owner = fixture.owner()?;
    let original = reachable(&owner)
        .await
        .map_err(|error| format!("initial real prefix probe: {error}"))?;
    drop(listener);
    tokio::time::timeout(Duration::from_millis(800), async {
        while owner.is_reachable() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|error| format!("withdrawal after actual listener close: {error}"))?;
    fixture.refresh(std::slice::from_ref(&fixture.authority))?;
    let listener = TcpListener::bind(address).await?;
    let recovered = reachable(&owner)
        .await
        .map_err(|error| format!("recovery after actual listener rebind: {error}"))?;
    assert_ne!(recovered.continuity, original.continuity);
    assert!(
        owner
            .check_evidence(&fixture.control, &fixture.authority, &original)
            .is_err()
    );
    owner.close(Duration::from_secs(1)).await?;
    drop(listener);
    let rebound = TcpListener::bind(address).await?;
    drop(rebound);
    Ok(())
}

#[tokio::test]
async fn lease_renewal_never_moves_the_local_choices_original_deadline() -> TestResult {
    let listener = TcpListener::bind((host_ip()?, 0)).await?;
    let fixture = Fixture::new("http://127.0.0.1:9".into(), listener.local_addr()?, 400)?;
    let mut owner = fixture.owner()?;
    reachable(&owner).await?;
    let deadline = owner.binding.deadline_ms;
    tokio::time::sleep(Duration::from_millis(2)).await;
    fixture.renew_lease()?;
    fixture.refresh(std::slice::from_ref(&fixture.authority))?;
    tokio::time::sleep_until(
        (fixture.control.started + Duration::from_millis(deadline + 5)).into(),
    )
    .await;
    assert!(fixture.control.current_lease().is_ok());
    assert!(!owner.is_reachable());
    assert_eq!(owner.binding.deadline_ms, deadline);
    owner.close(Duration::from_secs(1)).await?;
    Ok(())
}

#[tokio::test]
async fn cancelled_close_retains_original_task_and_cleanup_deadline_until_real_join() -> TestResult
{
    let listener = TcpListener::bind((host_ip()?, 0)).await?;
    let fixture = Fixture::new("http://127.0.0.1:9".into(), listener.local_addr()?, 10_000)?;
    let mut owner = fixture.owner()?;
    reachable(&owner).await?;
    let mut close = Box::pin(owner.close(Duration::from_millis(100)));
    std::future::poll_fn(|context| {
        assert!(Future::poll(close.as_mut(), context).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(close);
    assert!(owner.task.is_some());
    let deadline = owner.close_deadline;
    assert!(!owner.is_reachable());
    owner.close(Duration::from_secs(5)).await?;
    assert_eq!(owner.close_deadline, deadline);
    assert!(owner.task.is_none());
    Ok(())
}
