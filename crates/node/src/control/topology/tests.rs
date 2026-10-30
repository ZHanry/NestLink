use super::*;
use crate::{control::Runtime, gate::NodeGate, meter::Meter};
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{network::NetworkAuthoritySigner, nodes::NodePolicySigner};
use nestlink_protocol::{
    NodeChallenge, NodeRole,
    network::{GrantScope, PeerId},
    network_topology::TopologyPublisherClaims,
};
use nestlink_traversal::turn::TurnAuthorization;
use prost::Message;
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::sync::{Notify, watch};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const NODE_SEED: [u8; 32] = [101; 32];

fn id(value: u16) -> String {
    format!("{value:08x}-1111-4111-8111-111111111111")
}

struct Fixture {
    control: NodeControl,
    config: NodeConfig,
    authority: Arc<NetworkAuthoritySigner>,
    authority_key: [u8; 32],
    policy: NodePolicySigner,
    claims: TopologyPublisherClaims,
    publisher: SignedTopologyPublisher,
    revoked: BTreeSet<String>,
}

impl Fixture {
    fn new(origin: String) -> TestResult<Self> {
        Self::with_initial_delay(origin, 10_000, 0)
    }

    /// Reuse the signed NodeGate fixture pattern from control/services and
    /// control/turn. A delayed initial reply produces the real conservative
    /// request-relative deadline independently of the signed wall expiry.
    fn with_initial_delay(origin: String, lease_ms: u64, delay_ms: u64) -> TestResult<Self> {
        let started = Instant::now()
            .checked_sub(Duration::from_millis(delay_ms))
            .ok_or("invalid fixture start")?;
        let now = sample(started)?;
        let identity = NodeIdentity::from_seed(&NODE_SEED);
        let policy = NodePolicySigner::from_master_seed(&[102; 32])?;
        let authority = Arc::new(NetworkAuthoritySigner::from_master_seed(&[103; 32])?);
        let authority_key = authority.public_key();
        let challenge = NodeChallenge {
            schema_version: nestlink_protocol::SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            node_id: id(2),
            node_key_sha256: digest(&identity.public_key()).to_vec(),
            request_id: id(4),
            nonce: vec![1; 32],
            expires_at_unix_ms: now.unix_ms + 2000,
        };
        let lease = NodeLeaseClaims {
            schema_version: nestlink_protocol::SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            node_id: id(2),
            node_key_sha256: challenge.node_key_sha256.clone(),
            request_id: challenge.request_id.clone(),
            nonce: challenge.nonce.clone(),
            roles: vec![NodeRole::NodeRelay as i32],
            policy_revision: 1,
            lease_sequence: 1,
            issued_at_unix_ms: now.unix_ms,
            expires_at_unix_ms: now.unix_ms + lease_ms,
            server_forwarding_allowed: false,
            public_ingress_allowed: false,
            max_connections: 8,
            bytes_per_second: 1024,
            runtime_id: id(3),
            runtime_generation: 1,
        };
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
        let control = NodeControl {
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
            turn_authorization: Arc::new(TurnAuthorization::new(8)?),
            pump: tokio::spawn(std::future::pending::<Result<(), Error>>()),
            _usage_pump: tokio::spawn(async { Ok(()) }),
            runtime_id: id(3),
        };
        let config = NodeConfig {
            deployment_id: id(1),
            node_id: id(2),
            control_origin: origin,
            trusted_policy_issuer: URL_SAFE_NO_PAD.encode(policy.public_key()),
            identity_key_file: std::env::temp_dir().join("unused-topology-test-key"),
            service_usage_directory: None,
            roles: vec![NodeRole::NodeRelay as i32],
            allow_loopback_http: true,
        };
        let claims = TopologyPublisherClaims {
            scope: GrantScope {
                schema_version: SCHEMA_VERSION,
                deployment_id: id(1),
                space_id: id(5),
                grant_id: id(6),
                policy_epoch: 1,
                not_before_ms: now.unix_ms,
                expires_at_ms: now.unix_ms + 30_000,
            },
            node_id: id(2),
            public_key: identity.public_key(),
            peer: PeerId::from_public_key(&identity.public_key()),
            incarnation: incarnation(&lease),
            allowed_neighbors: vec![PeerId::from_public_key(
                &NodeIdentity::from_seed(&[104; 32]).public_key(),
            )],
            route_export_digests: vec![],
            allowed_prefixes: vec![],
        };
        let publisher = authority.sign_topology_publisher(&claims)?;
        Ok(Self {
            control,
            config,
            authority,
            authority_key,
            policy,
            claims,
            publisher,
            revoked: BTreeSet::new(),
        })
    }

    fn reporter(&self) -> TestResult<TopologyReporter> {
        Ok(TopologyReporter::new(
            self.config.clone(),
            NodeIdentity::from_seed(&NODE_SEED),
        )?)
    }

    fn context(&self) -> NetworkVerification<'_> {
        NetworkVerification {
            authority_key: &self.authority_key,
            deployment_id: &self.claims.scope.deployment_id,
            space_id: &self.claims.scope.space_id,
            policy_epoch: self.claims.scope.policy_epoch,
            now_ms: self.claims.scope.not_before_ms,
            revoked_grant_ids: &self.revoked,
        }
    }

    fn neighbors(&self) -> Vec<TopologyNeighbor> {
        vec![TopologyNeighbor {
            local: self.claims.peer,
            remote: self.claims.allowed_neighbors[0],
            local_endpoint_revision: 1,
            remote_endpoint_revision: 2,
            up: false,
        }]
    }

    fn prepare(&self, reporter: &TopologyReporter) -> TestResult<PreparedReport> {
        Ok(reporter.prepare(
            &self.control,
            &self.publisher,
            &self.context(),
            &[],
            self.neighbors(),
        )?)
    }

    fn advertisement(&self, prepared: &PreparedReport) -> TestResult<SignedTopologyAdvertisement> {
        Ok(self.authority.sign_topology_advertisement(
            &prepared.report,
            sample(self.control.started)?.unix_ms,
            prepared.lease.expires_at_unix_ms,
        )?)
    }

    async fn renew(&self) -> TestResult {
        tokio::time::sleep(Duration::from_millis(2)).await;
        let now = sample(self.control.started)?;
        let mut state = self.control.state.lock().map_err(|_| "poisoned runtime")?;
        let mut lease = state.gate.current(now)?.clone();
        lease.lease_sequence += 1;
        lease.request_id = id(1000 + lease.lease_sequence as u16);
        lease.nonce = vec![lease.lease_sequence as u8; 32];
        lease.issued_at_unix_ms = now.unix_ms;
        lease.expires_at_unix_ms = now.unix_ms + 10_000;
        let challenge = NodeChallenge {
            schema_version: lease.schema_version,
            deployment_id: lease.deployment_id.clone(),
            security_epoch: lease.security_epoch,
            node_id: lease.node_id.clone(),
            node_key_sha256: lease.node_key_sha256.clone(),
            request_id: lease.request_id.clone(),
            nonce: lease.nonce.clone(),
            expires_at_unix_ms: now.unix_ms + 2000,
        };
        state.gate.accept(
            &self.policy.sign(&lease)?.encode_to_vec(),
            &challenge,
            now.monotonic_ms,
            now,
        )?;
        Ok(())
    }
}

fn code<T>(result: Result<T, Error>) -> Option<ErrorCode> {
    match result {
        Err(Error::Authorization(error)) => Some(error.code),
        _ => None,
    }
}

#[tokio::test]
async fn registered_node_and_current_space_policy_cannot_be_replaced_by_publication_claims()
-> TestResult {
    let fixture = Fixture::new("http://127.0.0.1:9".into())?;
    let reporter = fixture.reporter()?;
    let valid = fixture.prepare(&reporter)?;
    assert!(!valid.report.claims().neighbors[0].up);
    assert!(valid.report.claims().prefixes.is_empty());
    // Topology observations need no forwarding permission. The fixture's
    // signed node lease explicitly denies forwarding throughout these cases.
    assert!(!valid.lease.server_forwarding_allowed);
    for change in 0..8 {
        let mut claims = fixture.claims.clone();
        match change {
            0 => claims.node_id = id(20),
            1 => claims.incarnation.runtime_id = id(21),
            2 => claims.incarnation.runtime_generation += 1,
            3 => claims.scope.space_id = id(22),
            4 => claims.scope.deployment_id = id(23),
            5 => claims.scope.policy_epoch += 1,
            6 => {
                claims.public_key = NodeIdentity::from_seed(&[105; 32]).public_key();
                claims.peer = PeerId::from_public_key(&claims.public_key);
            }
            _ => {}
        }
        let signed = if change == 7 {
            NetworkAuthoritySigner::from_master_seed(&[106; 32])?
                .sign_topology_publisher(&claims)?
        } else {
            fixture.authority.sign_topology_publisher(&claims)?
        };
        assert!(
            reporter
                .prepare(&fixture.control, &signed, &fixture.context(), &[], vec![])
                .is_err(),
            "accepted changed publication binding {change}",
        );
    }
    let wrong_identity =
        TopologyReporter::new(fixture.config.clone(), NodeIdentity::from_seed(&[107; 32]))?;
    assert_eq!(
        code(wrong_identity.prepare(
            &fixture.control,
            &fixture.publisher,
            &fixture.context(),
            &[],
            vec![]
        )),
        Some(ErrorCode::IdentityMismatch),
    );
    let revoked = BTreeSet::from([fixture.claims.scope.grant_id.clone()]);
    let mut context = fixture.context();
    context.revoked_grant_ids = &revoked;
    assert_eq!(
        code(reporter.prepare(&fixture.control, &fixture.publisher, &context, &[], vec![])),
        Some(ErrorCode::PolicyRevoked),
    );
    Ok(())
}

#[tokio::test]
async fn neighbor_claims_are_bounded_owned_unique_and_explicitly_allowed() -> TestResult {
    let fixture = Fixture::new("http://127.0.0.1:9".into())?;
    let reporter = fixture.reporter()?;
    for change in 0..5 {
        let mut neighbors = fixture.neighbors();
        match change {
            0 => neighbors[0].local = PeerId([7; 32]),
            1 => neighbors[0].remote = PeerId([8; 32]),
            2 => neighbors.push(neighbors[0].clone()),
            3 => neighbors[0].remote_endpoint_revision = 0,
            _ => neighbors = vec![neighbors[0].clone(); MAX_NEIGHBORS + 1],
        }
        assert!(
            reporter
                .prepare(
                    &fixture.control,
                    &fixture.publisher,
                    &fixture.context(),
                    &[],
                    neighbors
                )
                .is_err(),
            "accepted invalid neighbor observation {change}",
        );
    }
    // Rejected input cannot supersede a valid, already prepared observation.
    let prepared = fixture.prepare(&reporter)?;
    assert_eq!(prepared.report.claims().sequence, 1);
    Ok(())
}

#[tokio::test]
async fn publisher_reissue_and_reporter_recreation_keep_the_runtime_sequence_fence() -> TestResult {
    let fixture = Fixture::new("http://127.0.0.1:9".into())?;
    let first_reporter = fixture.reporter()?;
    let first = fixture.prepare(&first_reporter)?;
    let first_reply = fixture.advertisement(&first)?;
    drop(first_reporter);
    let mut claims = fixture.claims.clone();
    claims.scope.grant_id = id(30);
    let reissued = fixture.authority.sign_topology_publisher(&claims)?;
    let reporter = fixture.reporter()?;
    let second = reporter.prepare(&fixture.control, &reissued, &fixture.context(), &[], vec![])?;
    assert_eq!(first.report.claims().sequence, 1);
    assert_eq!(second.report.claims().sequence, 2);
    assert_ne!(
        first.report.claims().publisher_digest,
        second.report.claims().publisher_digest
    );
    assert_eq!(
        code(reporter.accept(&fixture.control, &fixture.context(), &first, &first_reply)),
        Some(ErrorCode::ReplayRejected),
    );
    let second_reply = fixture.advertisement(&second)?;
    assert_eq!(
        reporter
            .accept(&fixture.control, &fixture.context(), &second, &second_reply)?
            .claims()
            .report
            .sequence,
        2,
    );
    Ok(())
}

#[tokio::test]
async fn no_more_than_64_spaces_can_consume_runtime_watermarks_and_exhaustion_never_wraps()
-> TestResult {
    let fixture = Fixture::new("http://127.0.0.1:9".into())?;
    let reporter = fixture.reporter()?;
    for index in 0..64 {
        let space = id(100 + index);
        let mut claims = fixture.claims.clone();
        claims.scope.space_id = space.clone();
        let signed = fixture.authority.sign_topology_publisher(&claims)?;
        let mut context = fixture.context();
        context.space_id = &space;
        let prepared = reporter.prepare(&fixture.control, &signed, &context, &[], vec![])?;
        assert_eq!(prepared.report.claims().sequence, 1);
    }
    assert_eq!(
        code(reporter.prepare(
            &fixture.control,
            &fixture.publisher,
            &fixture.context(),
            &[],
            vec![],
        )),
        Some(ErrorCode::CapacityExceeded),
    );
    let space = id(100);
    let mut claims = fixture.claims.clone();
    claims.scope.space_id = space.clone();
    let signed = fixture.authority.sign_topology_publisher(&claims)?;
    let mut context = fixture.context();
    context.space_id = &space;
    assert_eq!(
        reporter
            .prepare(&fixture.control, &signed, &context, &[], vec![])?
            .report
            .claims()
            .sequence,
        2,
    );
    {
        let mut state = fixture
            .control
            .state
            .lock()
            .map_err(|_| "poisoned runtime")?;
        state
            .topology
            .sequences
            .insert(space.clone(), i64::MAX as u64);
    }
    assert_eq!(
        code(reporter.prepare(&fixture.control, &signed, &context, &[], vec![])),
        Some(ErrorCode::CapacityExceeded),
    );
    Ok(())
}

#[tokio::test]
async fn a_later_trusted_time_is_never_replaced_with_an_earlier_local_clock() -> TestResult {
    let fixture = Fixture::new("http://127.0.0.1:9".into())?;
    let reporter = fixture.reporter()?;
    let prepared = fixture.prepare(&reporter)?;
    let reply = fixture.advertisement(&prepared)?;
    let mut context = fixture.context();
    context.now_ms = prepared.report.claims().expires_at_ms;
    assert_eq!(
        code(reporter.accept(&fixture.control, &context, &prepared, &reply)),
        Some(ErrorCode::LeaseExpired),
    );
    context.now_ms = fixture.claims.scope.expires_at_ms;
    assert_eq!(
        code(reporter.prepare(&fixture.control, &fixture.publisher, &context, &[], vec![])),
        Some(ErrorCode::LeaseExpired),
    );
    Ok(())
}

#[tokio::test]
async fn renewed_node_leases_cannot_extend_either_original_report_expiration_anchor() -> TestResult
{
    for (lease_ms, initial_delay_ms) in [(400, 0), (2500, 2000)] {
        let fixture =
            Fixture::with_initial_delay("http://127.0.0.1:9".into(), lease_ms, initial_delay_ms)?;
        let reporter = fixture.reporter()?;
        let prepared = fixture.prepare(&reporter)?;
        let reply = fixture.advertisement(&prepared)?;
        fixture.renew().await?;
        let until = fixture.control.started + Duration::from_millis(prepared.deadline_ms + 5);
        tokio::time::sleep_until(until.into()).await;
        assert!(
            fixture.control.current_lease().is_ok(),
            "renewed node lease must remain live"
        );
        if initial_delay_ms > 0 {
            assert!(
                sample(fixture.control.started)?.unix_ms < prepared.report.claims().expires_at_ms,
                "the monotonic case must fail while the signed wall expiry remains live",
            );
        }
        assert_eq!(
            code(reporter.accept(&fixture.control, &fixture.context(), &prepared, &reply)),
            Some(ErrorCode::LeaseExpired),
        );
    }
    Ok(())
}

const CORRECT: u8 = 0;
const HANG: u8 = 1;
const REDIRECT: u8 = 2;
const OVERSIZE_LENGTH: u8 = 3;
const OVERSIZE_STREAM: u8 = 4;
const ANOTHER_REPORT: u8 = 5;
const BAD_SIGNATURE: u8 = 6;
const SLOW: u8 = 7;
const ALTERED_EXPIRY: u8 = 8;

struct HttpState {
    mode: AtomicU8,
    authority: Arc<NetworkAuthoritySigner>,
    authority_key: [u8; 32],
    publisher: SignedTopologyPublisher,
    claims: TopologyPublisherClaims,
    received: Mutex<Vec<SignedTopologyReport>>,
    changed: Notify,
    completed: AtomicUsize,
    redirect_hits: AtomicUsize,
}

impl HttpState {
    async fn wait_for_requests(&self, minimum: usize) -> TestResult {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let count = self
                    .received
                    .lock()
                    .map_err(|_| "poisoned HTTP requests")?
                    .len();
                if count >= minimum {
                    return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                }
                self.changed.notified().await;
            }
        })
        .await??;
        Ok(())
    }
}

struct HttpTask(tokio::task::JoinHandle<()>);
impl Drop for HttpTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn start_http(mode: u8) -> TestResult<(Fixture, Arc<HttpState>, HttpTask)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let fixture = Fixture::new(format!("http://{}", listener.local_addr()?))?;
    let state = Arc::new(HttpState {
        mode: AtomicU8::new(mode),
        authority: fixture.authority.clone(),
        authority_key: fixture.authority_key,
        publisher: fixture.publisher.clone(),
        claims: fixture.claims.clone(),
        received: Mutex::new(Vec::new()),
        changed: Notify::new(),
        completed: AtomicUsize::new(0),
        redirect_hits: AtomicUsize::new(0),
    });
    let router = Router::new()
        .route(
            "/api/v3/network/spaces/{space}/topology/reports/{node}",
            post(http_report),
        )
        .route("/redirect-target", post(redirect_target))
        .with_state(state.clone());
    let task = HttpTask(tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    }));
    Ok((fixture, state, task))
}

async fn redirect_target(State(state): State<Arc<HttpState>>) -> StatusCode {
    state.redirect_hits.fetch_add(1, Ordering::SeqCst);
    StatusCode::BAD_REQUEST
}

async fn http_report(
    State(state): State<Arc<HttpState>>,
    Json(mut signed): Json<SignedTopologyReport>,
) -> Result<Response, StatusCode> {
    state
        .received
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .push(signed.clone());
    state.changed.notify_one();
    let mode = state.mode.load(Ordering::SeqCst);
    match mode {
        HANG => return std::future::pending().await,
        REDIRECT => {
            return Ok((
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, "/redirect-target")],
            )
                .into_response());
        }
        OVERSIZE_LENGTH => return Ok(vec![b'x'; MAX_RESPONSE_BYTES + 1].into_response()),
        OVERSIZE_STREAM => {
            let chunks = vec![
                Ok::<_, std::io::Error>(vec![b' '; MAX_RESPONSE_BYTES]),
                Ok(vec![b' '; 1]),
            ];
            return Ok(Body::from_stream(futures_util::stream::iter(chunks)).into_response());
        }
        ANOTHER_REPORT | ALTERED_EXPIRY => {
            let mut report = TopologyReport::decode_canonical(&signed.claims)
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            if mode == ANOTHER_REPORT {
                report.sequence += 1;
            } else {
                report.expires_at_ms += 1;
            }
            signed = NodeIdentity::from_seed(&NODE_SEED)
                .sign_topology_report(&report)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
        SLOW => tokio::time::sleep(Duration::from_millis(750)).await,
        _ => {}
    }
    let now = sample(Instant::now())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unix_ms;
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &state.authority_key,
        deployment_id: &state.claims.scope.deployment_id,
        space_id: &state.claims.scope.space_id,
        policy_epoch: state.claims.scope.policy_epoch,
        now_ms: now,
        revoked_grant_ids: &revoked,
    };
    let publisher = verify_topology_publisher(
        &state.publisher,
        &context,
        &state.claims.node_id,
        &state.claims.public_key,
        &state.claims.incarnation,
        &[],
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let report =
        verify_topology_report(&signed, &publisher, &context, &state.claims.incarnation, 0)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let mut advertisement = state
        .authority
        .sign_topology_advertisement(&report, now, report.claims().expires_at_ms)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if mode == BAD_SIGNATURE {
        advertisement.signature[0] ^= 1;
    }
    state.completed.fetch_add(1, Ordering::SeqCst);
    Ok(Json(advertisement).into_response())
}

#[tokio::test]
async fn real_http_rejects_different_reports_and_corrupted_authority_responses() -> TestResult {
    for (mode, expected) in [
        (ANOTHER_REPORT, ErrorCode::IdentityMismatch),
        (ALTERED_EXPIRY, ErrorCode::IdentityMismatch),
        (BAD_SIGNATURE, ErrorCode::IdentityMismatch),
    ] {
        let (fixture, state, _server) = start_http(mode).await?;
        let result = fixture
            .reporter()?
            .publish(
                &fixture.control,
                &fixture.publisher,
                &fixture.context(),
                fixture.neighbors(),
            )
            .await;
        assert_eq!(code(result), Some(expected));
        assert_eq!(state.completed.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[tokio::test]
async fn real_http_rejects_declared_and_streamed_oversize_bodies_and_never_follows_redirects()
-> TestResult {
    for mode in [OVERSIZE_LENGTH, OVERSIZE_STREAM, REDIRECT] {
        let (fixture, state, _server) = start_http(mode).await?;
        let result = fixture
            .reporter()?
            .publish(
                &fixture.control,
                &fixture.publisher,
                &fixture.context(),
                vec![],
            )
            .await;
        if mode == REDIRECT {
            assert!(matches!(result, Err(Error::Control)));
            assert_eq!(state.redirect_hits.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(code(result), Some(ErrorCode::CapacityExceeded));
        }
        assert_eq!(
            state
                .received
                .lock()
                .map_err(|_| "poisoned HTTP requests")?
                .len(),
            1
        );
    }
    Ok(())
}

#[tokio::test]
async fn real_http_total_deadline_rejects_a_750ms_response_while_report_is_still_live() -> TestResult
{
    let (fixture, state, _server) = start_http(SLOW).await?;
    let reporter = fixture.reporter()?;
    let started = Instant::now();
    // The server response would still fit the 1000ms report TTL. It must fail
    // specifically because the complete HTTP request budget is only 700ms.
    let result = tokio::time::timeout(
        Duration::from_millis(900),
        reporter.publish(
            &fixture.control,
            &fixture.publisher,
            &fixture.context(),
            vec![],
        ),
    )
    .await?;
    assert!(matches!(result, Err(Error::Control)));
    assert!(started.elapsed() >= Duration::from_millis(600));
    assert_eq!(state.completed.load(Ordering::SeqCst), 0);
    assert_eq!(
        state
            .received
            .lock()
            .map_err(|_| "poisoned HTTP requests")?
            .len(),
        1
    );
    assert!(fixture.control.current_lease().is_ok());
    Ok(())
}

#[tokio::test]
async fn stop_cancels_in_flight_http_and_revokes_a_prepared_response() -> TestResult {
    let (fixture, state, _server) = start_http(HANG).await?;
    let reporter = fixture.reporter()?;
    let prepared = fixture.prepare(&reporter)?;
    let reply = fixture.advertisement(&prepared)?;
    let context = fixture.context();
    let mut publication =
        Box::pin(reporter.publish(&fixture.control, &fixture.publisher, &context, vec![]));
    tokio::select! {
        result = &mut publication => return Err(format!("report completed before stop: {}", result.is_ok()).into()),
        seen = state.wait_for_requests(1) => seen?,
    }
    fixture.control.stop();
    let result = tokio::time::timeout(Duration::from_millis(100), publication).await?;
    assert!(matches!(result, Err(Error::Control)));
    assert!(matches!(
        reporter.accept(&fixture.control, &context, &prepared, &reply),
        Err(Error::Control)
    ));
    Ok(())
}

#[tokio::test]
async fn cancellation_after_server_receipt_never_reuses_a_sequence_even_with_a_new_reporter()
-> TestResult {
    let (fixture, state, _server) = start_http(HANG).await?;
    let reporter = fixture.reporter()?;
    let context = fixture.context();
    let mut publication =
        Box::pin(reporter.publish(&fixture.control, &fixture.publisher, &context, vec![]));
    tokio::select! {
        result = &mut publication => return Err(format!("report completed before cancellation: {}", result.is_ok()).into()),
        seen = state.wait_for_requests(1) => seen?,
    }
    drop(publication);
    drop(reporter);
    state.mode.store(CORRECT, Ordering::SeqCst);
    let next = fixture
        .reporter()?
        .publish(&fixture.control, &fixture.publisher, &context, vec![])
        .await?;
    assert_eq!(next.claims().report.sequence, 2);
    let received = state
        .received
        .lock()
        .map_err(|_| "poisoned HTTP requests")?;
    let sequences = received
        .iter()
        .map(|signed| {
            TopologyReport::decode_canonical(&signed.claims).map(|report| report.sequence)
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(sequences, vec![1, 2]);
    Ok(())
}

#[tokio::test]
async fn concurrent_publishers_allocate_unique_sequences_and_discard_superseded_receipts()
-> TestResult {
    let (fixture, state, _server) = start_http(CORRECT).await?;
    let first = fixture.reporter()?;
    let second = fixture.reporter()?;
    let context = fixture.context();
    let (older, newer) = tokio::join!(
        first.publish(&fixture.control, &fixture.publisher, &context, vec![]),
        second.publish(&fixture.control, &fixture.publisher, &context, vec![]),
    );
    assert_eq!(code(older), Some(ErrorCode::ReplayRejected));
    assert_eq!(newer?.claims().report.sequence, 2);
    let received = state
        .received
        .lock()
        .map_err(|_| "poisoned HTTP requests")?;
    let mut sequences = received
        .iter()
        .map(|signed| {
            TopologyReport::decode_canonical(&signed.claims).map(|report| report.sequence)
        })
        .collect::<Result<Vec<_>, _>>()?;
    sequences.sort_unstable();
    assert_eq!(sequences, vec![1, 2]);
    Ok(())
}

#[tokio::test]
async fn reporter_reuses_the_existing_explicit_loopback_http_and_https_only_origin_rules()
-> TestResult {
    let fixture = Fixture::new("http://127.0.0.1:9".into())?;
    for (origin, allow_loopback, allowed) in [
        ("http://127.0.0.1:9", true, true),
        ("http://127.0.0.1:9", false, false),
        ("http://192.0.2.10:8080", true, false),
        ("https://control.example", false, true),
        ("https://control.example/path", false, false),
        ("https://user@control.example", false, false),
    ] {
        let mut config = fixture.config.clone();
        config.control_origin = origin.into();
        config.allow_loopback_http = allow_loopback;
        assert_eq!(
            TopologyReporter::new(config, NodeIdentity::from_seed(&NODE_SEED)).is_ok(),
            allowed,
            "origin {origin}"
        );
    }
    Ok(())
}
