//! Deterministic two-endpoint coordinator regression. Real Store validates
//! both Renew DeviceAction proofs. Only the M04 signed fixture wrapping is
//! synthetic: production Store media issuance stays closed and has its own
//! in-storage positive regressions. This does not claim native codec execution.
use super::*;
use crate::{DeploymentTrust, native::NativeMediaEvidence};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_policy::PathSet;
use nestlink_protocol::{
    Path, Permission, PermitClaims,
    api::{ApprovalChoice, PermitResponse, Principal, RemoteRequest, RenewalSubmission},
    media_authority::{
        FORMAT_CAPABILITY, FrozenMediaScope, MediaAnnouncement, MediaDirection, ProbeIdentity,
    },
    media_format::{FormatSet, FrameRate, VideoFormat},
};
use nestlink_remote::{
    AuthorizedConnection, RuntimeClock, SessionLifecycle, controller_proof, host_proof,
};
use nestlink_session::{
    MEDIA_REGRESSION_REQUEST_ID, MEDIA_REGRESSION_SESSION_ID, MediaSessionBinding, Session,
    SessionBinding,
};
use nestlink_storage::Store;
use prost::Message;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use tokio::{io::split, sync::watch, task::JoinHandle};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |t| t.as_secs())
}
fn password() -> Secret {
    Secret::from_text("native-dual-renewal-regression-password".into())
}
struct Running(JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Database(std::path::PathBuf);
impl Drop for Database {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
struct Fixture {
    store: Mutex<Store>,
    controller: Principal,
    id: String,
    format: VideoFormat,
    lose_response: bool,
    issuances: AtomicUsize,
}
fn wrapped(mut claims: PermitClaims, format: VideoFormat) -> Result<PermitResponse> {
    let set = FormatSet::new(vec![format])?;
    claims.media_format_version = 2;
    claims.media_formats = vec![format.encode()?];
    claims.media_format_sha256 = set.digest().to_vec();
    claims.required_capabilities = vec![FORMAT_CAPABILITY.into()];
    let signer = PermitSigner::from_seed([71; 32]);
    Ok(PermitResponse {
        permit: URL_SAFE_NO_PAD.encode(signer.sign(&claims)?.encode_to_vec()),
        claims,
    })
}
async fn current(
    State(state): State<Arc<Fixture>>,
) -> std::result::Result<Json<PermitResponse>, StatusCode> {
    let store = state
        .store
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let claims = store
        .current_permit(&state.controller, &state.id, now())
        .map_err(|_| StatusCode::FORBIDDEN)?;
    Ok(Json(
        wrapped(claims, state.format).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ))
}
async fn view(
    State(state): State<Arc<Fixture>>,
) -> std::result::Result<Json<RemoteView>, StatusCode> {
    let mut view = state
        .store
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .remote(&state.controller, &state.id)
        .map_err(|_| StatusCode::FORBIDDEN)?;
    // An issued lease, including its successor, owns its signed expiry.
    view.expires_at_unix_ms = 1;
    Ok(Json(view))
}
async fn renew(
    State(state): State<Arc<Fixture>>,
    Json(submission): Json<RenewalSubmission>,
) -> std::result::Result<Json<PermitResponse>, StatusCode> {
    let claims = {
        state
            .store
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .renew_permit(&state.controller, &state.id, submission, now())
            .map_err(|_| StatusCode::FORBIDDEN)?
    };
    state.issuances.fetch_add(1, Ordering::AcqRel);
    if state.lose_response {
        std::future::pending::<()>().await;
    }
    Ok(Json(
        wrapped(claims, state.format).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ))
}
struct LiveFence(Mutex<()>);
impl NativeExecutionFence for LiveFence {
    fn with_current(&self, operation: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        let _guard = self
            .0
            .lock()
            .map_err(|_| io::Error::other("test fence poisoned"))?;
        operation()
    }
}
struct Source {
    evidence: NativeMediaEvidence,
    fence: Arc<dyn NativeExecutionFence>,
}
impl NativeRenewalSource for Source {
    fn prepare<'a>(
        &'a self,
        _: &'a Sdk,
        _: &'a DeviceIdentity,
        _: &'a VerifiedPermit,
        _: EndpointRole,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = std::result::Result<PreparedNativeRenewal, SdkError>> + Send + 'a>,
    > {
        Box::pin(async {
            Ok(PreparedNativeRenewal {
                evidence: self.evidence.clone(),
                execution: self.fence.clone(),
            })
        })
    }
}
fn evidence(permit: &VerifiedPermit, role: EndpointRole) -> NativeMediaEvidence {
    let c = permit.claims();
    let local = MediaAnnouncement {
        version: 2,
        device_id: if role == EndpointRole::Controller {
            c.controller_device_id.clone()
        } else {
            c.host_device_id.clone()
        },
        direction: if role == EndpointRole::Controller {
            MediaDirection::Decode
        } else {
            MediaDirection::Encode
        },
        revision: 1,
        expires_at_unix_ms: now() * 1000 + 240000,
        probe: ProbeIdentity {
            generation: 1,
            resource_id: random_id(),
            backend: "cpu-software".into(),
            adapter_luid: None,
            driver_version: None,
        },
        formats: c.media_formats.clone(),
    };
    NativeMediaEvidence {
        frozen: FrozenMediaScope {
            version: 2,
            controller_revision: 1,
            host_revision: 1,
            formats: c.media_formats.clone(),
            sha256: c.media_format_sha256.clone(),
        },
        local,
    }
}
fn session(
    permit: VerifiedPermit,
    evidence: &NativeMediaEvidence,
    role: EndpointRole,
    clock: &RuntimeClock,
) -> Result<Session> {
    let c = permit.claims();
    let sample = clock.sample()?;
    let binding = SessionBinding {
        media: Some(MediaSessionBinding::from_local_announcement(
            &permit,
            &evidence.frozen,
            &evidence.local,
            role,
            sample.unix_ms,
        )?),
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        session_id: c.session_id.clone(),
        account_id: c.account_id.clone(),
        controller_device_id: c.controller_device_id.clone(),
        host_device_id: c.host_device_id.clone(),
        controller_key_sha256: c.controller_key_sha256.as_slice().try_into()?,
        host_key_sha256: c.host_key_sha256.as_slice().try_into()?,
        resource_id: c.resource_id.clone(),
        policy_revision: c.policy_revision,
        connection_generation: c.connection_generation,
        capability_sha256: c.capability_sha256.as_slice().try_into()?,
        granted_permissions: vec![Permission::View],
        supported_capabilities: c.required_capabilities.clone(),
        local_paths: PathSet::DIRECT,
    };
    let mut session = Session::activate_media_runtime_regression(
        permit,
        binding,
        Path::Direct,
        sample.monotonic_ms,
        sample,
        MEDIA_REGRESSION_REQUEST_ID,
    )?;
    session.cap_deadline_ms(sample.monotonic_ms + 5000)?;
    Ok(session)
}
async fn exercise(lost_response: bool) -> Result {
    let deployment = random_id();
    let signer = PermitSigner::from_seed([71; 32]);
    let issuer = signer.public_key();
    let database = Database(
        std::env::temp_dir().join(format!("nestlink-native-renewal-{}.sqlite", random_id())),
    );
    let mut store = Store::open(&database.0, &deployment)?;
    store.bootstrap_admin("admin", password().expose())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let router = nestlink_server::router(nestlink_server::AppState::new(
        store,
        VaultKey::from_bytes([72; 32]),
        signer,
        origin.clone(),
        false,
    )?);
    let server = Running(tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    }));
    let trust = || DeploymentTrust {
        deployment_id: deployment.clone(),
        permit_issuer: issuer,
    };
    let mut controller_sdk = Sdk::connect(&origin, trust(), true).await?;
    controller_sdk
        .login("admin".into(), password(), None)
        .await?;
    controller_sdk
        .create_account("native-host-owner".into(), password())
        .await?;
    let mut host_sdk = Sdk::connect(&origin, trust(), true).await?;
    host_sdk
        .login("native-host-owner".into(), password(), None)
        .await?;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    controller_sdk
        .enroll(
            &controller,
            "controller".into(),
            "windows".into(),
            vec!["controller".into(), "vp8".into(), FORMAT_CAPABILITY.into()],
            "direct_only".into(),
        )
        .await?;
    host_sdk
        .enroll(
            &host,
            "host".into(),
            "windows".into(),
            vec!["host".into(), "vp8".into(), FORMAT_CAPABILITY.into()],
            "direct_only".into(),
        )
        .await?;
    let request = controller_sdk
        .create_remote(RemoteRequest {
            id: MEDIA_REGRESSION_SESSION_ID.into(),
            controller_device_id: controller.device_id.clone(),
            host_device_id: host.device_id.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "direct_only".into(),
        })
        .await?;
    host_sdk
        .approve(
            &host,
            &request,
            ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32],
                paths: vec![Path::Direct as i32],
            },
        )
        .await?;
    let original = controller_sdk.permit(&request.id).await?;
    let format = VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(30, 1)?, 2000)?;
    let response = wrapped(original.claims().clone(), format)?;
    let old = verify_permit(&URL_SAFE_NO_PAD.decode(response.permit)?, &issuer)?;
    let fixture = Arc::new(Fixture {
        store: Mutex::new(Store::open_existing(&database.0, &deployment)?),
        controller: controller_sdk
            .principal()
            .ok_or("missing principal")?
            .clone(),
        id: request.id,
        format,
        lose_response: lost_response,
        issuances: AtomicUsize::new(0),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let replacement = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route(
            &format!("{}/remote/{{id}}", nestlink_protocol::API_BASE),
            get(view),
        )
        .route(
            &format!("{}/remote/{{id}}/permit", nestlink_protocol::API_BASE),
            get(current),
        )
        .route(
            &format!("{}/remote/{{id}}/renew", nestlink_protocol::API_BASE),
            post(renew),
        )
        .with_state(fixture.clone());
    let replacement_server = Running(tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    }));
    controller_sdk.origin = url::Url::parse(&replacement)?;
    host_sdk.origin = url::Url::parse(&replacement)?;
    let clock_c = RuntimeClock::default();
    let clock_h = RuntimeClock::default();
    let evidence_c = evidence(&old, EndpointRole::Controller);
    let evidence_h = evidence(&old, EndpointRole::Host);
    let mut session_c = session(old.clone(), &evidence_c, EndpointRole::Controller, &clock_c)?;
    let mut session_h = session(old.clone(), &evidence_h, EndpointRole::Host, &clock_h)?;
    let (c, h) = tokio::io::duplex(131072);
    let (mut cr, mut cw) = split(c);
    let (mut hr, mut hw) = split(h);
    tokio::try_join!(
        controller_proof(
            &mut cr,
            &mut cw,
            &mut session_c,
            &controller.identity,
            &host.identity.public_key(),
            &clock_c
        ),
        host_proof(
            &mut hr,
            &mut hw,
            &mut session_h,
            &host.identity,
            &controller.identity.public_key(),
            &clock_h
        )
    )?;
    let (_sc, rc) = watch::channel(None);
    let (_sh, rh) = watch::channel(None);
    let c = AuthorizedConnection::with_lifecycle(
        cr,
        cw,
        session_c,
        Path::Direct,
        clock_c,
        SessionLifecycle::new(rc),
    )?;
    let h = AuthorizedConnection::with_lifecycle(
        hr,
        hw,
        session_h,
        Path::Direct,
        clock_h,
        SessionLifecycle::new(rh),
    )?;
    let (c, h) = tokio::try_join!(c.negotiate_native_renewal(), h.negotiate_native_renewal())?;
    let mut channels_c = c.into_channels();
    let mut channels_h = h.into_channels();
    let lease_c = channels_c.lease_control();
    let lease_h = channels_h.lease_control();
    let sequence_c = Arc::new(AtomicU64::new(1));
    let sequence_h = Arc::new(AtomicU64::new(1));
    let mut coordinator_c = Coordinator::new(
        channels_c
            .take_native_renewal_port()
            .ok_or("missing controller port")?,
        old.clone(),
        host.identity.public_key(),
        EndpointRole::Controller,
        sequence_c.clone(),
    );
    let mut coordinator_h = Coordinator::new(
        channels_h
            .take_native_renewal_port()
            .ok_or("missing host port")?,
        old,
        controller.identity.public_key(),
        EndpointRole::Host,
        sequence_h.clone(),
    );
    let source_c = Source {
        evidence: evidence_c,
        fence: Arc::new(LiveFence(Mutex::new(()))),
    };
    let source_h = Source {
        evidence: evidence_h,
        fence: Arc::new(LiveFence(Mutex::new(()))),
    };
    // Rejection must preserve the coordinator and lease so this same fixture
    // can still complete the real dual-endpoint round immediately afterward.
    coordinator_c = crate::native::assert_coordinated_manual_renewal_rejected(
        coordinator_c,
        lease_c.clone(),
        sequence_c.clone(),
        &source_c.evidence,
    )?;
    // The host polls its private port repeatedly without preparing/signing when
    // there is no Offer. The controller is the sole issuance initiator.
    let host_round = async {
        loop {
            let permit = coordinator_h
                .step(&host_sdk, &host, &lease_h, &source_h)
                .await?;
            if permit.claims().lease_sequence == 2 {
                return Ok::<_, SdkError>(permit);
            }
        }
    };
    let (next_c, next_h) = tokio::try_join!(
        coordinator_c.step(&controller_sdk, &controller, &lease_c, &source_c),
        host_round
    )?;
    assert_eq!(next_c.claims(), next_h.claims());
    assert_eq!(next_c.claims().lease_sequence, 2);
    assert_eq!(sequence_c.load(Ordering::Acquire), 2);
    assert_eq!(sequence_h.load(Ordering::Acquire), 2);
    assert_eq!(fixture.issuances.load(Ordering::Acquire), 1);
    assert!(lease_c.remaining()? > Duration::from_secs(5));
    assert!(lease_h.remaining()? > Duration::from_secs(5));
    assert_eq!(
        lease_c.current_native_permit()?.claims().media_formats,
        next_c.claims().media_formats
    );
    channels_c.shutdown(StopReason::ExplicitExit).await?;
    channels_h.shutdown(StopReason::ExplicitExit).await?;
    drop(coordinator_c);
    drop(coordinator_h);
    drop(replacement_server);
    drop(server);
    drop(fixture);
    drop(database);
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_endpoint_driver_renews_with_real_store_proofs_and_exact_signed_media_fixture()
-> Result {
    exercise(false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_post_response_recovers_only_exact_next_after_both_real_store_proofs() -> Result {
    exercise(true).await
}
