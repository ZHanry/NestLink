//! Real HTTP transport tests; SDK setup verifies the original signed management
//! identity. The extra fixed handlers observe HTTP admission, not authorization.
use super::*;
use crate::{API_BASE, CONTROL_BYTES, Client, DeploymentTrust, Sdk};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use nestlink_protocol::{ErrorCode, api::ErrorResponse};
use serde_json::{Value, json};
use std::{
    io,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Probe {
    active: AtomicUsize,
    peak: AtomicUsize,
    held_calls: AtomicUsize,
    deletions: AtomicUsize,
    rejected: AtomicUsize,
    oversized: AtomicUsize,
    release: Semaphore,
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            held_calls: AtomicUsize::new(0),
            deletions: AtomicUsize::new(0),
            rejected: AtomicUsize::new(0),
            oversized: AtomicUsize::new(0),
            release: Semaphore::new(0),
        }
    }
}

struct Active(Arc<Probe>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn held(State(probe): State<Arc<Probe>>) -> Json<Value> {
    probe.held_calls.fetch_add(1, Ordering::SeqCst);
    let active = probe.active.fetch_add(1, Ordering::SeqCst) + 1;
    probe.peak.fetch_max(active, Ordering::SeqCst);
    let _active = Active(probe.clone());
    if let Ok(permit) = probe.release.acquire().await {
        permit.forget();
    }
    Json(json!({"completed": true}))
}

async fn deleted(State(probe): State<Arc<Probe>>) -> Json<Value> {
    probe.deletions.fetch_add(1, Ordering::SeqCst);
    Json(json!({"deleted": true}))
}

async fn rejected(State(probe): State<Arc<Probe>>, Path(code): Path<u16>) -> Response {
    probe.rejected.fetch_add(1, Ordering::SeqCst);
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST);
    (
        status,
        Json(ErrorResponse {
            code: if status == StatusCode::UNAUTHORIZED {
                ErrorCode::AuthRequired
            } else {
                ErrorCode::CapacityExceeded
            },
        }),
    )
        .into_response()
}

async fn oversized(State(probe): State<Arc<Probe>>) -> Body {
    probe.oversized.fetch_add(1, Ordering::SeqCst);
    Body::from(vec![b'x'; CONTROL_BYTES as usize + 1])
}

async fn chunked_oversized(State(probe): State<Arc<Probe>>) -> Body {
    probe.oversized.fetch_add(1, Ordering::SeqCst);
    Body::from_stream(futures_util::stream::iter([Ok::<_, io::Error>(
        vec![b'x'; CONTROL_BYTES as usize + 1],
    )]))
}

struct Fixture {
    origin: Url,
    deployment: String,
    issuer: [u8; 32],
    probe: Arc<Probe>,
    server: JoinHandle<io::Result<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new() -> Result<Self> {
        let deployment = nestlink_auth::random_id();
        let signer = nestlink_identity::PermitSigner::generate();
        let issuer = signer.public_key();
        let store = nestlink_storage::Store::in_memory(&deployment)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let origin = Url::parse(&format!("http://{}", listener.local_addr()?))?;
        let state = nestlink_server::AppState::new(
            store,
            nestlink_auth::VaultKey::from_bytes([177; 32]),
            signer,
            origin.origin().ascii_serialization(),
            false,
        )?;
        let probe = Arc::new(Probe::default());
        let observations = Router::new()
            .route(&format!("{API_BASE}/held"), get(held).delete(deleted))
            .route(&format!("{API_BASE}/reject/{{code}}"), post(rejected))
            .route(&format!("{API_BASE}/oversized"), get(oversized))
            .route(
                &format!("{API_BASE}/chunked-oversized"),
                get(chunked_oversized),
            )
            .with_state(probe.clone());
        let app = nestlink_server::router(state).merge(observations);
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self {
            origin,
            deployment,
            issuer,
            probe,
            server,
        })
    }

    async fn sdk(&self) -> Result<Sdk> {
        Ok(Sdk::connect(
            &self.origin.origin().ascii_serialization(),
            DeploymentTrust {
                deployment_id: self.deployment.clone(),
                permit_issuer: self.issuer,
            },
            true,
        )
        .await?)
    }
}

async fn until(mut condition: impl FnMut() -> bool) -> Result {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn independent_sdks_share_four_http_slots_and_delete_keeps_its_reserved_lane() -> Result {
    let f = Fixture::new().await?;
    let mut clients = Vec::new();
    for _ in 0..12 {
        clients.push(f.sdk().await?);
    }
    let deletion = f.sdk().await?;
    let mut workers = JoinSet::new();
    for sdk in clients {
        workers.spawn(async move {
            sdk.call::<(), Value>(Method::GET, "/held", None, false)
                .await
        });
    }
    until(|| f.probe.active.load(Ordering::SeqCst) == ORDINARY_ACTIVE).await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(f.probe.held_calls.load(Ordering::SeqCst), ORDINARY_ACTIVE);
    assert_eq!(
        deletion
            .call::<(), Value>(Method::DELETE, "/held", None, false)
            .await?,
        Some(json!({"deleted": true}))
    );
    assert_eq!(f.probe.deletions.load(Ordering::SeqCst), 1);
    assert_eq!(f.probe.active.load(Ordering::SeqCst), ORDINARY_ACTIVE);
    // A different original signed origin has independent admission even while
    // every ordinary slot on the first origin is occupied.
    let other = Fixture::new().await?;
    let _other_sdk = other.sdk().await?;
    f.probe.release.add_permits(12);
    while let Some(result) = workers.join_next().await {
        assert_eq!(result??, Some(json!({"completed": true})));
    }
    assert_eq!(f.probe.held_calls.load(Ordering::SeqCst), 12);
    assert_eq!(f.probe.peak.load(Ordering::SeqCst), ORDINARY_ACTIVE);
    Ok(())
}

#[tokio::test]
async fn bounded_waiters_cancel_and_excess_mutations_never_reach_http() -> Result {
    let f = Fixture::new().await?;
    let sdk = f.sdk().await?;
    let mut active = Vec::new();
    for _ in 0..ORDINARY_ACTIVE {
        active.push(acquire(&f.origin, &Method::GET).await?);
    }
    let gate = active[0]._owner.clone();
    let mutation = json!({"request_id": "unchanged-original-mutation"});
    let mut queued = Vec::new();
    for _ in 0..ORDINARY_WAITERS {
        let mut future =
            Box::pin(sdk.call::<_, Value>(Method::POST, "/reject/401", Some(&mutation), false));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut future)
                .await
                .is_err()
        );
        queued.push(future);
    }
    assert_eq!(gate.ordinary_waiters.available_permits(), 0);
    assert!(matches!(
        sdk.call::<_, Value>(Method::POST, "/reject/401", Some(&mutation), false)
            .await,
        Err(SdkError::Api(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::CapacityExceeded
        ))
    ));
    assert_eq!(f.probe.rejected.load(Ordering::SeqCst), 0);
    // Even a completely full ordinary waiting queue leaves DELETE independent.
    assert!(
        sdk.call::<(), Value>(Method::DELETE, "/held", None, false)
            .await?
            .is_some()
    );
    drop(queued);
    assert_eq!(gate.ordinary_waiters.available_permits(), ORDINARY_WAITERS);
    drop(active);
    assert_eq!(gate.ordinary.available_permits(), ORDINARY_ACTIVE);
    assert!(matches!(
        sdk.call::<_, Value>(Method::POST, "/reject/401", Some(&mutation), false)
            .await,
        Err(SdkError::Api(
            StatusCode::UNAUTHORIZED,
            ErrorCode::AuthRequired
        ))
    ));
    assert_eq!(f.probe.rejected.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn original_fifteen_second_budget_includes_wait_and_cannot_emit_a_late_post() -> Result {
    let f = Fixture::new().await?;
    let sdk = f.sdk().await?;
    let mut active = Vec::new();
    for _ in 0..ORDINARY_ACTIVE {
        active.push(acquire(&f.origin, &Method::GET).await?);
    }
    let gate = active[0]._owner.clone();
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(17),
        sdk.call::<(), Value>(Method::POST, "/reject/401", None, false),
    )
    .await?;
    assert!(matches!(result, Err(SdkError::Timeout)));
    assert!(started.elapsed() >= Duration::from_secs(14));
    assert_eq!(gate.ordinary_waiters.available_permits(), ORDINARY_WAITERS);
    assert_eq!(f.probe.rejected.load(Ordering::SeqCst), 0);
    drop(active);
    assert!(matches!(
        sdk.call::<(), Value>(Method::POST, "/reject/401", None, false)
            .await,
        Err(SdkError::Api(
            StatusCode::UNAUTHORIZED,
            ErrorCode::AuthRequired
        ))
    ));
    assert_eq!(f.probe.rejected.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn cancelling_an_active_http_future_immediately_releases_its_exact_origin_slot() -> Result {
    let f = Fixture::new().await?;
    let sdk = f.sdk().await?;
    let keeper = acquire(&f.origin, &Method::GET).await?;
    let gate = keeper._owner.clone();
    let request = tokio::spawn(async move {
        sdk.call::<(), Value>(Method::GET, "/held", None, false)
            .await
    });
    until(|| f.probe.held_calls.load(Ordering::SeqCst) == 1).await?;
    assert_eq!(gate.ordinary.available_permits(), ORDINARY_ACTIVE - 2);
    request.abort();
    assert!(matches!(request.await, Err(error) if error.is_cancelled()));
    assert_eq!(gate.ordinary.available_permits(), ORDINARY_ACTIVE - 1);
    f.probe.release.add_permits(1);
    drop(keeper);
    assert_eq!(gate.ordinary.available_permits(), ORDINARY_ACTIVE);
    Ok(())
}

#[tokio::test]
async fn original_response_bounds_and_401_429_do_not_retry_mutations_or_leak_slots() -> Result {
    let f = Fixture::new().await?;
    let sdk = f.sdk().await?;
    let keeper = acquire(&f.origin, &Method::GET).await?;
    let gate = keeper._owner.clone();
    for path in ["/oversized", "/chunked-oversized"] {
        assert!(matches!(
            sdk.call::<(), Value>(Method::GET, path, None, false).await,
            Err(SdkError::Invalid)
        ));
        assert_eq!(gate.ordinary.available_permits(), ORDINARY_ACTIVE - 1);
    }
    for (path, status, code) in [
        (
            "/reject/401",
            StatusCode::UNAUTHORIZED,
            ErrorCode::AuthRequired,
        ),
        (
            "/reject/429",
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::CapacityExceeded,
        ),
    ] {
        assert!(
            matches!(sdk.call::<_, Value>(Method::POST, path, Some(&json!({"immutable": true})), false).await,
            Err(SdkError::Api(actual_status, actual_code)) if actual_status == status && actual_code == code)
        );
        assert_eq!(gate.ordinary.available_permits(), ORDINARY_ACTIVE - 1);
    }
    assert_eq!(f.probe.rejected.load(Ordering::SeqCst), 2);
    assert_eq!(f.probe.oversized.load(Ordering::SeqCst), 2);
    // Distinct independently built reqwest clients also retain the same lane.
    let independent = Client::builder().no_proxy().build()?;
    assert!(
        crate::request::<Value>(&independent, &f.origin, Method::DELETE, "/held", None, None)
            .await?
            .is_some()
    );
    drop(keeper);
    assert_eq!(gate.ordinary.available_permits(), ORDINARY_ACTIVE);
    Ok(())
}

#[tokio::test]
async fn registry_is_bounded_canonical_and_never_replaces_a_live_origin_owner() -> Result {
    let mut registry = Registry::default();
    let mut owners = Vec::new();
    for index in 0..MAX_ORIGINS {
        owners.push(registry.get(&Url::parse(&format!(
            "https://control-{index}.example.test"
        ))?)?);
    }
    let original = registry.get(&Url::parse("https://control-0.example.test:443/")?)?;
    assert!(Arc::ptr_eq(&original, &owners[0]));
    assert_eq!(registry.origins.len(), MAX_ORIGINS);
    assert!(
        registry
            .get(&Url::parse("https://extra.example.test")?)
            .is_err()
    );
    let permit = owners[0].clone().acquire(false).await?;
    drop(original);
    drop(owners);
    let still_original = registry.get(&Url::parse("https://control-0.example.test")?)?;
    assert!(Arc::ptr_eq(&permit._owner, &still_original));
    assert_eq!(
        still_original.ordinary.available_permits(),
        ORDINARY_ACTIVE - 1
    );
    assert_eq!(registry.origins.len(), 1);
    drop((permit, still_original));
    let _next = registry.get(&Url::parse("https://extra.example.test")?)?;
    assert_eq!(registry.origins.len(), 1);
    Ok(())
}

#[tokio::test]
async fn deletion_waiting_is_finite_and_cancellation_restores_its_reserved_lane() -> Result {
    let owner = Arc::new(Admission::new());
    let active = owner.clone().acquire(true).await?;
    let mut queued = Vec::new();
    for _ in 0..DELETE_WAITERS {
        let mut pending = Box::pin(owner.clone().acquire(true));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut pending)
                .await
                .is_err()
        );
        queued.push(pending);
    }
    assert_eq!(owner.delete_waiters.available_permits(), 0);
    assert!(matches!(
        owner.clone().acquire(true).await,
        Err(SdkError::Api(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::CapacityExceeded
        ))
    ));
    // Saturated DELETE work also cannot consume an ordinary lane.
    let ordinary = owner.clone().acquire(false).await?;
    assert_eq!(owner.ordinary.available_permits(), ORDINARY_ACTIVE - 1);
    drop(queued);
    assert_eq!(owner.delete_waiters.available_permits(), DELETE_WAITERS);
    drop((active, ordinary));
    assert_eq!(owner.deletions.available_permits(), DELETE_ACTIVE);
    assert_eq!(owner.ordinary.available_permits(), ORDINARY_ACTIVE);
    Ok(())
}
