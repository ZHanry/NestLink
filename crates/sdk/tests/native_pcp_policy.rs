//! The additive policy endpoint uses real login and deployment authentication.
use axum::{
    extract::Request,
    middleware::{self, Next},
    response::IntoResponse,
};
use nestlink_auth::{Secret, VaultKey, hash_password, random_id};
use nestlink_identity::PermitSigner;
use nestlink_protocol::api::NativePcpPolicy;
use nestlink_sdk::{DeploymentTrust, Sdk, SdkError};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type PolicyReply = Arc<Mutex<Option<(StatusCode, Value)>>>;
const PASSWORD: &str = "native-pcp-policy-test-password";
const POLICY_PATH: &str = "/api/v3/discovery/native/pcp";

struct Running(tokio::task::JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Harness {
    sdk: Sdk,
    origin: String,
    deployment: String,
    reply: PolicyReply,
    discovery_calls: Arc<AtomicUsize>,
    _server: Running,
}

async fn harness(allowed: Option<bool>) -> TestResult<Harness> {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let vault = VaultKey::from_bytes([53; 32]);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", PASSWORD)?;
    let admin = store
        .login(
            "admin",
            PASSWORD,
            None,
            now,
            &vault,
            &hash_password(PASSWORD)?,
        )?
        .principal;
    store.create_member(&admin, "member", PASSWORD)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let mut state = AppState::new(store, vault, signer, origin.clone(), false)?;
    if let Some(allowed) = allowed {
        state = state.with_pcp_mapping(allowed);
    }
    let reply: PolicyReply = Arc::default();
    let injected = reply.clone();
    let discovery_calls = Arc::new(AtomicUsize::new(0));
    let calls = discovery_calls.clone();
    let app = router(state).layer(middleware::from_fn(move |request: Request, next: Next| {
        let injected = injected.clone();
        let calls = calls.clone();
        async move {
            let policy = request.uri().path() == POLICY_PATH;
            if request.uri().path() == "/api/v3/network/discovery" {
                calls.fetch_add(1, Ordering::SeqCst);
            }
            // Authenticate against the production Store before injecting a
            // successful authenticated response's fault. Never bypass login.
            let response = next.run(request).await;
            let replacement = if policy && response.status().is_success() {
                injected.lock().ok().and_then(|value| value.clone())
            } else {
                None
            };
            match replacement {
                Some((status, body)) => (status, axum::Json(body)).into_response(),
                None => response,
            }
        }
    }));
    let server = Running(tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }));
    let sdk = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment.clone(),
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    Ok(Harness {
        sdk,
        origin,
        deployment,
        reply,
        discovery_calls,
        _server: server,
    })
}

#[tokio::test]
async fn default_denies_mapping_and_policy_requires_a_live_authenticated_session() -> TestResult {
    let mut harness = harness(None).await?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;
    let policy_url = format!("{}{POLICY_PATH}", harness.origin);
    assert_eq!(
        http.get(&policy_url).send().await?.status(),
        StatusCode::UNAUTHORIZED,
    );
    assert!(matches!(
        harness.sdk.native_pcp_policy().await,
        Err(SdkError::SignIn)
    ));
    let health: Value = http
        .get(format!("{}/api/v3/health", harness.origin))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let health = health.as_object().ok_or("health object missing")?;
    for private in ["allowed", "allow_pcp_mapping", "native_pcp_policy"] {
        assert!(!health.contains_key(private));
    }
    harness
        .sdk
        .login("member".into(), Secret::from_text(PASSWORD.into()), None)
        .await?;
    assert_eq!(
        harness.sdk.native_pcp_policy().await?,
        NativePcpPolicy {
            deployment_id: harness.deployment.clone(),
            allowed: false,
        },
    );
    harness.sdk.logout().await?;
    assert!(matches!(
        harness.sdk.native_pcp_policy().await,
        Err(SdkError::SignIn)
    ));

    // Keep the original bearer after logout to exercise server-side live
    // authentication, independently of the SDK clearing its local login.
    let login: Value = http
        .post(format!("{}/api/v3/auth/login", harness.origin))
        .json(&json!({"username":"member","password":PASSWORD}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let token = login["access_token"].as_str().ok_or("token missing")?;
    assert_eq!(
        http.get(&policy_url).bearer_auth(token).send().await?.status(),
        StatusCode::OK,
    );
    http.post(format!("{}/api/v3/auth/logout", harness.origin))
        .header("Origin", harness.origin.as_str())
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(
        http.get(&policy_url).bearer_auth(token).send().await?.status(),
        StatusCode::UNAUTHORIZED,
    );
    Ok(())
}

#[tokio::test]
async fn enabled_policy_is_additive_and_does_not_change_the_strict_stun_document() -> TestResult {
    let mut harness = harness(Some(true)).await?;
    harness
        .sdk
        .login("member".into(), Secret::from_text(PASSWORD.into()), None)
        .await?;
    assert_eq!(
        harness.sdk.native_pcp_policy().await?,
        NativePcpPolicy {
            deployment_id: harness.deployment.clone(),
            allowed: true,
        },
    );
    let discovery = harness.sdk.native_discovery_config().await?;
    assert_eq!(
        serde_json::to_value(discovery)?,
        json!({"deployment_id":harness.deployment,"stun_servers":[]}),
    );
    assert_eq!(harness.discovery_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn wrong_deployment_invalid_shape_and_missing_endpoint_never_supply_permission() -> TestResult {
    let mut harness = harness(Some(true)).await?;
    harness
        .sdk
        .login("member".into(), Secret::from_text(PASSWORD.into()), None)
        .await?;
    *harness.reply.lock().map_err(|_| "reply lock poisoned")? = Some((
        StatusCode::OK,
        json!({"deployment_id":random_id(),"allowed":true}),
    ));
    assert!(matches!(
        harness.sdk.native_pcp_policy().await,
        Err(SdkError::Trust),
    ));
    *harness.reply.lock().map_err(|_| "reply lock poisoned")? = Some((
        StatusCode::OK,
        json!({"deployment_id":"invalid","allowed":true}),
    ));
    assert!(matches!(
        harness.sdk.native_pcp_policy().await,
        Err(SdkError::Proof(_)),
    ));
    for body in [
        json!({"deployment_id":harness.deployment}),
        json!({"deployment_id":harness.deployment,"allowed":"true"}),
        json!({"deployment_id":harness.deployment,"allowed":true,"gateway":"192.168.1.1"}),
    ] {
        *harness.reply.lock().map_err(|_| "reply lock poisoned")? = Some((StatusCode::OK, body));
        assert!(matches!(
            harness.sdk.native_pcp_policy().await,
            Err(SdkError::Json(_)),
        ));
    }
    for (status, body) in [
        (StatusCode::NOT_FOUND, Value::Null),
        (
            StatusCode::NOT_FOUND,
            json!({"code":nestlink_protocol::ErrorCode::ProtocolMismatch}),
        ),
        (StatusCode::UNAUTHORIZED, Value::Null),
        (StatusCode::FORBIDDEN, Value::Null),
        (StatusCode::SERVICE_UNAVAILABLE, Value::Null),
    ] {
        *harness.reply.lock().map_err(|_| "reply lock poisoned")? = Some((status, body));
        assert!(
            matches!(harness.sdk.native_pcp_policy().await, Err(SdkError::Api(actual, _)) if actual == status),
        );
    }
    assert_eq!(harness.discovery_calls.load(Ordering::SeqCst), 0);
    Ok(())
}
