use axum::{
    body::{Body, Bytes},
    extract::Request,
    middleware::{self, Next},
    response::IntoResponse,
};
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_protocol::api::NativeDiscoveryConfig;
use nestlink_sdk::{DeploymentTrust, Sdk, SdkError};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

struct Running(tokio::task::JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn discovery_requires_login_keeps_deployment_binding_and_never_grants_private_consent()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", "native-discovery-test-password")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let addresses = vec![
        "11.0.0.1:3478".parse()?,
        "[2606:4700:4700::1111]:3478".parse()?,
    ];
    let state = AppState::new(
        store,
        VaultKey::from_bytes([48; 32]),
        signer,
        origin.clone(),
        false,
    )?
    .with_stun_servers(addresses.clone())?;
    let changed: Arc<Mutex<Option<NativeDiscoveryConfig>>> = Arc::default();
    let injected = changed.clone();
    let app = router(state).layer(middleware::from_fn(move |request: Request, next: Next| {
        let injected = injected.clone();
        async move {
            let substitute = if request.uri().path() == "/api/v3/network/discovery" {
                injected.lock().ok().and_then(|value| value.clone())
            } else {
                None
            };
            if let Some(value) = substitute {
                axum::Json(value).into_response()
            } else {
                next.run(request).await
            }
        }
    }));
    let _server = Running(tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }));
    let anonymous = reqwest::Client::new()
        .get(format!("{origin}/api/v3/network/discovery"))
        .send()
        .await?;
    assert_eq!(anonymous.status(), reqwest::StatusCode::UNAUTHORIZED);
    let mut sdk = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment.clone(),
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    assert!(matches!(
        sdk.native_discovery_config().await,
        Err(SdkError::SignIn)
    ));
    sdk.login(
        "admin".into(),
        Secret::from_text("native-discovery-test-password".into()),
        None,
    )
    .await?;
    let valid = sdk.native_discovery_config().await?;
    assert_eq!(valid.deployment_id, deployment);
    assert_eq!(valid.stun_servers, addresses);
    let mut forged = valid.clone();
    forged.deployment_id = random_id();
    *changed.lock().map_err(|_| "injection lock poisoned")? = Some(forged);
    assert!(matches!(
        sdk.native_discovery_config().await,
        Err(SdkError::Trust)
    ));
    let mut private = valid;
    private.stun_servers = vec!["10.20.30.40:3478".parse()?];
    *changed.lock().map_err(|_| "injection lock poisoned")? = Some(private);
    assert!(matches!(
        sdk.native_discovery_config().await,
        Err(SdkError::Proof(_))
    ));
    for status in [
        reqwest::StatusCode::UNAUTHORIZED,
        reqwest::StatusCode::FORBIDDEN,
        reqwest::StatusCode::NOT_FOUND,
    ] {
        assert!(
            !SdkError::Api(status, nestlink_protocol::ErrorCode::AuthRequired)
                .discovery_temporarily_unavailable()
        );
    }
    assert!(!SdkError::Trust.discovery_temporarily_unavailable());
    assert!(!SdkError::Invalid.discovery_temporarily_unavailable());
    assert!(SdkError::Timeout.discovery_temporarily_unavailable());
    Ok(())
}

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone)]
enum DiscoveryReply {
    Deployment,
    Pending(reqwest::StatusCode),
    TrickleAfterHeaders(Duration),
    Bytes(Vec<u8>),
    OversizedChunks,
}

impl DiscoveryReply {
    async fn response(self) -> Option<axum::response::Response> {
        match self {
            Self::Deployment => None,
            Self::Pending(status) => Some(
                (
                    status,
                    Body::from_stream(futures_util::stream::pending::<Result<Bytes, Infallible>>()),
                )
                    .into_response(),
            ),
            Self::TrickleAfterHeaders(delay) => {
                // The request already spends part of its total budget waiting
                // for headers. Later bytes keep arriving before any idle
                // timeout, but must not restart or extend the total deadline.
                tokio::time::sleep(delay).await;
                let stream = futures_util::stream::unfold((), |()| async {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    Some((Ok::<_, Infallible>(Bytes::from_static(b" ")), ()))
                });
                Some(Body::from_stream(stream).into_response())
            }
            Self::Bytes(bytes) => Some(bytes.into_response()),
            Self::OversizedChunks => Some(
                Body::from_stream(futures_util::stream::iter([
                    Ok::<_, Infallible>(Bytes::from(vec![
                        b' ';
                        nestlink_protocol::CONTROL_BYTES as usize
                    ])),
                    Ok(Bytes::from_static(b" ")),
                ]))
                .into_response(),
            ),
        }
    }
}

struct DiscoveryHarness {
    sdk: Sdk,
    reply: Arc<Mutex<DiscoveryReply>>,
    _server: Running,
}

async fn streaming_discovery_harness() -> TestResult<DiscoveryHarness> {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", "native-discovery-stream-password")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let state = AppState::new(
        store,
        VaultKey::from_bytes([49; 32]),
        signer,
        origin.clone(),
        false,
    )?;
    let reply = Arc::new(Mutex::new(DiscoveryReply::Deployment));
    let injected = reply.clone();
    let app = router(state).layer(middleware::from_fn(move |request: Request, next: Next| {
        let injected = injected.clone();
        async move {
            let substitute = if request.uri().path() == "/api/v3/network/discovery" {
                injected.lock().ok().map(|reply| reply.clone())
            } else {
                None
            };
            if let Some(substitute) = substitute
                && let Some(response) = substitute.response().await
            {
                return response;
            }
            next.run(request).await
        }
    }));
    let server = Running(tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }));
    let mut sdk = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment,
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    sdk.login(
        "admin".into(),
        Secret::from_text("native-discovery-stream-password".into()),
        None,
    )
    .await?;
    Ok(DiscoveryHarness {
        sdk,
        reply,
        _server: server,
    })
}

#[tokio::test]
async fn rejection_headers_decide_fallback_without_waiting_for_an_error_body() -> TestResult {
    let harness = streaming_discovery_harness().await?;
    for (status, temporarily_unavailable) in [
        (reqwest::StatusCode::UNAUTHORIZED, false),
        (reqwest::StatusCode::FORBIDDEN, false),
        (reqwest::StatusCode::NOT_FOUND, false),
        (reqwest::StatusCode::FOUND, false),
        (reqwest::StatusCode::TOO_MANY_REQUESTS, false),
        (reqwest::StatusCode::INTERNAL_SERVER_ERROR, false),
        (reqwest::StatusCode::BAD_GATEWAY, true),
        (reqwest::StatusCode::SERVICE_UNAVAILABLE, true),
        (reqwest::StatusCode::GATEWAY_TIMEOUT, true),
    ] {
        *harness.reply.lock().map_err(|_| "reply lock poisoned")? = DiscoveryReply::Pending(status);
        // All error bodies remain pending forever. The deadline below is
        // shorter than discovery's budget, so only decisive headers can pass.
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            harness.sdk.native_discovery_config(),
        )
        .await?;
        let error = result.err().ok_or("HTTP rejection accepted")?;
        assert!(
            matches!(&error, SdkError::Api(actual, _) if *actual == status),
            "lost HTTP {status} classification: {error:?}",
        );
        assert_eq!(
            error.discovery_temporarily_unavailable(),
            temporarily_unavailable,
            "HTTP {status}",
        );
    }
    Ok(())
}

#[tokio::test]
async fn successful_pending_and_trickling_bodies_share_the_total_discovery_deadline() -> TestResult
{
    let harness = streaming_discovery_harness().await?;
    for reply in [
        DiscoveryReply::Pending(reqwest::StatusCode::OK),
        DiscoveryReply::TrickleAfterHeaders(Duration::from_millis(1500)),
    ] {
        *harness.reply.lock().map_err(|_| "reply lock poisoned")? = reply;
        // A separate body budget would take 4.5 seconds for the second case;
        // no timeout or an idle timeout would wait indefinitely on this stream.
        let result = tokio::time::timeout(
            Duration::from_secs(4),
            harness.sdk.native_discovery_config(),
        )
        .await?;
        let error = result.err().ok_or("unfinished response accepted")?;
        assert!(error.discovery_temporarily_unavailable(), "{error:?}");
        match error {
            SdkError::Timeout => {}
            SdkError::Transport(error) if error.is_timeout() => {}
            error => return Err(format!("unfinished success did not time out: {error:?}").into()),
        }
    }
    Ok(())
}

#[tokio::test]
async fn invalid_and_oversized_success_bodies_remain_hard_failures() -> TestResult {
    let harness = streaming_discovery_harness().await?;
    for reply in [
        DiscoveryReply::Bytes(b"{invalid JSON".to_vec()),
        DiscoveryReply::Bytes(Vec::new()),
        // This response has an exact size hint, producing Content-Length.
        DiscoveryReply::Bytes(vec![b' '; nestlink_protocol::CONTROL_BYTES as usize + 1]),
        DiscoveryReply::OversizedChunks,
    ] {
        *harness.reply.lock().map_err(|_| "reply lock poisoned")? = reply;
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            harness.sdk.native_discovery_config(),
        )
        .await?;
        let error = result.err().ok_or("invalid success accepted")?;
        assert!(
            matches!(&error, SdkError::Invalid | SdkError::Json(_)),
            "unexpected invalid-response classification: {error:?}",
        );
        assert!(!error.discovery_temporarily_unavailable());
    }
    Ok(())
}
