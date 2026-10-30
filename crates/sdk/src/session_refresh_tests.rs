use super::*;
use axum::{Json, Router, response::IntoResponse, routing::post};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn transient_refresh_retries_keep_the_same_login_and_auth_rejection_clears_it()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let account = random_id();
    let session = random_id();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let expected_session = session.clone();
    let expected_account = account.clone();
    let app = Router::new().route(
        &format!("{API_BASE}/auth/refresh"),
        post(move |Json(body): Json<Refresh>| {
            let attempt = count.fetch_add(1, Ordering::SeqCst);
            let session = expected_session.clone();
            let account = expected_account.clone();
            async move {
                if attempt < 2 {
                    assert_eq!(body.generation, 1);
                    assert_eq!(body.refresh_token.as_deref(), Some("B".repeat(43).as_str()));
                    let status = if attempt == 0 {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::TOO_MANY_REQUESTS
                    };
                    (
                        status,
                        Json(ErrorResponse {
                            code: ErrorCode::CapacityExceeded,
                        }),
                    )
                        .into_response()
                } else if attempt == 2 {
                    assert_eq!(body.generation, 1);
                    Json(LoginResponse {
                        principal: Principal {
                            account_id: account,
                            session_id: session,
                            name: "test".into(),
                            is_admin: false,
                            access_expires: 9999999999,
                        },
                        access_token: "C".repeat(43),
                        refresh_token: "D".repeat(43),
                        refresh_expires: 9999999999,
                        generation: 2,
                    })
                    .into_response()
                } else {
                    assert_eq!(body.generation, 2);
                    assert_eq!(body.refresh_token.as_deref(), Some("D".repeat(43).as_str()));
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(ErrorResponse {
                            code: ErrorCode::AuthRequired,
                        }),
                    )
                        .into_response()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = Url::parse(&format!("http://{}", listener.local_addr()?))?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let deployment_id = random_id();
    let issuer = nestlink_identity::PermitSigner::generate().public_key();
    let mut sdk = Sdk {
        client: Client::builder().no_proxy().build()?,
        origin,
        trust: DeploymentTrust {
            deployment_id: deployment_id.clone(),
            permit_issuer: issuer,
        },
        health: HealthResponse {
            product: "NestLink".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            api_base: API_BASE.into(),
            alpn: ALPN.into(),
            deployment_id,
            security_epoch: 1,
            permit_issuer: URL_SAFE_NO_PAD.encode(issuer),
            node_policy_issuer: URL_SAFE_NO_PAD.encode(issuer),
            native_ice_version: 0,
        },
        login: None,
    };
    sdk.install_login(LoginResponse {
        principal: Principal {
            account_id: account,
            session_id: session.clone(),
            name: "test".into(),
            is_admin: false,
            access_expires: 9999999999,
        },
        access_token: "A".repeat(43),
        refresh_token: "B".repeat(43),
        refresh_expires: 9999999999,
        generation: 1,
    })?;
    for expected in [
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        assert!(matches!(sdk.refresh().await, Err(SdkError::Api(status, _)) if status == expected));
        assert_eq!(
            sdk.principal().map(|user| user.session_id.as_str()),
            Some(session.as_str())
        );
    }
    sdk.refresh().await?;
    assert_eq!(
        sdk.principal().map(|user| user.session_id.as_str()),
        Some(session.as_str())
    );
    assert!(matches!(sdk.refresh().await, Err(SdkError::SignIn)));
    assert!(sdk.principal().is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    server.abort();
    Ok(())
}
