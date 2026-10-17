use axum::{Router, body::Body, http::Request};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, random_id};
use nestlink_identity::{InstallationIdentity, PermitSigner, digest};
use nestlink_protocol::{DeviceAction, DeviceActionClaims, SCHEMA_VERSION, api::DeviceDescriptor};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn app() -> Result<Router> {
    let mut store = Store::in_memory(&random_id())?;
    store.bootstrap_admin("admin", "browser-endpoint-http-password")?;
    Ok(router(AppState::new(
        store,
        VaultKey::from_bytes([8; 32]),
        PermitSigner::generate(),
        "https://console.example.test".into(),
        true,
    )?))
}

async fn call(
    app: &Router,
    path: &str,
    body: &Value,
    token: Option<&str>,
) -> Result<(axum::http::StatusCode, Value)> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("Content-Type", "application/json");
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(serde_json::to_vec(body)?))?)
        .await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 262_144).await?;
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, value))
}

#[tokio::test]
async fn browser_endpoint_registration_is_authenticated_signed_and_capped() -> Result {
    let app = app()?;
    let (status, grant) = call(
        &app,
        "/api/v3/auth/login",
        &json!({"username":"admin","password":"browser-endpoint-http-password"}),
        None,
    )
    .await?;
    assert_eq!(status, axum::http::StatusCode::OK);
    let token = grant["access_token"].as_str().ok_or("access token")?;
    let account_id = grant["principal"]["account_id"]
        .as_str()
        .ok_or("account id")?;

    let (status, _) = call(&app, "/api/v3/devices/challenge", &Value::Null, None).await?;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);

    let (status, challenge) =
        call(&app, "/api/v3/devices/challenge", &Value::Null, Some(token)).await?;
    assert_eq!(status, axum::http::StatusCode::OK);
    let identity = InstallationIdentity::generate();
    let descriptor = DeviceDescriptor {
        id: random_id(),
        name: "ephemeral browser".into(),
        platform: "web".into(),
        public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
        capabilities: vec!["controller".into(), "vp8".into()],
        path_mode: "direct_only".into(),
    };
    let claims = DeviceActionClaims {
        schema_version: SCHEMA_VERSION,
        action: DeviceAction::RegisterBrowserEndpoint as i32,
        deployment_id: challenge["deployment_id"]
            .as_str()
            .ok_or("deployment")?
            .into(),
        security_epoch: challenge["security_epoch"].as_u64().ok_or("epoch")?,
        account_id: account_id.into(),
        device_id: descriptor.id.clone(),
        resource_id: challenge["id"].as_str().ok_or("challenge id")?.into(),
        challenge: URL_SAFE_NO_PAD.decode(challenge["nonce"].as_str().ok_or("nonce")?)?,
        payload_sha256: digest(&serde_json::to_vec(&descriptor)?).to_vec(),
        expires_at_unix_ms: challenge["expires_at_unix_ms"]
            .as_u64()
            .ok_or("challenge expiry")?,
    };
    let registration = json!({
        "challenge_id": challenge["id"],
        "device": serde_json::to_value(&descriptor)?,
        "signature": URL_SAFE_NO_PAD.encode(identity.sign_action(&claims)?)
    });
    let (status, _) = call(&app, "/api/v3/devices/browser", &registration, None).await?;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    let (status, lease) = call(&app, "/api/v3/devices/browser", &registration, Some(token)).await?;
    assert_eq!(status, axum::http::StatusCode::CREATED);
    assert_eq!(lease["device_id"], registration["device"]["id"]);
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let expires = lease["expires_at_unix_ms"].as_u64().ok_or("lease expiry")?;
    assert!(expires > now_ms && expires <= now_ms + 600_000);

    // The route cannot turn a temporary browser endpoint into a host identity,
    // even when the submitted device descriptor is correctly signed.
    let (status, challenge) =
        call(&app, "/api/v3/devices/challenge", &Value::Null, Some(token)).await?;
    assert_eq!(status, axum::http::StatusCode::OK);
    let identity = InstallationIdentity::generate();
    let descriptor = DeviceDescriptor {
        id: random_id(),
        name: "browser host attempt".into(),
        platform: "web".into(),
        public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
        capabilities: vec!["controller".into(), "host".into(), "vp8".into()],
        path_mode: "direct_only".into(),
    };
    let claims = DeviceActionClaims {
        schema_version: SCHEMA_VERSION,
        action: DeviceAction::RegisterBrowserEndpoint as i32,
        deployment_id: challenge["deployment_id"]
            .as_str()
            .ok_or("deployment")?
            .into(),
        security_epoch: challenge["security_epoch"].as_u64().ok_or("epoch")?,
        account_id: account_id.into(),
        device_id: descriptor.id.clone(),
        resource_id: challenge["id"].as_str().ok_or("challenge id")?.into(),
        challenge: URL_SAFE_NO_PAD.decode(challenge["nonce"].as_str().ok_or("nonce")?)?,
        payload_sha256: digest(&serde_json::to_vec(&descriptor)?).to_vec(),
        expires_at_unix_ms: challenge["expires_at_unix_ms"]
            .as_u64()
            .ok_or("challenge expiry")?,
    };
    let registration = json!({
        "challenge_id": challenge["id"],
        "device": serde_json::to_value(&descriptor)?,
        "signature": URL_SAFE_NO_PAD.encode(identity.sign_action(&claims)?)
    });
    let (status, _) = call(&app, "/api/v3/devices/browser", &registration, Some(token)).await?;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    Ok(())
}
