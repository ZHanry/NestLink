use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::random_id;
use nestlink_identity::PermitSigner;
use nestlink_protocol::{
    ALPN, API_BASE,
    api::{HealthResponse, ServerIdentityChallenge, ServerIdentityClaims, ServerIdentityProof},
};
use nestlink_sdk::{DeploymentTrust, Sdk, SdkError};
use std::sync::Arc;
use tokio::task::JoinHandle;

struct Running(JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct FakeEndpoint {
    health: HealthResponse,
    attacker: PermitSigner,
    origin: String,
}

async fn health(State(state): State<Arc<FakeEndpoint>>) -> Json<HealthResponse> {
    Json(state.health.clone())
}

async fn identity_proof(
    State(state): State<Arc<FakeEndpoint>>,
    Json(challenge): Json<ServerIdentityChallenge>,
) -> Result<Json<ServerIdentityProof>, StatusCode> {
    let attacker_issuer = URL_SAFE_NO_PAD.encode(state.attacker.public_key());
    let mut claims = ServerIdentityClaims {
        nonce: challenge.nonce,
        management_origin: state.origin.clone(),
        product: state.health.product.clone(),
        version: state.health.version.clone(),
        api_base: state.health.api_base.clone(),
        alpn: state.health.alpn.clone(),
        deployment_id: state.health.deployment_id.clone(),
        security_epoch: state.health.security_epoch,
        permit_issuer: attacker_issuer,
        node_policy_issuer: state.health.node_policy_issuer.clone(),
    };
    let signature = state
        .attacker
        .sign_server_identity(&claims)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // The endpoint copies the expected public key into the transcript after
    // signing with its own key. This models a server that can echo health data
    // but cannot prove possession of the configured issuer private key.
    claims.permit_issuer = state.health.permit_issuer.clone();
    Ok(Json(ServerIdentityProof {
        claims,
        signature: URL_SAFE_NO_PAD.encode(signature),
    }))
}

#[tokio::test]
async fn self_reported_health_cannot_replace_issuer_private_key_proof()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deployment_id = random_id();
    let trusted_signer = PermitSigner::generate();
    let attacker = PermitSigner::generate();
    let health_response = HealthResponse {
        product: "NestLink".into(),
        version: "15.0.0-dev.1".into(),
        api_base: API_BASE.into(),
        alpn: ALPN.into(),
        deployment_id: deployment_id.clone(),
        security_epoch: 1,
        permit_issuer: URL_SAFE_NO_PAD.encode(trusted_signer.public_key()),
        node_policy_issuer: URL_SAFE_NO_PAD.encode([9; 32]),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let state = Arc::new(FakeEndpoint {
        health: health_response,
        attacker,
        origin: origin.clone(),
    });
    let app = Router::new()
        .route("/api/v3/health", get(health))
        .route("/api/v3/health/proof", post(identity_proof))
        .with_state(state);
    let _server = Running(tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }));

    let result = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id,
            permit_issuer: trusted_signer.public_key(),
        },
        true,
    )
    .await;
    assert!(matches!(result, Err(SdkError::Trust)));
    Ok(())
}
