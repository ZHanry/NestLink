//! Actual HTTP sockets backed by an on-disk deployment, not a mocked router.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password, random_id};
use nestlink_identity::{
    InstallationIdentity, PermitSigner,
    nodes::NodeIdentity,
    services::{approval_transcript, local_target_digest},
};
use nestlink_protocol::{NodeRole, api::*};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const PASSWORD: &str = "service-http-test-password";
struct Server {
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}
impl Server {
    async fn close(&mut self) -> Result {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn send(
    http: &Client,
    origin: &str,
    method: &str,
    path: &str,
    body: Value,
    token: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let mut request = http.request(method.parse()?, format!("{origin}{path}"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if body != Value::Null {
        request = request.json(&body);
    }
    let response = request.send().await?;
    let status = response.status();
    assert_eq!(
        response
            .headers()
            .get("Cache-Control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    Ok((status, response.json().await?))
}
#[tokio::test]
async fn actual_http_registry_signed_target_approval_replay_scope_and_revocation() -> Result {
    let directory = tempfile::tempdir()?;
    let mut store = Store::open(&directory.path().join("control.sqlite3"), &random_id())?;
    store.bootstrap_admin("admin", PASSWORD)?;
    let vault = VaultKey::from_bytes([3; 32]);
    let dummy = hash_password("http-services-dummy-password")?;
    let owner = store.login("admin", PASSWORD, None, now()?, &vault, &dummy)?;
    store.create_member(&owner.principal, "member", PASSWORD)?;
    let member = store.login("member", PASSWORD, None, now()?, &vault, &dummy)?;
    let identity = InstallationIdentity::generate();
    let host = random_id();
    let challenge = store.enrollment_challenge(&owner.principal, now()?)?;
    let mut registration = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: host.clone(),
            name: "local-host".into(),
            platform: "windows".into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            capabilities: vec!["host".into(), "vp8".into()],
            path_mode: "direct_only".into(),
        },
        signature: String::new(),
    };
    registration.signature =
        URL_SAFE_NO_PAD.encode(identity.sign_action(&store.registration_transcript(
            &owner.principal,
            &registration,
            now()?,
        )?)?);
    store.register_device(&owner.principal, registration, now()?)?;
    let node = random_id();
    let node_identity = NodeIdentity::generate();
    store.register_node(
        &owner.principal,
        NodeRegistration {
            id: node.clone(),
            name: "edge-only".into(),
            public_key: URL_SAFE_NO_PAD.encode(node_identity.public_key()),
            roles: vec![NodeRole::NodeEdge as i32],
            max_connections: 16,
            bytes_per_second: 1048576,
        },
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let app = router(AppState::new(
        store,
        vault,
        PermitSigner::generate(),
        origin.clone(),
        false,
    )?);
    let (stop, stop_rx) = tokio::sync::oneshot::channel();
    let mut server = Server {
        task: Some(tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = stop_rx.await;
            })
            .await
        })),
        stop: Some(stop),
    };
    let http = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let id = random_id();
    let create = ServiceCreate {
        id: id.clone(),
        definition: ServiceDefinition {
            name: "actual HTTP registry service".into(),
            host_device_id: host.clone(),
            edge_node_id: node,
            requested_ingress: ServiceIngress::Tcp { port: 29100 },
            allowed_sources: vec![],
            limits: ServiceLimits {
                maximum_connections: 8,
                bytes_per_second: 1048576,
                maximum_bytes: 1073741824,
                idle_timeout_seconds: 60,
            },
        },
    };
    assert_eq!(
        send(
            &http,
            &origin,
            "POST",
            "/api/v3/services",
            serde_json::to_value(&create)?,
            None
        )
        .await?
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, value) = send(
        &http,
        &origin,
        "POST",
        "/api/v3/services",
        serde_json::to_value(&create)?,
        Some(owner.access_token.expose()),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED);
    let view: ServiceView = serde_json::from_value(value)?;
    assert_eq!(view.publication, ServicePublicationStatus::NotPublished);
    assert_eq!(
        send(
            &http,
            &origin,
            "GET",
            &format!("/api/v3/services/{id}"),
            Value::Null,
            Some(member.access_token.expose())
        )
        .await?
        .0,
        StatusCode::FORBIDDEN
    );
    let approval_path = format!("/api/v3/services/{id}/approval");
    assert_eq!(
        send(
            &http,
            &origin,
            "POST",
            &format!("{approval_path}/challenge"),
            json!({"expected_revision":1}),
            Some(owner.access_token.expose())
        )
        .await?
        .0,
        StatusCode::FORBIDDEN
    );
    let policy = json!({"expected_revision":1,"policy":{"server_forwarding":"allow","peer_path_mode":"direct_only","public_ingress":"enabled"}});
    assert_eq!(
        send(
            &http,
            &origin,
            "PUT",
            "/api/v3/policy",
            policy,
            Some(owner.access_token.expose())
        )
        .await?
        .0,
        StatusCode::OK
    );
    let cookie_response = http
        .post(format!("{origin}{approval_path}/challenge"))
        .header(
            "Cookie",
            format!("nl15_access={}", owner.access_token.expose()),
        )
        .json(&json!({"expected_revision":1}))
        .send()
        .await?;
    assert_eq!(cookie_response.status(), StatusCode::FORBIDDEN);
    let (status, value) = send(
        &http,
        &origin,
        "POST",
        &format!("{approval_path}/challenge"),
        json!({"expected_revision":1}),
        Some(owner.access_token.expose()),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let challenge: ServiceApprovalChallenge = serde_json::from_value(value)?;
    let target = random_id();
    let choice = ServiceTargetChoice {
        expected_revision: 1,
        target_id: target.clone(),
        target_sha256: URL_SAFE_NO_PAD.encode(local_target_digest(
            &view,
            &target,
            "tcp",
            "127.0.0.1:8080".parse()?,
        )?),
        expires_at_unix_ms: challenge.issued_at_unix_ms + 60000,
    };
    let proof = ServiceTargetApproval {
        challenge_id: challenge.id.clone(),
        signature: URL_SAFE_NO_PAD
            .encode(identity.sign_action(&approval_transcript(&challenge, &choice)?)?),
        choice,
    };
    let mut wrong = proof.clone();
    wrong.choice.target_id = random_id();
    assert_eq!(
        send(
            &http,
            &origin,
            "POST",
            &approval_path,
            serde_json::to_value(wrong)?,
            Some(owner.access_token.expose())
        )
        .await?
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, value) = send(
        &http,
        &origin,
        "POST",
        &approval_path,
        serde_json::to_value(&proof)?,
        Some(owner.access_token.expose()),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let approved: ServiceView = serde_json::from_value(value)?;
    assert_eq!(approved.revision, 2);
    assert_eq!(approved.approval, ServiceApprovalState::ApprovedTarget);
    assert_eq!(approved.publication, ServicePublicationStatus::NotPublished);
    assert_eq!(
        send(
            &http,
            &origin,
            "POST",
            &approval_path,
            serde_json::to_value(proof)?,
            Some(owner.access_token.expose())
        )
        .await?
        .0,
        StatusCode::CONFLICT
    );
    let (status, value) = send(
        &http,
        &origin,
        "DELETE",
        &format!("/api/v3/services/{id}"),
        json!({"expected_revision":2}),
        Some(owner.access_token.expose()),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_value::<ServiceView>(value)?.approval,
        ServiceApprovalState::Revoked
    );
    assert_eq!(
        send(
            &http,
            &origin,
            "POST",
            &format!("{approval_path}/challenge"),
            json!({"expected_revision":3}),
            Some(owner.access_token.expose())
        )
        .await?
        .0,
        StatusCode::CONFLICT
    );
    server.close().await?;
    let raw = rusqlite::Connection::open(directory.path().join("control.sqlite3"))?;
    assert_eq!(
        raw.query_row("SELECT revision FROM services WHERE id=?1", [&id], |r| r
            .get::<_, u64>(0))?,
        3
    );
    assert!(raw.query_row(
        "SELECT revoked FROM service_target_approvals WHERE service_id=?1",
        [&id],
        |r| r.get::<_, bool>(0)
    )?);
    Ok(())
}
fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
