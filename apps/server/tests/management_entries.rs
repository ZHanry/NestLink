//! Separate configured entry points must share a single control runtime.
#[path = "../../../crates/node/tests/support/service_usage_directory.rs"]
mod service_usage_directory;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, random_bytes, random_id};
use nestlink_identity::{
    PermitSigner, nodes::NodeIdentity, turn::verify_turn_resource_snapshot, verify_server_identity,
};
use nestlink_node::control::{NodeConfig, NodeControl};
use nestlink_policy::{NetworkPolicy, ServerForwarding};
use nestlink_protocol::{
    NodeRole, SCHEMA_VERSION, SignedTurnResourceSnapshot, TurnResourceQueryClaims,
    api::NodeRegistration, api::ServerIdentityProof,
};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use serde_json::Value;
use service_usage_directory::ServiceUsageDirectory;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Running(tokio::task::JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn configured_entries_share_turn_runtime_and_replay_state() -> Result {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("control.sqlite3");
    let deployment = random_id();
    let mut store = Store::open(&database, &deployment)?;
    store.bootstrap_admin("admin", "management-entry-test-password")?;
    store.apply_policy(
        1,
        NetworkPolicy {
            server_forwarding: ServerForwarding::Allow,
            ..NetworkPolicy::default()
        },
    )?;
    let seed = [31; 32];
    let signer = PermitSigner::from_seed(seed);
    let permit_issuer = signer.public_key();
    let node_issuer = signer.node_policy_signer()?.public_key();
    let first = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let second = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let first_origin = format!("http://{}", first.local_addr()?);
    let second_origin = format!("http://{}", second.local_addr()?);
    let first_state = AppState::new(
        store,
        VaultKey::from_bytes([32; 32]),
        signer,
        first_origin.clone(),
        false,
    )?;
    let second_state = first_state.for_management_entry(second_origin.clone(), true);
    let _first = Running(tokio::spawn(async move {
        let _ = axum::serve(first, router(first_state)).await;
    }));
    let _second = Running(tokio::spawn(async move {
        let _ = axum::serve(second, router(second_state)).await;
    }));
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let login = serde_json::json!({"username":"admin","password":"management-entry-test-password"});
    let native_login = http
        .post(format!("{first_origin}/api/v3/auth/login"))
        .json(&login)
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(
        native_login.headers().get_all("set-cookie").iter().count(),
        2
    );
    assert!(
        native_login
            .headers()
            .get_all("set-cookie")
            .iter()
            .all(|v| { v.to_str().is_ok_and(|v| !v.contains("; Secure")) })
    );
    let token: Value = native_login.json().await?;
    let token = token["access_token"].as_str().ok_or("missing token")?;
    let browser_login = http
        .post(format!("{second_origin}/api/v3/auth/login"))
        .header("Origin", &second_origin)
        .json(&login)
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(
        browser_login.headers().get_all("set-cookie").iter().count(),
        2
    );
    assert!(
        browser_login
            .headers()
            .get_all("set-cookie")
            .iter()
            .all(|v| { v.to_str().is_ok_and(|v| v.contains("; Secure")) })
    );
    for (origin, other) in [
        (&first_origin, &second_origin),
        (&second_origin, &first_origin),
    ] {
        assert_eq!(
            http.get(format!("{origin}/api/v3/health"))
                .header("Origin", other)
                .send()
                .await?
                .status(),
            reqwest::StatusCode::FORBIDDEN
        );
        let proof: ServerIdentityProof = http
            .post(format!("{origin}/api/v3/health/proof"))
            .json(&serde_json::json!({"nonce":URL_SAFE_NO_PAD.encode([33; 32])}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(proof.claims.management_origin, *origin);
        verify_server_identity(
            &proof.claims,
            &URL_SAFE_NO_PAD.decode(&proof.signature)?,
            &permit_issuer,
        )?;
    }
    let node_seed = random_bytes::<32>();
    let node = NodeIdentity::from_seed(&node_seed);
    let node_id = random_id();
    http.post(format!("{second_origin}/api/v3/nodes"))
        .bearer_auth(token)
        .header("Origin", &second_origin)
        .json(&NodeRegistration {
            id: node_id.clone(),
            name: "shared-runtime".into(),
            public_key: URL_SAFE_NO_PAD.encode(node.public_key()),
            roles: vec![NodeRole::NodeRelay as i32],
            max_connections: 8,
            bytes_per_second: 1_048_576,
        })
        .send()
        .await?
        .error_for_status()?;
    let mut usage = ServiceUsageDirectory::new()?;
    let control = NodeControl::start(
        NodeConfig {
            deployment_id: deployment.clone(),
            node_id: node_id.clone(),
            control_origin: first_origin.clone(),
            trusted_policy_issuer: URL_SAFE_NO_PAD.encode(node_issuer),
            identity_key_file: "unused-shared-runtime-fixture".into(),
            service_usage_directory: Some(usage.path().to_path_buf()),
            roles: vec![NodeRole::NodeRelay as i32],
            allow_loopback_http: true,
        },
        NodeIdentity::from_seed(&node_seed),
    )?;
    usage.track(&control)?;
    tokio::time::timeout(Duration::from_secs(4), async {
        while control.authorize(NodeRole::NodeRelay, false).is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let lease = control.current_lease()?;
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let mut previous = 0;
    let mut last_query = None;
    for (sequence, origin) in [(1_000_000, &first_origin), (1_000_001, &second_origin)] {
        let query = node.sign_turn_resource_query(&TurnResourceQueryClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: deployment.clone(),
            security_epoch: lease.security_epoch,
            node_id: node_id.clone(),
            runtime_id: lease.runtime_id.clone(),
            runtime_generation: lease.runtime_generation,
            policy_revision: lease.policy_revision,
            lease_sequence: lease.lease_sequence,
            request_id: random_id(),
            request_sequence: sequence,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + 1000,
        })?;
        let response = http
            .post(format!("{origin}/api/v3/nodes/{node_id}/turn-resources"))
            .json(&query)
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK, "entry {origin}");
        let snapshot: SignedTurnResourceSnapshot = response.json().await?;
        let claims = verify_turn_resource_snapshot(&snapshot, &node_issuer, &query)?;
        assert!(claims.snapshot_sequence > previous);
        previous = claims.snapshot_sequence;
        last_query = Some(query);
    }
    assert_eq!(
        http.post(format!(
            "{first_origin}/api/v3/nodes/{node_id}/turn-resources"
        ))
        .json(&last_query.ok_or("missing query")?)
        .send()
        .await?
        .status(),
        reqwest::StatusCode::CONFLICT
    );
    control.stop();
    Ok(())
}
