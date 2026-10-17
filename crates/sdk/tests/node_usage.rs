use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, hash_password, random_id};
use nestlink_identity::{
    PermitSigner,
    nodes::{NodeIdentity, verify_usage_ack},
};
use nestlink_protocol::{
    NodeRole, NodeUsageClaims, SCHEMA_VERSION, SignedNodeUsageAck, api::NodeRegistration,
};
use nestlink_sdk::{DeploymentTrust, Sdk, SdkError};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Abort(tokio::task::JoinHandle<()>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn password() -> Secret {
    Secret::from_text("sdk-node-meter-test-password".into())
}
#[tokio::test]
async fn sdk_reads_durable_node_usage_and_http_retries_return_identical_signed_confirmation()
-> Result {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let node_issuer = signer.node_policy_signer()?.public_key();
    let vault = VaultKey::from_bytes([7; 32]);
    let now_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let mut s = Store::in_memory(&deployment)?;
    s.bootstrap_admin("admin", password().expose())?;
    let p = s
        .login(
            "admin",
            password().expose(),
            None,
            now_ms / 1000,
            &vault,
            &hash_password(password().expose())?,
        )?
        .principal;
    let node = NodeIdentity::generate();
    let id = random_id();
    let runtime = random_id();
    s.register_node(
        &p,
        NodeRegistration {
            id: id.clone(),
            name: "sdk-meter".into(),
            public_key: URL_SAFE_NO_PAD.encode(node.public_key()),
            roles: vec![NodeRole::NodeRelay as i32],
            max_connections: 16,
            bytes_per_second: 1024,
        },
    )?;
    let challenge = s.node_challenge(&id, now_ms)?;
    let lease = s.issue_node_lease(&node.prove(&challenge, &runtime)?, now_ms + 1)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let app = router(AppState::new(s, vault, signer, origin.clone(), false)?);
    let _server = Abort(tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    }));
    let trust = || DeploymentTrust {
        deployment_id: deployment.clone(),
        permit_issuer: issuer,
    };
    let mut sdk = Sdk::connect(&origin, trust(), true).await?;
    assert!(sdk.node_usage(&id, 0, 1).await.is_err());
    sdk.login("admin".into(), password(), None).await?;
    let reports = sdk.node_usage(&id, 0, 1).await?;
    assert_eq!(reports.entries.len(), 1);
    assert_eq!(reports.entries[0].report_sequence, 0);
    assert!(sdk.node_usage(&id, 0, 0).await.is_err());
    let sample_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let signed = node.sign_usage(&NodeUsageClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: deployment.clone(),
        security_epoch: lease.security_epoch,
        node_id: id.clone(),
        runtime_id: runtime.clone(),
        runtime_generation: 1,
        policy_revision: lease.policy_revision,
        lease_sequence: lease.lease_sequence,
        report_sequence: 1,
        opened_connections: 0,
        closed_connections: 0,
        admitted_bytes: 0,
        sampled_at_unix_ms: sample_ms,
    })?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let report_url = format!("{origin}/api/v3/nodes/{id}/report");
    let first: SignedNodeUsageAck = http
        .post(&report_url)
        .json(&signed)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let second: SignedNodeUsageAck = http
        .post(&report_url)
        .json(&signed)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(first, second);
    assert_eq!(verify_usage_ack(&first, &node_issuer)?.runtime_id, runtime);
    let page = sdk.node_usage(&id, 0, 1).await?;
    assert_eq!(page.entries[0].report_sequence, 1);
    assert!(page.entries[0].current);
    assert!(
        sdk.node_usage(&id, page.next_generation, 1)
            .await?
            .entries
            .is_empty()
    );
    sdk.create_account("member".into(), password()).await?;
    let mut member = Sdk::connect(&origin, trust(), true).await?;
    member.login("member".into(), password(), None).await?;
    assert!(matches!(
        member.node_usage(&id, 0, 1).await,
        Err(SdkError::Api(
            _,
            nestlink_protocol::ErrorCode::PermissionRequired
        ))
    ));
    sdk.revoke_node(&id).await?;
    assert!(!sdk.node_usage(&id, 0, 1).await?.entries[0].current);
    assert_eq!(
        http.post(report_url).json(&signed).send().await?.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    Ok(())
}
