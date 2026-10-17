//! Real HTTP administration and real WebSocket node challenge/renewal/revoke.
#[path = "../../../crates/node/tests/support/service_usage_directory.rs"]
mod service_usage_directory;
use service_usage_directory::ServiceUsageDirectory;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, random_bytes, random_id};
use nestlink_identity::{PermitSigner, nodes::NodeIdentity};
use nestlink_node::control::{NodeConfig, NodeControl};
use nestlink_policy::{NetworkPolicy, ServerForwarding};
use nestlink_protocol::{
    NodeRole, NodeUsageClaims, SCHEMA_VERSION,
    api::{NodeRegistration, NodeUsagePage},
};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use serde_json::Value;
use std::time::{Duration, Instant};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Abort(tokio::task::JoinHandle<()>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}
#[tokio::test]
async fn actual_control_channel_renews_and_admin_revocation_stops_node_under_two_seconds() -> Result
{
    let deployment = random_id();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("administrator", "node-http-test-password")?;
    store.apply_policy(
        1,
        NetworkPolicy {
            server_forwarding: ServerForwarding::Allow,
            ..NetworkPolicy::default()
        },
    )?;
    let signer = PermitSigner::generate();
    let policy_issuer = signer.node_policy_signer()?.public_key();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let origin = format!("http://{address}");
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([5; 32]),
        signer,
        origin.clone(),
        false,
    )?);
    let _server = Abort(tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    }));
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = http
        .post(format!("{origin}/api/v3/auth/login"))
        .json(&serde_json::json!({"username":"administrator","password":"node-http-test-password"}))
        .send()
        .await?
        .error_for_status()?;
    let login: Value = response.json().await?;
    let token = login["access_token"].as_str().ok_or("no token")?;
    let seed = random_bytes::<32>();
    let node = NodeIdentity::from_seed(&seed);
    let id = random_id();
    let descriptor = NodeRegistration {
        id: id.clone(),
        name: "real-relay".into(),
        public_key: URL_SAFE_NO_PAD.encode(node.public_key()),
        roles: vec![NodeRole::NodeRelay as i32],
        max_connections: 16,
        bytes_per_second: 1048576,
    };
    assert_eq!(
        http.post(format!("{origin}/api/v3/nodes"))
            .json(&descriptor)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    http.post(format!("{origin}/api/v3/nodes"))
        .bearer_auth(token)
        .json(&descriptor)
        .send()
        .await?
        .error_for_status()?;
    let mut service_usage_directory = ServiceUsageDirectory::new()?;
    let config = NodeConfig {
        deployment_id: deployment,
        node_id: id.clone(),
        control_origin: origin.clone(),
        trusted_policy_issuer: URL_SAFE_NO_PAD.encode(policy_issuer),
        identity_key_file: "unused-in-process-test".into(),
        service_usage_directory: Some(service_usage_directory.path().to_path_buf()),
        roles: descriptor.roles,
        allow_loopback_http: true,
    };
    let control = NodeControl::start(config.clone(), node)?;
    service_usage_directory.track(&control)?;
    let renewed = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if control
                .current_lease()
                .is_ok_and(|lease| lease.lease_sequence >= 2)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    if renewed.is_err() {
        return Err(format!(
            "initial node lease did not renew within six seconds; completion={:?}",
            tokio::time::timeout(Duration::from_millis(100), control.wait_finished()).await
        )
        .into());
    }
    let lease = control.authorize(NodeRole::NodeRelay, false)?;
    assert!(lease.lease_sequence >= 2);
    assert_eq!(lease.max_connections, 16);
    assert!(control.authorize(NodeRole::NodeEdge, true).is_err());
    let guard = control.reserve_capacity(NodeRole::NodeRelay, false)?;
    guard.admit(512, || Ok(()))?;
    let usage_url = format!(
        "{origin}/api/v3/nodes/{id}/usage?security_epoch={}&limit=100",
        lease.security_epoch
    );
    assert_eq!(
        http.get(&usage_url).send().await?.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let mut confirmed = None;
    let usage = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let page: NodeUsagePage = http
                .get(&usage_url)
                .bearer_auth(token)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            confirmed = page.entries.first().map(|r| {
                (
                    r.report_sequence,
                    r.opened_connections,
                    r.closed_connections,
                    r.admitted_bytes,
                )
            });
            if page.entries.first().is_some_and(|r| {
                r.admitted_bytes == 512 && r.opened_connections == 1 && r.report_sequence >= 2
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok::<(), reqwest::Error>(())
    })
    .await;
    if usage.is_err() {
        let stopped = *control.stopped().borrow();
        let lease = control.current_lease().map(|l| l.lease_sequence);
        let local = control.counters();
        let completion =
            tokio::time::timeout(Duration::from_millis(100), control.wait_finished()).await;
        return Err(format!(
            "node usage did not confirm admitted bytes within six seconds; stopped={stopped}, lease={lease:?}, local={local:?}, confirmed={confirmed:?}, completion={completion:?}",
        )
        .into());
    }
    usage??;
    let corrupt = NodeIdentity::generate().sign_usage(&NodeUsageClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: lease.deployment_id.clone(),
        security_epoch: lease.security_epoch,
        node_id: id.clone(),
        runtime_id: lease.runtime_id.clone(),
        runtime_generation: lease.runtime_generation,
        policy_revision: lease.policy_revision,
        lease_sequence: lease.lease_sequence,
        report_sequence: 99,
        opened_connections: 0,
        closed_connections: 0,
        admitted_bytes: 0,
        sampled_at_unix_ms: lease.issued_at_unix_ms,
    })?;
    assert_eq!(
        http.post(format!("{origin}/api/v3/nodes/{id}/report"))
            .bearer_auth(token)
            .json(&corrupt)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let restarted = NodeControl::start(config, NodeIdentity::from_seed(&seed))?;
    service_usage_directory.track(&restarted)?;
    let mut obsolete = control.stopped();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !*obsolete.borrow() {
            obsolete.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await
    .map_err(|_| "runtime takeover did not stop the old node within two seconds")??;
    assert!(guard.admit(1, || Ok(())).is_err());
    drop(guard);
    tokio::time::timeout(Duration::from_secs(2), async {
        while restarted.current_lease().is_err() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "new runtime did not become ready within two seconds; stopped={}",
            *restarted.stopped().borrow()
        )
    })?;
    let fresh = restarted.current_lease()?;
    assert_ne!(lease.runtime_id, fresh.runtime_id);
    assert_eq!(fresh.runtime_generation, lease.runtime_generation + 1);
    let page: NodeUsagePage = http
        .get(&usage_url)
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(page.entries.len(), 2);
    assert!(!page.entries[0].current);
    assert!(page.entries[1].current);
    assert_eq!(page.entries[0].admitted_bytes, 512);
    assert_eq!(page.entries[1].admitted_bytes, 0);
    let start = Instant::now();
    http.delete(format!("{origin}/api/v3/nodes/{id}"))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?;
    let mut stopped = restarted.stopped();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !*stopped.borrow() {
            stopped.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await
    .map_err(|_| "administrator revocation did not stop the node within two seconds")??;
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(restarted.authorize(NodeRole::NodeRelay, false).is_err());
    assert!(control.wait_finished().await.is_err());
    assert!(restarted.wait_finished().await.is_err());
    Ok(())
}
