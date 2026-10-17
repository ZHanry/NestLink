use super::*;
use crate::service_plane::test_support::{Fixture, TestResult, id, wall};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::nodes::{NodePolicySigner, verify_service_usage_report};
use nestlink_protocol::{NodeRole, api::ServiceIngress};
use std::{path::PathBuf, sync::Mutex};
use tokio::sync::Notify;

struct PrivateDirectory(PathBuf);
impl PrivateDirectory {
    fn new() -> TestResult<Self> {
        let directory =
            std::env::temp_dir().join(format!("nestlink-usage-http-{}", uuid::Uuid::new_v4()));
        nestlink_platform_security::new_private_directory(&directory)?;
        Ok(Self(directory))
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct HttpState {
    edge_key: [u8; 32],
    policy: NodePolicySigner,
    acknowledge_after: Option<usize>,
    attempts: Mutex<Vec<SignedServiceUsageReport>>,
    changed: Notify,
}
async fn report(
    State(state): State<Arc<HttpState>>,
    Json(report): Json<SignedServiceUsageReport>,
) -> Result<Json<SignedServiceUsageReportAck>, StatusCode> {
    let claims = verify_service_usage_report(&report, &state.edge_key)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let should_acknowledge = {
        let mut attempts = state
            .attempts
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        attempts.push(report.clone());
        state
            .acknowledge_after
            .is_some_and(|after| attempts.len() >= after)
    };
    state.changed.notify_one();
    if !should_acknowledge {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let accepted_at_unix_ms = wall().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let ack = state
        .policy
        .sign_service_usage_ack(&ServiceUsageReportAckClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: claims.deployment_id,
            security_epoch: claims.security_epoch,
            node_id: claims.node_id,
            node_runtime_id: claims.node_runtime_id,
            node_runtime_generation: claims.node_runtime_generation,
            grant_id: claims.grant_id,
            report_sequence: claims.report_sequence,
            report_sha256: digest(&report.claims),
            accepted_at_unix_ms,
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ack))
}

struct HttpTask(tokio::task::JoinHandle<()>);
impl Drop for HttpTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn start_http(
    fixture: &Fixture,
    directory: &PrivateDirectory,
    acknowledge_after: Option<usize>,
) -> TestResult<(NodeConfig, Arc<HttpState>, HttpTask)> {
    let state = Arc::new(HttpState {
        edge_key: fixture.edge.public_key(),
        policy: NodePolicySigner::from_master_seed(&[73; 32])?,
        acknowledge_after,
        attempts: Mutex::new(Vec::new()),
        changed: Notify::new(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route("/api/v3/nodes/{id}/service-usage", post(report))
        .with_state(state.clone());
    let task = HttpTask(tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    }));
    let config = NodeConfig {
        deployment_id: fixture.claims.deployment_id.clone(),
        node_id: fixture.claims.definition.edge_node_id.clone(),
        control_origin: origin,
        trusted_policy_issuer: URL_SAFE_NO_PAD.encode(state.policy.public_key()),
        identity_key_file: directory.0.join("unused-test-key"),
        service_usage_directory: Some(directory.0.join("ledger")),
        roles: vec![NodeRole::NodeEdge as i32],
        allow_loopback_http: true,
    };
    Ok((config, state, task))
}

async fn wait_attempts(state: &HttpState, minimum: usize) -> TestResult {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if state
                .attempts
                .lock()
                .map_err(|_| "poisoned attempts")?
                .len()
                >= minimum
            {
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            state.changed.notified().await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn unavailable_report_stops_within_budget_and_preserves_exact_pending_bytes_on_disk()
-> TestResult {
    let directory = PrivateDirectory::new()?;
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        9000,
    )?;
    let (config, http, _server) = start_http(&fixture, &directory, None).await?;
    let store = Arc::new(ServiceUsageStore::open(&directory.0.join("ledger"))?);
    store.activate(&fixture.verified()?)?;
    let cleanup = ServiceUsageStore::cleanup_owner(&store);
    let (shutdown, stopping) = watch::channel(false);
    let task = tokio::spawn(reporter(
        config,
        Arc::new(fixture.edge),
        fixture.claims.edge_runtime_id.clone(),
        store.clone(),
        stopping,
    ));
    wait_attempts(&http, 1).await?;
    shutdown.send_replace(true);
    tokio::time::timeout(Duration::from_secs(6), task).await???;
    let attempts = http.attempts.lock().map_err(|_| "poisoned attempts")?;
    assert!(attempts.len() >= 2);
    let expected = attempts.first().ok_or("missing real HTTP report")?.clone();
    assert!(attempts.iter().all(
        |attempt| attempt.claims == expected.claims && attempt.signature == expected.signature
    ));
    drop(attempts);
    let snapshot = store.snapshots(&id(10))?.remove(0);
    assert_eq!(snapshot.report_sequence, 0);
    let pending = snapshot
        .pending_report
        .ok_or("missing durable pending report")?;
    assert_eq!(pending.claims, expected.claims);
    assert_eq!(pending.signature, expected.signature);
    assert!(!cleanup.is_finished());
    drop(store);
    assert!(cleanup.is_finished());
    let reopened = ServiceUsageStore::open(&directory.0.join("ledger"))?;
    let persisted = reopened.snapshots(&id(10))?.remove(0);
    assert_eq!(persisted.report_sequence, 0);
    let pending = persisted
        .pending_report
        .ok_or("pending bytes lost on reopen")?;
    assert_eq!(pending.claims, expected.claims);
    assert_eq!(pending.signature, expected.signature);
    drop(reopened);
    Ok(())
}

#[tokio::test]
async fn a_lost_response_retries_one_frozen_report_until_the_exact_signed_ack() -> TestResult {
    let directory = PrivateDirectory::new()?;
    let fixture = Fixture::new(
        ServiceIngress::Tcp { port: 29100 },
        "tcp",
        "127.0.0.1:8080".parse()?,
        9000,
    )?;
    let (config, http, _server) = start_http(&fixture, &directory, Some(2)).await?;
    let store = Arc::new(ServiceUsageStore::open(&directory.0.join("ledger"))?);
    store.activate(&fixture.verified()?)?;
    let (shutdown, stopping) = watch::channel(false);
    let task = tokio::spawn(reporter(
        config,
        Arc::new(fixture.edge),
        fixture.claims.edge_runtime_id.clone(),
        store.clone(),
        stopping,
    ));
    wait_attempts(&http, 2).await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = store.snapshots(&id(10))?.remove(0);
            if snapshot.report_sequence == 1 && snapshot.pending_report.is_none() {
                assert!(!snapshot.needs_report);
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    shutdown.send_replace(true);
    tokio::time::timeout(Duration::from_secs(3), task).await???;
    let attempts = http.attempts.lock().map_err(|_| "poisoned attempts")?;
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].claims, attempts[1].claims);
    assert_eq!(attempts[0].signature, attempts[1].signature);
    let snapshot = store.snapshots(&id(10))?.remove(0);
    assert_eq!(snapshot.report_sha256, digest(&attempts[0].claims));
    assert_eq!(snapshot.highwater.admitted_bytes, 0);
    drop(attempts);
    drop(store);
    Ok(())
}
