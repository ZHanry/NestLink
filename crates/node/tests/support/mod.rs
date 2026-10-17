mod service_usage_directory;
use service_usage_directory::ServiceUsageDirectory;

use axum::{
    Json, Router,
    extract::{
        State,
        ws::{Message, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::SinkExt;
use nestlink_identity::{
    PermitSigner, digest,
    nodes::{NodeIdentity, NodePolicySigner, verify_proof, verify_usage},
};
use nestlink_node::control::{NodeConfig, NodeControl};
use nestlink_protocol::{
    NodeChallenge, NodeLeaseClaims, NodeProof, NodeRole, NodeUsageAckClaims, SCHEMA_VERSION,
    SignedNodeUsage, decode_bounded, nodes::NODE_MESSAGE_BYTES,
};
use prost::Message as ProstMessage;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Valid,
    WrongIssuer,
    WrongAck,
    LostFirstAck,
    UnavailableReport,
}
struct Inner {
    key: [u8; 32],
    issuer: NodePolicySigner,
    mode: Mode,
    last_ack: Mutex<Option<(Vec<u8>, NodeUsageAckClaims)>>,
    reports: Mutex<Vec<Vec<u8>>>,
    shutdown: tokio::sync::watch::Receiver<bool>,
}
pub struct Fixture {
    task: tokio::task::JoinHandle<()>,
    shutdown: tokio::sync::watch::Sender<bool>,
    state: Arc<Inner>,
    _service_usage_directory: ServiceUsageDirectory,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        self.task.abort();
    }
}
impl Fixture {
    pub fn reports(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .state
            .reports
            .lock()
            .map_err(|_| "poisoned reports")?
            .clone())
    }
}
async fn upgrade(State(state): State<Arc<Inner>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |mut socket|async move {
        let exchange=async {
            let challenge=NodeChallenge{schema_version:SCHEMA_VERSION,deployment_id:id(1),security_epoch:99,node_id:id(2),node_key_sha256:digest(&state.key).to_vec(),request_id:id(3),nonce:vec![9;32],expires_at_unix_ms:now()?+5000};
            socket.send(Message::Binary(challenge.encode_to_vec().into())).await?;
            let Some(Ok(Message::Binary(bytes)))=socket.recv().await else {return Err("missing proof".into());};
            let proof:NodeProof=decode_bounded(&bytes,NODE_MESSAGE_BYTES)?;
            assert_eq!(proof.challenge.as_ref(),Some(&challenge));
            verify_proof(&proof,&state.key)?;
            let issued=now()?;
            let lease=NodeLeaseClaims {schema_version:SCHEMA_VERSION,deployment_id:id(1),security_epoch:99,node_id:id(2),node_key_sha256:digest(&state.key).to_vec(),request_id:id(3),nonce:vec![9;32],roles:vec![NodeRole::NodeRelay as i32],policy_revision:1,lease_sequence:1,issued_at_unix_ms:issued,expires_at_unix_ms:issued+10000,server_forwarding_allowed:true,public_ingress_allowed:false,max_connections:1,bytes_per_second:1024,runtime_id:proof.runtime_id,runtime_generation:1};
            socket.send(Message::Binary(state.issuer.sign(&lease)?.encode_to_vec().into())).await?;
            // No renewal, but the separate HTTP reporter remains available.
            let mut shutdown=state.shutdown.clone();
            tokio::select!{_=tokio::time::sleep(Duration::from_secs(20))=>{},_=shutdown.changed()=>{}}
            socket.close().await?;
            Ok::<(),Box<dyn std::error::Error+Send+Sync>>(())
        };
        let _=exchange.await;
    })
}
async fn report(State(state): State<Arc<Inner>>, Json(signed): Json<SignedNodeUsage>) -> Response {
    let result = || -> Result<Response> {
        let c = verify_usage(&signed, &state.key)?;
        let mut reports = state.reports.lock().map_err(|_| "poisoned reports")?;
        reports.push(signed.claims.clone());
        if state.mode == Mode::UnavailableReport {
            return Ok(StatusCode::SERVICE_UNAVAILABLE.into_response());
        }
        let mut last = state.last_ack.lock().map_err(|_| "poisoned ack")?;
        let mut ack = if let Some((bytes, ack)) = last.as_ref() {
            assert_eq!(
                bytes, &signed.claims,
                "retry must preserve exact signed claim bytes"
            );
            ack.clone()
        } else {
            let ack = NodeUsageAckClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: c.deployment_id,
                security_epoch: c.security_epoch,
                node_id: c.node_id,
                runtime_id: c.runtime_id,
                runtime_generation: c.runtime_generation,
                report_sequence: c.report_sequence,
                report_sha256: digest(&signed.claims).to_vec(),
                accepted_at_unix_ms: now()?,
            };
            *last = Some((signed.claims, ack.clone()));
            ack
        };
        if state.mode == Mode::LostFirstAck && reports.len() == 1 {
            return Ok(StatusCode::SERVICE_UNAVAILABLE.into_response());
        }
        if state.mode == Mode::WrongAck {
            ack.runtime_id = id(99);
        }
        Ok(Json(state.issuer.sign_usage_ack(&ack)?).into_response())
    };
    result().unwrap_or_else(|_| StatusCode::BAD_REQUEST.into_response())
}
pub async fn peer(mode: Mode) -> Result<(NodeControl, Fixture)> {
    let node = NodeIdentity::generate();
    let issuer = PermitSigner::generate().node_policy_signer()?;
    let trust = if mode == Mode::WrongIssuer {
        PermitSigner::generate().node_policy_signer()?.public_key()
    } else {
        issuer.public_key()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    let state = Arc::new(Inner {
        key: node.public_key(),
        issuer,
        mode,
        last_ack: Mutex::new(None),
        reports: Mutex::new(Vec::new()),
        shutdown: receiver,
    });
    let app = Router::new()
        .route("/api/v3/nodes/{id}/control", get(upgrade))
        .route("/api/v3/nodes/{id}/report", post(report))
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let mut service_usage_directory = ServiceUsageDirectory::new()?;
    let config = NodeConfig {
        deployment_id: id(1),
        node_id: id(2),
        control_origin: format!("http://{address}"),
        trusted_policy_issuer: URL_SAFE_NO_PAD.encode(trust),
        identity_key_file: "unused-in-memory".into(),
        service_usage_directory: Some(service_usage_directory.path().to_path_buf()),
        roles: vec![NodeRole::NodeRelay as i32],
        allow_loopback_http: true,
    };
    let control = NodeControl::start(config, node)?;
    service_usage_directory.track(&control)?;
    Ok((
        control,
        Fixture {
            task,
            shutdown,
            state,
            _service_usage_directory: service_usage_directory,
        },
    ))
}
