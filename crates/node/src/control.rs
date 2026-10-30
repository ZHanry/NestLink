use crate::{
    gate::NodeGate,
    meter::{Counters, Meter},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use nestlink_identity::nodes::NodeIdentity;
use nestlink_protocol::{
    ContractError, ErrorCode, NodeChallenge, NodeLeaseClaims, NodeRole, NodeUsageClaims,
    SCHEMA_VERSION, SignedNodeUsageAck, decode_bounded,
    nodes::{NODE_CHALLENGE_MS, NODE_MESSAGE_BYTES},
};
use nestlink_session::ClockSample;
use nestlink_traversal::turn::TurnAuthorization;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Message as WsMessage, protocol::WebSocketConfig},
};
type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
mod closes;
mod resources;
mod services;
mod topology;
mod turn;
mod usage;
pub use closes::CloseReportStatus;
pub use resources::{
    RelayEndpointCandidate, RelayEndpointProof, RelayIoCleanup, RelayResourceReservation,
};
pub use services::ServiceNodePermit;
pub use topology::TopologyReporter;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub deployment_id: String,
    pub node_id: String,
    pub control_origin: String,
    pub trusted_policy_issuer: String,
    pub identity_key_file: std::path::PathBuf,
    /// Optional protected directory for the durable service-byte ledger. By
    /// default it is beside the installation identity key.
    #[serde(default)]
    pub service_usage_directory: Option<std::path::PathBuf>,
    pub roles: Vec<i32>,
    #[serde(default)]
    pub allow_loopback_http: bool,
}
impl NodeConfig {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = nestlink_platform_security::read_private(path, 16384)
            .map_err(|_| Error::Configuration)?;
        let mut config: Self =
            toml::from_str(std::str::from_utf8(&bytes).map_err(|_| Error::Configuration)?)
                .map_err(|_| Error::Configuration)?;
        config.validate()?;
        if config.identity_key_file.is_relative() {
            config.identity_key_file = path
                .parent()
                .ok_or(Error::Configuration)?
                .join(&config.identity_key_file);
        }
        if let Some(directory) = &mut config.service_usage_directory
            && directory.is_relative()
        {
            *directory = path.parent().ok_or(Error::Configuration)?.join(&*directory);
        }
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if !nestlink_protocol::valid_id(&self.deployment_id)
            || !nestlink_protocol::valid_id(&self.node_id)
            || !nestlink_protocol::nodes::valid_roles(&self.roles)
        {
            return Err(Error::Configuration);
        }
        self.issuer()?;
        self.url()?;
        Ok(())
    }
    fn issuer(&self) -> Result<[u8; 32], Error> {
        URL_SAFE_NO_PAD
            .decode(&self.trusted_policy_issuer)
            .map_err(|_| Error::Configuration)?
            .try_into()
            .map_err(|_| Error::Configuration)
    }
    fn url(&self) -> Result<url::Url, Error> {
        let mut origin = url::Url::parse(&self.control_origin).map_err(|_| Error::Configuration)?;
        let loopback = match origin.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(host)) => host == "localhost",
            None => false,
        };
        let development = self.allow_loopback_http && origin.scheme() == "http" && loopback;
        if (origin.scheme() != "https" && !development)
            || origin.origin().ascii_serialization() != self.control_origin
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.port() == Some(0)
        {
            return Err(Error::Configuration);
        }
        origin
            .set_scheme(if development { "ws" } else { "wss" })
            .map_err(|_| Error::Configuration)?;
        origin.set_path(&format!("/api/v3/nodes/{}/control", self.node_id));
        Ok(origin)
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid private node configuration")]
    Configuration,
    #[error("node control connection stopped, failed or timed out")]
    Control,
    #[error("node control transport was interrupted")]
    Transport,
    #[error("node {stage} failed: {cause}")]
    Phase {
        stage: &'static str,
        cause: Box<Error>,
    },
    #[error("node usage endpoint returned HTTP {0}")]
    UsageStatus(u16),
    #[error("node TURN resource endpoint returned HTTP {0}")]
    TurnResourceStatus(u16),
    #[error("persistent service usage store failed")]
    ServiceUsage(#[from] crate::service_usage::Error),
    #[error("node authorization failed: {0}")]
    Authorization(#[from] nestlink_protocol::ContractError),
}
pub struct NodeControl {
    state: Arc<Mutex<Runtime>>,
    started: Instant,
    stopped: watch::Receiver<bool>,
    stop_signal: watch::Sender<bool>,
    turn_authorization: Arc<TurnAuthorization>,
    pump: tokio::task::JoinHandle<Result<(), Error>>,
    _usage_pump: tokio::task::JoinHandle<Result<(), Error>>,
    runtime_id: String,
}
struct Runtime {
    gate: NodeGate,
    meter: Meter,
    ready: bool,
    service_shutdown: bool,
    resources: resources::Resources,
    service_resource_owner: Option<[u8; 16]>,
    service_usage: Arc<crate::service_usage::ServiceUsageStore>,
    topology: topology::ReporterState,
}
/// Reserves aggregate capacity only. The data service must separately verify its
/// resource/session permit before every admission and observe `stopped()`.
pub struct NodeCapacityReservation {
    state: Arc<Mutex<Runtime>>,
    started: Instant,
    role: NodeRole,
    public_ingress: bool,
    stopped: watch::Receiver<bool>,
}
impl NodeCapacityReservation {
    pub fn stopped(&self) -> watch::Receiver<bool> {
        self.stopped.clone()
    }
    /// The synchronous, bounded enqueue callback must not reenter node control.
    /// Only successful queue admission is counted; this is not a delivery receipt.
    pub fn admit<T>(
        &self,
        bytes: u64,
        enqueue: impl FnOnce() -> Result<T, ContractError>,
    ) -> Result<T, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        let now = sample(self.started)?;
        let rate = state
            .gate
            .authorize_forwarding(self.role, self.public_ingress, now)?
            .bytes_per_second;
        Ok(state.meter.admit(bytes, rate, now.monotonic_ms, enqueue)?)
    }
}
impl Drop for NodeCapacityReservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.meter.close();
        }
    }
}
impl Drop for NodeControl {
    fn drop(&mut self) {
        self.stop();
    }
}
impl NodeControl {
    /// Terminal stop for a shared control owner; wakes data I/O before cleanup.
    pub fn stop(&self) {
        self.stop_signal.send_replace(true);
        self.pump.abort();
        self.turn_authorization.revoke_all();
        if let Ok(mut state) = self.state.lock() {
            state.gate.stop();
            state.ready = false;
            state.service_shutdown = true;
            state.resources.stop();
            state.resources.services.stop();
        }
    }
    pub fn start(config: NodeConfig, identity: NodeIdentity) -> Result<Self, Error> {
        config.validate()?;
        let roles = config
            .roles
            .iter()
            .map(|r| NodeRole::try_from(*r).map_err(|_| Error::Configuration))
            .collect::<Result<Vec<_>, _>>()?;
        let runtime_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let gate = NodeGate::new(
            config.deployment_id.clone(),
            config.node_id.clone(),
            runtime_id.clone(),
            identity.public_key(),
            config.issuer()?,
            roles,
        )?;
        let usage_directory = config
            .service_usage_directory
            .clone()
            .or_else(|| {
                config
                    .identity_key_file
                    .parent()
                    .map(|p| p.join("service-usage"))
            })
            .ok_or(Error::Configuration)?;
        let usage_directory = if usage_directory.is_absolute() {
            usage_directory
        } else {
            std::env::current_dir()
                .map_err(|_| Error::Configuration)?
                .join(usage_directory)
        };
        let service_usage = Arc::new(crate::service_usage::ServiceUsageStore::open(
            &usage_directory,
        )?);
        let mut resources = resources::Resources::default();
        resources.services.set_usage_store(service_usage.clone());
        let service_resource_owner = Some(resources.services.owner_token());
        let state = Arc::new(Mutex::new(Runtime {
            gate,
            meter: Meter::default(),
            ready: false,
            service_shutdown: false,
            resources,
            service_resource_owner,
            service_usage: service_usage.clone(),
            topology: topology::ReporterState::default(),
        }));
        let turn_authorization = Arc::new(
            TurnAuthorization::new((nestlink_protocol::NODE_RESOURCE_ALLOCATIONS * 2) as usize)
                .map_err(|_| Error::Configuration)?,
        );
        let (sender, stopped) = watch::channel(false);
        let stop_signal = sender.clone();
        let started = Instant::now();
        let copy = state.clone();
        let turn_copy = turn_authorization.clone();
        let identity = Arc::new(identity);
        let usage_pump = tokio::spawn(usage::reporter(
            config.clone(),
            identity.clone(),
            runtime_id.clone(),
            service_usage,
            stopped.clone(),
        ));
        let runtime_id_for_control = runtime_id.clone();
        // This worker owns no forwarding capability or NodeControl reference.
        // Business stop wakes it for a fixed, bounded final cleanup-report drain.
        tokio::spawn(closes::reporter(
            config.clone(),
            identity.clone(),
            state.clone(),
            started,
            stopped.clone(),
        ));
        let pump = tokio::spawn(async move {
            let _stopper = Stopper {
                state: copy.clone(),
                turn_authorization: turn_copy.clone(),
                sender,
            };
            pump(config, identity, runtime_id, copy, turn_copy, started).await
        });
        Ok(Self {
            state,
            started,
            stopped,
            stop_signal,
            turn_authorization,
            pump,
            _usage_pump: usage_pump,
            runtime_id: runtime_id_for_control,
        })
    }
    /// Consume the control owner and preserve its task's terminal failure for
    /// local diagnostics. Cancellation drops the owner and stops authority.
    pub async fn wait_finished(mut self) -> Result<(), Error> {
        (&mut self.pump).await.map_err(|_| Error::Control)?
    }
    pub fn stopped(&self) -> watch::Receiver<bool> {
        self.stopped.clone()
    }
    /// Shared synchronous TURN authority consumed by the local TURN listeners.
    /// Only grants verified by the node control poll are installed into it.
    pub fn turn_authorization(&self) -> Arc<TurnAuthorization> {
        self.turn_authorization.clone()
    }
    pub fn current_lease(&self) -> Result<NodeLeaseClaims, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        Ok(state.gate.current(sample(self.started)?)?.clone())
    }
    /// Inspects policy only; forwarding must also hold `reserve_capacity()` and
    /// independently validated resource/session authority.
    pub fn authorize(
        &self,
        role: NodeRole,
        public_ingress: bool,
    ) -> Result<NodeLeaseClaims, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        Ok(state
            .gate
            .authorize_forwarding(role, public_ingress, sample(self.started)?)?
            .clone())
    }
    pub fn counters(&self) -> Result<Counters, Error> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Control)?
            .meter
            .counters())
    }
    pub fn reserve_capacity(
        &self,
        role: NodeRole,
        public_ingress: bool,
    ) -> Result<NodeCapacityReservation, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Control)?;
        if !state.ready || *self.stopped.borrow() {
            return Err(Error::Control);
        }
        let maximum = state
            .gate
            .authorize_forwarding(role, public_ingress, sample(self.started)?)?
            .max_connections;
        state.meter.reserve(maximum)?;
        Ok(NodeCapacityReservation {
            state: self.state.clone(),
            started: self.started,
            role,
            public_ingress,
            stopped: self.stopped.clone(),
        })
    }
    pub async fn finish(mut self) -> Result<(), Error> {
        (&mut self.pump).await.map_err(|_| Error::Control)?
    }
}
struct Stopper {
    state: Arc<Mutex<Runtime>>,
    turn_authorization: Arc<TurnAuthorization>,
    sender: watch::Sender<bool>,
}
impl Drop for Stopper {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.gate.stop();
            state.ready = false;
            state.service_shutdown = true;
            state.resources.stop();
            state.resources.services.stop();
        }
        self.turn_authorization.revoke_all();
        self.sender.send_replace(true);
    }
}
fn sample(started: Instant) -> Result<ClockSample, Error> {
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Control)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Control)?;
    let monotonic_ms = started
        .elapsed()
        .as_millis()
        .try_into()
        .map_err(|_| Error::Control)?;
    Ok(ClockSample {
        monotonic_ms,
        unix_ms,
    })
}
async fn pump(
    config: NodeConfig,
    identity: Arc<NodeIdentity>,
    runtime_id: String,
    state: Arc<Mutex<Runtime>>,
    turn_authorization: Arc<TurnAuthorization>,
    started: Instant,
) -> Result<(), Error> {
    let leases = lease_pump(
        config.clone(),
        identity.clone(),
        runtime_id.clone(),
        state.clone(),
        started,
    );
    let resources = resources::poll(config.clone(), identity.clone(), state.clone(), started);
    let service = services::poll(config.clone(), identity.clone(), state.clone(), started);
    let turn = turn::poll(config, identity, state, turn_authorization, started);
    tokio::select! {
        result=leases=>result.map_err(|cause| Error::Phase { stage: "lease pump", cause: Box::new(cause) }),
        result=resources=>result.map_err(|cause| Error::Phase { stage: "resource poll", cause: Box::new(cause) }),
        result=turn=>result.map_err(|cause| Error::Phase { stage: "TURN resource poll", cause: Box::new(cause) }),
        result=service=>result.map_err(|cause| Error::Phase { stage:"service resource poll",cause:Box::new(cause) }),
    }
}
async fn lease_pump(
    config: NodeConfig,
    identity: Arc<NodeIdentity>,
    runtime_id: String,
    state: Arc<Mutex<Runtime>>,
    started: Instant,
) -> Result<(), Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(700))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| Error::Control)?;
    let report_url = format!(
        "{}/api/v3/nodes/{}/report",
        config.control_origin, config.node_id
    );
    let issuer = config.issuer()?;
    let mut report_sequence = 0u64;
    let mut active = false;
    let initial_deadline = Instant::now() + Duration::from_secs(15);
    let mut retry_delay = Duration::from_millis(250);
    loop {
        let result = lease_channel(
            &config,
            &identity,
            &runtime_id,
            &state,
            started,
            &client,
            &report_url,
            &issuer,
            &mut report_sequence,
            &mut active,
        )
        .await;
        if !matches!(result, Err(Error::Transport)) {
            return result;
        }
        // Reconnecting cannot mint time or clear the gate's sequence/policy
        // watermarks. An expired, revoked or invalid lease remains terminal.
        let budget = if active {
            Duration::from_secs(15)
        } else {
            initial_deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::Control)?
        };
        supervise_lease(
            &state,
            started,
            active,
            budget,
            tokio::time::sleep(retry_delay),
        )
        .await?;
        retry_delay = (retry_delay * 2).min(Duration::from_secs(1));
    }
}

#[allow(clippy::too_many_arguments)]
async fn lease_channel(
    config: &NodeConfig,
    identity: &NodeIdentity,
    runtime_id: &str,
    state: &Arc<Mutex<Runtime>>,
    started: Instant,
    client: &reqwest::Client,
    report_url: &str,
    issuer: &[u8; 32],
    report_sequence: &mut u64,
    active: &mut bool,
) -> Result<(), Error> {
    let options = WebSocketConfig::default()
        .max_message_size(Some((NODE_MESSAGE_BYTES + 128) as usize))
        .max_frame_size(Some((NODE_MESSAGE_BYTES + 128) as usize));
    let connection = supervise_lease(
        state,
        started,
        *active,
        Duration::from_secs(15),
        tokio_tungstenite::connect_async_tls_with_config(
            config.url()?.as_str(),
            Some(options),
            false,
            Some(tokio_tungstenite::Connector::Rustls(Arc::new(
                nestlink_transport_stream::tls::public_client_config()
                    .map_err(|_| Error::Control)?,
            ))),
        ),
    )
    .await?;
    let (mut socket, _) = connection.map_err(transport_error)?;
    loop {
        // Separate timer keeps lease/clock checks running during blocked network IO.
        let exchange = async {
            let bytes = receive(&mut socket).await?;
            let challenge: NodeChallenge = decode_bounded(&bytes, NODE_MESSAGE_BYTES)?;
            challenge.validate()?;
            let now = sample(started)?;
            if challenge.deployment_id != config.deployment_id
                || challenge.node_id != config.node_id
                || challenge.expires_at_unix_ms <= now.unix_ms
                || challenge.expires_at_unix_ms > now.unix_ms.saturating_add(NODE_CHALLENGE_MS)
            {
                return Err(Error::Control);
            }
            let proof = identity.prove(&challenge, runtime_id)?;
            let requested = sample(started)?.monotonic_ms;
            socket
                .send(WsMessage::Binary(proof.encode_to_vec().into()))
                .await
                .map_err(transport_error)?;
            let lease = receive(&mut socket).await?;
            state.lock().map_err(|_| Error::Control)?.gate.accept(
                &lease,
                &challenge,
                requested,
                sample(started)?,
            )?;
            let claims = {
                let mut state = state.lock().map_err(|_| Error::Control)?;
                let now = sample(started)?;
                let lease = state.gate.current(now)?.clone();
                let count = state.meter.counters();
                NodeUsageClaims {
                    schema_version: SCHEMA_VERSION,
                    deployment_id: lease.deployment_id,
                    security_epoch: lease.security_epoch,
                    node_id: lease.node_id,
                    runtime_id: lease.runtime_id,
                    runtime_generation: lease.runtime_generation,
                    policy_revision: lease.policy_revision,
                    lease_sequence: lease.lease_sequence,
                    report_sequence: (*report_sequence)
                        .checked_add(1)
                        .filter(|n| *n <= i64::MAX as u64)
                        .ok_or(Error::Control)?,
                    opened_connections: count.opened_connections,
                    closed_connections: count.closed_connections,
                    admitted_bytes: count.admitted_bytes,
                    sampled_at_unix_ms: now.unix_ms,
                }
            };
            report(client, report_url, identity, issuer, &claims, started)
                .await
                .map_err(|cause| Error::Phase {
                    stage: "usage confirmation",
                    cause: Box::new(cause),
                })?;
            let mut state = state.lock().map_err(|_| Error::Control)?;
            state.gate.check_live(sample(started)?)?;
            state.ready = true;
            *report_sequence = claims.report_sequence;
            Ok::<(), Error>(())
        };
        supervise_lease(
            state,
            started,
            *active,
            Duration::from_secs(if *active { 12 } else { 6 }),
            exchange,
        )
        .await??;
        *active = true;
    }
}

async fn supervise_lease<T>(
    state: &Arc<Mutex<Runtime>>,
    started: Instant,
    active: bool,
    timeout: Duration,
    operation: impl std::future::Future<Output = T>,
) -> Result<T, Error> {
    tokio::pin!(operation);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let timeout = tokio::time::sleep(timeout);
    tokio::pin!(timeout);
    loop {
        tokio::select! {biased;
            _=&mut timeout=>return Err(Error::Control),
            _=tick.tick()=>{if active {let mut state=state.lock().map_err(|_|Error::Control)?;let now=sample(started)?;state.gate.check_live(now)?;state.resources.expire(now);}},
            result=&mut operation=>return Ok(result),
        }
    }
}

fn transport_error(error: tokio_tungstenite::tungstenite::Error) -> Error {
    use tokio_tungstenite::tungstenite::Error as WsError;
    match error {
        WsError::ConnectionClosed | WsError::AlreadyClosed | WsError::Io(_) => Error::Transport,
        WsError::Protocol(
            tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
        ) => Error::Transport,
        WsError::Http(response) if response.status().is_server_error() => Error::Transport,
        _ => Error::Control,
    }
}
async fn report(
    client: &reqwest::Client,
    url: &str,
    identity: &NodeIdentity,
    issuer: &[u8; 32],
    claims: &NodeUsageClaims,
    started: Instant,
) -> Result<(), Error> {
    let signed = identity.sign_usage(claims)?;
    let digest = nestlink_identity::digest(&signed.claims);
    for attempt in 0..2 {
        let result = tokio::time::timeout(Duration::from_millis(700), async {
            let response = client
                .post(url)
                .json(&signed)
                .send()
                .await
                .map_err(|_| Error::Control)?;
            if !response.status().is_success() {
                return Err(Error::UsageStatus(response.status().as_u16()));
            }
            let mut response = response.bytes_stream();
            let mut bytes = Vec::new();
            while let Some(chunk) = response.next().await {
                let chunk = chunk.map_err(|_| Error::Control)?;
                if bytes.len() + chunk.len() > 32768 {
                    return Err(Error::Control);
                }
                bytes.extend_from_slice(&chunk);
            }
            let signed: SignedNodeUsageAck =
                serde_json::from_slice(&bytes).map_err(|_| Error::Control)?;
            let ack = nestlink_identity::nodes::verify_usage_ack(&signed, issuer)?;
            if ack.deployment_id != claims.deployment_id
                || ack.security_epoch != claims.security_epoch
                || ack.node_id != claims.node_id
                || ack.runtime_id != claims.runtime_id
                || ack.runtime_generation != claims.runtime_generation
                || ack.report_sequence != claims.report_sequence
                || ack.report_sha256 != digest
                || ack.accepted_at_unix_ms > sample(started)?.unix_ms.saturating_add(1000)
                || ack.accepted_at_unix_ms.saturating_add(1000) < claims.sampled_at_unix_ms
            {
                return Err(Error::Authorization(ContractError::new(
                    ErrorCode::IdentityMismatch,
                    "node usage acknowledgement mismatch",
                )));
            }
            Ok(())
        })
        .await;
        match result {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(Error::Authorization(e))) => return Err(Error::Authorization(e)),
            _ if attempt == 0 => continue,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(Error::Control),
        }
    }
    Err(Error::Control)
}
async fn receive(socket: &mut Socket) -> Result<Vec<u8>, Error> {
    loop {
        match socket
            .next()
            .await
            .ok_or(Error::Transport)?
            .map_err(transport_error)?
        {
            WsMessage::Binary(bytes) if bytes.len() as u64 <= NODE_MESSAGE_BYTES + 128 => {
                return Ok(bytes.to_vec());
            }
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
            // Legacy servers use an empty close for authorization rejection.
            // A TCP reset/EOF is separately classified as interrupted transport.
            WsMessage::Close(None) => return Err(Error::Control),
            WsMessage::Close(Some(frame)) => {
                use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
                return Err(match frame.code {
                    CloseCode::Normal | CloseCode::Away | CloseCode::Restart | CloseCode::Again => {
                        Error::Transport
                    }
                    _ => Error::Control,
                });
            }
            _ => return Err(Error::Control),
        }
    }
}
