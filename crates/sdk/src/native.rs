//! Real bounded QUIC, direct TLS and WSS racing. The returned TLS transport must still
//! complete native endpoint proof before an AuthorizedConnection exposes data.
use crate::{
    DeviceIdentity, RelayRoute, Sdk, SdkError, SignalCursor,
    node_relay::{NativeRelayRoute, NodeQuicRoute, NodeRelayRoute},
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use nestlink_connectivity::{Failure, Outcome, Scheduler};
use nestlink_identity::{VerifiedPermit, digest};
use nestlink_platform_network::{NetworkMonitor, NetworkState, Reason};
use nestlink_policy::PathSet;
use nestlink_protocol::{
    CANDIDATE_COUNT, CONNECTION_BUDGET_MS, ContractError, DiscoveredRelayNode, ErrorCode, Path,
    Permission, PermitClaims,
    api::{Candidate, CandidateKind, SignalPayload, Transport},
    signaling::safe_peer_address,
};
pub use nestlink_remote::{CleanupStatus, StopReport};
use nestlink_remote::{NetworkBinding, RuntimeClock, SessionLifecycle, SessionSetup};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use nestlink_transport_quic::discovery::DiscoverySocket;
use quinn::AsyncUdpSocket;
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

#[path = "native/dual_stack.rs"]
mod dual_stack;
use dual_stack::AdditionalFamily;

const CONTROL_REQUEST_BUDGET: Duration = Duration::from_secs(5);
const CANDIDATE_GATHER_BUDGET: Duration = Duration::from_secs(3);
const RELAY_SETUP_BUDGET: Duration = Duration::from_secs(12);
// Allow the sleeping host inbox, STUN and signed relay discovery to complete.
// Every operation is still capped by this budget and the permit deadline.
const SIGNAL_WAIT_BUDGET: Duration = Duration::from_secs(20);
const SIGNAL_POLL_INTERVAL: Duration = Duration::from_millis(150);

/// Routes backed by one shared allocation. The node and allocation identifiers
/// are derived from the permit so both endpoints independently rendezvous at
/// the same node without trusting either endpoint to name a relay URL.
struct AutoNodeRelay {
    node_id: String,
    wss: Option<NodeRelayRoute>,
    quic: Option<NodeQuicRoute>,
}
impl AutoNodeRelay {
    fn routes(&self) -> Vec<NativeRelayRoute<'_>> {
        let mut routes = Vec::with_capacity(2);
        if let Some(route) = &self.quic {
            routes.push(NativeRelayRoute::Quic(route));
        }
        if let Some(route) = &self.wss {
            routes.push(NativeRelayRoute::Wss(route));
        }
        routes
    }
}

pub(super) fn initial_relay_allocation_id(
    claims: &PermitClaims,
    node: &DiscoveredRelayNode,
) -> Result<String, SdkError> {
    if !nestlink_protocol::valid_id(&node.node_id) {
        return Err(SdkError::Invalid);
    }
    let mut transcript = b"NestLink/v15/initial-native-allocation/v1\0".to_vec();
    for value in [
        claims.deployment_id.as_bytes(),
        claims.session_id.as_bytes(),
        claims.account_id.as_bytes(),
        claims.controller_device_id.as_bytes(),
        claims.host_device_id.as_bytes(),
        claims.resource_id.as_bytes(),
        claims.controller_key_sha256.as_slice(),
        claims.host_key_sha256.as_slice(),
        claims.capability_sha256.as_slice(),
        node.node_id.as_bytes(),
        node.runtime_id.as_bytes(),
        node.node_key_sha256.as_slice(),
    ] {
        let length: u32 = value.len().try_into().map_err(|_| SdkError::Invalid)?;
        transcript.extend_from_slice(&length.to_be_bytes());
        transcript.extend_from_slice(value);
    }
    for value in [
        claims.security_epoch,
        claims.policy_revision,
        claims.connection_generation,
        node.runtime_generation,
        node.endpoint_revision,
    ] {
        transcript.extend_from_slice(&value.to_be_bytes());
    }
    let mut permissions = claims.permissions.clone();
    permissions.sort_unstable();
    let mut paths = claims.paths.clone();
    paths.sort_unstable();
    for values in [&permissions, &paths] {
        let length: u32 = values.len().try_into().map_err(|_| SdkError::Invalid)?;
        transcript.extend_from_slice(&length.to_be_bytes());
        for value in values {
            transcript.extend_from_slice(&value.to_be_bytes());
        }
    }
    let mut bytes: [u8; 16] = digest(&transcript)[..16]
        .try_into()
        .map_err(|_| SdkError::Invalid)?;
    // UUIDv8 is reserved for application-defined deterministic identifiers.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(bytes).hyphenated().to_string())
}

async fn reserve_discovered_node(
    sdk: &Sdk,
    local: &DeviceIdentity,
    permit: &VerifiedPermit,
    discovery: &crate::NodeDiscovery,
    node: &DiscoveredRelayNode,
) -> Result<AutoNodeRelay, SdkError> {
    let allocation_id = initial_relay_allocation_id(permit.claims(), node)?;
    let allocation = sdk
        .reserve_relay_allocation(local, permit, &allocation_id, &node.node_id)
        .await?;
    let (wss, quic) = sdk
        .discovered_node_routes(discovery, local, permit, &allocation)
        .await?;
    if wss.is_none() && quic.is_none() {
        return Err(SdkError::Trust);
    }
    Ok(AutoNodeRelay {
        node_id: node.node_id.clone(),
        wss,
        quic,
    })
}

async fn discover_auto_node_relay(
    sdk: &Sdk,
    local: &DeviceIdentity,
    permit: &VerifiedPermit,
) -> Result<AutoNodeRelay, SdkError> {
    let discovery = sdk.discover_relay_nodes(local, permit).await?;
    let node_id = discovery
        .nodes()
        .iter()
        .find(|node| !node.quic_uri.is_empty() || !node.wss_origin.is_empty())
        .map(|node| node.node_id.clone())
        .ok_or(SdkError::Trust)?;
    let node = discovery
        .nodes()
        .iter()
        .find(|node| node.node_id == node_id)
        .ok_or(SdkError::Trust)?;
    reserve_discovered_node(sdk, local, permit, &discovery, node).await
}

async fn resolve_signed_node_host(
    host: url::Host<&str>,
    port: u16,
) -> Result<Vec<SocketAddr>, SdkError> {
    let mut addresses: Vec<_> = match host {
        url::Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
        url::Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
        url::Host::Domain(domain) => tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((domain, port)),
        )
        .await
        .map_err(|_| SdkError::Timeout)?
        .map_err(|_| SdkError::Invalid)?
        .take(33)
        .collect(),
    };
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty()
        || addresses.len() > 32
        || addresses
            .iter()
            .any(|address| address.ip().is_unspecified() || address.ip().is_multicast())
    {
        return Err(SdkError::Invalid);
    }
    Ok(addresses)
}

async fn signed_node_addresses(
    node: &DiscoveredRelayNode,
    transport: Transport,
) -> Result<Vec<SocketAddr>, SdkError> {
    let (addresses, allow_loopback, forbid_non_loopback_http) = match transport {
        Transport::Quic if !node.quic_uri.is_empty() => {
            let uri = url::Url::parse(&node.quic_uri).map_err(|_| SdkError::Invalid)?;
            if uri.scheme() != "quic"
                || !uri.username().is_empty()
                || uri.password().is_some()
                || uri.query().is_some()
                || uri.fragment().is_some()
                || !matches!(uri.path(), "" | "/")
            {
                return Err(SdkError::Invalid);
            }
            let port = uri
                .port()
                .filter(|port| *port != 0)
                .ok_or(SdkError::Invalid)?;
            let host = uri.host().ok_or(SdkError::Invalid)?;
            (
                resolve_signed_node_host(host, port).await?,
                node.allow_loopback,
                false,
            )
        }
        Transport::Wss if !node.wss_origin.is_empty() => {
            let origin = crate::parse_origin(&node.wss_origin, node.allow_loopback)?;
            let port = origin.port_or_known_default().ok_or(SdkError::Invalid)?;
            let host = origin.host().ok_or(SdkError::Invalid)?;
            (
                resolve_signed_node_host(host, port).await?,
                node.allow_loopback,
                origin.scheme() == "http",
            )
        }
        _ => return Ok(Vec::new()),
    };
    if addresses.iter().any(|address| {
        (!allow_loopback && address.ip().is_loopback())
            || (forbid_non_loopback_http && !address.ip().is_loopback())
    }) {
        return Err(SdkError::Trust);
    }
    Ok(addresses)
}

pub(super) async fn node_matches_relay_markers(
    node: &DiscoveredRelayNode,
    markers: &[Candidate],
) -> Result<bool, SdkError> {
    for transport in [Transport::Quic, Transport::Wss] {
        let addresses: Vec<_> = markers
            .iter()
            .filter(|marker| marker.kind == CandidateKind::Relay && marker.transport == transport)
            .map(|marker| marker.address)
            .collect();
        if !addresses.is_empty()
            && signed_node_addresses(node, transport)
                .await?
                .iter()
                .any(|address| addresses.contains(address))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn refresh_auto_node_relay(
    sdk: &Sdk,
    local: &DeviceIdentity,
    permit: &VerifiedPermit,
    previous: Option<&AutoNodeRelay>,
    peer_candidates: &[Candidate],
) -> Result<Option<AutoNodeRelay>, SdkError> {
    let discovery = sdk.discover_relay_nodes(local, permit).await?;
    let mut matching_node_ids = Vec::new();
    if peer_candidates
        .iter()
        .any(|candidate| candidate.kind == CandidateKind::Relay)
    {
        let matches = futures_util::future::join_all(discovery.nodes().iter().map(|node| async {
            Ok::<_, SdkError>((
                node.node_id.clone(),
                node_matches_relay_markers(node, peer_candidates).await?,
            ))
        }))
        .await;
        for matched in matches {
            let (node_id, is_match) = matched?;
            if is_match {
                matching_node_ids.push(node_id);
            }
        }
    }
    matching_node_ids.sort();
    matching_node_ids.dedup();
    let previous_node_id = previous
        .filter(|previous| {
            discovery
                .nodes()
                .iter()
                .any(|node| node.node_id == previous.node_id)
        })
        .map(|previous| previous.node_id.as_str());
    let node_id = matching_node_ids
        .first()
        .map(String::as_str)
        .or(previous_node_id)
        .or_else(|| {
            discovery
                .nodes()
                .iter()
                .find(|node| !node.quic_uri.is_empty() || !node.wss_origin.is_empty())
                .map(|node| node.node_id.as_str())
        });
    let Some(node_id) = node_id else {
        return Ok(None);
    };
    let node = discovery
        .nodes()
        .iter()
        .find(|node| node.node_id == node_id)
        .ok_or(SdkError::Trust)?;
    reserve_discovered_node(sdk, local, permit, &discovery, node)
        .await
        .map(Some)
}

#[derive(Debug, thiserror::Error)]
pub enum DialError {
    #[error("native endpoint binding rejected")]
    Binding,
    #[error("native endpoint setup failed")]
    Setup,
    #[error("native connection contract: {0}")]
    Contract(#[from] ContractError),
    #[error("native candidate race failed: {code:?}")]
    Failed {
        code: ErrorCode,
        failures: Vec<Failure>,
    },
    #[error("network generation changed; new candidates and authorization required")]
    NetworkChanged,
    #[error("native connection cancelled")]
    Cancelled,
    #[error("native permit expired")]
    Expired,
}
#[derive(Debug, thiserror::Error)]
pub enum SessionEstablishError {
    #[error(transparent)]
    Sdk(#[from] SdkError),
    #[error(transparent)]
    Dial(#[from] DialError),
    #[error(transparent)]
    Remote(#[from] nestlink_remote::RemoteError),
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error("the current permit changed during native session establishment")]
    PermitChanged,
    #[error("the selected endpoint role, local policy or session binding is invalid")]
    Binding,
    #[error("no supported current candidates are available for signaling")]
    NoCandidates,
    #[error("no signed, authorized relay route is available for this session")]
    RelayOnlyUnsupported,
    #[error("no signed current peer candidates arrived before the signaling deadline")]
    SignalTimeout,
    #[error("native session establishment was cancelled")]
    Cancelled,
}

/// Local permissions and transports accepted by this endpoint.
pub struct NativeSessionOptions {
    pub granted_permissions: Vec<Permission>,
    pub supported_capabilities: Vec<String>,
    pub local_paths: PathSet,
}
/// Locally supplied direction evidence; remote announcements alone must not
/// be used to construct this value by the application provider.
#[derive(Clone, Debug)]
pub struct NativeMediaEvidence {
    pub frozen: nestlink_protocol::media_authority::FrozenMediaScope,
    pub local: nestlink_protocol::media_authority::MediaAnnouncement,
}
impl NativeMediaEvidence {
    pub(super) fn bind(
        &self,
        permit: &VerifiedPermit,
        role: EndpointRole,
        now: u64,
    ) -> Result<nestlink_session::MediaSessionBinding, SdkError> {
        Ok(
            nestlink_session::MediaSessionBinding::from_local_announcement(
                permit,
                &self.frozen,
                &self.local,
                role,
                now,
            )?,
        )
    }
}
/// Separate entry point keeps legacy callers explicit and source compatible.
pub struct NativeMediaSessionOptions {
    pub session: NativeSessionOptions,
    pub media: Option<NativeMediaEvidence>,
}
/// Explicit local dialing scope. Public unicast is permitted; private/ULA
/// destinations require an administrator-configured prefix, and metadata,
/// loopback and link-local remain blocked even inside a permitted prefix.
#[derive(Clone)]
pub struct AddressPolicy {
    prefixes: Vec<(IpAddr, u8)>,
    #[cfg(test)]
    pub(super) test_loopback: bool,
}
impl AddressPolicy {
    pub fn new(prefixes: &[String]) -> Result<Self, DialError> {
        if prefixes.len() > 32 {
            return Err(DialError::Binding);
        }
        let mut parsed = Vec::new();
        for prefix in prefixes {
            let (address, bits) = prefix.split_once('/').ok_or(DialError::Binding)?;
            let address: IpAddr = address.parse().map_err(|_| DialError::Binding)?;
            let bits: u8 = bits.parse().map_err(|_| DialError::Binding)?;
            let maximum = if address.is_ipv4() { 32 } else { 128 };
            if bits > maximum {
                return Err(DialError::Binding);
            }
            parsed.push((address, bits));
        }
        Ok(Self {
            prefixes: parsed,
            #[cfg(test)]
            test_loopback: false,
        })
    }
    pub fn allows(&self, address: IpAddr) -> bool {
        #[cfg(test)]
        if self.test_loopback && address.is_loopback() {
            return true;
        }
        if !safe_peer_address(address) {
            return false;
        }
        let private = match address {
            IpAddr::V4(ip) => ip.is_private(),
            IpAddr::V6(ip) => ip.is_unique_local(),
        };
        !private
            || self
                .prefixes
                .iter()
                .any(|(network, prefix)| match (address, *network) {
                    (IpAddr::V4(ip), IpAddr::V4(network)) => {
                        let mask = u32::MAX.checked_shl(32 - u32::from(*prefix)).unwrap_or(0);
                        ip.to_bits() & mask == network.to_bits() & mask
                    }
                    (IpAddr::V6(ip), IpAddr::V6(network)) => {
                        let mask = u128::MAX.checked_shl(128 - u32::from(*prefix)).unwrap_or(0);
                        ip.to_bits() & mask == network.to_bits() & mask
                    }
                    _ => false,
                })
    }
}
pub struct NativeEndpoint {
    endpoint: Option<quinn::Endpoint>,
    socket: Option<Arc<DiscoverySocket>>,
    additional_family: Option<AdditionalFamily>,
    network_generation: AtomicU64,
    lifecycle: watch::Sender<NetworkState>,
    monitor: Option<(watch::Receiver<NetworkState>, u64)>,
    monitor_task: Option<MonitorTask>,
    local_generation: u64,
    local_device: String,
    local_fingerprint: [u8; 32],
    peer_key: [u8; 32],
    role: EndpointRole,
    tls_config: rustls::ClientConfig,
    permit: VerifiedPermit,
    address_policy: AddressPolicy,
    authorization_deadline: Instant,
    authorization_clock: Mutex<Option<u64>>,
    signal_sequence: AtomicU64,
}

#[derive(Clone, Copy)]
struct LocalAcceptPolicy {
    direct_available: bool,
    paths: PathSet,
}
pub struct ConnectedQuic {
    pub connection: quinn::Connection,
    pub candidate: Candidate,
    pub failures: Vec<Failure>,
    pub network: NetworkBinding,
    _endpoint: quinn::Endpoint,
}
pub enum NativeTransport {
    Quic {
        connection: quinn::Connection,
        endpoint: quinn::Endpoint,
        carrier: Option<nestlink_transport_quic::node::Carrier>,
    },
    DirectTls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    Wss(Box<tokio_rustls::TlsStream<nestlink_transport_wss::ByteStream>>),
}
impl NativeTransport {
    fn close(&self) {
        if let Self::Quic { connection, .. } = self {
            connection.close(0u32.into(), b"candidate discarded");
        }
    }
}
/// TLS identity has been checked. Native session proof is required before use
/// with AuthorizedConnection, for every transport including direct TCP.
pub struct NativeConnection {
    pub transport: NativeTransport,
    pub candidate: Candidate,
    pub failures: Vec<Failure>,
    pub network: NetworkBinding,
    pub(crate) authorization_deadline: Instant,
}
/// A proved session with its selected path and candidate diagnostics retained.
pub struct NativeSession {
    pub channels: nestlink_remote::ChannelRuntime,
    pub candidate: Candidate,
    pub failures: Vec<Failure>,
    pub control: NativeSessionControl,
    lifecycle_owner: Option<watch::Sender<Option<StopReason>>>,
}
#[derive(Clone)]
pub struct NativeSessionControl {
    sequence: std::sync::Arc<std::sync::atomic::AtomicU64>,
    renewal: Option<std::sync::Arc<tokio::sync::Mutex<crate::native_renewal::Coordinator>>>,
    lease: nestlink_remote::LeaseControl,
}
impl NativeSessionControl {
    pub fn lease_remaining(&self) -> Result<std::time::Duration, nestlink_remote::RemoteError> {
        self.lease.remaining()
    }
    pub fn lease_sequence(&self) -> u64 {
        self.sequence.load(std::sync::atomic::Ordering::Acquire)
    }
    pub fn has_native_renewal(&self) -> bool {
        self.renewal.is_some()
    }
    pub async fn native_renewal_step(
        &self,
        sdk: &Sdk,
        identity: &DeviceIdentity,
        source: &dyn crate::native_renewal::NativeRenewalSource,
    ) -> Result<VerifiedPermit, SdkError> {
        let coordinator = self.renewal.as_ref().ok_or(SdkError::Trust)?;
        coordinator
            .lock()
            .await
            .step(sdk, identity, &self.lease, source)
            .await
    }
    pub async fn current_native_permit(&self) -> Result<VerifiedPermit, SdkError> {
        if let Some(coordinator) = &self.renewal {
            return Ok(coordinator.lock().await.current().clone());
        }
        Ok(self.lease.current_native_permit()?)
    }
    /// Caller must obtain this evidence from its actual local direction provider.
    /// A closed historical probe UUID never replaces the live media owner UUID.
    pub fn renew_with_media(
        &self,
        permit: VerifiedPermit,
        request_started_ms: u64,
        evidence: &NativeMediaEvidence,
        role: EndpointRole,
        execution: &dyn nestlink_remote::native_renewal::NativeExecutionFence,
    ) -> Result<(), nestlink_remote::RemoteError> {
        if self.renewal.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "coordinated native renewal requires both endpoint drivers",
            )
            .into());
        }
        let expected = self.lease.current_native_permit()?.claims().lease_sequence;
        self.lease.renew_with_local_media(
            permit,
            request_started_ms,
            expected,
            &evidence.frozen,
            &evidence.local,
            role,
            execution,
        )
    }
    /// Request terminal teardown. The first stop reason wins.
    pub fn stop(&self, reason: StopReason) -> Result<(), nestlink_remote::RemoteError> {
        self.lease.stop(reason).map(|_| ())
    }
}
impl NativeSession {
    pub async fn shutdown(
        &mut self,
        reason: StopReason,
    ) -> Result<StopReport, nestlink_remote::RemoteError> {
        self.channels.shutdown(reason).await
    }
}
impl NativeConnection {
    /// Bind the original endpoint/network facts and selected path before proof.
    /// The same API exposes independent QUIC channels or framed TLS/WSS queues.
    pub async fn authorize(
        self,
        mut setup: nestlink_remote::SessionSetup,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
    ) -> Result<NativeSession, nestlink_remote::RemoteError> {
        setup
            .session
            .cap_deadline_ms(setup.clock.deadline_ms(self.authorization_deadline)?)?;
        setup.path = self.candidate.path();
        setup.lifecycle.network = Some(self.network);
        let mut channels = match self.transport {
            NativeTransport::Quic {
                connection,
                endpoint,
                carrier,
            } => {
                if let Some(carrier) = &carrier {
                    setup.lifecycle.carrier = Some(carrier.subscribe_failure());
                }
                let channels = nestlink_remote::quic::authorize(
                    connection,
                    Some(endpoint),
                    setup,
                    &local.identity,
                    peer_key,
                )
                .await?;
                if let Some(carrier) = carrier {
                    channels.with_transport_owner(carrier)
                } else {
                    channels
                }
            }
            NativeTransport::DirectTls(io) => {
                authorize_stream(io, setup, &local.identity, peer_key).await?
            }
            NativeTransport::Wss(io) => {
                authorize_stream(io, setup, &local.identity, peer_key).await?
            }
        };
        let lease = channels.lease_control();
        let sequence = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
            lease.current_native_permit()?.claims().lease_sequence,
        ));
        let renewal = match channels.take_native_renewal_port() {
            Some(port) => Some(std::sync::Arc::new(tokio::sync::Mutex::new(
                crate::native_renewal::Coordinator::new(
                    port,
                    lease.current_native_permit()?,
                    *peer_key,
                    if local.device_id
                        == lease.current_native_permit()?.claims().controller_device_id
                    {
                        EndpointRole::Controller
                    } else {
                        EndpointRole::Host
                    },
                    sequence.clone(),
                ),
            ))),
            None => None,
        };
        let control = NativeSessionControl {
            lease,
            renewal,
            sequence,
        };
        Ok(NativeSession {
            channels,
            candidate: self.candidate,
            failures: self.failures,
            control,
            lifecycle_owner: None,
        })
    }
}
async fn authorize_stream<
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    io: T,
    setup: nestlink_remote::SessionSetup,
    identity: &nestlink_identity::InstallationIdentity,
    peer_key: &[u8; 32],
) -> Result<nestlink_remote::ChannelRuntime, nestlink_remote::RemoteError> {
    let nestlink_remote::SessionSetup {
        mut session,
        path,
        role,
        clock,
        lifecycle,
    } = setup;
    let (mut read, mut write) = tokio::io::split(io);
    match role {
        nestlink_session::EndpointRole::Controller => {
            nestlink_remote::controller_proof(
                &mut read,
                &mut write,
                &mut session,
                identity,
                peer_key,
                &clock,
            )
            .await?
        }
        nestlink_session::EndpointRole::Host => {
            nestlink_remote::host_proof(
                &mut read,
                &mut write,
                &mut session,
                identity,
                peer_key,
                &clock,
            )
            .await?
        }
    }
    Ok(nestlink_remote::AuthorizedConnection::with_lifecycle(
        read, write, session, path, clock, lifecycle,
    )?
    .negotiate_native_renewal()
    .await?
    .into_channels())
}
struct MonitorTask(tokio::task::JoinHandle<()>);
impl Drop for MonitorTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl NativeEndpoint {
    pub(crate) fn cap_authorization_deadline(
        &mut self,
        deadline: Instant,
    ) -> Result<(), DialError> {
        if deadline <= Instant::now() {
            return Err(DialError::Expired);
        }
        self.authorization_deadline = self.authorization_deadline.min(deadline);
        Ok(())
    }
    pub fn new(
        bound: SocketAddr,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        permit: VerifiedPermit,
        stun_servers: Vec<SocketAddr>,
        address_policy: AddressPolicy,
    ) -> Result<Self, DialError> {
        let c = permit.claims();
        let (local_digest, peer_digest, role) = if local.device_id == c.controller_device_id {
            (
                &c.controller_key_sha256,
                &c.host_key_sha256,
                EndpointRole::Controller,
            )
        } else if local.device_id == c.host_device_id {
            (
                &c.host_key_sha256,
                &c.controller_key_sha256,
                EndpointRole::Host,
            )
        } else {
            return Err(DialError::Binding);
        };
        if *local_digest != digest(&local.identity.public_key()) || *peer_digest != digest(peer_key)
        {
            return Err(DialError::Binding);
        }
        let now = live(&permit)?;
        let authorization_deadline =
            Instant::now() + Duration::from_millis(permit.claims().expires_at_unix_ms - now);
        let direct = c.paths.contains(&(Path::Direct as i32));
        let (endpoint, socket) = if direct {
            let (endpoint, socket) = nestlink_transport_quic::discovery_endpoint(
                bound,
                &local.identity,
                digest(peer_key),
                stun_servers,
            )
            .map_err(|_| DialError::Setup)?;
            (Some(endpoint), Some(socket))
        } else {
            (None, None)
        };
        let local_generation = 1;
        let (lifecycle, _) = watch::channel(NetworkState {
            generation: local_generation,
            available: true,
            reason: Reason::Started,
        });
        let tls_config =
            nestlink_transport_stream::tls::client_config(&local.identity, digest(peer_key))
                .map_err(|_| DialError::Setup)?;
        Ok(Self {
            endpoint,
            socket,
            additional_family: None,
            network_generation: AtomicU64::new(local_generation),
            lifecycle,
            monitor: None,
            monitor_task: None,
            local_generation,
            local_device: local.device_id.clone(),
            local_fingerprint: local.identity.fingerprint(),
            peer_key: *peer_key,
            role,
            tls_config,
            permit,
            address_policy,
            authorization_deadline,
            authorization_clock: Mutex::new(Some(now)),
            signal_sequence: AtomicU64::new(0),
        })
    }
    /// Capture OS generation before socket construction, so a notification
    /// during setup cannot be lost between endpoint creation and subscription.
    pub fn new_monitored(
        bound: SocketAddr,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        permit: VerifiedPermit,
        stun_servers: Vec<SocketAddr>,
        address_policy: AddressPolicy,
        monitor: &NetworkMonitor,
    ) -> Result<Self, DialError> {
        Self::with_monitor(monitor, || {
            Self::new(bound, local, peer_key, permit, stun_servers, address_policy)
        })
    }
    /// Complete the control-plane and native transport flow for one endpoint.
    /// When relay is locally permitted and no explicit route was supplied, both
    /// peers discover a signed relay node and derive the same allocation ID.
    /// Relay-only sessions advertise a route candidate so the signed signaling
    /// exchange can rendezvous even though there are no direct candidates.
    pub fn verified_permit(&self) -> &VerifiedPermit {
        &self.permit
    }
    pub async fn establish(
        &self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        options: NativeSessionOptions,
        routes: &[NativeRelayRoute<'_>],
        stun_servers: Vec<SocketAddr>,
        cancel: watch::Receiver<bool>,
    ) -> Result<NativeSession, SessionEstablishError> {
        self.establish_with_media(
            sdk,
            local,
            NativeMediaSessionOptions {
                session: options,
                media: None,
            },
            routes,
            stun_servers,
            cancel,
        )
        .await
    }
    pub async fn establish_with_media(
        &self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        options: NativeMediaSessionOptions,
        routes: &[NativeRelayRoute<'_>],
        stun_servers: Vec<SocketAddr>,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<NativeSession, SessionEstablishError> {
        let NativeMediaSessionOptions {
            session: options,
            media,
        } = options;
        self.validate_local(local, &options, routes)?;
        self.check()?;
        self.ensure_current_permit(sdk, local, cancel.clone())
            .await?;

        let direct_allowed = options.local_paths.contains(Path::Direct)
            && self.permit.claims().paths.contains(&(Path::Direct as i32));
        let relay_allowed = options.local_paths.contains(Path::Relay)
            && self.permit.claims().paths.contains(&(Path::Relay as i32));
        let mut local_candidates = Vec::new();
        if direct_allowed {
            let gathered = tokio::select! {
                biased;
                _ = cancellation(&mut cancel) => return Err(SessionEstablishError::Cancelled),
                result = tokio::time::timeout(
                    CANDIDATE_GATHER_BUDGET,
                    self.gather_direct_candidates(stun_servers),
                ) => result,
            };
            match gathered {
                Ok(Ok(gathered)) => {
                    self.check()?;
                    local_candidates.extend(gathered);
                }
                Ok(Err(_)) | Err(_) if relay_allowed => {
                    // A usable signed node route can still establish the session
                    // when direct candidate gathering is unavailable.
                    self.check()?;
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(SdkError::Timeout.into()),
            }
        }
        local_candidates = bounded_unique(local_candidates, CANDIDATE_COUNT as usize);

        // A normal self-hosted deployment already has a mutually authenticated
        // WSS relay on its approved management origin. Do not require a separate
        // data node just to connect across restrictive NAT/firewalls.
        let combined_relay = if routes.is_empty() && relay_allowed {
            tokio::select! {
                biased;
                _ = cancellation(&mut cancel) => return Err(SessionEstablishError::Cancelled),
                result = tokio::time::timeout(CONTROL_REQUEST_BUDGET, sdk.relay_route(&self.permit)) => result.ok().and_then(Result::ok),
            }
        } else {
            None
        };
        let mut auto_relay = None;
        if routes.is_empty() && relay_allowed {
            let prepared = tokio::select! {
                biased;
                _ = cancellation(&mut cancel) => return Err(SessionEstablishError::Cancelled),
                result = tokio::time::timeout(
                    RELAY_SETUP_BUDGET,
                    discover_auto_node_relay(sdk, local, &self.permit),
                ) => result,
            };
            if let Ok(Ok(relay)) = prepared {
                auto_relay = Some(relay);
            }
        }
        let network_generation = self.local_generation;
        let mut signaling_routes = routes.to_vec();
        if let Some(relay) = &auto_relay {
            signaling_routes.extend(relay.routes());
        }
        if let Some(relay) = &combined_relay {
            signaling_routes.push(NativeRelayRoute::Combined(relay));
        }
        let mut signal_candidates = local_candidates.clone();
        let relay_marker = signaling_routes.iter().find_map(|route| {
            route
                .candidates(network_generation)
                .ok()?
                .into_iter()
                .find(|candidate| safe_peer_address(candidate.address.ip()))
        });
        if let Some(marker) = relay_marker {
            signal_candidates.truncate((CANDIDATE_COUNT as usize).saturating_sub(1));
            signal_candidates.push(marker);
        }
        if signal_candidates.is_empty() {
            for route in &signaling_routes {
                if let Ok(candidates) = route.candidates(network_generation) {
                    signal_candidates.extend(
                        candidates
                            .into_iter()
                            .filter(|candidate| safe_peer_address(candidate.address.ip())),
                    );
                }
            }
            signal_candidates = bounded_unique(signal_candidates, CANDIDATE_COUNT as usize);
        }
        if signal_candidates.is_empty() {
            if relay_allowed && !self.permit.claims().paths.contains(&(Path::Direct as i32)) {
                return Err(SessionEstablishError::RelayOnlyUnsupported);
            }
            return Err(SessionEstablishError::NoCandidates);
        }
        let signal = SignalPayload {
            ice: None,
            connection_generation: self.permit.claims().connection_generation,
            lease_sequence: self.permit.claims().lease_sequence,
            network_generation,
            sequence: self.next_signal_sequence()?,
            candidates: signal_candidates,
            description: None,
        };
        signal.validate(self.permit.claims())?;
        self.check()?;
        tokio::select! {
            biased;
            _ = cancellation(&mut cancel) => return Err(SessionEstablishError::Cancelled),
            result = tokio::time::timeout(
                CONTROL_REQUEST_BUDGET,
                sdk.publish_signal(local, &self.permit, signal),
            ) => result.map_err(|_| SdkError::Timeout)??,
        }
        self.check()?;

        let (peer_generation, peer_candidates) = self
            .wait_for_peer_candidates(sdk, local, &mut cancel)
            .await?;
        self.ensure_current_permit(sdk, local, cancel.clone())
            .await?;

        // Discovery routes carry a five-second request deadline. Refresh the
        // same allocation after signaling may have waited for the peer.
        if routes.is_empty() && relay_allowed {
            let refreshed = tokio::select! {
                biased;
                _ = cancellation(&mut cancel) => return Err(SessionEstablishError::Cancelled),
                result = tokio::time::timeout(
                    RELAY_SETUP_BUDGET,
                    refresh_auto_node_relay(
                        sdk,
                        local,
                        &self.permit,
                        auto_relay.as_ref(),
                        &peer_candidates,
                    ),
                ) => result,
            };
            auto_relay = match refreshed {
                Ok(Ok(relay)) => relay,
                _ => None,
            };
        }
        let mut active_routes = routes.to_vec();
        if let Some(relay) = &auto_relay {
            active_routes.extend(relay.routes());
        }
        if let Some(relay) = &combined_relay {
            active_routes.push(NativeRelayRoute::Combined(relay));
        }
        if local_candidates.is_empty() && active_routes.is_empty() {
            if relay_allowed && !self.permit.claims().paths.contains(&(Path::Direct as i32)) {
                return Err(SessionEstablishError::RelayOnlyUnsupported);
            }
            return Err(SessionEstablishError::NoCandidates);
        }

        let candidates = self.race_candidates(
            peer_generation,
            peer_candidates,
            &active_routes,
            options.local_paths,
        )?;
        let direct_available = options.local_paths.contains(Path::Direct)
            && local_candidates
                .iter()
                .any(|candidate| candidate.path() == Path::Direct)
            && candidates
                .iter()
                .any(|candidate| candidate.path() == Path::Direct);
        let relay_candidates: Vec<_> = candidates
            .iter()
            .filter(|candidate| candidate.path() == Path::Relay)
            .cloned()
            .collect();

        let connection = match self.role {
            EndpointRole::Controller => {
                self.dial_native_with_local_paths(
                    local,
                    &active_routes,
                    peer_generation,
                    candidates,
                    options.local_paths,
                    cancel.clone(),
                )
                .await?
            }
            EndpointRole::Host => {
                self.accept_or_relay(
                    peer_generation,
                    &relay_candidates,
                    &active_routes,
                    local,
                    LocalAcceptPolicy {
                        direct_available,
                        paths: options.local_paths,
                    },
                    cancel.clone(),
                )
                .await?
            }
        };
        self.check()?;
        self.ensure_current_permit(sdk, local, cancel.clone())
            .await?;

        let clock = RuntimeClock::default();
        let request_started_ms = clock.monotonic_ms();
        let sample = clock.sample().map_err(nestlink_remote::RemoteError::from)?;
        let binding = session_binding(
            &self.permit,
            options,
            media.as_ref(),
            self.role,
            sample.unix_ms,
        )?;
        let path = connection.candidate.path();
        let session = Session::activate(
            self.permit.clone(),
            binding,
            path,
            request_started_ms,
            sample,
        )?;
        let (_stop_owner, stop) = watch::channel(None);
        let setup = SessionSetup {
            session,
            path,
            role: self.role,
            clock,
            lifecycle: SessionLifecycle::new(stop),
        };
        let mut session = tokio::select! {
            biased;
            _ = cancellation(&mut cancel) => return Err(SessionEstablishError::Cancelled),
            result = connection.authorize(setup, local, &self.peer_key) => result?,
        };
        session.lifecycle_owner = Some(_stop_owner);
        if let Err(error) = self.check() {
            let reason = match error {
                DialError::NetworkChanged => StopReason::NetworkChanged,
                DialError::Expired => StopReason::Expired,
                _ => StopReason::Revoked,
            };
            let _ = session.control.stop(reason);
            let _ =
                tokio::time::timeout(Duration::from_secs(2), session.channels.wait_stopped()).await;
            return Err(error.into());
        }
        if let Err(error) = self.ensure_current_permit(sdk, local, cancel.clone()).await {
            let _ = session.control.stop(StopReason::Revoked);
            let _ =
                tokio::time::timeout(Duration::from_secs(2), session.channels.wait_stopped()).await;
            return Err(error);
        }
        Ok(session)
    }

    fn validate_local(
        &self,
        local: &DeviceIdentity,
        options: &NativeSessionOptions,
        routes: &[NativeRelayRoute<'_>],
    ) -> Result<(), SessionEstablishError> {
        if local.device_id != self.local_device
            || local.identity.fingerprint() != self.local_fingerprint
            || routes.len() > CANDIDATE_COUNT as usize
            || options.local_paths.is_empty()
            || PathSet::from_wire(&self.permit.claims().paths)?
                .intersection(options.local_paths)
                .is_empty()
        {
            return Err(SessionEstablishError::Binding);
        }
        let expected_role = if local.device_id == self.permit.claims().controller_device_id {
            EndpointRole::Controller
        } else if local.device_id == self.permit.claims().host_device_id {
            EndpointRole::Host
        } else {
            return Err(SessionEstablishError::Binding);
        };
        if self.role != expected_role {
            return Err(SessionEstablishError::Binding);
        }
        Ok(())
    }

    async fn ensure_current_permit(
        &self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<(), SessionEstablishError> {
        self.check()?;
        let request = async {
            match self.role {
                EndpointRole::Controller if self.permit.claims().lease_sequence == 1 => {
                    sdk.permit(&self.permit.claims().session_id).await
                }
                EndpointRole::Controller => {
                    sdk.current_controller_permit(local, &self.permit.claims().session_id)
                        .await
                }
                EndpointRole::Host => {
                    sdk.host_permit(local, &self.permit.claims().session_id)
                        .await
                }
            }
        };
        let current = tokio::select! {
            biased;
            _ = cancellation(&mut cancel) => return Err(SessionEstablishError::Cancelled),
            result = tokio::time::timeout(CONTROL_REQUEST_BUDGET, request) => {
                result.map_err(|_| SdkError::Timeout)??
            },
        };
        if current.claims() != self.permit.claims() || current.digest() != self.permit.digest() {
            return Err(SessionEstablishError::PermitChanged);
        }
        self.check()?;
        Ok(())
    }

    async fn wait_for_peer_candidates(
        &self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<(u64, Vec<Candidate>), SessionEstablishError> {
        let mut cursor = SignalCursor::new(&self.permit, local)?;
        let deadline = Instant::now() + SIGNAL_WAIT_BUDGET;
        loop {
            self.check()?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SessionEstablishError::SignalTimeout);
            }
            let request_budget = remaining.min(CONTROL_REQUEST_BUDGET);
            let signals = tokio::select! {
                biased;
                _ = cancellation(cancel) => return Err(SessionEstablishError::Cancelled),
                result = tokio::time::timeout(
                    request_budget,
                    sdk.peer_signals(local, &self.permit, &mut cursor),
                ) => result.map_err(|_| SdkError::Timeout)??,
            };
            self.check()?;
            for signal in signals {
                signal.validate(self.permit.claims())?;
                if !signal.candidates.is_empty() {
                    return Ok((signal.network_generation, signal.candidates));
                }
            }
            tokio::select! {
                biased;
                _ = cancellation(cancel) => return Err(SessionEstablishError::Cancelled),
                _ = tokio::time::sleep(SIGNAL_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now()))) => {},
            }
        }
    }

    fn race_candidates(
        &self,
        peer_generation: u64,
        peer_candidates: Vec<Candidate>,
        routes: &[NativeRelayRoute<'_>],
        local_paths: PathSet,
    ) -> Result<Vec<Candidate>, SessionEstablishError> {
        let mut direct: Vec<_> = peer_candidates
            .into_iter()
            .filter(|candidate| {
                candidate.path() == Path::Direct && local_paths.contains(Path::Direct)
            })
            .collect();
        let mut relay = Vec::new();
        if local_paths.contains(Path::Relay)
            && self.permit.claims().paths.contains(&(Path::Relay as i32))
        {
            for route in routes {
                relay.extend(route.candidates(peer_generation)?);
            }
        }
        direct = bounded_unique(direct, CANDIDATE_COUNT as usize);
        relay = bounded_unique(relay, CANDIDATE_COUNT as usize);
        if !direct.is_empty() && !relay.is_empty() {
            direct.truncate((CANDIDATE_COUNT as usize).div_ceil(2));
            relay.truncate(CANDIDATE_COUNT as usize - direct.len());
        }
        direct.extend(relay);
        let candidates = bounded_unique(direct, CANDIDATE_COUNT as usize);
        if candidates.is_empty() {
            return Err(SessionEstablishError::NoCandidates);
        }
        Ok(candidates)
    }

    async fn accept_or_relay(
        &self,
        peer_generation: u64,
        relay_candidates: &[Candidate],
        routes: &[NativeRelayRoute<'_>],
        local: &DeviceIdentity,
        policy: LocalAcceptPolicy,
        cancel: watch::Receiver<bool>,
    ) -> Result<NativeConnection, DialError> {
        if policy.direct_available && !relay_candidates.is_empty() {
            let direct = self.accept_native(peer_generation, cancel.clone());
            let relay = self.dial_native_with_local_paths(
                local,
                routes,
                peer_generation,
                relay_candidates.to_vec(),
                policy.paths.intersection(PathSet::RELAY),
                cancel,
            );
            tokio::pin!(direct);
            tokio::pin!(relay);
            tokio::select! {
                biased;
                result = &mut direct => match result {
                    Ok(connection) => Ok(connection),
                    Err(error @ (DialError::Cancelled | DialError::NetworkChanged | DialError::Expired)) => Err(error),
                    Err(_) => relay.await,
                },
                result = &mut relay => match result {
                    Ok(connection) => Ok(connection),
                    Err(error @ (DialError::Cancelled | DialError::NetworkChanged | DialError::Expired)) => Err(error),
                    Err(_) => direct.await,
                },
            }
        } else if policy.direct_available {
            self.accept_native(peer_generation, cancel).await
        } else if !relay_candidates.is_empty() {
            self.dial_native_with_local_paths(
                local,
                routes,
                peer_generation,
                relay_candidates.to_vec(),
                policy.paths.intersection(PathSet::RELAY),
                cancel,
            )
            .await
        } else {
            Err(DialError::Binding)
        }
    }

    async fn accept_native(
        &self,
        peer_generation: u64,
        cancel: watch::Receiver<bool>,
    ) -> Result<NativeConnection, DialError> {
        let connection = self.accept(cancel).await?;
        self.check()?;
        Ok(NativeConnection {
            transport: NativeTransport::Quic {
                connection: connection.clone(),
                endpoint: self
                    .endpoint_for(connection.remote_address())
                    .ok_or(DialError::Binding)?
                    .clone(),
                carrier: None,
            },
            candidate: inbound_candidate(connection.remote_address(), peer_generation),
            failures: Vec::new(),
            network: self.network_binding()?,
            authorization_deadline: self.authorization_deadline,
        })
    }

    fn next_signal_sequence(&self) -> Result<u64, SessionEstablishError> {
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SessionEstablishError::Binding)?
            .as_millis()
            .try_into()
            .map_err(|_| SessionEstablishError::Binding)?;
        loop {
            let previous = self.signal_sequence.load(Ordering::Acquire);
            let next = now.max(
                previous
                    .checked_add(1)
                    .ok_or(SessionEstablishError::Binding)?,
            );
            if next > i64::MAX as u64 {
                return Err(SessionEstablishError::Binding);
            }
            if self
                .signal_sequence
                .compare_exchange(previous, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(next);
            }
        }
    }
    /// Relay-only creates no UDP endpoint and sends no discovery traffic.
    pub fn discovery_socket(&self) -> Option<Arc<DiscoverySocket>> {
        self.socket.clone()
    }
    /// Carry this original network baseline through proof into SessionLifecycle.
    /// Keep the endpoint alive for its session; dropping it closes the observer.
    pub fn network_binding(&self) -> Result<NetworkBinding, DialError> {
        self.check()?;
        NetworkBinding::new(self.lifecycle.subscribe(), self.local_generation)
            .map_err(|_| DialError::NetworkChanged)
    }
    pub fn local_addr(&self) -> Result<SocketAddr, DialError> {
        self.socket
            .as_ref()
            .ok_or(DialError::Binding)?
            .local_addr()
            .map_err(|_| DialError::Setup)
    }
    /// Platform adapters invalidate the entire race, including TCP and WSS.
    /// A changed endpoint must be rebuilt with fresh candidates/authorization.
    pub fn invalidate_network(&self, generation: u64) -> Result<(), DialError> {
        if generation <= self.network_generation.load(Ordering::Acquire) {
            return Err(DialError::Binding);
        }
        self.network_generation
            .fetch_max(generation, Ordering::AcqRel);
        self.lifecycle.send_modify(|state| {
            state.generation = state.generation.max(generation);
            state.reason = Reason::Interface;
        });
        for socket in self.discovery_sockets() {
            socket
                .invalidate_network(generation)
                .map_err(|_| DialError::Setup)?;
        }
        Ok(())
    }
    pub async fn accept(
        &self,
        cancel: watch::Receiver<bool>,
    ) -> Result<quinn::Connection, DialError> {
        self.check()?;
        self.guarded(self.accept_direct(), cancel).await
    }
    async fn guarded<F: Future<Output = Result<quinn::Connection, DialError>>>(
        &self,
        future: F,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<quinn::Connection, DialError> {
        if *cancel.borrow() {
            return Err(DialError::Cancelled);
        }
        tokio::pin!(future);
        let end = tokio::time::sleep(Duration::from_millis(CONNECTION_BUDGET_MS));
        tokio::pin!(end);
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {biased;
                _=&mut end=>return Err(DialError::Failed {code:ErrorCode::DirectUnavailable,failures:vec![]}),
                result=cancel.changed()=>{if result.is_err() || *cancel.borrow(){return Err(DialError::Cancelled);}},
                _=tick.tick()=>self.check()?,
                result=&mut future=>{let connection=result?;if let Err(error)=self.check(){connection.close(0u32.into(),b"stale authorization");return Err(error);}return Ok(connection);}
            }
        }
    }
    /// Supply peer candidates only after SDK signature/cursor validation. Local
    /// generation and the peer's signed generation are separate network facts.
    pub async fn dial(
        &self,
        peer_generation: u64,
        candidates: Vec<Candidate>,
        cancel: watch::Receiver<bool>,
    ) -> Result<ConnectedQuic, DialError> {
        if !self.permit.claims().paths.contains(&(Path::Direct as i32)) {
            return Err(DialError::Binding);
        }
        let connected = self
            .race(
                peer_generation,
                candidates,
                PathSet::DIRECT,
                None,
                true,
                cancel,
            )
            .await?;
        let NativeTransport::Quic {
            connection,
            endpoint,
            ..
        } = connected.transport
        else {
            return Err(DialError::Setup);
        };
        Ok(ConnectedQuic {
            connection,
            candidate: connected.candidate,
            failures: connected.failures,
            network: connected.network,
            _endpoint: endpoint,
        })
    }
    /// Relay addresses must belong to a RelayRoute resolved from this SDK's
    /// approved management origin. Peer declarations never choose its URL.
    pub async fn dial_native(
        &self,
        local: &DeviceIdentity,
        relay: Option<&RelayRoute<'_>>,
        peer_generation: u64,
        candidates: Vec<Candidate>,
        cancel: watch::Receiver<bool>,
    ) -> Result<NativeConnection, DialError> {
        if local.device_id != self.local_device
            || local.identity.fingerprint() != self.local_fingerprint
        {
            return Err(DialError::Binding);
        }
        let routes: Vec<_> = relay.into_iter().map(NativeRelayRoute::Combined).collect();
        self.dial_native_with_relays(local, &routes, peer_generation, candidates, cancel)
            .await
    }
    /// Direct and explicitly approved node routes share the same bounded race,
    /// permit, policy and network lifecycle. Peer candidates cannot add routes.
    pub async fn dial_native_with_relays(
        &self,
        local: &DeviceIdentity,
        routes: &[NativeRelayRoute<'_>],
        peer_generation: u64,
        candidates: Vec<Candidate>,
        cancel: watch::Receiver<bool>,
    ) -> Result<NativeConnection, DialError> {
        let permitted = PathSet::from_wire(&self.permit.claims().paths)?;
        self.dial_native_with_local_paths(
            local,
            routes,
            peer_generation,
            candidates,
            permitted,
            cancel,
        )
        .await
    }
    async fn dial_native_with_local_paths(
        &self,
        local: &DeviceIdentity,
        routes: &[NativeRelayRoute<'_>],
        peer_generation: u64,
        candidates: Vec<Candidate>,
        local_paths: PathSet,
        cancel: watch::Receiver<bool>,
    ) -> Result<NativeConnection, DialError> {
        if local.device_id != self.local_device
            || local.identity.fingerprint() != self.local_fingerprint
            || routes.len() > CANDIDATE_COUNT as usize
        {
            return Err(DialError::Binding);
        }
        let paths = PathSet::from_wire(&self.permit.claims().paths)?.intersection(local_paths);
        if paths.is_empty() {
            return Err(DialError::Binding);
        }
        self.race(
            peer_generation,
            candidates,
            paths,
            Some((routes, local)),
            false,
            cancel,
        )
        .await
    }
    async fn race(
        &self,
        peer_generation: u64,
        candidates: Vec<Candidate>,
        paths: PathSet,
        relay: Option<(&[NativeRelayRoute<'_>], &DeviceIdentity)>,
        quic_only: bool,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<NativeConnection, DialError> {
        let (routes, local) = match relay {
            Some((routes, local)) => (routes, Some(local)),
            None => (&[][..], None),
        };
        self.check()?;
        if *cancel.borrow() {
            return Err(DialError::Cancelled);
        }
        if candidates.len() > CANDIDATE_COUNT as usize {
            return Err(DialError::Binding);
        }
        let mut rejected = Vec::new();
        let mut allowed = Vec::new();
        for candidate in candidates {
            candidate.validate()?;
            if candidate.generation != peer_generation {
                return Err(DialError::Binding);
            }
            let supported = match (candidate.path(), candidate.transport) {
                (Path::Direct, Transport::Quic) => self.endpoint_for(candidate.address).is_some(),
                (Path::Direct, Transport::Tls) => !quic_only,
                (Path::Relay, Transport::Wss) => !quic_only,
                (Path::Relay, Transport::Quic) => !quic_only,
                _ => false,
            };
            let code = if !paths.contains(candidate.path()) {
                Some(("path-policy", ErrorCode::PermissionRequired))
            } else if !supported {
                Some(("transport-policy", ErrorCode::ProtocolMismatch))
            } else if candidate.path() == Path::Direct
                && !self.address_policy.allows(candidate.address.ip())
            {
                Some(("address-policy", ErrorCode::PermissionRequired))
            } else if candidate.path() == Path::Relay
                && !routes.iter().any(|r| r.allows(&self.permit, &candidate))
            {
                Some(("relay-authority", ErrorCode::PermissionRequired))
            } else {
                None
            };
            if let Some((stage, code)) = code {
                rejected.push(Failure {
                    candidate,
                    stage: stage.into(),
                    code,
                });
            } else {
                allowed.push(candidate);
            }
        }
        let mut scheduler = Scheduler::new(peer_generation, 0, paths, allowed)?;
        type Pending<'a> = Pin<
            Box<
                dyn Future<Output = (usize, &'static str, Result<NativeTransport, ()>)> + Send + 'a,
            >,
        >;
        let mut pending = FuturesUnordered::<Pending<'_>>::new();
        let started = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            self.check()?;
            let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            for attempt in scheduler.poll(elapsed) {
                let endpoint = self.endpoint_for(attempt.candidate.address);
                let config = self.tls_config.clone();
                let permit = &self.permit;
                pending.push(Box::pin(async move {
                    let budget = Duration::from_millis(attempt.deadline_ms.saturating_sub(elapsed));
                    let address = attempt.candidate.address;
                    let stage = match attempt.candidate.transport {
                        Transport::Quic if attempt.candidate.path() == Path::Relay => {
                            "node-quic-inner-tls"
                        }
                        Transport::Quic => "quic-tls",
                        Transport::Tls => "direct-tcp-tls",
                        Transport::Wss => "wss-inner-tls",
                        Transport::WebRtc => "unsupported-webrtc",
                    };
                    let attempt_io = async {
                        if attempt.candidate.path() == Path::Relay {
                            let local = local.ok_or(())?;
                            let route = routes
                                .iter()
                                .find(|r| r.allows(permit, &attempt.candidate))
                                .ok_or(())?;
                            return route.connect(local, permit, &attempt.candidate).await;
                        }
                        match attempt.candidate.transport {
                            Transport::Quic => {
                                let endpoint = endpoint.ok_or(())?;
                                let connection =
                                    nestlink_transport_quic::connect(endpoint, address, budget)
                                        .await
                                        .map_err(|_| ())?;
                                Ok(NativeTransport::Quic {
                                    connection,
                                    endpoint: endpoint.clone(),
                                    carrier: None,
                                })
                            }
                            Transport::Tls => {
                                nestlink_transport_stream::connect(address, config, budget)
                                    .await
                                    .map(|stream| NativeTransport::DirectTls(Box::new(stream)))
                                    .map_err(|_| ())
                            }
                            Transport::Wss => Err(()),
                            Transport::WebRtc => Err(()),
                        }
                    };
                    let result = tokio::time::timeout(budget, attempt_io)
                        .await
                        .unwrap_or(Err(()));
                    (attempt.id, stage, result)
                }));
            }
            if let Outcome::Failed(code) = scheduler.outcome() {
                rejected.extend_from_slice(scheduler.failures());
                return Err(DialError::Failed {
                    code: *code,
                    failures: rejected,
                });
            }
            tokio::select! {biased;
                result=cancel.changed()=>{if result.is_err() || *cancel.borrow(){return Err(DialError::Cancelled);}},
                _=tick.tick()=>{},
                Some((id,stage,result))=pending.next(),if !pending.is_empty()=>{
                    self.check()?;
                    let elapsed=u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let code=if matches!(stage,"wss-inner-tls"|"node-quic-inner-tls") {ErrorCode::RelayUnavailable} else {ErrorCode::DirectUnavailable};
                    let success=result.is_ok();scheduler.finish(id,success,stage,code,elapsed);
                    if let Ok(transport)=result {
                        if let Outcome::Connected(candidate)=scheduler.outcome() {
                            rejected.extend_from_slice(scheduler.failures());
                            return Ok(NativeConnection {transport,candidate:candidate.clone(),failures:rejected,network:self.network_binding()?,authorization_deadline:self.authorization_deadline});
                        }
                        transport.close();
                    }
                }
            }
        }
    }
    fn check(&self) -> Result<(), DialError> {
        if self.monitor.as_ref().is_some_and(|(receiver, baseline)| {
            let state = receiver.borrow();
            !state.available || state.generation != *baseline
        }) || self.network_generation.load(Ordering::Acquire) != self.local_generation
            || self
                .discovery_sockets()
                .iter()
                .any(|s| s.generation() != self.local_generation)
        {
            return Err(DialError::NetworkChanged);
        }
        let mut clock = self
            .authorization_clock
            .lock()
            .map_err(|_| DialError::Setup)?;
        let previous = clock.ok_or(DialError::Expired)?;
        let now = match live(&self.permit) {
            Ok(now) => now,
            Err(error) => {
                *clock = None;
                return Err(error);
            }
        };
        if Instant::now() >= self.authorization_deadline || now < previous {
            *clock = None;
            return Err(DialError::Expired);
        }
        *clock = Some(now);
        Ok(())
    }
}
fn live(permit: &VerifiedPermit) -> Result<u64, DialError> {
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DialError::Expired)?
        .as_millis()
        .try_into()
        .map_err(|_| DialError::Expired)?;
    if now < permit.claims().issued_at_unix_ms || now >= permit.claims().expires_at_unix_ms {
        return Err(DialError::Expired);
    }
    Ok(now)
}

async fn cancellation(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() || cancel.changed().await.is_err() {
            return;
        }
    }
}

fn bounded_unique(candidates: Vec<Candidate>, limit: usize) -> Vec<Candidate> {
    let mut unique = Vec::with_capacity(candidates.len().min(limit));
    for candidate in candidates {
        if !unique.contains(&candidate) {
            unique.push(candidate);
            if unique.len() == limit {
                break;
            }
        }
    }
    unique
}

fn fixed_digest(value: &[u8]) -> Result<[u8; 32], SessionEstablishError> {
    value.try_into().map_err(|_| SessionEstablishError::Binding)
}

fn session_binding(
    permit: &VerifiedPermit,
    options: NativeSessionOptions,
    evidence: Option<&NativeMediaEvidence>,
    role: EndpointRole,
    now_unix_ms: u64,
) -> Result<SessionBinding, SessionEstablishError> {
    let claims = permit.claims();
    let media = match (
        nestlink_protocol::media_authority::permit_formats(claims)?,
        evidence,
    ) {
        (None, None) => None,
        (Some(_), Some(evidence)) => Some(evidence.bind(permit, role, now_unix_ms)?),
        _ => return Err(SessionEstablishError::Binding),
    };
    Ok(SessionBinding {
        media,
        deployment_id: claims.deployment_id.clone(),
        security_epoch: claims.security_epoch,
        session_id: claims.session_id.clone(),
        account_id: claims.account_id.clone(),
        controller_device_id: claims.controller_device_id.clone(),
        host_device_id: claims.host_device_id.clone(),
        controller_key_sha256: fixed_digest(&claims.controller_key_sha256)?,
        host_key_sha256: fixed_digest(&claims.host_key_sha256)?,
        resource_id: claims.resource_id.clone(),
        policy_revision: claims.policy_revision,
        connection_generation: claims.connection_generation,
        capability_sha256: fixed_digest(&claims.capability_sha256)?,
        granted_permissions: options.granted_permissions,
        supported_capabilities: options.supported_capabilities,
        local_paths: options.local_paths,
    })
}

fn inbound_candidate(address: SocketAddr, generation: u64) -> Candidate {
    let kind = match address.ip() {
        IpAddr::V4(ip) if ip.is_private() => CandidateKind::Lan,
        IpAddr::V6(_) => CandidateKind::Ipv6,
        _ => CandidateKind::Reflexive,
    };
    Candidate {
        address,
        kind,
        transport: Transport::Quic,
        generation,
    }
}

// Test-only bridge lets the real two-endpoint fixture exercise this public
// entry point while keeping NativeSessionControl's fields private.
#[cfg(all(test, feature = "media-runtime-test-support"))]
#[allow(clippy::expect_used)]
pub(crate) fn assert_coordinated_manual_renewal_rejected(
    coordinator: crate::native_renewal::Coordinator,
    lease: nestlink_remote::LeaseControl,
    sequence: Arc<AtomicU64>,
    evidence: &NativeMediaEvidence,
) -> Result<crate::native_renewal::Coordinator, Box<dyn std::error::Error + Send + Sync>> {
    struct NeverFence;
    impl nestlink_remote::native_renewal::NativeExecutionFence for NeverFence {
        fn with_current(&self, _: &mut dyn FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
            panic!("manual renewal entered execution fence despite coordinator");
        }
    }
    let before = lease.current_native_permit()?;
    let before_sequence = sequence.load(Ordering::Acquire);
    let shared = Arc::new(tokio::sync::Mutex::new(coordinator));
    let control = NativeSessionControl {
        sequence: sequence.clone(),
        renewal: Some(shared.clone()),
        lease: lease.clone(),
    };
    let error = control
        .renew_with_media(
            before.clone(),
            lease.renewal_clock()?.monotonic_ms,
            evidence,
            EndpointRole::Controller,
            &NeverFence,
        )
        .expect_err("coordinated session must reject manual renewal");
    assert!(
        error
            .to_string()
            .contains("coordinated native renewal requires both endpoint drivers")
    );
    assert_eq!(lease.current_native_permit()?.claims(), before.claims());
    assert_eq!(sequence.load(Ordering::Acquire), before_sequence);
    assert!(lease.remaining()?.as_millis() > 0);
    assert_eq!(
        shared
            .try_lock()
            .expect("coordinator unlocked")
            .current()
            .claims(),
        before.claims()
    );
    drop(control);
    let coordinator = Arc::try_unwrap(shared)
        .map_err(|_| std::io::Error::other("unexpected coordinator alias"))?
        .into_inner();
    Ok(coordinator)
}
