//! Independent HTTP node, two inner TLS endpoints and real authorized business frames.
#[path = "../../node/tests/support/service_usage_directory.rs"]
mod service_usage_directory;
use service_usage_directory::ServiceUsageDirectory;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::{
    PermitSigner, VerifiedPermit, nodes::NodeIdentity, relay::VerifiedRelayAllocation,
};
use nestlink_node::control::{NodeConfig, NodeControl};
use nestlink_policy::PathSet;
use nestlink_protocol::{
    NodeRole, Path, Permission,
    api::{ApprovalChoice, NetworkPolicy, NodeRegistration, PolicyUpdate, RemoteRequest},
};
use nestlink_remote::{ChannelRuntime, RuntimeClock, SessionLifecycle, SessionSetup};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, NativeRelayRoute, Sdk,
    native::{AddressPolicy, NativeConnection, NativeEndpoint},
};
use nestlink_server::{AppState, node_quic, node_relay, relay_selector::RelaySelector, router};
use nestlink_session::{EndpointRole, Session, SessionBinding};
use nestlink_storage::Store;
use nestlink_transport_stream::Channel;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[path = "node_relay/closes.rs"]
mod closes;
#[path = "node_relay/reconnection.rs"]
mod reconnection;
#[path = "node_relay/recovery.rs"]
mod recovery;
#[path = "node_relay/signed_discovery.rs"]
mod signed_discovery;
#[derive(Default)]
struct CloseFaults {
    lose_next: std::sync::atomic::AtomicBool,
    corrupt_ack: std::sync::atomic::AtomicBool,
    lost_responses: std::sync::atomic::AtomicUsize,
    corrupt_responses: std::sync::atomic::AtomicUsize,
}
struct Abort(tokio::task::JoinHandle<()>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Fixture {
    sdk: Sdk,
    controller: DeviceIdentity,
    host: DeviceIdentity,
    permit: VerifiedPermit,
    allocation: VerifiedRelayAllocation,
    control: Arc<NodeControl>,
    selector: Arc<RelaySelector>,
    node_id: String,
    origin: String,
    quic_uri: String,
    control_origin: String,
    reconnected_clocks: Option<[RuntimeClock; 2]>,
    lost_commit_responses: Arc<std::sync::atomic::AtomicUsize>,
    close_faults: Arc<CloseFaults>,
    endpoints: [NativeEndpoint; 2],
    control_server: Abort,
    relay: Abort,
    quic: Abort,
    _service_usage_directory: ServiceUsageDirectory,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.control.stop();
    }
}
impl Fixture {
    async fn new() -> Result<Self> {
        Self::with_byte_limit(None).await
    }
    async fn with_byte_limit(byte_limit: Option<u64>) -> Result<Self> {
        Self::with_quic_bound(byte_limit, "127.0.0.1:0").await
    }
    async fn with_quic_bound(byte_limit: Option<u64>, quic_bound: &str) -> Result<Self> {
        Self::with_bounds(byte_limit, quic_bound, "127.0.0.1:0").await
    }
    async fn with_bounds(
        byte_limit: Option<u64>,
        quic_bound: &str,
        wss_bound: &str,
    ) -> Result<Self> {
        Self::with_response_fault(byte_limit, quic_bound, wss_bound, false).await
    }
    async fn with_response_fault(
        byte_limit: Option<u64>,
        quic_bound: &str,
        wss_bound: &str,
        drop_commit: bool,
    ) -> Result<Self> {
        let deployment = random_id();
        let signer = PermitSigner::generate();
        let issuer = signer.public_key();
        let policy = signer.node_policy_signer()?.public_key();
        let mut store = Store::in_memory(&deployment)?;
        let password = || Secret::from_text("independent-relay-fixture-password".into());
        store.bootstrap_admin("admin", password().expose())?;
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", http.local_addr()?);
        let control_origin = origin.clone();
        let app = router(AppState::new(
            store,
            VaultKey::from_bytes([6; 32]),
            signer,
            origin.clone(),
            false,
        )?);
        let lost_commit_responses = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let injected = lost_commit_responses.clone();
        let once = Arc::new(std::sync::atomic::AtomicBool::new(drop_commit));
        let close_faults = Arc::new(CloseFaults::default());
        let fault = close_faults.clone();
        let app = app.layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let injected = injected.clone();
                let once = once.clone();
                let fault = fault.clone();
                async move {
                    let commit = request.method() == axum::http::Method::POST
                        && request.uri().path().ends_with("/reconnect");
                    let close = request.method() == axum::http::Method::POST
                        && request.uri().path().ends_with("/close");
                    let response = next.run(request).await;
                    if close && response.status() == axum::http::StatusCode::OK {
                        if fault
                            .lose_next
                            .swap(false, std::sync::atomic::Ordering::SeqCst)
                        {
                            fault
                                .lost_responses
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let (mut parts, _) = response.into_parts();
                            parts.headers.remove(axum::http::header::CONTENT_LENGTH);
                            return axum::response::Response::from_parts(
                                parts,
                                axum::body::Body::from_stream(futures_util::stream::once(async {
                                    Err::<Vec<u8>, std::io::Error>(std::io::Error::other(
                                        "fixture close response lost after database commit",
                                    ))
                                })),
                            );
                        }
                        if fault.corrupt_ack.load(std::sync::atomic::Ordering::SeqCst) {
                            let (mut parts, body) = response.into_parts();
                            parts.headers.remove(axum::http::header::CONTENT_LENGTH);
                            let mutated = async {
                                let bytes = axum::body::to_bytes(body, 32768).await?;
                                let mut ack: nestlink_protocol::SignedRelayCloseAck =
                                    serde_json::from_slice(&bytes)?;
                                *ack.signature
                                    .first_mut()
                                    .ok_or("fixture signature missing")? ^= 1;
                                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                                    serde_json::to_vec(&ack)?,
                                )
                            }
                            .await;
                            return match mutated {
                                Ok(bytes) => {
                                    fault
                                        .corrupt_responses
                                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    axum::response::Response::from_parts(
                                        parts,
                                        axum::body::Body::from(bytes),
                                    )
                                }
                                Err(error) => {
                                    let mut response = axum::response::Response::new(
                                        axum::body::Body::from(error.to_string()),
                                    );
                                    *response.status_mut() =
                                        axum::http::StatusCode::INTERNAL_SERVER_ERROR;
                                    response
                                }
                            };
                        }
                    }
                    if commit
                        && response.status() == axum::http::StatusCode::OK
                        && once.swap(false, std::sync::atomic::Ordering::SeqCst)
                    {
                        injected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let (mut parts, _) = response.into_parts();
                        parts.headers.remove(axum::http::header::CONTENT_LENGTH);
                        axum::response::Response::from_parts(
                            parts,
                            axum::body::Body::from_stream(futures_util::stream::once(async {
                                Err::<Vec<u8>, std::io::Error>(std::io::Error::other(
                                    "fixture response lost after database commit",
                                ))
                            })),
                        )
                    } else {
                        response
                    }
                }
            },
        ));
        let control_server = Abort(tokio::spawn(async move {
            let _ = axum::serve(
                http,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
        }));
        let mut sdk = Sdk::connect(
            &origin,
            DeploymentTrust {
                deployment_id: deployment.clone(),
                permit_issuer: issuer,
            },
            true,
        )
        .await?;
        sdk.login("admin".into(), password(), None).await?;
        sdk.set_policy(PolicyUpdate {
            expected_revision: 1,
            policy: NetworkPolicy {
                server_forwarding: "allow".into(),
                peer_path_mode: "direct_preferred".into(),
                public_ingress: "disabled".into(),
            },
        })
        .await?;
        if let Some(bytes) = byte_limit {
            let quota = sdk.relay_quota().await?;
            sdk.set_relay_quota(nestlink_protocol::api::RelayQuotaUpdate {
                expected_revision: quota.revision,
                limits: nestlink_protocol::api::RelayQuotaLimits {
                    bytes_per_allocation: bytes,
                    ..quota.limits
                },
            })
            .await?;
        }
        let controller = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        for (key, name) in [(&controller, "controller"), (&host, "host")] {
            sdk.enroll(
                key,
                name.into(),
                "windows".into(),
                vec!["vp8".into(), "controller".into(), "host".into()],
                "direct_preferred".into(),
            )
            .await?;
        }
        let remote = sdk
            .create_remote(RemoteRequest {
                id: random_id(),
                controller_device_id: controller.device_id.clone(),
                host_device_id: host.device_id.clone(),
                permissions: vec![Permission::View as i32],
                path_mode: "relay_only".into(),
            })
            .await?;
        sdk.approve(
            &host,
            &remote,
            ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32],
                paths: vec![Path::Relay as i32],
            },
        )
        .await?;
        let permit = sdk.permit(&remote.id).await?;
        let node = NodeIdentity::generate();
        let quic_listener = nestlink_transport_quic::node::listener(quic_bound.parse()?, &node)?;
        let quic_uri = format!("quic://{}", quic_listener.local_addr()?);
        let node_id = random_id();
        sdk.register_node(NodeRegistration {
            id: node_id.clone(),
            name: "independent-fixture".into(),
            public_key: URL_SAFE_NO_PAD.encode(node.public_key()),
            roles: vec![NodeRole::NodeRelay as i32],
            max_connections: 8,
            bytes_per_second: 16 * 1024 * 1024,
        })
        .await?;
        let mut service_usage_directory = ServiceUsageDirectory::new()?;
        let control = Arc::new(NodeControl::start(
            NodeConfig {
                deployment_id: deployment,
                node_id: node_id.clone(),
                control_origin: origin,
                trusted_policy_issuer: URL_SAFE_NO_PAD.encode(policy),
                identity_key_file: "unused-fixture".into(),
                service_usage_directory: Some(service_usage_directory.path().to_path_buf()),
                roles: vec![NodeRole::NodeRelay as i32],
                allow_loopback_http: true,
            },
            node,
        )?);
        service_usage_directory.track(&control)?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while control.authorize(NodeRole::NodeRelay, false).is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|error| format!("fixture node authorization timed out: {error}"))?;
        let allocation = sdk
            .reserve_relay_allocation(&controller, &permit, &random_id(), &node_id)
            .await?;
        let http = tokio::net::TcpListener::bind(wss_bound).await?;
        let origin = format!("http://127.0.0.1:{}", http.local_addr()?.port());
        let selector = RelaySelector::new(control.clone());
        let shared = selector.clone();
        let relay = Abort(tokio::spawn(async move {
            let _ = node_relay::serve_with_selector(http, shared, std::future::pending()).await;
        }));
        let shared = selector.clone();
        let quic = Abort(tokio::spawn(async move {
            let _ =
                node_quic::serve_with_selector(quic_listener, shared, std::future::pending()).await;
        }));
        let endpoints = [
            NativeEndpoint::new(
                "0.0.0.0:0".parse()?,
                &controller,
                &host.identity.public_key(),
                permit.clone(),
                vec![],
                AddressPolicy::new(&[])?,
            )?,
            NativeEndpoint::new(
                "0.0.0.0:0".parse()?,
                &host,
                &controller.identity.public_key(),
                permit.clone(),
                vec![],
                AddressPolicy::new(&[])?,
            )?,
        ];
        Ok(Self {
            sdk,
            controller,
            host,
            permit,
            allocation,
            control,
            selector,
            node_id,
            origin,
            quic_uri,
            control_origin,
            reconnected_clocks: None,
            lost_commit_responses,
            close_faults,
            endpoints,
            control_server,
            relay,
            quic,
            _service_usage_directory: service_usage_directory,
        })
    }
    async fn channels(
        &self,
    ) -> Result<(
        ChannelRuntime,
        ChannelRuntime,
        watch::Sender<Option<nestlink_session::StopReason>>,
    )> {
        let (c, h, keep, _clocks) = self.channels_with_clocks().await?;
        Ok((c, h, keep))
    }
    async fn channels_with_clocks(
        &self,
    ) -> Result<(
        ChannelRuntime,
        ChannelRuntime,
        watch::Sender<Option<nestlink_session::StopReason>>,
        [RuntimeClock; 2],
    )> {
        let route = self
            .sdk
            .node_relay_route(&self.origin, true, &self.permit, &self.allocation)
            .await?;
        self.channels_on_route(NativeRelayRoute::Wss(&route)).await
    }
    async fn quic_channels(
        &self,
    ) -> Result<(
        ChannelRuntime,
        ChannelRuntime,
        watch::Sender<Option<nestlink_session::StopReason>>,
    )> {
        let route = self
            .sdk
            .node_quic_route(&self.quic_uri, true, &self.permit, &self.allocation)
            .await?;
        let (c, h, keep, _clocks) = self
            .channels_on_route(NativeRelayRoute::Quic(&route))
            .await?;
        Ok((c, h, keep))
    }
    async fn channels_on_route(
        &self,
        route: NativeRelayRoute<'_>,
    ) -> Result<(
        ChannelRuntime,
        ChannelRuntime,
        watch::Sender<Option<nestlink_session::StopReason>>,
        [RuntimeClock; 2],
    )> {
        let (c, h, keep, clocks) = self.native_sessions_on_route(route).await?;
        Ok((c.channels, h.channels, keep, clocks))
    }
    async fn native_sessions_on_route(
        &self,
        route: NativeRelayRoute<'_>,
    ) -> Result<(
        nestlink_sdk::native::NativeSession,
        nestlink_sdk::native::NativeSession,
        watch::Sender<Option<nestlink_session::StopReason>>,
        [RuntimeClock; 2],
    )> {
        let candidates = route.candidates(1)?;
        let routes = [route];
        let (_cancel, cancel) = watch::channel(false);
        let (c, h) = tokio::try_join!(
            self.endpoints[0].dial_native_with_relays(
                &self.controller,
                &routes,
                1,
                candidates.clone(),
                cancel.clone()
            ),
            self.endpoints[1].dial_native_with_relays(&self.host, &routes, 1, candidates, cancel)
        )?;
        let (keep, stop) = watch::channel(None);
        let (c, h) = tokio::try_join!(
            authorize_native(c, self, true, stop.clone()),
            authorize_native(h, self, false, stop)
        )?;
        Ok((c.0, h.0, keep, [c.1, h.1]))
    }
    async fn closed(&self) -> Result {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.control.counters()?.closed_connections
                != self.control.counters()?.opened_connections
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(), nestlink_node::control::Error>(())
        })
        .await
        .map_err(|error| {
            format!(
                "fixture sockets did not close: {error}; counters={:?}",
                self.control.counters()
            )
        })??;
        Ok(())
    }
    async fn pending(&self, expected: usize) -> Result {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.selector.pending_candidates()? != expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(), std::io::Error>(())
        })
        .await??;
        Ok(())
    }
}
async fn authorize(
    io: NativeConnection,
    f: &Fixture,
    controller: bool,
    stop: watch::Receiver<Option<nestlink_session::StopReason>>,
) -> Result<(ChannelRuntime, RuntimeClock)> {
    let (session, clock) = authorize_native(io, f, controller, stop).await?;
    Ok((session.channels, clock))
}
async fn authorize_native(
    io: NativeConnection,
    f: &Fixture,
    controller: bool,
    stop: watch::Receiver<Option<nestlink_session::StopReason>>,
) -> Result<(nestlink_sdk::native::NativeSession, RuntimeClock)> {
    let p = f.permit.claims();
    let clock = f
        .reconnected_clocks
        .as_ref()
        .map(|clocks| clocks[if controller { 0 } else { 1 }].clone())
        .unwrap_or_default();
    let binding = SessionBinding {
        deployment_id: p.deployment_id.clone(),
        security_epoch: p.security_epoch,
        session_id: p.session_id.clone(),
        account_id: p.account_id.clone(),
        controller_device_id: p.controller_device_id.clone(),
        host_device_id: p.host_device_id.clone(),
        controller_key_sha256: f.controller.identity.fingerprint(),
        host_key_sha256: f.host.identity.fingerprint(),
        resource_id: p.resource_id.clone(),
        policy_revision: p.policy_revision,
        connection_generation: p.connection_generation,
        capability_sha256: p.capability_sha256.as_slice().try_into()?,
        granted_permissions: vec![Permission::View],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::RELAY,
    };
    let session = Session::activate(f.permit.clone(), binding, Path::Relay, 0, clock.sample()?)?;
    let (local, peer) = if controller {
        (&f.controller, &f.host)
    } else {
        (&f.host, &f.controller)
    };
    let result = io
        .authorize(
            SessionSetup {
                session,
                path: Path::Relay,
                role: if controller {
                    EndpointRole::Controller
                } else {
                    EndpointRole::Host
                },
                clock: clock.clone(),
                lifecycle: SessionLifecycle::new(stop),
            },
            local,
            &peer.identity.public_key(),
        )
        .await?;
    Ok((result, clock))
}
#[tokio::test]
async fn independent_node_relays_inner_tls_and_business_frames_then_stops_both_idle_peers() -> Result
{
    let f = Fixture::new().await?;
    let (mut c, mut h, _keep) = f.channels().await?;
    let bytes = vec![37; 256 * 1024];
    let (sent, received) = tokio::join!(h.send(Channel::Video, &bytes), c.receive());
    sent?;
    assert_eq!(received?.payload, bytes);
    let (sent, received) = tokio::join!(c.send(Channel::Video, b"opposite direction"), h.receive());
    sent?;
    assert_eq!(received?.payload, b"opposite direction");
    assert_eq!(f.control.counters()?.opened_connections, 2);
    assert!(f.control.counters()?.admitted_bytes > 256 * 1024);
    let started = Instant::now();
    f.sdk.revoke_remote(&f.permit.claims().session_id).await?;
    let (c, h) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(c?.is_err());
    assert!(h?.is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    f.closed().await?;
    f.receipts(1, 0).await?;
    Ok(())
}

#[tokio::test]
async fn quic_virtual_udp_relays_native_channels_then_remote_revocation_stops_idle_peers() -> Result
{
    let f = Fixture::new().await?;
    let (mut c, mut h, _keep) = f.quic_channels().await?;
    let payload = vec![71; 256 * 1024];
    let (sent, received) = tokio::join!(h.send(Channel::Video, &payload), c.receive());
    sent?;
    assert_eq!(received?.payload, payload);
    let (sent, received) = tokio::join!(c.send(Channel::Video, b"reverse QUIC"), h.receive());
    sent?;
    assert_eq!(received?.payload, b"reverse QUIC");
    assert_eq!(f.control.counters()?.opened_connections, 2);
    assert!(f.control.counters()?.admitted_bytes > payload.len() as u64);
    f.sdk.revoke_remote(&f.permit.claims().session_id).await?;
    let (c, h) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(c?.is_err());
    assert!(h?.is_err());
    f.closed().await?;
    f.receipts(1, 0).await?;
    Ok(())
}

#[tokio::test]
async fn an_ipv6_outer_node_carries_the_pinned_inner_quic_session() -> Result {
    let f = Fixture::with_quic_bound(None, "[::1]:0").await?;
    let (mut c, h, _keep) = f.quic_channels().await?;
    let (sent, received) = tokio::join!(h.send(Channel::Video, &[29; 8192]), c.receive());
    sent?;
    assert_eq!(received?.payload, [29; 8192]);
    assert_eq!(f.control.counters()?.opened_connections, 2);
    Ok(())
}
#[tokio::test]
async fn canceling_quic_listener_owner_stops_actual_peers_and_shared_node_control() -> Result {
    let f = Fixture::new().await?;
    let (mut c, mut h, _keep) = f.quic_channels().await?;
    f.quic.0.abort();
    let (c, h) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(c?.is_err());
    assert!(h?.is_err());
    f.closed().await?;
    assert!(f.control.authorize(NodeRole::NodeRelay, false).is_err());
    Ok(())
}

#[tokio::test]
async fn quic_resource_http_loss_closes_idle_actual_peers() -> Result {
    let f = Fixture::new().await?;
    let (mut c, mut h, _keep) = f.quic_channels().await?;
    f.control_server.0.abort();
    let (c, h) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(c?.is_err());
    assert!(h?.is_err());
    f.closed().await?;
    Ok(())
}

#[tokio::test]
async fn quic_lifetime_exhaustion_does_not_admit_bytes_past_the_limit() -> Result {
    let limit = 65536;
    let f = Fixture::with_byte_limit(Some(limit)).await?;
    let (mut c, mut h, _keep) = f.quic_channels().await?;
    let (sent, received) = tokio::join!(h.send(Channel::Video, &[9; 4096]), c.receive());
    sent?;
    assert_eq!(received?.payload, [9; 4096]);
    h.send(Channel::Video, &[8; 65536]).await?;
    let (c, h) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(
        c.map_err(|_| format!("quota controller remained open: {:?}", f.control.counters()))?
            .is_err()
    );
    assert!(
        h.map_err(|_| format!("quota host remained open: {:?}", f.control.counters()))?
            .is_err()
    );
    f.closed().await?;
    assert!(f.control.counters()?.admitted_bytes <= limit);
    assert!(f.control.counters()?.admitted_bytes > 4096);
    Ok(())
}

#[tokio::test]
async fn quic_quota_revision_stops_existing_business_without_revoking_the_node() -> Result {
    let f = Fixture::new().await?;
    let (mut c, mut h, _keep) = f.quic_channels().await?;
    let quota = f.sdk.relay_quota().await?;
    f.sdk
        .set_relay_quota(nestlink_protocol::api::RelayQuotaUpdate {
            expected_revision: quota.revision,
            limits: nestlink_protocol::api::RelayQuotaLimits {
                max_allocations: 0,
                ..quota.limits
            },
        })
        .await?;
    let (c, h) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(c?.is_err());
    assert!(h?.is_err());
    f.closed().await?;
    assert!(f.control.authorize(NodeRole::NodeRelay, false).is_ok());
    Ok(())
}

#[tokio::test]
async fn native_candidate_race_uses_approved_wss_when_the_quic_carrier_is_unreachable() -> Result {
    let f = Fixture::new().await?;
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let quic = f
        .sdk
        .node_quic_route(
            &format!("quic://{}", blackhole.local_addr()?),
            true,
            &f.permit,
            &f.allocation,
        )
        .await?;
    let wss = f
        .sdk
        .node_relay_route(&f.origin, true, &f.permit, &f.allocation)
        .await?;
    let routes = [NativeRelayRoute::Quic(&quic), NativeRelayRoute::Wss(&wss)];
    let mut candidates = routes[0].candidates(1)?;
    candidates.extend(routes[1].candidates(1)?);
    let (_cancel, cancel) = watch::channel(false);
    let (c, h) = tokio::try_join!(
        f.endpoints[0].dial_native_with_relays(
            &f.controller,
            &routes,
            1,
            candidates.clone(),
            cancel.clone()
        ),
        f.endpoints[1].dial_native_with_relays(&f.host, &routes, 1, candidates, cancel)
    )?;
    assert_eq!(
        c.candidate.transport,
        nestlink_protocol::api::Transport::Wss
    );
    assert_eq!(
        h.candidate.transport,
        nestlink_protocol::api::Transport::Wss
    );
    let (_keep, stop) = watch::channel(None);
    let (mut c, h) = tokio::try_join!(
        authorize(c, &f, true, stop.clone()),
        authorize(h, &f, false, stop)
    )?;
    let (sent, received) = tokio::join!(
        h.0.send(Channel::Video, b"UDP unavailable; WSS won"),
        c.0.receive()
    );
    sent?;
    assert_eq!(received?.payload, b"UDP unavailable; WSS won");
    Ok(())
}

#[tokio::test]
async fn one_endpoint_udp_blackhole_still_selects_wss_for_both_without_a_split_pair() -> Result {
    use nestlink_transport_quic::node::{read_message, write_message};
    for blocked_controller in [false, true] {
        let f = Fixture::new().await?;
        let reachable = if blocked_controller {
            &f.host
        } else {
            &f.controller
        };
        let (outer, connection, mut write, mut read, nonce) = raw_quic_as(&f, reachable).await?;
        write_message(
            &mut write,
            &hello_as(
                &f,
                reachable,
                &nonce,
                nestlink_protocol::RelayTransport::QuicDatagram,
            )?,
        )
        .await?;
        f.pending(1).await?;
        assert_eq!(f.control.counters()?.opened_connections, 0);
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let blocked_uri = format!("quic://{}", blackhole.local_addr()?);
        let q_c = f
            .sdk
            .node_quic_route(
                if blocked_controller {
                    &blocked_uri
                } else {
                    &f.quic_uri
                },
                true,
                &f.permit,
                &f.allocation,
            )
            .await?;
        let q_h = f
            .sdk
            .node_quic_route(
                if blocked_controller {
                    &f.quic_uri
                } else {
                    &blocked_uri
                },
                true,
                &f.permit,
                &f.allocation,
            )
            .await?;
        let wss = f
            .sdk
            .node_relay_route(&f.origin, true, &f.permit, &f.allocation)
            .await?;
        let routes_c = [NativeRelayRoute::Quic(&q_c), NativeRelayRoute::Wss(&wss)];
        let routes_h = [NativeRelayRoute::Quic(&q_h), NativeRelayRoute::Wss(&wss)];
        let candidates =
            |routes: &[NativeRelayRoute<'_>]| -> Result<Vec<nestlink_protocol::api::Candidate>> {
                let mut candidates = routes[0].candidates(1)?;
                candidates.extend(routes[1].candidates(1)?);
                Ok(candidates)
            };
        let (_cancel, cancel) = watch::channel(false);
        let (c, h) = tokio::try_join!(
            f.endpoints[0].dial_native_with_relays(
                &f.controller,
                &routes_c,
                1,
                candidates(&routes_c)?,
                cancel.clone()
            ),
            f.endpoints[1].dial_native_with_relays(
                &f.host,
                &routes_h,
                1,
                candidates(&routes_h)?,
                cancel
            )
        )?;
        assert_eq!(
            c.candidate.transport,
            nestlink_protocol::api::Transport::Wss
        );
        assert_eq!(
            h.candidate.transport,
            nestlink_protocol::api::Transport::Wss
        );
        assert!(
            tokio::time::timeout(
                Duration::from_secs(2),
                read_message::<nestlink_protocol::api::RelayReady>(&mut read)
            )
            .await?
            .is_err()
        );
        // Discarding the authenticated QUIC loser must not stop WSS business.
        connection.close(0u32.into(), b"discarded candidate");
        outer.close(0u32.into(), b"discarded candidate");
        f.pending(0).await?;
        assert_eq!(f.control.counters()?.opened_connections, 2);
        let (_keep, stop) = watch::channel(None);
        let (mut c, mut h) = tokio::try_join!(
            authorize(c, &f, true, stop.clone()),
            authorize(h, &f, false, stop)
        )?;
        let payload = vec![41; 256 * 1024];
        let (sent, received) = tokio::join!(h.0.send(Channel::Video, &payload), c.0.receive());
        sent?;
        assert_eq!(received?.payload, payload);
        let (sent, received) = tokio::join!(
            c.0.send(Channel::Video, b"same WSS pair survived"),
            h.0.receive()
        );
        sent?;
        assert_eq!(received?.payload, b"same WSS pair survived");
        assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
    }
    Ok(())
}

#[tokio::test]
async fn quic_routes_reject_unapproved_literals_permits_loopback_and_invalid_uris() -> Result {
    let f = Fixture::new().await?;
    assert!(
        f.sdk
            .node_quic_route(&f.quic_uri, false, &f.permit, &f.allocation)
            .await
            .is_err()
    );
    for uri in [
        "https://127.0.0.1:28743",
        "quic://user@127.0.0.1:28743",
        "quic://127.0.0.1:0",
        "quic://127.0.0.1:28743/foreign",
        "quic://127.0.0.1:28743?x=1",
    ] {
        assert!(
            f.sdk
                .node_quic_route(uri, true, &f.permit, &f.allocation)
                .await
                .is_err()
        );
    }
    let route = f
        .sdk
        .node_quic_route(&f.quic_uri, true, &f.permit, &f.allocation)
        .await?;
    assert!(
        route
            .connect_at(&f.controller, &f.permit, "127.0.0.1:1".parse()?)
            .await
            .is_err()
    );
    let foreign = DeviceIdentity {
        device_id: f.controller.device_id.clone(),
        identity: nestlink_identity::InstallationIdentity::generate(),
    };
    assert!(
        route
            .connect_at(&foreign, &f.permit, route.addresses()[0])
            .await
            .is_err()
    );
    let view = f
        .sdk
        .create_remote(RemoteRequest {
            id: random_id(),
            controller_device_id: f.controller.device_id.clone(),
            host_device_id: f.host.device_id.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "relay_only".into(),
        })
        .await?;
    f.sdk
        .approve(
            &f.host,
            &view,
            ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32],
                paths: vec![Path::Relay as i32],
            },
        )
        .await?;
    let other = f.sdk.permit(&view.id).await?;
    assert!(
        f.sdk
            .node_quic_route(&f.quic_uri, true, &other, &f.allocation)
            .await
            .is_err()
    );
    assert!(
        route
            .connect_at(&f.controller, &other, route.addresses()[0])
            .await
            .is_err()
    );
    assert_eq!(f.control.counters()?.opened_connections, 0);
    Ok(())
}

#[tokio::test]
async fn allocation_pins_the_actual_outer_quic_node_certificate_key() -> Result {
    let f = Fixture::new().await?;
    let endpoint =
        nestlink_transport_quic::node::listener("127.0.0.1:0".parse()?, &NodeIdentity::generate())?;
    let uri = format!("quic://{}", endpoint.local_addr()?);
    let route = f
        .sdk
        .node_quic_route(&uri, true, &f.permit, &f.allocation)
        .await?;
    let _server = Abort(tokio::spawn(async move {
        if let Some(incoming) = endpoint.accept().await {
            let _ = incoming.await;
        }
        endpoint.close(0u32.into(), b"wrong-key fixture complete");
    }));
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            route.connect_at(&f.controller, &f.permit, route.addresses()[0])
        )
        .await?
        .is_err()
    );
    assert_eq!(f.control.counters()?.opened_connections, 0);
    Ok(())
}

#[tokio::test]
async fn network_generation_change_releases_established_quic_relay_peers() -> Result {
    let f = Fixture::new().await?;
    let (mut c, mut h, _keep) = f.quic_channels().await?;
    f.endpoints[0].invalidate_network(2)?;
    let (c, h) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(c?.is_err());
    assert!(h?.is_err());
    f.closed().await?;
    assert!(f.control.authorize(NodeRole::NodeRelay, false).is_ok());
    Ok(())
}

#[tokio::test]
async fn canceling_a_pending_quic_candidate_removes_it_without_committing_a_role() -> Result {
    let f = Fixture::new().await?;
    let route = f
        .sdk
        .node_quic_route(&f.quic_uri, true, &f.permit, &f.allocation)
        .await?;
    let routes = [NativeRelayRoute::Quic(&route)];
    let (cancel, stop) = watch::channel(false);
    let pending = f.endpoints[0].dial_native_with_relays(
        &f.controller,
        &routes,
        1,
        routes[0].candidates(1)?,
        stop,
    );
    tokio::pin!(pending);
    tokio::select! {
        _ = &mut pending => return Err("candidate finished before a host or cancellation".into()),
        result = f.pending(1) => { result?; },
    }
    assert_eq!(f.control.counters()?.opened_connections, 0);
    cancel.send(true)?;
    assert!(matches!(
        pending.await,
        Err(nestlink_sdk::native::DialError::Cancelled)
    ));
    f.closed().await?;
    f.pending(0).await?;
    assert_eq!(f.control.counters()?.admitted_bytes, 0);
    assert!(f.control.authorize(NodeRole::NodeRelay, false).is_ok());
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
    Ok(())
}

#[tokio::test]
async fn discarding_an_established_inner_quic_candidate_drops_the_carrier_owner() -> Result {
    let f = Fixture::new().await?;
    let route = f
        .sdk
        .node_quic_route(&f.quic_uri, true, &f.permit, &f.allocation)
        .await?;
    let (c, h) = tokio::try_join!(
        route.connect_at(&f.controller, &f.permit, route.addresses()[0]),
        route.connect_at(&f.host, &f.permit, route.addresses()[0])
    )?;
    drop(c);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), h.connection.closed())
            .await
            .is_ok()
    );
    f.closed().await?;
    assert_eq!(f.control.counters()?.opened_connections, 2);
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            route.connect_at(&f.controller, &f.permit, route.addresses()[0])
        )
        .await?
        .is_err()
    );
    assert_eq!(f.control.counters()?.opened_connections, 2);
    Ok(())
}

async fn raw_quic(
    f: &Fixture,
) -> Result<(
    quinn::Endpoint,
    quinn::Connection,
    quinn::SendStream,
    quinn::RecvStream,
    [u8; 32],
)> {
    raw_quic_as(f, &f.controller).await
}
async fn raw_quic_as(
    f: &Fixture,
    device: &DeviceIdentity,
) -> Result<(
    quinn::Endpoint,
    quinn::Connection,
    quinn::SendStream,
    quinn::RecvStream,
    [u8; 32],
)> {
    let address = url::Url::parse(&f.quic_uri)?
        .socket_addrs(|| None)?
        .remove(0);
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    let mut crypto = nestlink_transport_stream::tls::client_config(
        &device.identity,
        f.allocation
            .claims()
            .node_key_sha256
            .as_slice()
            .try_into()?,
    )?;
    crypto.alpn_protocols = vec![nestlink_protocol::relay_datagram::ALPN.to_vec()];
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    )));
    let connection = endpoint.connect(address, "peer.nestlink.invalid")?.await?;
    let (write, mut read) = connection.accept_bi().await?;
    let challenge: nestlink_protocol::api::NodeRelayChallenge =
        nestlink_transport_quic::node::read_message(&mut read).await?;
    let nonce = URL_SAFE_NO_PAD
        .decode(challenge.nonce)?
        .try_into()
        .map_err(|_| "challenge")?;
    Ok((endpoint, connection, write, read, nonce))
}

#[tokio::test]
async fn quic_rejects_wrong_transport_replayed_challenges_and_pre_authentication_datagrams()
-> Result {
    use nestlink_transport_quic::node::{read_message, write_message};
    let f = Fixture::new().await?;
    let (first, first_connection, mut write, mut read, old_nonce) = raw_quic(&f).await?;
    let make_hello =
        |nonce: &[u8; 32], transport| -> Result<nestlink_protocol::api::NodeRelayHello> {
            let proof = nestlink_identity::relay::node_relay_transcript(
                f.allocation.claims(),
                &f.controller.device_id,
                transport,
                nonce,
            )?;
            Ok(nestlink_protocol::api::NodeRelayHello {
                device_id: f.controller.device_id.clone(),
                public_key: URL_SAFE_NO_PAD.encode(f.controller.identity.public_key()),
                allocation: URL_SAFE_NO_PAD.encode(f.allocation.signed_bytes()),
                signature: URL_SAFE_NO_PAD.encode(f.controller.identity.sign_action(&proof)?),
            })
        };
    write_message(
        &mut write,
        &make_hello(&old_nonce, nestlink_protocol::RelayTransport::WssStream)?,
    )
    .await?;
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            read_message::<nestlink_protocol::api::RelayReady>(&mut read)
        )
        .await?
        .is_err()
    );
    first_connection.close(0u32.into(), b"fixture");
    first.close(0u32.into(), b"fixture");
    let (second, connection, mut write, mut read, nonce) = raw_quic(&f).await?;
    assert_ne!(old_nonce, nonce);
    write_message(
        &mut write,
        &make_hello(&old_nonce, nestlink_protocol::RelayTransport::QuicDatagram)?,
    )
    .await?;
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            read_message::<nestlink_protocol::api::RelayReady>(&mut read)
        )
        .await?
        .is_err()
    );
    connection.close(0u32.into(), b"fixture");
    second.close(0u32.into(), b"fixture");
    let (third, connection, _write, mut read, _nonce) = raw_quic(&f).await?;
    connection.send_datagram(
        nestlink_protocol::relay_datagram::encode(1, &[1; 1200])?
            .remove(0)
            .into(),
    )?;
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            read_message::<nestlink_protocol::api::RelayReady>(&mut read)
        )
        .await?
        .is_err()
    );
    third.close(0u32.into(), b"fixture");
    assert_eq!(f.control.counters()?.opened_connections, 0);
    assert_eq!(f.control.counters()?.admitted_bytes, 0);
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
    Ok(())
}
#[tokio::test]
async fn canceling_the_listener_owner_closes_idle_websockets_and_cannot_leave_node_authority()
-> Result {
    let f = Fixture::new().await?;
    let (mut c, mut h, _keep) = f.channels().await?;
    f.relay.0.abort();
    let (c, h) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(c?.is_err());
    assert!(h?.is_err());
    assert!(f.control.authorize(NodeRole::NodeRelay, false).is_err());
    f.closed().await?;
    Ok(())
}
#[tokio::test]
async fn lost_resource_http_authority_stops_data_without_relying_on_new_business_traffic() -> Result
{
    let f = Fixture::new().await?;
    let (mut c, mut h, _keep) = f.channels().await?;
    f.control_server.0.abort();
    let (c, h) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(c?.is_err());
    assert!(h?.is_err());
    f.closed().await?;
    Ok(())
}
#[tokio::test]
async fn a_route_refuses_foreign_literals_permits_and_unapproved_plaintext_origins() -> Result {
    let f = Fixture::new().await?;
    assert!(
        f.sdk
            .node_relay_route("http://192.168.1.8:28745", true, &f.permit, &f.allocation)
            .await
            .is_err()
    );
    assert!(
        f.sdk
            .node_relay_route(&f.origin, false, &f.permit, &f.allocation)
            .await
            .is_err()
    );
    let route = f
        .sdk
        .node_relay_route(&f.origin, true, &f.permit, &f.allocation)
        .await?;
    let hostile = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    assert!(
        route
            .connect_at(&f.controller, &f.permit, hostile.local_addr()?)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), hostile.accept())
            .await
            .is_err()
    );
    let view = f
        .sdk
        .create_remote(RemoteRequest {
            id: random_id(),
            controller_device_id: f.controller.device_id.clone(),
            host_device_id: f.host.device_id.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "relay_only".into(),
        })
        .await?;
    f.sdk
        .approve(
            &f.host,
            &view,
            ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32],
                paths: vec![Path::Relay as i32],
            },
        )
        .await?;
    let other = f.sdk.permit(&view.id).await?;
    assert!(
        f.sdk
            .node_relay_route(&f.origin, true, &other, &f.allocation)
            .await
            .is_err()
    );
    assert!(
        route
            .connect_at(&f.controller, &other, route.addresses()[0])
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn resource_byte_exhaustion_closes_the_real_pair_and_never_admits_past_its_limit() -> Result {
    let limit = 65536;
    let f = Fixture::with_byte_limit(Some(limit)).await?;
    let (mut c, mut h, _keep) = f.channels().await?;
    let first = vec![5; 4096];
    let (sent, received) = tokio::join!(h.send(Channel::Video, &first), c.receive());
    sent?;
    assert_eq!(received?.payload, first);
    let oversized = vec![6; 65536];
    h.send(Channel::Video, &oversized).await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), c.receive())
            .await?
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), h.receive())
            .await?
            .is_err()
    );
    f.closed().await?;
    assert!(f.control.counters()?.admitted_bytes <= limit);
    assert!(f.control.counters()?.admitted_bytes > 4096);
    Ok(())
}
#[tokio::test]
async fn a_quota_revision_closes_existing_business_while_global_node_authority_stays_live() -> Result
{
    let f = Fixture::new().await?;
    let (mut c, mut h, _keep) = f.channels().await?;
    let quota = f.sdk.relay_quota().await?;
    f.sdk
        .set_relay_quota(nestlink_protocol::api::RelayQuotaUpdate {
            expected_revision: quota.revision,
            limits: nestlink_protocol::api::RelayQuotaLimits {
                max_allocations: 0,
                ..quota.limits
            },
        })
        .await?;
    let (c, h) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(c?.is_err());
    assert!(h?.is_err());
    f.closed().await?;
    assert!(f.control.authorize(NodeRole::NodeRelay, false).is_ok());
    assert!(
        f.sdk
            .reserve_relay_allocation(&f.controller, &f.permit, &random_id(), &f.node_id)
            .await
            .is_err()
    );
    f.receipts(1, 0).await?;
    Ok(())
}
#[tokio::test]
async fn renewed_grant_keeps_the_same_real_socket_alive_past_its_original_deadline() -> Result {
    let f = Fixture::new().await?;
    let (c, h, _keep, clocks) = f.channels_with_clocks().await?;
    renewal_survives(&f, c, h, clocks).await
}
#[tokio::test]
async fn renewed_quic_grant_extends_the_same_virtual_udp_pair_without_resetting_usage() -> Result {
    let f = Fixture::new().await?;
    let route = f
        .sdk
        .node_quic_route(&f.quic_uri, true, &f.permit, &f.allocation)
        .await?;
    let (c, h, _keep, clocks) = f.channels_on_route(NativeRelayRoute::Quic(&route)).await?;
    renewal_survives(&f, c, h, clocks).await
}
async fn renewal_survives(
    f: &Fixture,
    mut c: ChannelRuntime,
    h: ChannelRuntime,
    clocks: [RuntimeClock; 2],
) -> Result {
    let original = f.allocation.claims().expires_at_unix_ms;
    let stopped = [
        c.lease_control().subscribe_stopped(),
        h.lease_control().subscribe_stopped(),
    ];
    let diagnostic = |stage: &str| {
        format!(
            "relay renewal stage={stage}; original_permit_issued_unix_ms={}; original_permit_expires_unix_ms={}; original_grant_issued_unix_ms={}; original_grant_expires_unix_ms={original}; controller_clock={:?}; host_clock={:?}; controller_stop={:?}; host_stop={:?}",
            f.permit.claims().issued_at_unix_ms,
            f.permit.claims().expires_at_unix_ms,
            f.allocation.claims().issued_at_unix_ms,
            clocks[0].sample(),
            clocks[1].sample(),
            *stopped[0].borrow(),
            *stopped[1].borrow(),
        )
    };
    let failure = |stage: &str, error: &dyn std::fmt::Debug| {
        std::io::Error::other(format!("{}; error={error:?}", diagnostic(stage)))
    };
    let require_original_live = |stage: &str| -> std::io::Result<u64> {
        let now = clocks[0]
            .sample()
            .map_err(|error| failure(stage, &error))?
            .unix_ms;
        if now >= original || stopped.iter().any(|report| report.borrow().is_some()) {
            return Err(failure(
                stage,
                &"original authorization expired or session stopped",
            ));
        }
        Ok(now)
    };
    eprintln!("{}", diagnostic("channels ready"));
    // reserve_node_relay returns the old grant while at least 5000 ms remain.
    // Use its signed deadline, including setup/handshake time already spent.
    let renew_at = original
        .checked_sub(4800)
        .ok_or_else(|| failure("renewal window", &"invalid original grant deadline"))?;
    loop {
        let now = require_original_live("waiting for renewal window")?;
        if now >= renew_at {
            break;
        }
        tokio::time::sleep(Duration::from_millis(renew_at - now)).await;
    }
    eprintln!("{}", diagnostic("before renewal proof"));
    let view = f
        .sdk
        .remote(&f.permit.claims().session_id)
        .await
        .map_err(|error| failure("remote view", &error))?;
    let signature = f
        .sdk
        .renewal_signature(&f.host, &view, &f.permit)
        .map_err(|error| failure("renewal proof", &error))?;
    require_original_live("before permit renewal")?;
    eprintln!("{}", diagnostic("before permit renewal"));
    let starts = [clocks[0].monotonic_ms(), clocks[1].monotonic_ms()];
    let renewed = f
        .sdk
        .renew_permit(&f.controller, &view, &f.permit, signature)
        .await
        .map_err(|error| failure("permit renewal", &error))?;
    eprintln!("{}", diagnostic("after permit renewal"));
    require_original_live("before controller lease renewal")?;
    c.lease_control()
        .renew(renewed.clone(), starts[0])
        .map_err(|error| failure("controller lease renewal", &error))?;
    eprintln!("{}", diagnostic("after controller lease renewal"));
    require_original_live("before host lease renewal")?;
    h.lease_control()
        .renew(renewed.clone(), starts[1])
        .map_err(|error| failure("host lease renewal", &error))?;
    eprintln!("{}", diagnostic("after host lease renewal"));
    require_original_live("before allocation renewal")?;
    eprintln!("{}", diagnostic("before allocation renewal"));
    let grant = f
        .sdk
        .reserve_relay_allocation(
            &f.controller,
            &renewed,
            &f.allocation.claims().allocation_id,
            &f.node_id,
        )
        .await
        .map_err(|error| failure("allocation renewal", &error))?;
    eprintln!("{}", diagnostic("after allocation renewal"));
    assert_eq!(
        grant.claims().allocation_id,
        f.allocation.claims().allocation_id
    );
    assert!(grant.claims().grant_sequence > f.allocation.claims().grant_sequence);
    assert!(grant.claims().expires_at_unix_ms > original);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !f.control.resource_snapshot().is_ok_and(|s| {
            s.allocations.iter().any(|c| {
                c.allocation_id == grant.claims().allocation_id
                    && c.grant_sequence == grant.claims().grant_sequence
            })
        }) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|error| failure("node observes renewed grant", &error))?;
    eprintln!("{}", diagnostic("node observed renewed grant"));
    let now = clocks[0]
        .sample()
        .map_err(|error| failure("before original allocation deadline", &error))?
        .unix_ms;
    tokio::time::sleep(Duration::from_millis(original.saturating_sub(now) + 100)).await;
    let after = clocks[0]
        .sample()
        .map_err(|error| failure("after original allocation deadline", &error))?
        .unix_ms;
    assert!(
        after > original,
        "{}",
        diagnostic("original allocation deadline was not crossed")
    );
    eprintln!(
        "{}",
        diagnostic("before traffic past original allocation deadline")
    );
    let before = f.control.counters()?.admitted_bytes;
    let (sent, received) = tokio::join!(
        h.send(Channel::Video, b"after original allocation expiry"),
        c.receive()
    );
    sent.map_err(|error| failure("send past original allocation deadline", &error))?;
    assert_eq!(
        received
            .map_err(|error| failure("receive past original allocation deadline", &error))?
            .payload,
        b"after original allocation expiry"
    );
    eprintln!(
        "{}",
        diagnostic("after traffic past original allocation deadline")
    );
    assert!(f.control.counters()?.admitted_bytes > before);
    assert_eq!(f.control.counters()?.opened_connections, 2);
    Ok(())
}

type RawSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
async fn raw(f: &Fixture) -> Result<(RawSocket, [u8; 32])> {
    use futures_util::StreamExt;
    let mut url = url::Url::parse(&f.origin)?;
    url.set_scheme("ws").map_err(|_| "scheme")?;
    url.set_path(&format!(
        "/api/v3/nodes/{}/relay/{}",
        f.node_id,
        f.allocation.claims().allocation_id
    ));
    let (mut socket, _) = tokio_tungstenite::connect_async(url.as_str()).await?;
    let message = tokio::time::timeout(Duration::from_secs(1), socket.next())
        .await?
        .ok_or("no challenge")??;
    let tokio_tungstenite::tungstenite::Message::Text(bytes) = message else {
        return Err("not a challenge".into());
    };
    let challenge: nestlink_protocol::api::NodeRelayChallenge = serde_json::from_str(&bytes)?;
    Ok((
        socket,
        URL_SAFE_NO_PAD
            .decode(challenge.nonce)?
            .try_into()
            .map_err(|_| "challenge size")?,
    ))
}
fn hello(
    f: &Fixture,
    nonce: &[u8; 32],
    transport: nestlink_protocol::RelayTransport,
) -> Result<nestlink_protocol::api::NodeRelayHello> {
    hello_as(f, &f.controller, nonce, transport)
}
fn hello_as(
    f: &Fixture,
    device: &DeviceIdentity,
    nonce: &[u8; 32],
    transport: nestlink_protocol::RelayTransport,
) -> Result<nestlink_protocol::api::NodeRelayHello> {
    let proof = nestlink_identity::relay::node_relay_transcript(
        f.allocation.claims(),
        &device.device_id,
        transport,
        nonce,
    )?;
    Ok(nestlink_protocol::api::NodeRelayHello {
        device_id: device.device_id.clone(),
        public_key: URL_SAFE_NO_PAD.encode(device.identity.public_key()),
        allocation: URL_SAFE_NO_PAD.encode(f.allocation.signed_bytes()),
        signature: URL_SAFE_NO_PAD.encode(device.identity.sign_action(&proof)?),
    })
}
async fn submit(socket: &mut RawSocket, hello: &nestlink_protocol::api::NodeRelayHello) -> Result {
    use futures_util::SinkExt;
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::to_string(hello)?.into(),
        ))
        .await?;
    Ok(())
}
async fn rejected(socket: &mut RawSocket) -> Result {
    use futures_util::StreamExt;
    tokio::time::timeout(Duration::from_secs(1), async {
        match socket.next().await {
            None | Some(Err(_)) | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => {
                Ok(())
            }
            _ => Err::<(), Box<dyn std::error::Error + Send + Sync>>(
                "unproved socket received relay data/ready".into(),
            ),
        }
    })
    .await??;
    Ok(())
}
async fn ready(socket: &mut RawSocket) -> Result {
    use futures_util::StreamExt;
    let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await?
        .ok_or("pair closed before ready")??;
    let tokio_tungstenite::tungstenite::Message::Text(bytes) = message else {
        return Err("pair did not send ready".into());
    };
    assert!(serde_json::from_str::<nestlink_protocol::api::RelayReady>(&bytes)?.ready);
    Ok(())
}

#[tokio::test]
async fn crossed_arrival_orders_select_one_carrier_and_loser_cleanup_keeps_winners_live() -> Result
{
    use futures_util::{SinkExt, StreamExt};
    use nestlink_protocol::RelayTransport;
    use nestlink_transport_quic::node::{read_message, write_message};
    for quic_wins in [false, true] {
        for quic_first in [false, true] {
            let f = Fixture::new().await?;
            let (outer_c, c_quic, mut write_c, mut read_c, c_nonce) = raw_quic(&f).await?;
            let (mut h_wss, h_nonce) = raw(&f).await?;
            let c_hello = hello(&f, &c_nonce, RelayTransport::QuicDatagram)?;
            let h_hello = hello_as(&f, &f.host, &h_nonce, RelayTransport::WssStream)?;
            if quic_first {
                write_message(&mut write_c, &c_hello).await?;
                f.pending(1).await?;
                submit(&mut h_wss, &h_hello).await?;
            } else {
                submit(&mut h_wss, &h_hello).await?;
                f.pending(1).await?;
                write_message(&mut write_c, &c_hello).await?;
            }
            f.pending(2).await?;
            assert_eq!(f.control.counters()?.opened_connections, 0);
            assert_eq!(f.control.counters()?.admitted_bytes, 0);
            if quic_wins {
                let (outer_h, h_quic, mut write_h, mut read_h, nonce) =
                    raw_quic_as(&f, &f.host).await?;
                write_message(
                    &mut write_h,
                    &hello_as(&f, &f.host, &nonce, RelayTransport::QuicDatagram)?,
                )
                .await?;
                assert!(
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        read_message::<nestlink_protocol::api::RelayReady>(&mut read_c)
                    )
                    .await??
                    .ready
                );
                assert!(
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        read_message::<nestlink_protocol::api::RelayReady>(&mut read_h)
                    )
                    .await??
                    .ready
                );
                rejected(&mut h_wss).await?;
                drop(h_wss);
                let packet = nestlink_protocol::relay_datagram::encode(
                    1,
                    b"QUIC winner survives WSS cleanup",
                )?
                .remove(0);
                c_quic.send_datagram(packet.clone().into())?;
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), h_quic.read_datagram())
                        .await??
                        .as_ref(),
                    packet
                );
                assert_eq!(f.control.counters()?.opened_connections, 2);
                assert_eq!(f.control.counters()?.admitted_bytes, packet.len() as u64);
                // Keep actual endpoints owned until all observations complete.
                outer_h.close(0u32.into(), b"fixture completed");
            } else {
                let (mut c_wss, nonce) = raw(&f).await?;
                submit(&mut c_wss, &hello(&f, &nonce, RelayTransport::WssStream)?).await?;
                ready(&mut c_wss).await?;
                ready(&mut h_wss).await?;
                assert!(
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        read_message::<nestlink_protocol::api::RelayReady>(&mut read_c)
                    )
                    .await?
                    .is_err()
                );
                c_quic.close(0u32.into(), b"loser cleanup");
                outer_c.close(0u32.into(), b"loser cleanup");
                let payload = b"WSS winner survives QUIC cleanup";
                c_wss
                    .send(tokio_tungstenite::tungstenite::Message::Binary(
                        payload.to_vec().into(),
                    ))
                    .await?;
                let message = tokio::time::timeout(Duration::from_secs(2), h_wss.next())
                    .await?
                    .ok_or("winner stopped")??;
                assert_eq!(message.into_data().as_ref(), payload);
                assert_eq!(f.control.counters()?.opened_connections, 2);
                assert_eq!(f.control.counters()?.admitted_bytes, payload.len() as u64);
            }
            f.pending(0).await?;
            assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn canceling_pending_wss_and_duplicate_socket_candidates_does_not_burn_or_close_the_grant()
-> Result {
    use futures_util::{SinkExt, StreamExt};
    use nestlink_protocol::RelayTransport;
    let f = Fixture::new().await?;
    let (mut canceled, nonce) = raw(&f).await?;
    submit(
        &mut canceled,
        &hello(&f, &nonce, RelayTransport::WssStream)?,
    )
    .await?;
    f.pending(1).await?;
    canceled.close(None).await?;
    drop(canceled);
    f.pending(0).await?;
    assert_eq!(f.control.counters()?.opened_connections, 0);
    let (mut winner, nonce) = raw(&f).await?;
    submit(&mut winner, &hello(&f, &nonce, RelayTransport::WssStream)?).await?;
    f.pending(1).await?;
    let (mut duplicate, nonce) = raw(&f).await?;
    submit(
        &mut duplicate,
        &hello(&f, &nonce, RelayTransport::WssStream)?,
    )
    .await?;
    f.pending(2).await?;
    assert_eq!(f.control.counters()?.opened_connections, 0);
    let (mut host, nonce) = raw(&f).await?;
    submit(
        &mut host,
        &hello_as(&f, &f.host, &nonce, RelayTransport::WssStream)?,
    )
    .await?;
    ready(&mut winner).await?;
    ready(&mut host).await?;
    rejected(&mut duplicate).await?;
    drop(duplicate);
    f.pending(0).await?;
    winner
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            b"same grant remains live".to_vec().into(),
        ))
        .await?;
    let received = tokio::time::timeout(Duration::from_secs(2), host.next())
        .await?
        .ok_or("winner closed")??;
    assert_eq!(received.into_data().as_ref(), b"same grant remains live");
    assert_eq!(f.control.counters()?.opened_connections, 2);
    assert_eq!(f.control.counters()?.closed_connections, 0);
    Ok(())
}

#[tokio::test]
async fn revoking_a_pending_allocation_closes_both_carrier_candidates_without_admission() -> Result
{
    use nestlink_protocol::RelayTransport;
    use nestlink_transport_quic::node::{read_message, write_message};
    let f = Fixture::new().await?;
    let (outer, _connection, mut write, mut read, nonce) = raw_quic(&f).await?;
    write_message(
        &mut write,
        &hello(&f, &nonce, RelayTransport::QuicDatagram)?,
    )
    .await?;
    let (mut wss, nonce) = raw(&f).await?;
    submit(&mut wss, &hello(&f, &nonce, RelayTransport::WssStream)?).await?;
    f.pending(2).await?;
    f.sdk.revoke_remote(&f.permit.claims().session_id).await?;
    rejected(&mut wss).await?;
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            read_message::<nestlink_protocol::api::RelayReady>(&mut read)
        )
        .await?
        .is_err()
    );
    f.pending(0).await?;
    assert_eq!(f.control.counters()?.opened_connections, 0);
    assert_eq!(f.control.counters()?.admitted_bytes, 0);
    assert!(f.control.authorize(NodeRole::NodeRelay, false).is_ok());
    let (mut late, nonce) = raw(&f).await?;
    submit(
        &mut late,
        &hello_as(&f, &f.host, &nonce, RelayTransport::WssStream)?,
    )
    .await?;
    rejected(&mut late).await?;
    assert_eq!(f.control.counters()?.opened_connections, 0);
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
    outer.close(0u32.into(), b"fixture completed");
    Ok(())
}
#[tokio::test]
async fn two_approved_addresses_of_one_carrier_race_without_reserving_duplicate_roles() -> Result {
    let f = Fixture::with_bounds(None, "127.0.0.1:0", "0.0.0.0:0").await?;
    let first = f
        .sdk
        .node_relay_route(&f.origin, true, &f.permit, &f.allocation)
        .await?;
    let mut second_origin = url::Url::parse(&f.origin)?;
    second_origin.set_host(Some("127.0.0.2"))?;
    let second = f
        .sdk
        .node_relay_route(
            second_origin.as_str().trim_end_matches('/'),
            true,
            &f.permit,
            &f.allocation,
        )
        .await?;
    assert_ne!(first.addresses(), second.addresses());
    let routes = [
        NativeRelayRoute::Wss(&first),
        NativeRelayRoute::Wss(&second),
    ];
    let mut candidates = routes[0].candidates(1)?;
    candidates.extend(routes[1].candidates(1)?);
    let (_cancel, cancel) = watch::channel(false);
    let controller = f.endpoints[0].dial_native_with_relays(
        &f.controller,
        &routes,
        1,
        candidates.clone(),
        cancel.clone(),
    );
    tokio::pin!(controller);
    tokio::select! {
        _ = &mut controller => return Err("controller finished before its peer arrived".into()),
        result = f.pending(2) => result?,
    }
    assert_eq!(f.control.counters()?.opened_connections, 0);
    let (c, h) = tokio::try_join!(
        controller,
        f.endpoints[1].dial_native_with_relays(&f.host, &routes, 1, candidates, cancel)
    )?;
    assert!(
        first.addresses().contains(&c.candidate.address)
            || second.addresses().contains(&c.candidate.address)
    );
    assert!(
        first.addresses().contains(&h.candidate.address)
            || second.addresses().contains(&h.candidate.address)
    );
    f.pending(0).await?;
    assert_eq!(f.control.counters()?.opened_connections, 2);
    let (_keep, stop) = watch::channel(None);
    let (mut c, h) = tokio::try_join!(
        authorize(c, &f, true, stop.clone()),
        authorize(h, &f, false, stop)
    )?;
    let (sent, received) = tokio::join!(
        h.0.send(Channel::Video, b"two approved literal addresses"),
        c.0.receive()
    );
    sent?;
    assert_eq!(received?.payload, b"two approved literal addresses");
    assert_eq!(f.control.counters()?.closed_connections, 0);
    Ok(())
}

#[tokio::test]
async fn unmatched_pairing_timeout_clears_the_real_socket_without_using_or_refunding_capacity()
-> Result {
    let f = Fixture::new().await?;
    let (mut socket, nonce) = raw(&f).await?;
    submit(
        &mut socket,
        &hello(&f, &nonce, nestlink_protocol::RelayTransport::WssStream)?,
    )
    .await?;
    f.pending(1).await?;
    assert_eq!(f.control.counters()?.opened_connections, 0);
    tokio::time::timeout(Duration::from_secs(6), async {
        use futures_util::StreamExt;
        match socket.next().await {
            None | Some(Err(_)) | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => {
                Ok(())
            }
            _ => Err::<(), Box<dyn std::error::Error + Send + Sync>>(
                "unpaired socket received ready/data".into(),
            ),
        }
    })
    .await??;
    f.pending(0).await?;
    assert_eq!(f.control.counters()?.opened_connections, 0);
    assert_eq!(f.control.counters()?.admitted_bytes, 0);
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
    Ok(())
}

#[tokio::test]
async fn wrong_keys_transports_replayed_socket_proofs_and_closed_ids_cannot_occupy_a_slot() -> Result
{
    use nestlink_protocol::RelayTransport;
    let f = Fixture::new().await?;
    for wrong_key in [true, false] {
        let (mut socket, nonce) = raw(&f).await?;
        let mut body = hello(
            &f,
            &nonce,
            if wrong_key {
                RelayTransport::WssStream
            } else {
                RelayTransport::QuicDatagram
            },
        )?;
        if wrong_key {
            body.public_key = URL_SAFE_NO_PAD.encode(f.host.identity.public_key());
        }
        submit(&mut socket, &body).await?;
        rejected(&mut socket).await?;
        assert_eq!(f.control.counters()?.opened_connections, 0);
    }
    let (mut first, nonce) = raw(&f).await?;
    let body = hello(&f, &nonce, RelayTransport::WssStream)?;
    submit(&mut first, &body).await?;
    f.pending(1).await?;
    let (mut replay, new_nonce) = raw(&f).await?;
    assert_ne!(new_nonce, nonce);
    submit(&mut replay, &body).await?;
    rejected(&mut replay).await?;
    assert_eq!(f.control.counters()?.opened_connections, 0);
    // A closed *pending* socket has not used the grant. Commit an actual
    // matching pair before proving that a used allocation cannot reconnect.
    let (mut host, nonce) = raw(&f).await?;
    submit(
        &mut host,
        &hello_as(&f, &f.host, &nonce, RelayTransport::WssStream)?,
    )
    .await?;
    ready(&mut first).await?;
    ready(&mut host).await?;
    assert_eq!(f.control.counters()?.opened_connections, 2);
    first.close(None).await?;
    drop(first);
    f.closed().await?;
    let (mut closed, nonce) = raw(&f).await?;
    submit(&mut closed, &hello(&f, &nonce, RelayTransport::WssStream)?).await?;
    rejected(&mut closed).await?;
    assert_eq!(f.control.counters()?.opened_connections, 2);
    f.receipts(1, 0).await?;
    Ok(())
}
