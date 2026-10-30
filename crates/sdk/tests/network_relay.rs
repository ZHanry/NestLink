//! Actual management HTTP, signed node polls, mTLS relay and remote business proof.
#[path = "../../node/tests/support/service_usage_directory.rs"]
mod service_usage_directory;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, random_bytes, random_id};
use nestlink_identity::{PermitSigner, VerifiedPermit, nodes::NodeIdentity};
use nestlink_node::control::{NodeConfig, NodeControl};
use nestlink_policy::PathSet;
use nestlink_protocol::{
    NodeRole, Path, Permission,
    api::{
        ApprovalChoice, NetworkAuthorityChangeRequest, NetworkIssueRequest, NetworkMemberRequest,
        NetworkPolicy, NetworkRemotePathRequest, NetworkRemoteRelayRequest, NodeEndpoints,
        NodeEndpointsUpdate, NodeRegistration, PolicyUpdate, RelayAllocationRequest, RemoteRequest,
    },
    network::SpaceRole,
};
use nestlink_remote::{ChannelRuntime, RuntimeClock, SessionLifecycle, SessionSetup};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, Sdk, native::AddressPolicy,
    network::routed::PinnedNetworkSpace,
};
use nestlink_server::{AppState, node_quic, router};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use nestlink_storage::Store;
use nestlink_transport_quic::routed::{self, NetworkNodeListener};
use nestlink_transport_stream::Channel;
use service_usage_directory::ServiceUsageDirectory;
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::watch, task::JoinHandle, time::Instant};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Default)]
struct PendingFixture {
    http_task: Option<JoinHandle<()>>,
    control: Option<Arc<NodeControl>>,
}
impl Drop for PendingFixture {
    fn drop(&mut self) {
        if let Some(control) = &self.control {
            control.stop();
        }
        if let Some(task) = &self.http_task {
            task.abort();
        }
    }
}

struct Fixture {
    sdk: Sdk,
    controller: DeviceIdentity,
    host: DeviceIdentity,
    permit: VerifiedPermit,
    pin: PinnedNetworkSpace,
    allocation: String,
    control: Arc<NodeControl>,
    node: NetworkNodeListener,
    shutdown: watch::Sender<bool>,
    node_task: Option<JoinHandle<io::Result<()>>>,
    http_task: Option<JoinHandle<()>>,
    _usage: ServiceUsageDirectory,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        self.control.stop();
        self.node.request_close();
        if let Some(task) = &self.node_task {
            task.abort();
        }
        if let Some(task) = &self.http_task {
            task.abort();
        }
    }
}
impl Fixture {
    async fn new() -> Result<Self> {
        let deployment = random_id();
        let signer = PermitSigner::generate();
        let permit_issuer = signer.public_key();
        let node_issuer = signer.node_policy_signer()?.public_key();
        let network_issuer = signer.network_authority_signer()?.public_key();
        let mut store = Store::in_memory(&deployment)?;
        let password = "network-relay-actual-business-password";
        store.bootstrap_admin("admin", password)?;
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", http.local_addr()?);
        let app = router(AppState::new(
            store,
            VaultKey::from_bytes([6; 32]),
            signer,
            origin.clone(),
            false,
        )?);
        let mut pending = PendingFixture {
            http_task: Some(tokio::spawn(async move {
                let _ = axum::serve(http, app).await;
            })),
            control: None,
        };
        let mut sdk = Sdk::connect(
            &origin,
            DeploymentTrust {
                deployment_id: deployment.clone(),
                permit_issuer,
            },
            true,
        )
        .await?;
        sdk.login("admin".into(), Secret::from_text(password.into()), None)
            .await?;
        sdk.set_policy(PolicyUpdate {
            expected_revision: 1,
            policy: NetworkPolicy {
                server_forwarding: "allow".into(),
                peer_path_mode: "direct_preferred".into(),
                public_ingress: "disabled".into(),
            },
        })
        .await?;
        let controller = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        for (device, name) in [(&controller, "controller"), (&host, "host")] {
            sdk.enroll(
                device,
                name.into(),
                "windows".into(),
                vec!["controller".into(), "host".into(), "vp8".into()],
                "direct_preferred".into(),
            )
            .await?;
        }
        let remote = sdk
            .create_remote(RemoteRequest {
                id: random_id(),
                controller_device_id: controller.device_id.clone(),
                host_device_id: host.device_id.clone(),
                permissions: vec![Permission::View as i32, Permission::FileRead as i32],
                path_mode: "relay_only".into(),
            })
            .await?;
        sdk.approve(
            &host,
            &remote,
            ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32, Permission::FileRead as i32],
                paths: vec![Path::Relay as i32],
            },
        )
        .await?;
        let permit = sdk.permit(&remote.id).await?;
        let space = random_id();
        let pin = PinnedNetworkSpace::new(space.clone(), network_issuer)?.with_loopback_node(true);
        let mut policy = sdk.configure_network_authority(&space, 0).await?;
        assert_eq!(
            policy.authority_public_key,
            URL_SAFE_NO_PAD.encode(network_issuer)
        );
        for device in [&controller, &host] {
            let member = sdk
                .set_network_member(
                    &space,
                    &device.device_id,
                    NetworkMemberRequest {
                        expected_policy_revision: policy.revision,
                        expected_membership_epoch: 0,
                        role: SpaceRole::Member,
                    },
                )
                .await?;
            policy = member.policy;
        }
        let expires = (RuntimeClock::default().sample()?.unix_ms + 20_000)
            .min(permit.claims().expires_at_unix_ms);
        let grants = [random_id(), random_id()];
        for (device, grant) in [(&controller, &grants[0]), (&host, &grants[1])] {
            sdk.issue_network_membership(
                &space,
                &device.device_id,
                NetworkIssueRequest {
                    grant_id: grant.clone(),
                    expected_policy_epoch: policy.policy_epoch,
                    expected_membership_epoch: 1,
                    expires_at_unix_ms: expires,
                },
            )
            .await?;
        }
        let node_seed = random_bytes::<32>();
        let node_identity = NodeIdentity::from_seed(&node_seed);
        let node_id = random_id();
        sdk.register_node(NodeRegistration {
            id: node_id.clone(),
            name: "network actual node".into(),
            public_key: URL_SAFE_NO_PAD.encode(node_identity.public_key()),
            roles: vec![NodeRole::NodeRelay as i32],
            max_connections: 8,
            bytes_per_second: 16 * 1024 * 1024,
        })
        .await?;
        let mut usage = ServiceUsageDirectory::new()?;
        let control = Arc::new(NodeControl::start(
            NodeConfig {
                deployment_id: deployment,
                node_id: node_id.clone(),
                control_origin: origin,
                trusted_policy_issuer: URL_SAFE_NO_PAD.encode(node_issuer),
                identity_key_file: "unused-network-test-identity".into(),
                service_usage_directory: Some(usage.path().to_path_buf()),
                roles: vec![NodeRole::NodeRelay as i32],
                allow_loopback_http: true,
            },
            node_identity,
        )?);
        pending.control = Some(control.clone());
        usage.track(&control)?;
        let node = routed::node_listener_with_legacy(
            "127.0.0.1:0".parse()?,
            &NodeIdentity::from_seed(&node_seed),
            control.clone(),
        )?;
        sdk.set_node_endpoints(
            &node_id,
            NodeEndpointsUpdate {
                expected_revision: 0,
                endpoints: NodeEndpoints {
                    quic_uri: Some(format!("quic://{}", node.local_addr()?)),
                    wss_origin: None,
                    allow_loopback: true,
                },
            },
        )
        .await?;
        let node_lease = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(lease) = control.authorize(NodeRole::NodeRelay, false) {
                    break lease;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let allocation = random_id();
        sdk.reserve_network_remote_relay(
            &space,
            &controller,
            &permit,
            NetworkRemoteRelayRequest {
                path: NetworkRemotePathRequest {
                    connectivity_grant_id: random_id(),
                    path_grant_id: random_id(),
                    controller_membership_grant_id: grants[0].clone(),
                    host_membership_grant_id: grants[1].clone(),
                    expected_policy_epoch: policy.policy_epoch,
                    expires_at_unix_ms: expires.min(node_lease.expires_at_unix_ms),
                },
                transit_grant_id: random_id(),
                allocation: RelayAllocationRequest {
                    allocation_id: allocation.clone(),
                    node_id,
                    device_id: controller.device_id.clone(),
                    signature: String::new(),
                },
            },
        )
        .await
        .map_err(|error| format!("reserve actual network relay: {error}"))?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while !control.resource_snapshot().is_ok_and(|s| {
                s.network_routes.iter().any(|r| {
                    r.allocation
                        .as_ref()
                        .is_some_and(|entry| entry.allocation_id == allocation)
                })
            }) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let endpoint = node.endpoint()?.clone();
        let shared = control.clone();
        let (shutdown, mut stopped) = watch::channel(false);
        let node_task = tokio::spawn(async move {
            node_quic::serve(endpoint, shared, async move {
                if !*stopped.borrow() {
                    let _ = stopped.changed().await;
                }
            })
            .await
        });
        pending.control = None;
        Ok(Self {
            sdk,
            controller,
            host,
            permit,
            pin,
            allocation,
            control,
            node,
            shutdown,
            node_task: Some(node_task),
            http_task: pending.http_task.take(),
            _usage: usage,
        })
    }
    fn setup(
        &self,
        role: EndpointRole,
        stop: watch::Receiver<Option<StopReason>>,
    ) -> Result<SessionSetup> {
        let p = self.permit.claims();
        let clock = RuntimeClock::default();
        let now = clock.sample()?;
        let session = Session::activate(
            self.permit.clone(),
            SessionBinding {
                media: None,
                deployment_id: p.deployment_id.clone(),
                security_epoch: p.security_epoch,
                session_id: p.session_id.clone(),
                account_id: p.account_id.clone(),
                controller_device_id: p.controller_device_id.clone(),
                host_device_id: p.host_device_id.clone(),
                controller_key_sha256: self.controller.identity.fingerprint(),
                host_key_sha256: self.host.identity.fingerprint(),
                resource_id: p.resource_id.clone(),
                policy_revision: p.policy_revision,
                connection_generation: p.connection_generation,
                capability_sha256: p.capability_sha256.as_slice().try_into()?,
                granted_permissions: vec![Permission::View, Permission::FileRead],
                supported_capabilities: vec!["vp8".into()],
                local_paths: PathSet::RELAY,
            },
            Path::Relay,
            now.monotonic_ms,
            now,
        )?;
        Ok(SessionSetup {
            session,
            path: Path::Relay,
            role,
            clock,
            lifecycle: SessionLifecycle::new(stop),
        })
    }
    async fn channels(
        &self,
        binds: [SocketAddr; 2],
    ) -> Result<(
        ChannelRuntime,
        ChannelRuntime,
        watch::Sender<Option<StopReason>>,
    )> {
        let c = self
            .sdk
            .verified_network_remote_relay(
                &self.pin,
                &self.controller,
                &self.permit,
                &self.host.identity.public_key(),
                &self.allocation,
            )
            .await?;
        let h = self
            .sdk
            .verified_network_remote_relay(
                &self.pin,
                &self.host,
                &self.permit,
                &self.controller.identity.public_key(),
                &self.allocation,
            )
            .await?;
        let (keep, stop) = watch::channel(None);
        let (_cancel, cancel) = watch::channel(false);
        let policy = AddressPolicy::new(&[])?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let controller_key = self.controller.identity.public_key();
        let host_key = self.host.identity.public_key();
        let (c, h) = tokio::try_join!(
            self.sdk.connect_network_remote_relay(
                c,
                binds[0],
                &self.controller,
                &host_key,
                self.setup(EndpointRole::Controller, stop.clone())?,
                &policy,
                cancel.clone(),
                deadline
            ),
            self.sdk.connect_network_remote_relay(
                h,
                binds[1],
                &self.host,
                &controller_key,
                self.setup(EndpointRole::Host, stop)?,
                &policy,
                cancel,
                deadline
            ),
        )?;
        Ok((c, h, keep))
    }
    async fn finish(&mut self) -> Result {
        self.shutdown.send_replace(true);
        if let Some(task) = self.node_task.as_mut() {
            tokio::time::timeout(Duration::from_secs(5), task).await???;
        }
        self.node_task = None;
        self.node
            .close_and_wait(Instant::now() + Duration::from_secs(5))
            .await?;
        if let Some(task) = self.http_task.take() {
            task.abort();
            assert!(task.await.is_err_and(|e| e.is_cancelled()));
        }
        Ok(())
    }
}

fn unused_udp() -> io::Result<SocketAddr> {
    UdpSocket::bind("127.0.0.1:0")?.local_addr()
}
fn rebind(addresses: &[SocketAddr]) -> io::Result<Vec<UdpSocket>> {
    addresses.iter().map(UdpSocket::bind).collect()
}

#[tokio::test]
async fn current_http_node_snapshot_carries_business_and_revocation_closes_all_original_udp_owners()
-> Result {
    let mut f = Fixture::new().await?;
    let sockets = [
        UdpSocket::bind("127.0.0.1:0")?,
        UdpSocket::bind("127.0.0.1:0")?,
    ];
    let addresses = [sockets[0].local_addr()?, sockets[1].local_addr()?];
    drop(sockets);
    let (mut controller, mut host, _stop) = f.channels(addresses).await?;
    let payload = vec![71; 256 * 1024];
    let transfer_deadline = Instant::now() + Duration::from_secs(5);
    for chunk in payload.chunks(nestlink_protocol::FILE_CHUNK_BYTES as usize) {
        let (sent, received) = tokio::time::timeout_at(transfer_deadline, async {
            tokio::join!(host.send(Channel::FileRead, chunk), controller.receive())
        })
        .await?;
        sent?;
        let frame = received?;
        assert_eq!(frame.channel, Channel::FileRead);
        assert_eq!(frame.payload, chunk);
    }
    assert!(
        controller
            .send(Channel::Input, b"membership cannot authorize input")
            .await
            .is_err()
    );
    assert_eq!(f.control.counters()?.opened_connections, 2);
    assert!(f.control.counters()?.admitted_bytes > payload.len() as u64);
    f.sdk
        .revoke_network_remote_relay(f.pin.space_id(), &f.allocation)
        .await?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let (c, h) = tokio::time::timeout_at(deadline, async {
        tokio::try_join!(controller.wait_stopped(), host.wait_stopped())
    })
    .await??;
    assert_eq!(c.reason, StopReason::Revoked);
    assert_eq!(h.reason, StopReason::Revoked);
    drop((controller, host));
    let _sockets = rebind(&addresses)?;
    assert!(
        f.sdk
            .verified_network_remote_relay(
                &f.pin,
                &f.controller,
                &f.permit,
                &f.host.identity.public_key(),
                &f.allocation
            )
            .await
            .is_err()
    );
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
    let node_address = f.node.local_addr()?;
    f.finish().await?;
    let _node_socket = UdpSocket::bind(node_address)?;
    Ok(())
}

#[tokio::test]
async fn cancelling_unpaired_actual_node_connection_releases_its_socket_without_opening_business()
-> Result {
    let mut f = Fixture::new().await?;
    let route = f
        .sdk
        .verified_network_remote_relay(
            &f.pin,
            &f.controller,
            &f.permit,
            &f.host.identity.public_key(),
            &f.allocation,
        )
        .await?;
    let address = unused_udp()?;
    let (_keep, stop) = watch::channel(None);
    let (cancel, cancelled) = watch::channel(false);
    let policy = AddressPolicy::new(&[])?;
    let setup = f.setup(EndpointRole::Controller, stop)?;
    {
        let peer_key = f.host.identity.public_key();
        let connection = f.sdk.connect_network_remote_relay(
            route,
            address,
            &f.controller,
            &peer_key,
            setup,
            &policy,
            cancelled,
            Instant::now() + Duration::from_secs(5),
        );
        tokio::pin!(connection);
        tokio::select! {
            result = &mut connection => return Err(format!("unpaired endpoint finished before cancellation: {}", result.is_ok()).into()),
            _ = tokio::time::sleep(Duration::from_millis(200)) => {},
        }
        cancel.send(true)?;
        assert!(matches!(
            connection.await,
            Err(nestlink_sdk::native::SessionEstablishError::Cancelled)
        ));
    }
    assert_eq!(f.control.counters()?.opened_connections, 0);
    let _socket = UdpSocket::bind(address)?;
    f.finish().await?;
    Ok(())
}

#[tokio::test]
async fn authority_rotation_epoch_advance_and_grant_revocation_remove_live_node_routes_and_original_socket_owners()
-> Result {
    for action in 0..4 {
        let mut f = Fixture::new().await?;
        let addresses = [unused_udp()?, unused_udp()?];
        let old = f
            .sdk
            .network_remote_relay(f.pin.space_id(), &f.allocation)
            .await?;
        let (mut controller, mut host, _stop) = f.channels(addresses).await?;
        host.send(Channel::FileRead, b"business before authority change")
            .await?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), controller.receive())
                .await??
                .payload,
            b"business before authority change"
        );
        let current = f.sdk.network_authority_state(f.pin.space_id()).await?;
        let change = NetworkAuthorityChangeRequest {
            expected_revision: current.policy.revision,
            expected_policy_epoch: current.policy.policy_epoch,
        };
        match action {
            0 => {
                let changed = f
                    .sdk
                    .rotate_network_authority(f.pin.space_id(), change)
                    .await?;
                assert_ne!(
                    changed.policy.authority_public_key,
                    current.policy.authority_public_key
                );
                // Operator pins are not updated by a response to this action.
                assert_eq!(
                    URL_SAFE_NO_PAD.encode(f.pin.authority_key()),
                    current.policy.authority_public_key
                );
            }
            1 => {
                let changed = f
                    .sdk
                    .advance_network_policy_epoch(f.pin.space_id(), change)
                    .await?;
                assert_eq!(
                    changed.authority_public_key,
                    current.policy.authority_public_key
                );
                assert!(changed.policy_epoch > current.policy.policy_epoch);
            }
            2 => {
                f.sdk
                    .revoke_network_authority(f.pin.space_id(), change)
                    .await?
            }
            _ => {
                let changed = f
                    .sdk
                    .revoke_network_membership_grant(
                        f.pin.space_id(),
                        &old.path.controller_membership.grant_id,
                        current.policy.revision,
                    )
                    .await?;
                assert_eq!(changed.policy_epoch, current.policy.policy_epoch);
                assert_eq!(changed.revision, current.policy.revision + 1);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        tokio::time::timeout_at(deadline, async {
            while !f.control.resource_snapshot().is_ok_and(|snapshot| {
                snapshot.network_routes.iter().all(|resource| {
                    resource
                        .allocation
                        .as_ref()
                        .is_none_or(|allocation| allocation.allocation_id != f.allocation)
                })
            }) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let (c, h) = tokio::time::timeout_at(deadline, async {
            tokio::try_join!(controller.wait_stopped(), host.wait_stopped())
        })
        .await??;
        assert_eq!(c.reason, StopReason::Revoked);
        assert_eq!(h.reason, StopReason::Revoked);
        drop((controller, host));
        let _sockets = rebind(&addresses)?;
        assert!(
            f.sdk
                .network_remote_relay(f.pin.space_id(), &f.allocation)
                .await
                .is_err()
        );
        assert!(
            f.sdk
                .network_remote_path(f.pin.space_id(), &old.path.path.grant_id)
                .await
                .is_err()
        );
        assert!(
            f.sdk
                .network_membership_grant(
                    f.pin.space_id(),
                    &old.path.controller_membership.grant_id
                )
                .await
                .is_err()
        );
        assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
        f.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn authority_rotation_interrupts_unpaired_node_setup_with_physical_release_receipt() -> Result
{
    let mut f = Fixture::new().await?;
    let route = f
        .sdk
        .verified_network_remote_relay(
            &f.pin,
            &f.controller,
            &f.permit,
            &f.host.identity.public_key(),
            &f.allocation,
        )
        .await?;
    let address = unused_udp()?;
    let (_keep, stop) = watch::channel(None);
    let (_cancel, cancel) = watch::channel(false);
    let policy = AddressPolicy::new(&[])?;
    let peer_key = f.host.identity.public_key();
    let setup = f.setup(EndpointRole::Controller, stop)?;
    {
        let connection = f.sdk.connect_network_remote_relay(
            route,
            address,
            &f.controller,
            &peer_key,
            setup,
            &policy,
            cancel,
            Instant::now() + Duration::from_secs(5),
        );
        tokio::pin!(connection);
        tokio::select! {
            result=&mut connection=>return Err(format!("unpaired node setup finished before authority change: {}",result.is_ok()).into()),
            _=tokio::time::sleep(Duration::from_millis(200))=>{},
        }
        let current = f.sdk.network_authority_state(f.pin.space_id()).await?;
        f.sdk
            .rotate_network_authority(
                f.pin.space_id(),
                NetworkAuthorityChangeRequest {
                    expected_revision: current.policy.revision,
                    expected_policy_epoch: current.policy.policy_epoch,
                },
            )
            .await?;
        assert!(
            tokio::time::timeout(Duration::from_secs(5), connection)
                .await?
                .is_err()
        );
    }
    assert_eq!(f.control.counters()?.opened_connections, 0);
    let _socket = UdpSocket::bind(address)?;
    f.finish().await?;
    Ok(())
}
