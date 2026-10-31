//! Actual product actors, two managed nodes, input cleanup and new video proof.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::nodes::NodeIdentity;
use nestlink_node::control::{NodeConfig, NodeControl};
use nestlink_protocol::{NodeRole, network::SpaceRole};
use nestlink_sdk::{DeploymentTrust, Sdk};
use nestlink_transport_quic::routed::{self, NetworkNodeListener};
use tokio::{sync::watch, task::JoinHandle};
#[path = "../../../node/tests/support/service_usage_directory.rs"]
mod service_usage_directory;
use service_usage_directory::ServiceUsageDirectory;

fn phase(name: &str, error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("product original route {name}: {error:?}"))
}

#[tokio::test]
async fn signed_direct_space_path_uses_original_media_and_input_owner_and_revocation_releases_pressed_keys()
-> Result {
    let server = Server::start(None).await?;
    let mut admin = Sdk::connect(&server.config.origin, DeploymentTrust {
        deployment_id: server.config.deployment_id.clone(), permit_issuer: server.config.permit_issuer,
    }, true).await?;
    admin.login("admin".into(), password(), None).await?;
    admin.set_policy(PolicyUpdate { expected_revision: 1, policy: NetworkPolicy {
        server_forwarding: "allow".into(), peer_path_mode: "direct_only".into(), public_ingress: "disabled".into(),
    }}).await?;
    let address = routed_ipv4()?;
    let controller_identity = DeviceIdentity::generate();
    let host_identity = DeviceIdentity::generate();
    let controller_id = controller_identity.device_id.clone();
    let host_id = host_identity.device_id.clone();
    let space = nestlink_auth::random_id();
    let mut policy = admin.configure_network_authority(&space, 0).await?;
    let grants = [nestlink_auth::random_id(), nestlink_auth::random_id()];
    let scope = NativeSpacePathSettings {
        deployment_id: server.config.deployment_id.clone(), space_id: space.clone(),
        authority_key: server.network_authority_key,
        controller_membership_grant_id: grants[0].clone(), host_membership_grant_id: grants[1].clone(),
    };
    let config = || -> Result<NativeSessionConfig> {
        let mut config = NativeSessionConfig::new(Arc::new(NetworkMonitor::start()?)).with_space_path(scope.clone())?;
        config.bind_address = (address, 0).into();
        config.use_deployment_stun = false;
        config.private_network_prefixes = vec![format!("{address}/32")];
        config.supported_capabilities = vec!["vp8".into(), "opus".into()];
        Ok(config)
    };
    let mut controller_core = AppCore::with_identity_and_native_session(Limits::default(), controller_identity, config()?)?;
    let mut host_core = AppCore::with_identity_and_native_session(Limits::default(), host_identity, config()?)?;
    let controller = connect(&controller_core, &server).await?;
    let host = connect(&host_core, &server).await?;
    for (handle, name) in [(&controller, "controller"), (&host, "host")] {
        success(handle.submit(Action::EnrollLocalDevice { name: name.into(), platform: "linux-x11".into(),
            capabilities: vec![name.into(), "vp8".into(), "opus".into()], path_mode: "direct_only".into() })?).await?;
    }
    for device in [&controller_id, &host_id] {
        policy = admin.set_network_member(&space, device, NetworkMemberRequest {
            expected_policy_revision: policy.revision, expected_membership_epoch: 0, role: SpaceRole::Member,
        }).await?.policy;
    }
    let expires = nestlink_remote::RuntimeClock::default().sample()?.unix_ms + 60_000;
    for (device, grant) in [(&controller_id, &grants[0]), (&host_id, &grants[1])] {
        admin.issue_network_membership(&space, device, NetworkIssueRequest {
            grant_id: grant.clone(), expected_policy_epoch: policy.policy_epoch,
            expected_membership_epoch: 1, expires_at_unix_ms: expires,
        }).await?;
    }
    success(controller.submit(Action::RequestRemote { host_device_id: host_id,
        permissions: vec![Permission::View as i32, Permission::Input as i32],
        path_mode: "direct_only".into(), access: RemoteAccess::LocalApproval })?).await?;
    let request = controller.snapshot().selected_request.data.as_ref().ok_or("missing direct request")?.clone();
    success(host.submit(Action::ApproveRemote { request_id: request.id.clone(), expected_nonce: request.nonce.clone(),
        expected_policy_revision: request.policy_revision, choice: ApprovalChoice { approved: true,
            permissions: vec![Permission::View as i32, Permission::Input as i32], paths: vec![Path::Direct as i32] } })?).await?;
    success(controller.submit(Action::IssueRemotePermit { request_id: request.id.clone() })?).await?;
    tokio::try_join!(
        session_success(controller.submit(Action::StartNativeSession { request_id: request.id.clone(), relay_node_id: None })?),
        session_success(host.submit(Action::StartNativeSession { request_id: request.id.clone(), relay_node_id: None })?),
    )?;
    let log = Arc::new(Mutex::new(Vec::new()));
    let (binding, input) = prepare_display(&host, &controller, log.clone()).await?;
    video(&host, &controller, &binding).await?;
    controller.send_native_input(&input, NativeInputAction::Key { code: 8, down: true }).await?;
    wait_input(&log, "Key { code: 8, down: true }").await?;
    let path = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = controller.snapshot();
            let session = snapshot.native_session.data.as_ref().ok_or("missing direct session")?;
            assert_eq!(session.path, Some(Path::Direct as i32));
            if let Some(binding) = session.quality.as_ref().and_then(|quality| quality.original_binding.as_ref()) {
                assert!(binding.transport_group.is_some());
                if let Some(path) = &binding.path_grant_id { return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(path.clone()); }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    let current = admin.network_remote_path(&space, &path).await?;
    assert_eq!(current.request_id, request.id);
    assert_eq!(current.controller_membership.grant_id, grants[0]);
    assert_eq!(current.host_membership.grant_id, grants[1]);
    admin.revoke_network_remote_path(&space, &path).await?;
    wait_input(&log, "release-key:8").await?;
    for handle in [&controller, &host] {
        wait_view(handle, |snapshot| snapshot.native_session.data.as_ref()
            .is_some_and(|session| session.status == NativeSessionStatus::Stopped)).await?;
    }
    assert!(controller.send_native_input(&input, NativeInputAction::Key { code: 9, down: true }).await.is_err());
    assert_eq!(controller_core.shutdown(Duration::from_secs(5)).await, ShutdownState::Complete);
    assert_eq!(host_core.shutdown(Duration::from_secs(5)).await, ShutdownState::Complete);
    Ok(())
}

struct Node {
    id: String,
    control: Arc<NodeControl>,
    listener: NetworkNodeListener,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<io::Result<()>>>,
    _usage: ServiceUsageDirectory,
}
impl Drop for Node {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.control.stop();
        self.listener.request_close();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Node {
    async fn start(sdk: &Sdk, address: std::net::Ipv4Addr) -> Result<Self> {
        let id = nestlink_auth::random_id();
        let seed = nestlink_auth::random_bytes::<32>();
        let identity = Arc::new(NodeIdentity::from_seed(&seed));
        sdk.register_node(NodeRegistration {
            id: id.clone(),
            name: "app-core signed original relay".into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            roles: vec![NodeRole::NodeRelay as i32],
            max_connections: 8,
            bytes_per_second: 16 * 1024 * 1024,
        })
        .await?;
        let mut usage = ServiceUsageDirectory::new()?;
        let control = Arc::new(NodeControl::start(
            NodeConfig {
                deployment_id: sdk.health().deployment_id.clone(),
                node_id: id.clone(),
                control_origin: sdk.management_origin().into(),
                trusted_policy_issuer: sdk.health().node_policy_issuer.clone(),
                identity_key_file: "unused-product-route-fixture".into(),
                service_usage_directory: Some(usage.path().to_path_buf()),
                roles: vec![NodeRole::NodeRelay as i32],
                allow_loopback_http: true,
            },
            NodeIdentity::from_seed(&seed),
        )?);
        usage.track(&control)?;
        let listener =
            routed::node_listener_with_legacy((address, 0).into(), &identity, control.clone())?;
        sdk.set_node_endpoints(
            &id,
            NodeEndpointsUpdate {
                expected_revision: 0,
                endpoints: NodeEndpoints {
                    quic_uri: Some(format!("quic://{}", listener.local_addr()?)),
                    wss_origin: None,
                    allow_loopback: false,
                },
            },
        )
        .await?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while control.authorize(NodeRole::NodeRelay, false).is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let endpoint = listener.endpoint()?.clone();
        let selector = nestlink_server::relay_selector::RelaySelector::new(control.clone());
        let (stop, mut stopping) = watch::channel(false);
        let task = tokio::spawn(async move {
            nestlink_server::node_quic::serve_with_chain_identity(
                endpoint,
                selector,
                identity,
                async move {
                    if !*stopping.borrow() {
                        let _ = stopping.changed().await;
                    }
                },
            )
            .await
        });
        Ok(Self {
            id,
            control,
            listener,
            stop,
            task: Some(task),
            _usage: usage,
        })
    }
    async fn close(&mut self) -> Result {
        self.stop.send_replace(true);
        if let Some(task) = self.task.as_mut() {
            tokio::time::timeout(Duration::from_secs(3), task).await???;
        }
        self.task = None;
        self.listener
            .close_and_wait(tokio::time::Instant::now() + Duration::from_secs(3))
            .await?;
        Ok(())
    }
}

async fn prepare_display(
    host: &CoreHandle,
    controller: &CoreHandle,
    log: Arc<Mutex<Vec<String>>>,
) -> Result<(NativeSessionBinding, NativeInputBinding)> {
    let binding = host
        .native_host_session_binding()
        .ok_or("missing proved product host")?;
    host.publish_native_display_candidates(
        &binding,
        vec![DisplayDescriptor {
            source: 0,
            left: 0,
            top: 0,
            width: 64,
            height: 48,
            label: "Fresh product screen".into(),
        }],
        false,
    )?;
    host.configure_native_video_stream(&binding, 0, 64, 48, 1)
        .await?;
    host.attach_native_input_device(
        &binding,
        0,
        1,
        InputProbe(log),
        InputLayout {
            left: 0,
            top: 0,
            width: 64,
            height: 48,
        },
    )
    .await?;
    host.advertise_native_displays(&binding).await?;
    complete_display_switch(host, controller, &binding, 1).await?;
    let input = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(layout) = controller.native_input_layout()? {
                break Ok::<_, NativeInputError>(layout.binding);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    Ok((binding, input))
}
async fn video(
    host: &CoreHandle,
    controller: &CoreHandle,
    binding: &NativeSessionBinding,
) -> Result {
    let frame_binding = NativeVideoBinding {
        source: 0,
        width: 64,
        height: 48,
        layout_epoch: 1,
    };
    let due = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if host
                .native_video_keyframe_needed(binding, frame_binding)
                .await?
            {
                return Ok::<_, NativeVideoError>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    due?;
    let mut encoder = nestlink_media_codec::Vp8Encoder::new(nestlink_media_codec::VideoConfig {
        width: 64,
        height: 48,
        fps: 30,
        bitrate_kbps: 1000,
    })?;
    let pts = host.native_video_capture_pts(binding, Instant::now())?;
    let encoded = encoder.encode(&[0, 255, 0, 255].repeat(64 * 48), pts, true)?;
    host.send_native_video_frame(binding, frame_binding, pts, encoded.keyframe, encoded.data)
        .await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(frame) = controller.poll_native_video()? {
                assert_eq!(
                    frame.sequence, 1,
                    "a new generation cannot inherit old video sequence"
                );
                assert_eq!((frame.width, frame.height), (64, 48));
                assert!(frame.pixels.chunks_exact(4).all(|pixel| pixel[1] > 240));
                return Ok::<_, NativeVideoError>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn product_route_set_recovers_after_total_old_node_loss_releases_pressed_input_and_requests_fresh_keyframe()
-> Result {
    let server = Server::start(None).await?;
    let mut admin = Sdk::connect(
        &server.config.origin,
        DeploymentTrust {
            deployment_id: server.config.deployment_id.clone(),
            permit_issuer: server.config.permit_issuer,
        },
        true,
    )
    .await?;
    admin.login("admin".into(), password(), None).await?;
    admin
        .set_policy(PolicyUpdate {
            expected_revision: 1,
            policy: NetworkPolicy {
                server_forwarding: "allow".into(),
                peer_path_mode: "relay_only".into(),
                public_ingress: "disabled".into(),
            },
        })
        .await?;
    let address = routed_ipv4()?;
    let mut initial_node = Node::start(&admin, address).await?;
    let mut standby_node = Node::start(&admin, address).await?;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let controller_id = controller.device_id.clone();
    let host_id = host.device_id.clone();
    let space = nestlink_auth::random_id();
    let mut policy = admin.configure_network_authority(&space, 0).await?;
    let grants = [nestlink_auth::random_id(), nestlink_auth::random_id()];
    let route = NativeRouteSetSettings {
        deployment_id: server.config.deployment_id.clone(),
        space_id: space.clone(),
        authority_key: server.network_authority_key,
        controller_membership_grant_id: grants[0].clone(),
        host_membership_grant_id: grants[1].clone(),
        node_ids: [initial_node.id.clone(), standby_node.id.clone()],
    };
    let config = || -> Result<NativeSessionConfig> {
        let mut config = NativeSessionConfig::new(Arc::new(NetworkMonitor::start()?))
            .with_route_set(route.clone())?;
        config.use_deployment_stun = false;
        config.private_network_prefixes = vec![format!("{address}/32")];
        config.supported_capabilities = vec!["vp8".into(), "opus".into()];
        Ok(config)
    };
    let mut controller_core =
        AppCore::with_identity_and_native_session(Limits::default(), controller, config()?)?;
    let mut host_core =
        AppCore::with_identity_and_native_session(Limits::default(), host, config()?)?;
    let controller = connect(&controller_core, &server).await?;
    let host = connect(&host_core, &server).await?;
    for (handle, name) in [(&controller, "controller"), (&host, "host")] {
        success(handle.submit(Action::EnrollLocalDevice {
            name: name.into(),
            platform: "linux-x11".into(),
            capabilities: vec![name.into(), "vp8".into(), "opus".into()],
            path_mode: "relay_only".into(),
        })?)
        .await?;
    }
    for device in [&controller_id, &host_id] {
        let member = admin
            .set_network_member(
                &space,
                device,
                NetworkMemberRequest {
                    expected_policy_revision: policy.revision,
                    expected_membership_epoch: 0,
                    role: SpaceRole::Member,
                },
            )
            .await?;
        policy = member.policy;
    }
    let expires = nestlink_remote::RuntimeClock::default().sample()?.unix_ms + 60_000;
    for (device, grant) in [(&controller_id, &grants[0]), (&host_id, &grants[1])] {
        admin
            .issue_network_membership(
                &space,
                device,
                NetworkIssueRequest {
                    grant_id: grant.clone(),
                    expected_policy_epoch: policy.policy_epoch,
                    expected_membership_epoch: 1,
                    expires_at_unix_ms: expires,
                },
            )
            .await?;
    }
    success(controller.submit(Action::RequestRemote {
        host_device_id: host_id,
        permissions: vec![Permission::View as i32, Permission::Input as i32],
        path_mode: "relay_only".into(),
        access: RemoteAccess::LocalApproval,
    })?)
    .await?;
    let request = controller
        .snapshot()
        .selected_request
        .data
        .as_ref()
        .ok_or("missing request")?
        .clone();
    success(host.submit(Action::ApproveRemote {
        request_id: request.id.clone(),
        expected_nonce: request.nonce.clone(),
        expected_policy_revision: request.policy_revision,
        choice: ApprovalChoice {
            approved: true,
            permissions: vec![Permission::View as i32, Permission::Input as i32],
            paths: vec![Path::Relay as i32],
        },
    })?)
    .await?;
    success(controller.submit(Action::IssueRemotePermit {
        request_id: request.id.clone(),
    })?)
    .await?;
    tokio::try_join!(
        session_success(controller.submit(Action::StartNativeSession {
            request_id: request.id.clone(),
            relay_node_id: None
        })?),
        session_success(host.submit(Action::StartNativeSession {
            request_id: request.id.clone(),
            relay_node_id: None
        })?),
    )?;
    let input_log = Arc::new(Mutex::new(Vec::new()));
    let (old_binding, old_input) = prepare_display(&host, &controller, input_log.clone()).await
        .map_err(|error| phase("initial display/input proof", error))?;
    video(&host, &controller, &old_binding).await.map_err(|error| phase("initial VP8 pixels", error))?;
    controller
        .send_native_input(
            &old_input,
            NativeInputAction::Key {
                code: 8,
                down: true,
            },
        )
        .await?;
    wait_input(&input_log, "Key { code: 8, down: true }").await.map_err(|error| phase("initial pressed key", error))?;
    let old_group = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let snapshot = controller.snapshot();
            if let Some(binding) = snapshot
                .native_session
                .data
                .as_ref()
                .and_then(|session| session.quality.as_ref())
                .and_then(|quality| quality.original_binding.as_ref())
            {
                break binding.transport_group;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await.map_err(|error| phase("original transport-group observation", error))?;
    // The actor really prepares the other original node; this is not a fake
    // proposal injected into a scheduler and does not carry business I/O.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if standby_node
                .control
                .counters()
                .is_ok_and(|counters| counters.opened_connections >= 2)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await.map_err(|error| phase("actual standby node pair", error))?;
    initial_node.close().await.map_err(|error| phase("total initial-node loss", error))?;
    wait_input(&input_log, "release-key:8").await.map_err(|error| phase("old input release", error))?;
    for handle in [&controller, &host] {
        wait_view(handle, |snapshot| {
            snapshot
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    session.status == NativeSessionStatus::Connected
                        && session.connection_generation == old_binding.connection_generation + 1
                })
        })
        .await.map_err(|error| phase("successor generation connected", error))?;
    }
    assert!(
        controller
            .send_native_input(
                &old_input,
                NativeInputAction::Key {
                    code: 9,
                    down: true
                }
            )
            .await
            .is_err()
    );
    assert!(
        host.configure_native_video_stream(&old_binding, 0, 64, 48, 1)
            .await
            .is_err()
    );
    assert!(
        controller.poll_native_video()?.is_none(),
        "old decoded pixels cannot cross the generation"
    );
    let resets = input_log
        .lock()
        .map_err(|_| "input log poisoned")?
        .iter()
        .filter(|event| event.as_str() == "reset")
        .count();
    assert_eq!(
        resets, 1,
        "old platform input must be joined exactly once before recovery"
    );
    let (new_binding, new_input) = prepare_display(&host, &controller, input_log.clone()).await?;
    assert_eq!(
        new_binding.connection_generation,
        old_binding.connection_generation + 1
    );
    assert_ne!(new_input, old_input);
    video(&host, &controller, &new_binding).await?;
    controller
        .send_native_input(
            &new_input,
            NativeInputAction::Key {
                code: 10,
                down: true,
            },
        )
        .await?;
    wait_input(&input_log, "Key { code: 10, down: true }").await?;
    assert!(
        !input_log
            .lock()
            .map_err(|_| "input log poisoned")?
            .iter()
            .any(|event| event == "Key { code: 9, down: true }")
    );
    wait_view(&controller, |snapshot| {
        snapshot
            .native_session
            .data
            .as_ref()
            .and_then(|session| session.quality.as_ref())
            .and_then(|quality| quality.original_binding.as_ref())
            .is_some_and(|binding| binding.transport_group != old_group)
    })
    .await?;
    assert_eq!(
        controller_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        host_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    standby_node.close().await?;
    Ok(())
}
