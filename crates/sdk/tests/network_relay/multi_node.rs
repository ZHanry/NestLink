//! Two independent NodeControl owners share only the real management service.
//! This is a lab qualification of explicit routes, not automatic failover or
//! two independently deployed Linux machines.
use super::*;

// Retain bounded, credential-free observations around the real failure. These
// facts cannot make a route ready or replace any live admission check.
fn report_node_state(label: &str, control: &NodeControl, f: &Fixture) {
    use nestlink_transport_stream::tls::CurrentClientPins;
    let Ok(sample) = RuntimeClock::default().sample() else {
        eprintln!("two-node {label}: diagnostic clock unavailable");
        return;
    };
    let now = sample.unix_ms;
    let lease_remaining = control
        .current_lease()
        .map(|lease| lease.expires_at_unix_ms.saturating_sub(now));
    let resources = control.resource_snapshot().map(|snapshot| {
        (
            snapshot.expires_at_unix_ms.saturating_sub(now),
            snapshot.network_routes.len(),
            snapshot.query.map(|query| query.request_sequence),
        )
    });
    eprintln!(
        "two-node {label}: lease_remaining_ms={lease_remaining:?} resources=(remaining_ms,routes,sequence){resources:?} controller_pin={} host_pin={} stopped={}",
        control.contains(&f.controller.identity.fingerprint()),
        control.contains(&f.host.identity.fingerprint()),
        *control.stopped().borrow(),
    );
}

struct SchedulerObservation(JoinHandle<()>);
impl Drop for SchedulerObservation {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl SchedulerObservation {
    fn start() -> Self {
        Self(tokio::spawn(async {
            let mut tick = tokio::time::interval(Duration::from_millis(100));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut previous = Instant::now();
            for _ in 0..300 {
                tick.tick().await;
                let elapsed = previous.elapsed();
                if elapsed >= Duration::from_millis(250) {
                    eprintln!("two-node scheduler observation gap_ms={}", elapsed.as_millis());
                }
                previous = Instant::now();
            }
        }))
    }
}

struct SecondNode {
    id: String,
    allocation: String,
    control: Arc<NodeControl>,
    listener: NetworkNodeListener,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<io::Result<()>>>,
    _usage: ServiceUsageDirectory,
}
impl Drop for SecondNode {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        self.control.stop();
        self.listener.request_close();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl SecondNode {
    async fn new(f: &Fixture) -> Result<Self> {
        let seed = random_bytes::<32>();
        let identity = NodeIdentity::from_seed(&seed);
        let id = random_id();
        f.sdk
            .register_node(NodeRegistration {
                id: id.clone(),
                name: "second independent relay runtime".into(),
                public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
                roles: vec![NodeRole::NodeRelay as i32],
                max_connections: 8,
                bytes_per_second: 16 * 1024 * 1024,
            })
            .await?;
        let mut usage = ServiceUsageDirectory::new()?;
        let control = Arc::new(NodeControl::start(
            NodeConfig {
                deployment_id: f.permit.claims().deployment_id.clone(),
                node_id: id.clone(),
                control_origin: f.sdk.management_origin().into(),
                trusted_policy_issuer: f.sdk.health().node_policy_issuer.clone(),
                identity_key_file: "unused-second-test-identity".into(),
                service_usage_directory: Some(usage.path().to_path_buf()),
                roles: vec![NodeRole::NodeRelay as i32],
                allow_loopback_http: true,
            },
            identity,
        )?);
        let mut pending = PendingFixture {
            http_task: None,
            control: Some(control.clone()),
        };
        usage.track(&control)?;
        let listener = routed::node_listener_with_legacy(
            "127.0.0.1:0".parse()?,
            &NodeIdentity::from_seed(&seed),
            control.clone(),
        )?;
        f.sdk
            .set_node_endpoints(
                &id,
                NodeEndpointsUpdate {
                    expected_revision: 0,
                    endpoints: NodeEndpoints {
                        quic_uri: Some(format!("quic://{}", listener.local_addr()?)),
                        wss_origin: None,
                        allow_loopback: true,
                    },
                },
            )
            .await?;
        let lease = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(lease) = control.authorize(NodeRole::NodeRelay, false) {
                    break lease;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let first = f
            .sdk
            .network_remote_relay(f.pin.space_id(), &f.allocation)
            .await?;
        let decode_expiry = |value: &nestlink_protocol::api::NetworkGrantView| -> Result<u64> {
            Ok(nestlink_protocol::network::GrantClaims::decode_canonical(
                &URL_SAFE_NO_PAD.decode(&value.claims)?,
            )?
            .scope()
            .expires_at_ms)
        };
        let expires = lease
            .expires_at_unix_ms
            .min(decode_expiry(&first.path.controller_membership)?)
            .min(decode_expiry(&first.path.host_membership)?)
            .min(f.permit.claims().expires_at_unix_ms);
        let policy = f.sdk.network_policy(f.pin.space_id()).await?;
        let allocation = random_id();
        f.sdk
            .reserve_network_remote_relay(
                f.pin.space_id(),
                &f.controller,
                &f.permit,
                NetworkRemoteRelayRequest {
                    path: NetworkRemotePathRequest {
                        connectivity_grant_id: random_id(),
                        path_grant_id: random_id(),
                        controller_membership_grant_id: first.path.controller_membership.grant_id,
                        host_membership_grant_id: first.path.host_membership.grant_id,
                        expected_policy_epoch: policy.policy_epoch,
                        expires_at_unix_ms: expires,
                    },
                    transit_grant_id: random_id(),
                    allocation: RelayAllocationRequest {
                        allocation_id: allocation.clone(),
                        node_id: id.clone(),
                        device_id: f.controller.device_id.clone(),
                        signature: String::new(),
                    },
                },
            )
            .await?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while !control.resource_snapshot().is_ok_and(|snapshot| {
                snapshot.network_routes.iter().any(|resource| {
                    resource
                        .allocation
                        .as_ref()
                        .is_some_and(|grant| grant.allocation_id == allocation)
                })
            }) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let endpoint = listener.endpoint()?.clone();
        let shared = control.clone();
        let (shutdown, mut stopped) = watch::channel(false);
        let task = tokio::spawn(async move {
            node_quic::serve(endpoint, shared, async move {
                if !*stopped.borrow() {
                    let _ = stopped.changed().await;
                }
            })
            .await
        });
        pending.control = None;
        Ok(Self {
            id,
            allocation,
            control,
            listener,
            shutdown,
            task: Some(task),
            _usage: usage,
        })
    }
    async fn finish(&mut self) -> Result {
        self.shutdown.send_replace(true);
        if let Some(task) = self.task.as_mut() {
            tokio::time::timeout(Duration::from_secs(5), task).await???;
        }
        self.task = None;
        self.listener
            .close_and_wait(Instant::now() + Duration::from_secs(5))
            .await?;
        Ok(())
    }
}

async fn transfer(controller: &mut ChannelRuntime, host: &ChannelRuntime, byte: u8) -> Result {
    let payload = vec![byte; 256 * 1024];
    let deadline = Instant::now() + Duration::from_secs(5);
    for chunk in payload.chunks(nestlink_protocol::FILE_CHUNK_BYTES as usize) {
        let (sent, received) = tokio::time::timeout_at(deadline, async {
            tokio::join!(host.send(Channel::FileRead, chunk), controller.receive())
        })
        .await?;
        sent?;
        let frame = received?;
        assert_eq!(frame.channel, Channel::FileRead);
        assert_eq!(frame.payload, chunk);
    }
    Ok(())
}

#[tokio::test]
async fn two_registered_nodes_carry_distinct_authorized_routes_and_one_revoke_preserves_the_other()
-> Result {
    let _scheduler = SchedulerObservation::start();
    let started = Instant::now();
    let mut f = Fixture::new().await?;
    eprintln!("two-node first runtime ready elapsed_ms={}", started.elapsed().as_millis());
    let mut second = SecondNode::new(&f).await?;
    eprintln!("two-node both runtimes ready elapsed_ms={}", started.elapsed().as_millis());
    let first = f
        .sdk
        .network_remote_relay(f.pin.space_id(), &f.allocation)
        .await?;
    let other = f
        .sdk
        .network_remote_relay(f.pin.space_id(), &second.allocation)
        .await?;
    assert_ne!(first.node.node_id, second.id);
    assert_eq!(other.node.node_id, second.id);
    assert_ne!(first.path.path.grant_id, other.path.path.grant_id);
    let discovery = f.sdk.discover_relay_nodes(&f.controller, &f.permit).await?;
    assert!(
        discovery
            .nodes()
            .iter()
            .any(|node| node.node_id == first.node.node_id)
    );
    assert!(
        discovery
            .nodes()
            .iter()
            .any(|node| node.node_id == second.id)
    );
    let first_binds = [unused_udp()?, unused_udp()?];
    let second_binds = [unused_udp()?, unused_udp()?];
    report_node_state("first before connection", &f.control, &f);
    report_node_state("second before first connection", &second.control, &f);
    let (mut c1, mut h1, _stop1) = f
        .channels(first_binds)
        .await
        .map_err(|error| {
            report_node_state("first after failed connection", &f.control, &f);
            report_node_state("second after failed first connection", &second.control, &f);
            format!("two-node first route establishment after {}ms: {error}", started.elapsed().as_millis())
        })?;
    eprintln!("two-node first route proved elapsed_ms={}", started.elapsed().as_millis());
    report_node_state("second before connection", &second.control, &f);
    let (mut c2, mut h2, _stop2) = f
        .channels_for(&second.allocation, second_binds)
        .await
        .map_err(|error| {
            report_node_state("first after failed second connection", &f.control, &f);
            report_node_state("second after failed connection", &second.control, &f);
            format!("two-node second route establishment after {}ms: {error}", started.elapsed().as_millis())
        })?;
    transfer(&mut c1, &h1, 31)
        .await
        .map_err(|error| format!("two-node first route before revocation: {error}"))?;
    transfer(&mut c2, &h2, 93)
        .await
        .map_err(|error| format!("two-node second route before revocation: {error}"))?;
    assert_eq!(f.control.counters()?.opened_connections, 2);
    assert_eq!(second.control.counters()?.opened_connections, 2);
    assert!(f.control.counters()?.admitted_bytes > 262_144);
    assert!(second.control.counters()?.admitted_bytes > 262_144);
    f.sdk.revoke_node(&first.node.node_id).await?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let (one, two) = tokio::time::timeout_at(deadline, async {
        tokio::try_join!(c1.wait_stopped(), h1.wait_stopped())
    })
    .await??;
    assert_eq!(one.reason, StopReason::Revoked);
    assert_eq!(two.reason, StopReason::Revoked);
    assert!(
        f.sdk
            .network_remote_relay(f.pin.space_id(), &f.allocation)
            .await
            .is_err()
    );
    assert_eq!(
        f.sdk
            .network_remote_relay(f.pin.space_id(), &second.allocation)
            .await?
            .node
            .node_id,
        second.id
    );
    transfer(&mut c2, &h2, 147).await.map_err(|error| {
        format!("two-node surviving route after other node revocation: {error}")
    })?;
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 2);
    drop((c1, h1));
    let _first = rebind(&first_binds)?;
    c2.shutdown(StopReason::ExplicitExit).await?;
    h2.shutdown(StopReason::ExplicitExit).await?;
    drop((c2, h2));
    let _second = rebind(&second_binds)?;
    let node_addresses = [f.node.local_addr()?, second.listener.local_addr()?];
    second.finish().await?;
    // The revoked runtime may already have stopped itself. Reap that same
    // listener task and require its specific refusal, rather than treating an
    // arbitrary task failure as successful cleanup.
    f.control.stop();
    if let Some(task) = f.node_task.as_mut() {
        let result = tokio::time::timeout(Duration::from_secs(5), task).await??;
        assert!(result.is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied));
    }
    f.node_task = None;
    f.finish().await?;
    let _nodes = rebind(&node_addresses)?;
    Ok(())
}
