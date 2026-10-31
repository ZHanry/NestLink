//! Registered NRD2 nodes and the production management/SDK/business owners.
//! Real current-authority probes and periodic reports seed the registered route.
use super::*;
use nestlink_identity::{
    digest,
    network::NetworkVerification,
    network_topology::{
        SignedTopologyPublisher, verify_topology_advertisement, verify_topology_publisher,
        verify_topology_update,
    },
};
use nestlink_platform_files::{ApprovedReadRoot, FileRoots};
use nestlink_protocol::{
    api::{NetworkRemoteRelayChainRequest, NetworkTopologyPublisherRequest, NetworkTopologyQuery},
    network::{GrantClaims, PeerId},
    network_topology::{BootIncarnation, TopologyAdvertisement, TopologySync},
};
use nestlink_remote::files::{FileReadClient, FileReadServer, FileReadVerifier, FileShutdown};
use nestlink_sdk::SdkError;
use std::collections::BTreeSet;

pub(super) struct ChainNode {
    pub(super) id: String,
    identity: Arc<NodeIdentity>,
    pub(super) control: Arc<NodeControl>,
    listener: NetworkNodeListener,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<io::Result<()>>>,
    _usage: ServiceUsageDirectory,
}
impl Drop for ChainNode {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        self.control.stop();
        self.listener.request_close();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl ChainNode {
    pub(super) async fn new(f: &Fixture) -> Result<Self> {
        let seed = random_bytes::<32>();
        let identity = Arc::new(NodeIdentity::from_seed(&seed));
        let id = random_id();
        f.sdk
            .register_node(NodeRegistration {
                id: id.clone(),
                name: "second NRD2 registered relay".into(),
                public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
                roles: vec![NodeRole::NodeRelay as i32],
                max_connections: 8,
                bytes_per_second: 16 * 1024 * 1024,
            })
            .await?;
        let mut usage = ServiceUsageDirectory::new()?;
        let config = NodeConfig {
            deployment_id: f.permit.claims().deployment_id.clone(),
            node_id: id.clone(),
            control_origin: f.sdk.management_origin().into(),
            trusted_policy_issuer: f.sdk.health().node_policy_issuer.clone(),
            identity_key_file: "unused-nrd2-fixture-key".into(),
            service_usage_directory: Some(usage.path().to_path_buf()),
            roles: vec![NodeRole::NodeRelay as i32],
            allow_loopback_http: true,
        };
        let reporter = Arc::new(nestlink_node::control::TopologyReporter::new(
            config.clone(),
            NodeIdentity::from_seed(&seed),
        )?);
        let control = Arc::new(NodeControl::start(config, NodeIdentity::from_seed(&seed))?);
        let mut pending = PendingFixture {
            http_task: None,
            control: Some(control.clone()),
        };
        usage.track(&control)?;
        let listener =
            routed::node_listener_with_legacy("127.0.0.1:0".parse()?, &identity, control.clone())?;
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
        tokio::time::timeout(Duration::from_secs(3), async {
            while control.authorize(NodeRole::NodeRelay, false).is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let (shutdown, mut stopped) = watch::channel(false);
        let endpoint = listener.endpoint()?.clone();
        let selector = nestlink_server::relay_selector::RelaySelector::new(control.clone());
        let signer = identity.clone();
        let task = tokio::spawn(async move {
            node_quic::serve_with_topology_identity(
                endpoint,
                selector,
                signer,
                reporter,
                async move {
                    if !*stopped.borrow() {
                        let _ = stopped.changed().await;
                    }
                },
            )
            .await
        });
        pending.control = None;
        Ok(Self {
            id,
            identity,
            control,
            listener,
            shutdown,
            task: Some(task),
            _usage: usage,
        })
    }
    pub(super) async fn finish(&mut self) -> Result {
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
async fn reserve(f: &Fixture, second: &ChainNode) -> Result<String> {
    let nodes = [
        (&f.node_id, &f.node_identity, &f.control),
        (&second.id, &second.identity, &second.control),
    ];
    let policy = f.sdk.network_policy(f.pin.space_id()).await?;
    let mut publishers = Vec::new();
    for index in 0..2 {
        publishers.push(
            f.sdk
                .issue_network_topology_publisher(
                    f.pin.space_id(),
                    nodes[index].0,
                    NetworkTopologyPublisherRequest {
                        publisher_id: random_id(),
                        expected_policy_epoch: policy.policy_epoch,
                        allowed_node_ids: vec![nodes[1 - index].0.clone()],
                        route_export_grant_ids: Vec::new(),
                        expires_at_ms: RuntimeClock::default().sample()?.unix_ms + 60_000,
                    },
                )
                .await?,
        );
    }
    let first_digests = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Some(digests) =
                topology_digests(f, second, &publishers, policy.policy_epoch).await?
            {
                break Result::Ok(digests);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    let now = RuntimeClock::default().sample()?.unix_ms;
    let leases = [
        nodes[0].2.authorize(NodeRole::NodeRelay, false)?,
        nodes[1].2.authorize(NodeRole::NodeRelay, false)?,
    ];
    let expires = (now + 6_000)
        .min(leases[0].expires_at_unix_ms)
        .min(leases[1].expires_at_unix_ms);
    let old = f
        .sdk
        .network_remote_relay(f.pin.space_id(), &f.allocation)
        .await?;
    let route = random_id();
    let mut request = NetworkRemoteRelayChainRequest {
        route_id: route.clone(),
        path: NetworkRemotePathRequest {
            connectivity_grant_id: random_id(),
            path_grant_id: random_id(),
            controller_membership_grant_id: old.path.controller_membership.grant_id,
            host_membership_grant_id: old.path.host_membership.grant_id,
            expected_policy_epoch: policy.policy_epoch,
            expires_at_unix_ms: expires,
        },
        node_ids: [f.node_id.clone(), second.id.clone()],
        transit_grant_ids: [random_id(), random_id()],
        topology_digests: first_digests,
        device_id: f.controller.device_id.clone(),
        signature: String::new(),
    };
    let reservation_started = Instant::now();
    let mut attempt = 0u32;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            attempt += 1;
            let post_started = Instant::now();
            let result = f
                .sdk
                .reserve_network_remote_chain(
                    f.pin.space_id(),
                    &f.controller,
                    &f.permit,
                    request.clone(),
                )
                .await;
            let status = match &result {
                Ok(_) => "created".to_owned(),
                Err(SdkError::Api(status, _)) => status.as_u16().to_string(),
                Err(_) => "sdk_error".to_owned(),
            };
            eprintln!(
                "registered chain reservation: attempt={attempt}, post_us={}, total_us={}, status={status}, original_expires_at_ms={expires}",
                post_started.elapsed().as_micros(), reservation_started.elapsed().as_micros()
            );
            match result {
                Ok(_) => break Result::Ok(()),
                Err(SdkError::Api(status, _)) if status == reqwest::StatusCode::CONFLICT => {
                    // Periodic real reports can replace the exact head between
                    // query and reservation. Keep every UUID and original expiry.
                    loop {
                        if let Some(digests) =
                            topology_digests(f, second, &publishers, policy.policy_epoch).await?
                        {
                            request.topology_digests = digests;
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await??;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if [&f.control, &second.control].into_iter().all(|control| {
                control
                    .network_chain_routes()
                    .is_ok_and(|routes| !routes.is_empty())
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(route)
}
async fn topology_digests(
    f: &Fixture,
    second: &ChainNode,
    publishers: &[SignedTopologyPublisher],
    policy_epoch: u64,
) -> Result<Option<[[u8; 32]; 2]>> {
    topology_digests_in_space(f, second, publishers, policy_epoch, f.pin.space_id()).await
}
async fn topology_digests_in_space(
    f: &Fixture,
    second: &ChainNode,
    publishers: &[SignedTopologyPublisher],
    policy_epoch: u64,
    space_id: &str,
) -> Result<Option<[[u8; 32]; 2]>> {
    let nonce = random_bytes::<32>();
    let query_started = Instant::now();
    let signed = f
        .sdk
        .network_topology_update(
            space_id,
            NetworkTopologyQuery {
                after_cursor: None,
                nonce,
            },
        )
        .await?;
    let query_elapsed = query_started.elapsed();
    let verification_started = Instant::now();
    let now = RuntimeClock::default().sample()?.unix_ms;
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: f.pin.authority_key(),
        deployment_id: &f.permit.claims().deployment_id,
        space_id,
        policy_epoch,
        now_ms: now,
        revoked_grant_ids: &revoked,
    };
    let update = verify_topology_update(&signed, &context, &nonce)?;
    let TopologySync::Full { advertisements, .. } = &update.claims().sync else {
        return Err("expected full topology".into());
    };
    let nodes = [
        (&f.node_id, &f.node_identity, &f.control),
        (&second.id, &second.identity, &second.control),
    ];
    let mut digests = [[0; 32]; 2];
    for signed in advertisements {
        let claims = TopologyAdvertisement::decode_canonical(&signed.claims)?;
        let Some(index) = nodes
            .iter()
            .position(|(id, _, _)| **id == claims.report.node_id)
        else {
            continue;
        };
        if claims.expires_at_ms <= now.saturating_add(200)
            || !claims.report.neighbors.iter().any(|neighbor| {
                neighbor.up
                    && neighbor.remote == PeerId::from_public_key(&nodes[1 - index].1.public_key())
                    && neighbor.local_endpoint_revision == 1
                    && neighbor.remote_endpoint_revision == 1
            })
        {
            continue;
        }
        let lease = nodes[index].2.authorize(NodeRole::NodeRelay, false)?;
        let incarnation = BootIncarnation {
            runtime_id: lease.runtime_id,
            runtime_generation: lease.runtime_generation,
        };
        let publisher = verify_topology_publisher(
            &publishers[index],
            &context,
            nodes[index].0,
            &nodes[index].1.public_key(),
            &incarnation,
            &[],
        )?;
        let advertisement =
            verify_topology_advertisement(signed, &publisher, &context, &incarnation, 0)?;
        assert!(
            advertisement.claims().report.sequence > 1,
            "the real owner must advance its sequence after initial down observations"
        );
        digests[index] = advertisement.digest();
        eprintln!(
            "registered topology head: position={index}, sequence={}, remaining_ms={}",
            advertisement.claims().report.sequence,
            advertisement
                .claims()
                .expires_at_ms
                .saturating_sub(RuntimeClock::default().sample()?.unix_ms)
        );
    }
    eprintln!(
        "registered topology query: query_us={}, verification_us={}, total_us={}, complete={}",
        query_elapsed.as_micros(),
        verification_started.elapsed().as_micros(),
        query_started.elapsed().as_micros(),
        !digests.contains(&[0; 32])
    );
    Ok((!digests.contains(&[0; 32])).then_some(digests))
}
struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!("nestlink-registered-chain-{}", random_id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("source"));
        let _ = std::fs::remove_dir(&self.0);
    }
}
#[tokio::test]
async fn registered_nrd2_nodes_read_an_approved_os_file_and_revoke_both_original_hops() -> Result {
    transfer(true).await
}
#[tokio::test]
async fn registered_nrd2_nodes_keep_host_initiated_quic_and_controller_business_permissions()
-> Result {
    transfer(false).await
}
#[tokio::test]
async fn registered_topology_owner_isolates_a_revoked_space_on_the_same_real_neighbor() -> Result {
    let mut f = Fixture::with_peer_order(Some(true)).await?;
    let mut second = ChainNode::new(&f).await?;
    let other_space = random_id();
    let other_policy = f.sdk.configure_network_authority(&other_space, 0).await?;
    assert_eq!(
        other_policy.authority_public_key,
        URL_SAFE_NO_PAD.encode(f.pin.authority_key())
    );
    let nodes = [&f.node_id, &second.id];
    let mut other_publishers = Vec::new();
    for index in 0..2 {
        other_publishers.push(
            f.sdk
                .issue_network_topology_publisher(
                    &other_space,
                    nodes[index],
                    NetworkTopologyPublisherRequest {
                        publisher_id: random_id(),
                        expected_policy_epoch: other_policy.policy_epoch,
                        allowed_node_ids: vec![nodes[1 - index].clone()],
                        route_export_grant_ids: Vec::new(),
                        expires_at_ms: RuntimeClock::default().sample()?.unix_ms + 60_000,
                    },
                )
                .await?,
        );
    }
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if topology_digests_in_space(
                &f,
                &second,
                &other_publishers,
                other_policy.policy_epoch,
                &other_space,
            )
            .await?
            .is_some()
            {
                break Result::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    let route = reserve(&f, &second).await?;
    let before = f.sdk.network_remote_chain(f.pin.space_id(), &route).await?;
    let path = GrantClaims::decode_canonical(&URL_SAFE_NO_PAD.decode(&before.path.path.claims)?)?;
    let original_expiry = path.scope().expires_at_ms;
    f.sdk
        .revoke_network_topology_publisher(&other_space, &f.node_id)
        .await?;
    let mut readbacks = 0;
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut withdrawn_at = None;
        loop {
            let current = f.sdk.network_remote_chain(f.pin.space_id(), &route).await?;
            let path =
                GrantClaims::decode_canonical(&URL_SAFE_NO_PAD.decode(&current.path.path.claims)?)?;
            assert_eq!(path.scope().expires_at_ms, original_expiry);
            assert!(RuntimeClock::default().sample()?.unix_ms < original_expiry);
            readbacks += 1;
            if withdrawn_at.is_none()
                && f.control.network_topology_authority(&other_space).is_err()
                && second
                    .control
                    .network_topology_authority(&other_space)
                    .is_ok_and(|authority| {
                        authority
                            .neighbors
                            .iter()
                            .all(|neighbor| neighbor.node.node_id != f.node_id)
                    })
            {
                withdrawn_at = Some(Instant::now());
            }
            if withdrawn_at.is_some_and(|at| at.elapsed() >= Duration::from_millis(1300)) {
                break Result::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    assert!(readbacks >= 2);
    let addresses = [f.node.local_addr()?, second.listener.local_addr()?];
    second.finish().await?;
    f.finish().await?;
    let _nodes = rebind(&addresses)?;
    eprintln!(
        "registered topology owner: shared_real_neighbor_spaces=2, revoked_other_space=true, original_chain_survives_report_ttl=true, original_grant_expiry_unchanged=true, released_udp_sockets=2"
    );
    Ok(())
}
#[tokio::test]
async fn registered_topology_owner_withdraws_a_stopped_real_neighbor_before_original_chain_expiry()
-> Result {
    let mut f = Fixture::with_peer_order(Some(true)).await?;
    let mut second = ChainNode::new(&f).await?;
    let route = reserve(&f, &second).await?;
    let before = f.sdk.network_remote_chain(f.pin.space_id(), &route).await?;
    let path = GrantClaims::decode_canonical(&URL_SAFE_NO_PAD.decode(&before.path.path.claims)?)?;
    let original_expiry = path.scope().expires_at_ms;
    let nodes = [f.node.local_addr()?, second.listener.local_addr()?];
    second.finish().await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match f.sdk.network_remote_chain(f.pin.space_id(), &route).await {
                Err(SdkError::Api(status, _)) if status == reqwest::StatusCode::FORBIDDEN => {
                    break Result::Ok(());
                }
                Err(error) => return Err(error.into()),
                Ok(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    })
    .await??;
    assert!(
        RuntimeClock::default().sample()?.unix_ms < original_expiry,
        "actual probe withdrawal must retire the route before its original grant expiry"
    );
    f.finish().await?;
    let _nodes = rebind(&nodes)?;
    eprintln!(
        "registered topology owner: real_neighbor_stopped=true, original_unexpired_chain_retired=true, released_udp_sockets=2"
    );
    Ok(())
}
async fn transfer(controller_first: bool) -> Result {
    let mut f = Fixture::with_peer_order(Some(controller_first)).await?;
    let mut second = ChainNode::new(&f).await?;
    let route = reserve(&f, &second).await?;
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    let c = f
        .sdk
        .verified_network_remote_chain(&f.pin, &f.controller, &f.permit, &host_key, &route)
        .await?;
    let h = f
        .sdk
        .verified_network_remote_chain(&f.pin, &f.host, &f.permit, &controller_key, &route)
        .await?;
    let addresses = [unused_udp()?, unused_udp()?];
    let (_keep, stop) = watch::channel(None);
    let (_cancel, cancel) = watch::channel(false);
    let policy = AddressPolicy::new(&[])?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut controller, mut host) = tokio::try_join!(
        f.sdk.connect_network_remote_chain(
            c,
            addresses[0],
            &f.controller,
            &host_key,
            f.setup(EndpointRole::Controller, stop.clone())?,
            &policy,
            cancel.clone(),
            deadline
        ),
        f.sdk.connect_network_remote_chain(
            h,
            addresses[1],
            &f.host,
            &controller_key,
            f.setup(EndpointRole::Host, stop)?,
            &policy,
            cancel,
            deadline
        ),
    )?;
    assert_eq!(
        controller.lease_control().current_native_permit()?.digest(),
        f.permit.digest()
    );
    assert_eq!(
        host.lease_control().current_native_permit()?.digest(),
        f.permit.digest()
    );
    assert!(
        matches!(controller.send(Channel::Input,b"unapproved").await,
        Err(nestlink_remote::RemoteError::Authorization(ref error)) if error.code==nestlink_protocol::ErrorCode::PermissionRequired)
    );
    let directory = Directory::new()?;
    let bytes: Vec<_> = (0..98_335).map(|index| (index % 251) as u8).collect();
    std::fs::write(directory.0.join("source"), &bytes)?;
    let root_id = random_id();
    let (root, _consent) =
        ApprovedReadRoot::open(&root_id, &directory.0, nestlink_protocol::FILE_SIZE_BYTES)?;
    let generation = f.permit.claims().connection_generation;
    let mut server = FileReadServer::start(&mut host, generation, FileRoots::new(vec![root])?)?;
    let mut client = FileReadClient::attach(&mut controller, generation)?;
    let mut download = tokio::time::timeout_at(
        deadline,
        client.open(&random_id(), &root_id, "source", 0, None),
    )
    .await??;
    assert_eq!(download.manifest().sha256, digest(&bytes));
    let mut verifier = FileReadVerifier::new(download.manifest().clone())?;
    let mut received = Vec::new();
    while let Some(chunk) = tokio::time::timeout_at(deadline, client.next(&mut download)).await?? {
        verifier.accept(&chunk)?;
        received.extend_from_slice(&chunk.data);
    }
    verifier.finish()?;
    assert!(download.source_verified());
    assert_eq!(received, bytes);
    client.retire()?;
    f.sdk
        .revoke_network_remote_chain(f.pin.space_id(), &route)
        .await?;
    let cleanup = Instant::now() + Duration::from_secs(5);
    let (a, b) = tokio::time::timeout_at(cleanup, async {
        tokio::try_join!(controller.wait_stopped(), host.wait_stopped())
    })
    .await??;
    assert_eq!(a.reason, StopReason::Revoked);
    assert_eq!(b.reason, StopReason::Revoked);
    // FileReadServer::shutdown stops its entire proved lease. Collect this
    // worker only after both original sessions independently observed revoke.
    assert_eq!(
        tokio::time::timeout_at(cleanup, server.shutdown(b.reason)).await??,
        FileShutdown::Finished
    );
    assert!(server.monitor().status().finished);
    assert!(!server.monitor().status().cleanup_timed_out);
    drop((controller, host));
    let _clients = rebind(&addresses)?;
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 3);
    assert!(
        f.sdk
            .verified_network_remote_chain(&f.pin, &f.controller, &f.permit, &host_key, &route)
            .await
            .is_err()
    );
    let nodes = [f.node.local_addr()?, second.listener.local_addr()?];
    second.finish().await?;
    f.finish().await?;
    let _nodes = rebind(&nodes)?;
    eprintln!(
        "registered NRD2: controller_first={controller_first}, approved_os_file_bytes={}, revoked_both_hops=true, released_udp_sockets=4",
        bytes.len()
    );
    Ok(())
}
