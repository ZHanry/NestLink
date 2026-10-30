//! Registered NRD2 nodes and the production management/SDK/business owners.
//! Explicit signed topology fixtures seed this component scenario. Continuous
//! production adjacency discovery/reporting is a separate required acceptance.
use super::*;
use nestlink_identity::{
    digest,
    network::NetworkVerification,
    network_topology::{
        SignedTopologyAdvertisement, verify_topology_advertisement, verify_topology_publisher,
    },
};
use nestlink_platform_files::{ApprovedReadRoot, FileRoots};
use nestlink_protocol::{
    api::{NetworkRemoteRelayChainRequest, NetworkTopologyPublisherRequest},
    network::PeerId,
    network_topology::{BootIncarnation, TopologyNeighbor, TopologyReport},
};
use nestlink_remote::files::{FileReadClient, FileReadServer, FileReadVerifier};
use std::collections::BTreeSet;

struct ChainNode {
    id: String,
    identity: Arc<NodeIdentity>,
    control: Arc<NodeControl>,
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
    async fn new(f: &Fixture) -> Result<Self> {
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
        let control = Arc::new(NodeControl::start(
            NodeConfig {
                deployment_id: f.permit.claims().deployment_id.clone(),
                node_id: id.clone(),
                control_origin: f.sdk.management_origin().into(),
                trusted_policy_issuer: f.sdk.health().node_policy_issuer.clone(),
                identity_key_file: "unused-nrd2-fixture-key".into(),
                service_usage_directory: Some(usage.path().to_path_buf()),
                roles: vec![NodeRole::NodeRelay as i32],
                allow_loopback_http: true,
            },
            NodeIdentity::from_seed(&seed),
        )?);
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
            node_quic::serve_with_chain_identity(endpoint, selector, signer, async move {
                if !*stopped.borrow() {
                    let _ = stopped.changed().await;
                }
            })
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
    let now = RuntimeClock::default().sample()?.unix_ms;
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: f.pin.authority_key(),
        deployment_id: &f.permit.claims().deployment_id,
        space_id: f.pin.space_id(),
        policy_epoch: policy.policy_epoch,
        now_ms: now,
        revoked_grant_ids: &revoked,
    };
    let leases = [
        nodes[0].2.authorize(NodeRole::NodeRelay, false)?,
        nodes[1].2.authorize(NodeRole::NodeRelay, false)?,
    ];
    let expires = (now + 6_000)
        .min(leases[0].expires_at_unix_ms)
        .min(leases[1].expires_at_unix_ms);
    let mut digests = Vec::new();
    for index in 0..2 {
        let (id, identity, _) = nodes[index];
        let incarnation = BootIncarnation {
            runtime_id: leases[index].runtime_id.clone(),
            runtime_generation: leases[index].runtime_generation,
        };
        let publisher = verify_topology_publisher(
            &publishers[index],
            &context,
            id,
            &identity.public_key(),
            &incarnation,
            &[],
        )?;
        let signed = identity.sign_topology_report(&TopologyReport {
            schema_version: 1,
            deployment_id: f.permit.claims().deployment_id.clone(),
            space_id: f.pin.space_id().into(),
            policy_epoch: policy.policy_epoch,
            node_id: id.clone(),
            peer: PeerId::from_public_key(&identity.public_key()),
            publisher_digest: publisher.digest(),
            incarnation: incarnation.clone(),
            sequence: 1,
            not_before_ms: now,
            expires_at_ms: expires,
            neighbors: vec![TopologyNeighbor {
                local: PeerId::from_public_key(&identity.public_key()),
                remote: PeerId::from_public_key(&nodes[1 - index].1.public_key()),
                local_endpoint_revision: 1,
                remote_endpoint_revision: 1,
                up: true,
            }],
            prefixes: Vec::new(),
        })?;
        let response = reqwest::Client::new()
            .post(format!(
                "{}/api/v3/network/spaces/{}/topology/reports/{id}",
                f.sdk.management_origin(),
                f.pin.space_id()
            ))
            .json(&signed)
            .send()
            .await?
            .error_for_status()?
            .json::<SignedTopologyAdvertisement>()
            .await?;
        digests.push(
            verify_topology_advertisement(&response, &publisher, &context, &incarnation, 0)?
                .digest(),
        );
    }
    let old = f
        .sdk
        .network_remote_relay(f.pin.space_id(), &f.allocation)
        .await?;
    let route = random_id();
    f.sdk
        .reserve_network_remote_chain(
            f.pin.space_id(),
            &f.controller,
            &f.permit,
            NetworkRemoteRelayChainRequest {
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
                topology_digests: digests.try_into().map_err(|_| "digests")?,
                device_id: f.controller.device_id.clone(),
                signature: String::new(),
            },
        )
        .await?;
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
    let mut server = FileReadServer::start(&mut host, 9, FileRoots::new(vec![root])?)?;
    let mut client = FileReadClient::attach(&mut controller, 9)?;
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
    server.shutdown(StopReason::ExplicitExit).await?;
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
