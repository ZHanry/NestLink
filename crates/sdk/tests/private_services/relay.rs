//! Real private-service business over the registered NRD1/NRD2 resource stream.
//! No remote request, remote permit, fabricated node snapshot or legacy relay
//! allocation supplies the independent private-service authority in these tests.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{
    network::NetworkVerification,
    network_topology::{
        SignedTopologyPublisher, verify_topology_advertisement, verify_topology_publisher,
        verify_topology_update,
    },
    nodes::NodeIdentity,
};
use nestlink_node::control::{NodeConfig, NodeControl, TopologyReporter};
use nestlink_protocol::{
    NodeRole,
    network::{GrantClaims, PeerId, Purpose},
    network_topology::{BootIncarnation, TopologyAdvertisement, TopologySync},
};
use nestlink_sdk::{
    SdkError,
    services::{PrivateServiceHost, PrivateServiceRelayPolicy},
};
use nestlink_transport_quic::routed::{self, NetworkNodeListener};
use std::{collections::BTreeSet, io};
use tokio::{sync::watch, task::JoinHandle, time::Instant};
#[path = "../../../node/tests/support/service_usage_directory.rs"]
mod service_usage_directory;
use service_usage_directory::ServiceUsageDirectory;

struct RelayNode {
    id: String,
    identity: Arc<NodeIdentity>,
    control: Arc<NodeControl>,
    listener: NetworkNodeListener,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<io::Result<()>>>,
    _usage: ServiceUsageDirectory,
}
impl Drop for RelayNode {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.control.stop();
        self.listener.request_close();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
struct PendingControl(Option<Arc<NodeControl>>);
impl Drop for PendingControl {
    fn drop(&mut self) {
        if let Some(control) = &self.0 {
            control.stop();
        }
    }
}
impl RelayNode {
    async fn start(sdk: &Sdk) -> Result<Self> {
        let seed = nestlink_auth::random_bytes::<32>();
        let identity = Arc::new(NodeIdentity::from_seed(&seed));
        let id = random_id();
        sdk.register_node(NodeRegistration {
            id: id.clone(),
            name: "real private-service relay".into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            roles: vec![NodeRole::NodeRelay as i32],
            max_connections: 8,
            bytes_per_second: 16 * 1024 * 1024,
        })
        .await?;
        let mut usage = ServiceUsageDirectory::new()?;
        let config = NodeConfig {
            deployment_id: sdk.health().deployment_id.clone(),
            node_id: id.clone(),
            control_origin: sdk.management_origin().into(),
            trusted_policy_issuer: sdk.health().node_policy_issuer.clone(),
            identity_key_file: "unused-private-relay-fixture-key".into(),
            service_usage_directory: Some(usage.path().to_path_buf()),
            roles: vec![NodeRole::NodeRelay as i32],
            allow_loopback_http: true,
        };
        let reporter = Arc::new(TopologyReporter::new(
            config.clone(),
            NodeIdentity::from_seed(&seed),
        )?);
        let control = Arc::new(NodeControl::start(config, NodeIdentity::from_seed(&seed))?);
        let mut pending = PendingControl(Some(control.clone()));
        usage.track(&control)?;
        let listener = routed::node_listener_with_legacy(
            "127.0.0.1:0".parse()?,
            &identity,
            control.clone(),
        )?;
        sdk.set_node_endpoints(
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
        let endpoint = listener.endpoint()?.clone();
        let selector = nestlink_server::relay_selector::RelaySelector::new(control.clone());
        let signer = identity.clone();
        let (stop, mut stopped) = watch::channel(false);
        let task = tokio::spawn(async move {
            nestlink_server::node_quic::serve_with_topology_identity(
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
        pending.0 = None;
        Ok(Self {
            id,
            identity,
            control,
            listener,
            stop,
            task: Some(task),
            _usage: usage,
        })
    }
    async fn finish(&mut self) -> Result {
        let address = self.listener.local_addr()?;
        self.stop.send_replace(true);
        if let Some(task) = self.task.as_mut() {
            tokio::time::timeout(Duration::from_secs(5), task).await???;
        }
        self.task = None;
        self.listener
            .close_and_wait(Instant::now() + Duration::from_secs(5))
            .await?;
        self.control.stop();
        drop(std::net::UdpSocket::bind(address)?);
        Ok(())
    }
}

struct Relays {
    nodes: Vec<RelayNode>,
    publishers: Vec<SignedTopologyPublisher>,
    authority: [u8; 32],
    space: String,
    deployment: String,
    epoch: u64,
}
impl Relays {
    async fn start(f: &Fixture, hops: usize) -> Result<Self> {
        assert!((1..=2).contains(&hops));
        let policy = f.sdk.network_policy(&f.exposure.space_id).await?;
        let authority = URL_SAFE_NO_PAD
            .decode(&policy.authority_public_key)?
            .try_into()
            .map_err(|_| "bad fixture network authority")?;
        let mut nodes = Vec::new();
        for _ in 0..hops {
            nodes.push(RelayNode::start(&f.sdk).await?);
        }
        let mut publishers = Vec::new();
        if hops == 2 {
            for index in 0..2 {
                publishers.push(
                    f.sdk
                        .issue_network_topology_publisher(
                            &f.exposure.space_id,
                            &nodes[index].id,
                            NetworkTopologyPublisherRequest {
                                publisher_id: random_id(),
                                expected_policy_epoch: policy.policy_epoch,
                                allowed_node_ids: vec![nodes[1 - index].id.clone()],
                                route_export_grant_ids: Vec::new(),
                                expires_at_ms: wall_ms()? + 60_000,
                            },
                        )
                        .await?,
                );
            }
        }
        let relays = Self {
            nodes,
            publishers,
            authority,
            space: f.exposure.space_id.clone(),
            deployment: f.deployment.clone(),
            epoch: policy.policy_epoch,
        };
        relays.heads(&f.sdk).await?;
        Ok(relays)
    }
    async fn heads(&self, sdk: &Sdk) -> Result<Vec<[u8; 32]>> {
        if self.nodes.len() == 1 {
            return Ok(Vec::new());
        }
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                let nonce = nestlink_auth::random_bytes::<32>();
                let signed = sdk
                    .network_topology_update(
                        &self.space,
                        NetworkTopologyQuery {
                            after_cursor: None,
                            nonce,
                        },
                    )
                    .await?;
                let now = wall_ms()?;
                let revoked = BTreeSet::new();
                let context = NetworkVerification {
                    authority_key: &self.authority,
                    deployment_id: &self.deployment,
                    space_id: &self.space,
                    policy_epoch: self.epoch,
                    now_ms: now,
                    revoked_grant_ids: &revoked,
                };
                let update = verify_topology_update(&signed, &context, &nonce)?;
                let TopologySync::Full { advertisements, .. } = &update.claims().sync else {
                    return Err("expected complete real topology".into());
                };
                let mut digests = vec![[0; 32]; 2];
                for signed in advertisements {
                    let claims = TopologyAdvertisement::decode_canonical(&signed.claims)?;
                    let Some(index) = self.nodes.iter().position(|node| node.id == claims.report.node_id) else {
                        continue;
                    };
                    let other = &self.nodes[1 - index];
                    if claims.expires_at_ms <= now.saturating_add(200)
                        || !claims.report.neighbors.iter().any(|neighbor| {
                            neighbor.up
                                && neighbor.remote == PeerId::from_public_key(&other.identity.public_key())
                                && neighbor.local_endpoint_revision == 1
                                && neighbor.remote_endpoint_revision == 1
                        })
                    {
                        continue;
                    }
                    let node = &self.nodes[index];
                    let lease = node.control.authorize(NodeRole::NodeRelay, false)?;
                    let incarnation = BootIncarnation {
                        runtime_id: lease.runtime_id,
                        runtime_generation: lease.runtime_generation,
                    };
                    let publisher = verify_topology_publisher(
                        &self.publishers[index],
                        &context,
                        &node.id,
                        &node.identity.public_key(),
                        &incarnation,
                        &[],
                    )?;
                    let advertisement = verify_topology_advertisement(
                        signed, &publisher, &context, &incarnation, 0,
                    )?;
                    assert!(advertisement.claims().report.sequence > 1);
                    digests[index] = advertisement.digest();
                }
                if !digests.contains(&[0; 32]) {
                    return Ok(digests);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?
    }
    async fn request(
        &self,
        sdk: &Sdk,
        service: &str,
        template: PrivateServiceAccessRequest,
        consumer: &DeviceIdentity,
    ) -> Result<nestlink_identity::services::private::VerifiedPrivateServiceLease> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let mut request = template.clone();
                request.route = PrivateServiceRouteRequest::Relay {
                    node_ids: self.nodes.iter().map(|node| node.id.clone()).collect(),
                    topology_digests: self.heads(sdk).await?,
                    signature: String::new(),
                };
                let signed = URL_SAFE_NO_PAD.encode(
                    consumer.identity.sign_private_service_route(service, &request)?,
                );
                if let PrivateServiceRouteRequest::Relay { signature, .. } = &mut request.route {
                    *signature = signed;
                }
                match sdk.request_private_service(service, request).await {
                    Ok(lease) => return Ok(lease),
                    Err(SdkError::Api(reqwest::StatusCode::CONFLICT, _)) if self.nodes.len() == 2 => {
                        // Real periodic reports may replace the head between GET
                        // and POST. Retain the original request ID and quota.
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        })
        .await?
    }
    async fn assert_private_resources(&self, grant_id: &str) -> Result {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let mut ready = true;
                for node in &self.nodes {
                    let snapshot = node.control.resource_snapshot()?;
                    assert!(snapshot.allocations.is_empty(), "private service allocated a legacy relay");
                    let resources: Vec<_> = snapshot.network_routes.iter().filter(|route| {
                        route.allocation.as_ref().is_some_and(|allocation| allocation.session_id == grant_id)
                    }).collect();
                    if resources.is_empty() {
                        ready = false;
                        continue;
                    }
                    assert_eq!(resources.len(), 1);
                    let resource = resources[0];
                    assert!(resource.business_permit.is_empty(), "private service borrowed a RemotePermit");
                    assert!(resource.relay_bundle_json.is_empty());
                    assert!(resource.chain_bundle_json.is_empty());
                    assert_eq!(resource.network_schema_version, self.nodes.len() as u32);
                    let grant: PrivateServiceGrant = serde_json::from_slice(&resource.private_service_bundle_json)?;
                    assert_eq!(grant.network.grant_id, grant_id);
                    let path = nestlink_sdk::network_management::decode_network_grant(&grant.network.path)?;
                    let GrantClaims::Path(path) = GrantClaims::decode_canonical(&path.claims)? else {
                        return Err("private resource did not contain a path grant".into());
                    };
                    assert_eq!(path.purpose, Purpose::PrivateService);
                    assert!(!path.policy.allow_direct);
                    assert_eq!(path.policy.max_hops as usize, self.nodes.len());
                    assert_eq!(grant.network.relay.as_ref().ok_or("missing private relay route")?.nodes.len(), self.nodes.len());
                }
                if ready {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?
    }
    async fn assert_released(&self) -> Result {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let mut released = true;
                for node in &self.nodes {
                    let counters = node.control.counters()?;
                    assert!(counters.admitted_bytes > 0, "registered hop never carried the actual business");
                    released &= counters.opened_connections > 0
                        && counters.opened_connections == counters.closed_connections;
                }
                if released {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?
    }
    async fn finish(&mut self) -> Result {
        for node in &mut self.nodes {
            node.finish().await?;
        }
        Ok(())
    }
}

async fn consumer_login(f: &Fixture) -> Result<Sdk> {
    let mut sdk = Sdk::connect(
        &f.origin,
        DeploymentTrust { deployment_id: f.deployment.clone(), permit_issuer: f.issuer },
        true,
    ).await?;
    sdk.login("admin".into(), Secret::from_text(PASSWORD.into()), None).await?;
    Ok(sdk)
}
async fn close_host(host: &mut PrivateServiceHost, usage: &std::path::Path) -> Result {
    let endpoint = host.address();
    host.wait_stopped().await?;
    drop(std::net::UdpSocket::bind(endpoint)?);
    std::fs::remove_dir_all(usage)?;
    Ok(())
}
fn usage_grant(lease: &nestlink_identity::services::private::VerifiedPrivateServiceLease) -> Result<ServiceUsageBudgetGrantClaims> {
    Ok(decode_service_message(&lease.lease().claims().usage_grant.claims, SERVICE_USAGE_BYTES)?)
}

#[derive(Clone, Copy)]
enum End {
    Acl,
    Login,
    Expiry,
}
async fn tcp(hops: usize, end: End) -> Result {
    tokio::time::timeout(Duration::from_secs(30), async {
        let backend = TcpListener::bind("127.0.0.1:0").await?;
        let approval_ms = if matches!(end, End::Expiry) { 8_000 } else { 60_000 };
        let f = Fixture::configured("tcp", backend.local_addr()?, "relay_only", approval_ms).await?;
        let mut relays = Relays::start(&f, hops).await?;
        let mut consumer_sdk = consumer_login(&f).await?;
        let request = f.request(&f.consumer);
        let outsider = f.request(&f.outsider);
        let policy = PrivateServiceRelayPolicy::from_local_choice(&[], true)?;
        assert!(f.sdk.pending_remote().await?.is_empty());
        let mut host = f.sdk.start_private_service_host_with_relay_policy(
            f.host.clone(), f.consent,
            PrivateServiceHostConfig { listen: "127.0.0.1:0".parse()?, advertised_ip: "127.0.0.1".parse()?, usage_directory: f.usage.join("ledger") },
            policy.clone(),
        ).await?;
        // Membership and relay selection do not authorize this business.
        assert!(relays.request(&consumer_sdk, &f.view.id, outsider, &f.outsider).await.is_err());
        assert!(consumer_sdk.request_private_service(&f.view.id, request.clone()).await.is_err());
        assert!(tokio::time::timeout(Duration::from_millis(100), backend.accept()).await.is_err());
        let lease = relays.request(&consumer_sdk, &f.view.id, request, &f.consumer).await?;
        let grant = usage_grant(&lease)?;
        assert_eq!(lease.claims().consumer_login_id, consumer_sdk.principal().ok_or("missing consumer login")?.session_id);
        assert!(lease.lease().claims().expires_at_unix_ms <= f.view.approval_expires_at_unix_ms.ok_or("missing original approval deadline")?);
        if matches!(end, End::Expiry) {
            assert_eq!(lease.lease().claims().expires_at_unix_ms, f.view.approval_expires_at_unix_ms.ok_or("missing original approval deadline")?);
        }
        assert!(consumer_sdk.connect_private_service_with_relay_policy(&f.outsider, lease.clone(), &policy).await.is_err());
        assert!(consumer_sdk.connect_private_service(&f.consumer, lease.clone()).await.is_err(), "loopback relay still requires this machine's explicit local selection");
        let mut connection = consumer_sdk.connect_private_service_with_relay_policy(&f.consumer, lease.clone(), &policy).await?;
        let (mut target, _) = tokio::time::timeout(Duration::from_secs(3), backend.accept()).await??;
        connection.stream()?.write_all(b"original private TCP").await?;
        let mut request_bytes = [0; 20];
        target.read_exact(&mut request_bytes).await?;
        assert_eq!(&request_bytes, b"original private TCP");
        target.write_all(b"reply through registered relay").await?;
        let mut reply = [0; 30];
        connection.stream()?.read_exact(&mut reply).await?;
        assert_eq!(&reply, b"reply through registered relay");
        relays.assert_private_resources(&grant.grant_id).await?;
        match end {
            End::Acl => { f.sdk.revoke_private_service(&f.view.id, &f.rule, f.exposure.revision).await?; }
            End::Login => { consumer_sdk.logout().await?; assert!(f.sdk.me().await.is_ok()); }
            End::Expiry => {
                tokio::time::sleep(Duration::from_millis(lease.lease().claims().expires_at_unix_ms.saturating_sub(wall_ms()?) + 100)).await;
            }
        }
        // Keep both public owners alive: only the original current grant or
        // fixed deadline may end the already connected, locally approved TCP.
        let mut byte = [0];
        assert_eq!(tokio::time::timeout(Duration::from_secs(3), target.read(&mut byte)).await??, 0);
        assert!(f.sdk.current_private_service(&f.view.id, &grant.grant_id).await.is_err());
        relays.assert_released().await?;
        if matches!(end, End::Expiry) {
            // The local approval ends the original host listener independently
            // of the test's later cleanup/join request.
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    match std::net::UdpSocket::bind(host.address()) {
                        Ok(rebound) => {
                            drop(rebound);
                            if host.is_finished() { return Ok::<_, io::Error>(()); }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }).await??;
        }
        connection.close().await?;
        close_host(&mut host, &f.usage).await?;
        relays.finish().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }).await??;
    Ok(())
}

#[tokio::test]
async fn single_relay_tcp_uses_private_authority_and_acl_revoke_closes_original_backend() -> Result {
    tcp(1, End::Acl).await
}
#[tokio::test]
async fn two_relay_tcp_uses_private_authority_and_acl_revoke_closes_original_backend() -> Result {
    tcp(2, End::Acl).await
}
#[tokio::test]
async fn two_relay_tcp_keeps_original_consumer_login_and_signout_closes_backend() -> Result {
    tcp(2, End::Login).await
}
#[tokio::test]
async fn single_relay_tcp_fixed_target_expiry_closes_backend_without_a_local_stop() -> Result {
    tcp(1, End::Expiry).await
}

async fn udp(hops: usize) -> Result {
    tokio::time::timeout(Duration::from_secs(25), async {
        let backend = UdpSocket::bind("127.0.0.1:0").await?;
        let f = Fixture::with_path_policy("udp", backend.local_addr()?, "relay_only").await?;
        let mut relays = Relays::start(&f, hops).await?;
        let request = f.request(&f.consumer);
        let policy = PrivateServiceRelayPolicy::from_local_choice(&[], true)?;
        let mut host = f.sdk.start_private_service_host_with_relay_policy(
            f.host.clone(), f.consent,
            PrivateServiceHostConfig { listen: "127.0.0.1:0".parse()?, advertised_ip: "127.0.0.1".parse()?, usage_directory: f.usage.join("ledger") },
            policy.clone(),
        ).await?;
        let lease = relays.request(&f.sdk, &f.view.id, request, &f.consumer).await?;
        let grant = usage_grant(&lease)?;
        let mut connection = f.sdk.connect_private_service_with_relay_policy(&f.consumer, lease, &policy).await?;
        let mut bytes = [0; 128];
        for payload in [&b""[..], &b"original private UDP"[..]] {
            connection.send_datagram(payload)?;
            let (length, peer) = tokio::time::timeout(Duration::from_secs(3), backend.recv_from(&mut bytes)).await??;
            assert_eq!(&bytes[..length], payload);
            backend.send_to(payload, peer).await?;
            assert_eq!(tokio::time::timeout(Duration::from_secs(3), connection.receive_datagram()).await??, payload);
        }
        relays.assert_private_resources(&grant.grant_id).await?;
        f.sdk.revoke_private_service(&f.view.id, &f.rule, f.exposure.revision).await?;
        assert!(tokio::time::timeout(Duration::from_secs(3), connection.receive_datagram()).await?.is_err());
        relays.assert_released().await?;
        let _ = connection.send_datagram(b"revoked UDP cannot reach the backend");
        assert!(tokio::time::timeout(Duration::from_millis(200), backend.recv_from(&mut bytes)).await.is_err());
        connection.close().await?;
        close_host(&mut host, &f.usage).await?;
        relays.finish().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }).await??;
    Ok(())
}
#[tokio::test]
async fn single_relay_udp_keeps_empty_datagrams_and_acl_revocation_releases_original_mapping() -> Result {
    udp(1).await
}
#[tokio::test]
async fn two_relay_udp_keeps_empty_datagrams_and_acl_revocation_releases_both_original_hops() -> Result {
    udp(2).await
}
