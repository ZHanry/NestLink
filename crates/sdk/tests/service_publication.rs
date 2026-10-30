//! Actual management HTTP, independent node poll, pinned QUIC and public TCP.
#[path = "../../node/tests/support/service_usage_directory.rs"]
mod service_usage_directory;
use service_usage_directory::ServiceUsageDirectory;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, hash_password, random_id};
use nestlink_identity::{PermitSigner, nodes::NodeIdentity};
use nestlink_node::control::{NodeConfig, NodeControl};
use nestlink_protocol::{NodeRole, api::*, service_plane::publication::*};
use nestlink_protocol::{
    network::SpaceRole,
    spaces::{service_publication::*, *},
};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, Sdk,
    services::{LocalServiceTargetConsent, ServiceHostWait},
};
use nestlink_server::{AppState, router, service_edge};
use nestlink_storage::Store;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn wall() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[tokio::test]
async fn actual_http_quic_tcp_publication_retains_half_close_renews_and_physically_stops() -> Result
{
    tokio::time::timeout(Duration::from_secs(25), run(false)).await??;
    Ok(())
}

#[tokio::test]
async fn space_publication_rule_is_enforced_by_real_http_quic_and_physical_ingress_teardown()
-> Result {
    tokio::time::timeout(Duration::from_secs(25), run(true)).await??;
    Ok(())
}
async fn run(space_policy: bool) -> Result {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let policy_issuer = signer.node_policy_signer()?.public_key();
    let password = "service-publication-loopback-password";
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", password)?;
    let vault = VaultKey::from_bytes([44; 32]);
    let dummy = hash_password("service-publication-unused-dummy")?;
    let admin = store
        .login("admin", password, None, wall()?, &vault, &dummy)?
        .principal;
    let edge_seed = [97; 32];
    let edge_identity = Arc::new(NodeIdentity::from_seed(&edge_seed));
    let node_id = random_id();
    store.register_node(
        &admin,
        NodeRegistration {
            id: node_id.clone(),
            name: "service-QUIC-loopback-edge".into(),
            public_key: URL_SAFE_NO_PAD.encode(edge_identity.public_key()),
            roles: vec![NodeRole::NodeEdge as i32],
            max_connections: 16,
            bytes_per_second: 1048576,
        },
    )?;
    let endpoint =
        nestlink_transport_quic::service::listener("127.0.0.1:0".parse()?, &edge_identity)?;
    let public_reservation = loop {
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        if !(28743..=29055).contains(&socket.local_addr()?.port()) {
            break socket;
        }
    };
    let public_address = public_reservation.local_addr()?;
    let namespace = store.set_service_edge_namespace(
        &admin,
        &node_id,
        ServiceEdgeNamespaceUpdate {
            expected_revision: 0,
            config: ServiceEdgeNamespace {
                service_suffix: "svc.example.test".into(),
                management_hostname: "control.example.test".into(),
                public_ports: vec![public_address.port()],
                quic_address: endpoint.local_addr()?.to_string(),
            },
        },
        wall()?,
    )?;
    let http = TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", http.local_addr()?);
    let app = router(AppState::new(store, vault, signer, origin.clone(), false)?);
    let _server = Abort(tokio::spawn(async move {
        axum::serve(
            http,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    }));
    let mut sdk = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment.clone(),
            permit_issuer: issuer,
        },
        true,
    )
    .await
    .map_err(|e| format!("connect: {e:?}"))?;
    sdk.login("admin".into(), Secret::from_text(password.into()), None)
        .await?;
    sdk.set_policy(PolicyUpdate {
        expected_revision: 1,
        policy: NetworkPolicy {
            server_forwarding: "allow".into(),
            peer_path_mode: "direct_only".into(),
            public_ingress: "enabled".into(),
        },
    })
    .await?;
    let host = Arc::new(DeviceIdentity::generate());
    sdk.enroll(
        &host,
        "fixed local target host".into(),
        "windows".into(),
        vec!["host".into(), "vp8".into()],
        "direct_only".into(),
    )
    .await?;
    let mut service_usage_directory = ServiceUsageDirectory::new()?;
    let control = Arc::new(NodeControl::start(
        NodeConfig {
            deployment_id: deployment.clone(),
            node_id: node_id.clone(),
            control_origin: origin.clone(),
            trusted_policy_issuer: URL_SAFE_NO_PAD.encode(policy_issuer),
            identity_key_file: "unused-service-fixture".into(),
            service_usage_directory: Some(service_usage_directory.path().to_path_buf()),
            roles: vec![NodeRole::NodeEdge as i32],
            allow_loopback_http: true,
        },
        NodeIdentity::from_seed(&edge_seed),
    )?);
    service_usage_directory.track(&control)?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if control.authorize(NodeRole::NodeEdge, true).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let (stop_edge, stopped_edge) = tokio::sync::oneshot::channel();
    let edge_control = control.clone();
    let mut edge = Abort(tokio::spawn(async move {
        service_edge::serve(
            endpoint,
            edge_control,
            edge_identity,
            namespace,
            "127.0.0.1".parse().map_err(std::io::Error::other)?,
            async {
                let _ = stopped_edge.await;
            },
        )
        .await
    }));
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let backend_address = backend.local_addr()?;
    let mut backend_worker = Abort(tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await?;
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await?;
        if bytes != b"fixed backend after visitor FIN" {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
        stream.write_all(b"late reply after FIN").await?;
        stream.shutdown().await?;
        Ok::<(), std::io::Error>(())
    }));
    let definition = sdk
        .create_service(&ServiceCreate {
            id: random_id(),
            definition: ServiceDefinition {
                name: "real fixed target".into(),
                host_device_id: host.device_id.clone(),
                edge_node_id: node_id.clone(),
                requested_ingress: ServiceIngress::Tcp {
                    port: public_address.port(),
                },
                allowed_sources: vec![ServiceSourceNetwork {
                    address: "127.0.0.1".into(),
                    prefix: 32,
                }],
                limits: ServiceLimits {
                    maximum_connections: 8,
                    bytes_per_second: 65536,
                    maximum_bytes: 10485760,
                    idle_timeout_seconds: 5,
                },
            },
        })
        .await
        .map_err(|e| format!("create service: {e:?}"))?;
    let consent =
        LocalServiceTargetConsent::from_local_choice(&definition, "tcp", backend_address)?;
    let approved = sdk
        .approve_service_target(&host, &consent, 60000)
        .await
        .map_err(|e| format!("approve target: {e:?}"))?;
    assert_eq!(approved.revision, definition.revision + 1);
    let scoped_rule = if space_policy {
        let space = sdk
            .create_space(SpaceCreateRequest {
                name: "Actual service publication rules".into(),
            })
            .await?;
        sdk.create_account("space-guest".into(), Secret::from_text(password.into()))
            .await?;
        let mut guest = Sdk::connect(
            &origin,
            DeploymentTrust {
                deployment_id: deployment.clone(),
                permit_issuer: issuer,
            },
            true,
        )
        .await?;
        guest
            .login(
                "space-guest".into(),
                Secret::from_text(password.into()),
                None,
            )
            .await?;
        let guest_account = guest.principal().ok_or("guest missing")?.account_id.clone();
        let invitation = sdk
            .invite_to_space(
                &space.space_id,
                SpaceInvitationRequest {
                    expected_revision: space.revision,
                    role: SpaceRole::Guest,
                    target_account_id: Some(guest_account),
                    expires_at_unix_ms: space.observed_at_unix_ms + 60_000,
                },
            )
            .await?;
        let accepted = guest
            .accept_space_invitation(
                &space.space_id,
                &invitation.invitation.invitation_id,
                SpaceInvitationAcceptance {
                    token: invitation.token,
                },
            )
            .await?;
        let joined = sdk
            .join_space_device(
                &space.space_id,
                SpaceDeviceJoin {
                    expected_revision: accepted.revision,
                    expected_membership_epoch: 0,
                    installation_id: host.device_id.clone(),
                },
            )
            .await?;
        let bound = sdk
            .bind_space_service(
                &space.space_id,
                &definition.id,
                SpaceServiceBindingRequest {
                    expected_revision: joined.revision,
                    expected_service_revision: approved.revision,
                },
            )
            .await?;
        let policy = sdk.space_service_policy(&space.space_id).await?;
        assert!(policy.bindings[0].rules.is_empty());
        assert!(
            guest
                .space_service_policy(&space.space_id)
                .await?
                .bindings
                .is_empty()
        );
        let account = sdk
            .principal()
            .ok_or("publisher missing")?
            .account_id
            .clone();
        let request = || SpaceServiceRuleRequest {
            expected_revision: bound.revision,
            expected_binding_epoch: policy.bindings[0].binding_epoch,
            subject: SpaceServiceSubject::Account {
                account_id: account.clone(),
            },
            protocol: SpaceServiceProtocol::Tcp,
            port: public_address.port(),
            operation: SpaceServiceOperation::Publish,
            expires_at_unix_ms: bound.observed_at_unix_ms + 60_000,
        };
        assert!(
            matches!(guest.grant_space_service_rule(&space.space_id,&definition.id,request()).await,Err(nestlink_sdk::SdkError::Api(status,_)) if status.as_u16()==403)
        );
        let mut wrong = request();
        wrong.protocol = SpaceServiceProtocol::Udp;
        assert!(
            matches!(sdk.grant_space_service_rule(&space.space_id,&definition.id,wrong).await,Err(nestlink_sdk::SdkError::Api(status,_)) if status.as_u16()==403)
        );
        let mut wrong = request();
        wrong.subject = SpaceServiceSubject::Device {
            installation_id: random_id(),
        };
        assert!(
            matches!(sdk.grant_space_service_rule(&space.space_id,&definition.id,wrong).await,Err(nestlink_sdk::SdkError::Api(status,_)) if status.as_u16()==403)
        );
        sdk.grant_space_service_rule(&space.space_id, &definition.id, request())
            .await?;
        let rules = sdk.space_service_policy(&space.space_id).await?;
        Some((space.space_id, rules.bindings[0].rules[0].rule_id.clone()))
    } else {
        None
    };
    drop(public_reservation);
    let mut runtime = sdk
        .start_service_host(host.clone(), consent)
        .await
        .map_err(|e| format!("start tcp host: {e:?}"))?;
    assert_eq!(
        sdk.service(&definition.id).await?.publication,
        ServicePublicationStatus::Published
    );
    assert!(
        sdk.stop_service_publication(&definition.id, approved.revision - 1)
            .await
            .is_err()
    );
    assert_eq!(
        sdk.services(None, 100).await?.services[0].publication,
        ServicePublicationStatus::Published
    );
    let publication_id = runtime.publication_id()?;
    let first_sequence = control
        .service_publication(&publication_id)?
        .lease()?
        .claims()
        .lease_sequence;
    let mut visitor = TcpStream::connect(public_address).await?;
    visitor
        .write_all(b"fixed backend after visitor FIN")
        .await?;
    visitor.shutdown().await?;
    let mut reply = Vec::new();
    visitor.read_to_end(&mut reply).await?;
    assert_eq!(reply, b"late reply after FIN");
    (&mut backend_worker.0).await??;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if control.service_publication(&publication_id).is_ok_and(|p| {
                p.lease()
                    .is_ok_and(|l| l.claims().lease_sequence > first_sequence)
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    assert!(runtime.counters()?.admitted_bytes > 0);
    if let Some((space, rule)) = &scoped_rule {
        let current = sdk.space_service_policy(space).await?;
        sdk.revoke_space_service_rule(
            space,
            &definition.id,
            rule,
            SpaceRevisionRequest {
                expected_revision: current.space.revision,
            },
        )
        .await?;
        assert!(
            sdk.space_audit(space)
                .await?
                .iter()
                .any(|entry| entry.action == "space_service_rule_revoked"
                    && &entry.target_id == rule)
        );
    } else {
        sdk.stop_service_publication(&definition.id, approved.revision)
            .await?;
    }
    assert_eq!(
        sdk.service(&definition.id).await?.publication,
        ServicePublicationStatus::Stopping
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if runtime.cleanup_pending() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    assert!(matches!(
        runtime.wait_stopped(Duration::from_secs(3)).await,
        ServiceHostWait::Stopped(_)
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(listener) = TcpListener::bind(public_address).await {
                drop(listener);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    assert!(sdk.service(&definition.id).await?.target_id.is_some());
    exercise_udp(&sdk, host, node_id, public_address)
        .await
        .map_err(|e| format!("udp phase: {e:?}"))?;
    let _ = stop_edge.send(());
    (&mut edge.0).await??;
    control.stop();
    Ok(())
}

async fn exercise_udp(
    sdk: &Sdk,
    host: Arc<DeviceIdentity>,
    node: String,
    public: std::net::SocketAddr,
) -> Result {
    use nestlink_node::service_plane::DatagramPacket;
    use tokio::net::UdpSocket;
    let backend = UdpSocket::bind("127.0.0.1:0").await?;
    let target = backend.local_addr()?;
    let mut backend_worker = Abort(tokio::spawn(async move {
        let mut peers = std::collections::HashSet::new();
        let mut bytes = [0; DatagramPacket::MAX_PAYLOAD + 1];
        for _ in 0..4 {
            let (n, peer) = backend.recv_from(&mut bytes).await?;
            peers.insert(peer);
            backend.send_to(&bytes[..n], peer).await?;
        }
        Ok::<_, std::io::Error>(peers.len())
    }));
    let definition = sdk
        .create_service(&ServiceCreate {
            id: random_id(),
            definition: ServiceDefinition {
                name: "native QUIC DATAGRAM public UDP".into(),
                host_device_id: host.device_id.clone(),
                edge_node_id: node,
                requested_ingress: ServiceIngress::Udp {
                    port: public.port(),
                },
                allowed_sources: vec![ServiceSourceNetwork {
                    address: "127.0.0.1".into(),
                    prefix: 32,
                }],
                limits: ServiceLimits {
                    maximum_connections: 8,
                    bytes_per_second: 65536,
                    maximum_bytes: 10485760,
                    idle_timeout_seconds: 5,
                },
            },
        })
        .await
        .map_err(|e| format!("create service: {e:?}"))?;
    let consent = LocalServiceTargetConsent::from_local_choice(&definition, "udp", target)?;
    let approved = sdk
        .approve_service_target(&host, &consent, 60000)
        .await
        .map_err(|e| format!("approve target: {e:?}"))?;
    let mut runtime = sdk.start_service_host(host, consent).await?;
    let visitor = UdpSocket::bind("127.0.0.1:0").await?;
    visitor.connect(public).await?;
    let other = UdpSocket::bind("127.0.0.1:0").await?;
    other.connect(public).await?;
    let mut bytes = [0; DatagramPacket::MAX_PAYLOAD + 1];
    visitor.send(&[]).await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), visitor.recv(&mut bytes)).await??,
        0
    );
    assert!(runtime.counters()?.admitted_bytes >= 2);
    let maximum = vec![0xa7; DatagramPacket::MAX_PAYLOAD];
    visitor.send(&maximum).await?;
    let n = tokio::time::timeout(Duration::from_secs(2), visitor.recv(&mut bytes)).await??;
    assert_eq!(&bytes[..n], maximum);
    other.send(b"other peer").await?;
    let n = tokio::time::timeout(Duration::from_secs(2), other.recv(&mut bytes)).await??;
    assert_eq!(&bytes[..n], b"other peer");
    visitor
        .send(&vec![0; DatagramPacket::MAX_PAYLOAD + 1])
        .await?;
    visitor.send(&vec![0; 60000]).await?;
    visitor.send(b"after oversize").await?;
    let n = tokio::time::timeout(Duration::from_secs(2), visitor.recv(&mut bytes)).await??;
    assert_eq!(&bytes[..n], b"after oversize");
    assert_eq!((&mut backend_worker.0).await??, 2);
    sdk.stop_service_publication(&definition.id, approved.revision)
        .await?;
    assert!(matches!(
        runtime.wait_stopped(Duration::from_secs(3)).await,
        ServiceHostWait::Stopped(_)
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(socket) = UdpSocket::bind(public).await {
                drop(socket);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    Ok(())
}
