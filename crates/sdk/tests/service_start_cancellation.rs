//! Cancel an actual pinned attachment after proof and before Web readiness.
#[path = "../../node/tests/support/service_usage_directory.rs"]
mod service_usage_directory;
use service_usage_directory::ServiceUsageDirectory;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, hash_password, random_id};
use nestlink_identity::{PermitSigner, nodes::NodeIdentity};
use nestlink_node::control::{NodeConfig, NodeControl};
use nestlink_protocol::{NodeRole, api::*, service_plane::publication::*};
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk, services::LocalServiceTargetConsent};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use nestlink_transport_quic::service::{self as carrier, read_message, write_message};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

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
async fn cancel_during_actual_quic_web_readiness_drains_the_same_endpoint() -> Result {
    tokio::time::timeout(Duration::from_secs(25), run()).await??;
    Ok(())
}
async fn run() -> Result {
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
    let _namespace = store.set_service_edge_namespace(
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
    .await?;
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
            deployment_id: deployment,
            node_id: node_id.clone(),
            control_origin: origin,
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

    let (proved, proof_seen) = tokio::sync::oneshot::channel();
    let edge_control = control.clone();
    let mut edge = Abort(tokio::spawn(async move {
        let incoming = tokio::time::timeout(Duration::from_secs(3), endpoint.accept())
            .await?
            .ok_or("no attachment")?;
        let connection = incoming.await?;
        assert!(carrier::negotiated_service(&connection));
        let peer = connection.remote_address();
        let (mut send, mut recv) = connection.accept_bi().await?;
        let intro: ServiceHostIntroduction = read_message(&mut recv).await?;
        let publication = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(owner) = edge_control.service_publication(&intro.publication_id) {
                    break owner;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let lease = publication.lease()?;
        let challenge = edge_identity.challenge_service_attachment(&lease, wall_ms()?)?;
        write_message(
            &mut send,
            &ServiceAttachmentOffer {
                lease: lease.signed().clone(),
                challenge: challenge.clone(),
            },
        )
        .await?;
        let proof: ServiceAttachmentProof = read_message(&mut recv).await?;
        nestlink_identity::service_plane::publication::verify_attachment_proof(
            &lease,
            &challenge,
            &proof,
            &intro.host_public_key,
            &edge_identity.public_key(),
            wall_ms()?,
        )?;
        let _ = proved.send(peer);
        // Never send Ready. Cancellation must end this wait without the 90s
        // certificate deadline, and without swapping to another connection.
        connection.closed().await;
        drop((send, recv, connection));
        endpoint.close(0u32.into(), b"cancel fixture ended");
        endpoint.wait_idle().await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }));
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let definition = sdk
        .create_service(&ServiceCreate {
            id: random_id(),
            definition: ServiceDefinition {
                name: "cancel while waiting for web readiness".into(),
                host_device_id: host.device_id.clone(),
                edge_node_id: node_id,
                requested_ingress: ServiceIngress::Http {
                    hostname: "app.svc.example.test".into(),
                },
                allowed_sources: vec![ServiceSourceNetwork {
                    address: "127.0.0.1".into(),
                    prefix: 32,
                }],
                limits: ServiceLimits {
                    maximum_connections: 2,
                    bytes_per_second: 65536,
                    maximum_bytes: 1048576,
                    idle_timeout_seconds: 5,
                },
            },
        })
        .await?;
    let consent =
        LocalServiceTargetConsent::from_local_choice(&definition, "http", backend.local_addr()?)?;
    sdk.approve_service_target(&host, &consent, 60000).await?;
    let (cancel, cancelled) = tokio::sync::watch::channel(false);
    let start = sdk.start_service_host_cancellable(host, consent, cancelled);
    tokio::pin!(start);
    let peer = tokio::select! {biased;
        peer=proof_seen=>peer?,
        result=&mut start=>{match result{Err(error)=>return Err(format!("start ended before proof: {error}").into()),Ok(runtime)=>{drop(runtime);return Err("start accepted without Ready".into());}}},
    };
    let cancelled_at = std::time::Instant::now();
    cancel.send_replace(true);
    match tokio::time::timeout(Duration::from_secs(5), &mut start).await? {
        Err(nestlink_sdk::SdkError::ServiceIo(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::Interrupted)
        }
        Err(error) => return Err(format!("wrong cancellation result: {error}").into()),
        Ok(runtime) => {
            drop(runtime);
            return Err("cancelled startup became ready".into());
        }
    }
    assert!(cancelled_at.elapsed() < Duration::from_secs(5));
    (&mut edge.0).await??;
    // Binding the exact client endpoint's UDP port proves its OS socket was
    // released before Interrupted was returned, rather than merely signalling.
    let rebound = tokio::net::UdpSocket::bind(peer).await.map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("client UDP port {peer} is still held after Interrupted: {error}"),
        )
    })?;
    drop(rebound);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), backend.accept())
            .await
            .is_err()
    );
    control.stop();
    Ok(())
}
fn wall_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
