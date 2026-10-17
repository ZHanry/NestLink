//! Actual HTTP reservations and the WSS node lease channel on isolated loopback.
#[path = "../../node/tests/support/service_usage_directory.rs"]
mod service_usage_directory;
use service_usage_directory::ServiceUsageDirectory;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::{PermitSigner, nodes::NodeIdentity, relay::node_relay_transcript};
use nestlink_node::control::{NodeConfig, NodeControl, RelayEndpointProof};
use nestlink_protocol::{
    NodeRole, Path, Permission, RelayTransport,
    api::{
        ApprovalChoice, NetworkPolicy, NodeRegistration, PolicyUpdate, RelayQuotaUpdate,
        RemoteRequest,
    },
};
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use std::time::Duration;
use tokio::io::AsyncReadExt;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Abort(tokio::task::JoinHandle<()>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn password() -> Secret {
    Secret::from_text("relay-allocation-sdk-test-password".into())
}
#[tokio::test]
async fn sdk_reserves_independent_capacity_and_the_combined_socket_observes_it() -> Result {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let node_issuer = signer.node_policy_signer()?.public_key();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", password().expose())?;
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", http.local_addr()?);
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([7; 32]),
        signer,
        origin.clone(),
        false,
    )?);
    let _server = Abort(tokio::spawn(async move {
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
    assert!(sdk.relay_reservations().await.is_err());
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
    let request = sdk
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
        &request,
        ApprovalChoice {
            approved: true,
            permissions: vec![Permission::View as i32],
            paths: vec![Path::Relay as i32],
        },
    )
    .await?;
    let permit = sdk.permit(&request.id).await?;
    let quota = sdk.relay_quota().await?;
    sdk.set_relay_quota(RelayQuotaUpdate {
        expected_revision: quota.revision,
        limits: nestlink_protocol::api::RelayQuotaLimits {
            max_allocations: 1,
            max_account_endpoints: 2,
            ..quota.limits
        },
    })
    .await?;
    let node = NodeIdentity::generate();
    let node_id = random_id();
    sdk.register_node(NodeRegistration {
        id: node_id.clone(),
        name: "allocation-relay".into(),
        public_key: URL_SAFE_NO_PAD.encode(node.public_key()),
        roles: vec![NodeRole::NodeRelay as i32],
        max_connections: 2,
        bytes_per_second: 1048576,
    })
    .await?;
    let mut service_usage_directory = ServiceUsageDirectory::new()?;
    let control = NodeControl::start(
        NodeConfig {
            deployment_id: deployment.clone(),
            node_id: node_id.clone(),
            control_origin: origin.clone(),
            trusted_policy_issuer: URL_SAFE_NO_PAD.encode(node_issuer),
            identity_key_file: "unused-fixture".into(),
            service_usage_directory: Some(service_usage_directory.path().to_path_buf()),
            roles: vec![NodeRole::NodeRelay as i32],
            allow_loopback_http: true,
        },
        node,
    )?;
    service_usage_directory.track(&control)?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if control.authorize(NodeRole::NodeRelay, false).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    // Poll an actual unpaired socket through the DB commit, then cancel the
    // client future. Cleanup must own the reservation across that boundary.
    {
        let connecting = sdk.connect_relay(&controller, &permit);
        let held = async {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if sdk.relay_reservations().await?.combined_allocations == 1 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Ok::<(), nestlink_sdk::SdkError>(())
            })
            .await??;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::select! {result=connecting=>return Err(format!("unpaired relay completed before cancellation: {}",result.is_ok()).into()),result=held=>result?}
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if sdk.relay_reservations().await?.held_allocations == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok::<(), nestlink_sdk::SdkError>(())
    })
    .await??;
    let allocation_id = random_id();
    let allocation = sdk
        .reserve_relay_allocation(&controller, &permit, &allocation_id, &node_id)
        .await?;
    let claims = allocation.claims();
    assert_eq!(claims.runtime_id, control.current_lease()?.runtime_id);
    assert!(allocation.matches(permit.claims())?);
    assert_eq!(
        claims,
        sdk.reserve_relay_allocation(&host, &permit, &allocation_id, &node_id)
            .await?
            .claims()
    );
    let usage = sdk.relay_reservations().await?;
    assert_eq!(
        (
            usage.held_allocations,
            usage.held_endpoint_slots,
            usage.independent_allocations,
            usage.combined_allocations
        ),
        (1, 2, 1, 0)
    );
    // A real combined WebSocket cannot create a second allocation behind SQLite.
    assert!(sdk.connect_relay(&controller, &permit).await.is_err());
    assert!(
        sdk.reserve_relay_allocation(&controller, &permit, &random_id(), &node_id)
            .await
            .is_err()
    );
    assert!(
        sdk.reserve_relay_allocation(
            &DeviceIdentity::generate(),
            &permit,
            &allocation_id,
            &node_id
        )
        .await
        .is_err()
    );
    let raw = reqwest::Client::new()
        .post(format!(
            "{origin}/api/v3/remote/{}/relay/allocation",
            request.id
        ))
        .json(&nestlink_protocol::api::RelayAllocationRequest {
            allocation_id: random_id(),
            node_id: node_id.clone(),
            device_id: controller.device_id.clone(),
            signature: URL_SAFE_NO_PAD.encode([0; 64]),
        })
        .send()
        .await?;
    assert_eq!(raw.status(), reqwest::StatusCode::UNAUTHORIZED);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if control.resource_snapshot().is_ok_and(|s| {
                s.allocations
                    .iter()
                    .any(|c| c.allocation_id == allocation_id)
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let challenge = [3; 32]; // Public deterministic service challenge for this isolated fixture.
    let controller_signature = controller.identity.sign_action(&node_relay_transcript(
        claims,
        &controller.device_id,
        RelayTransport::WssStream,
        &challenge,
    )?)?;
    let host_signature = host.identity.sign_action(&node_relay_transcript(
        claims,
        &host.device_id,
        RelayTransport::WssStream,
        &challenge,
    )?)?;
    let controller_key = controller.identity.public_key();
    let host_key = host.identity.public_key();
    let controller_proof = |transport, signature| RelayEndpointProof {
        device_id: &controller.device_id,
        public_key: &controller_key,
        transport,
        signature,
    };
    assert!(
        control
            .reserve_relay_endpoint(
                allocation.signed_bytes(),
                controller_proof(RelayTransport::QuicDatagram, &controller_signature),
                &challenge
            )
            .is_err()
    );
    assert!(
        control
            .reserve_relay_endpoint(
                allocation.signed_bytes(),
                controller_proof(RelayTransport::WssStream, &controller_signature),
                &[4; 32]
            )
            .is_err()
    );
    let controller_guard = control.reserve_relay_endpoint(
        allocation.signed_bytes(),
        controller_proof(RelayTransport::WssStream, &controller_signature),
        &challenge,
    )?;
    assert!(
        control
            .reserve_relay_endpoint(
                allocation.signed_bytes(),
                controller_proof(RelayTransport::WssStream, &controller_signature),
                &challenge
            )
            .is_err()
    );
    let host_guard = control.reserve_relay_endpoint(
        allocation.signed_bytes(),
        RelayEndpointProof {
            device_id: &host.device_id,
            public_key: &host_key,
            transport: RelayTransport::WssStream,
            signature: &host_signature,
        },
        &challenge,
    )?;
    assert_eq!(control.counters()?.opened_connections, 2);
    assert!(
        controller_guard
            .admit(1024, || Err::<(), _>(
                nestlink_protocol::ContractError::new(
                    nestlink_protocol::ErrorCode::CapacityExceeded,
                    "test queue full"
                )
            ))
            .is_err()
    );
    assert_eq!(control.counters()?.admitted_bytes, 0);
    controller_guard.admit(1024, || Ok(()))?;
    host_guard.admit(2048, || Ok(()))?;
    assert_eq!(control.counters()?.admitted_bytes, 3072);
    // A data service must select the guard while its real socket is idle too.
    let idle_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut idle_client = tokio::net::TcpStream::connect(idle_listener.local_addr()?).await?;
    let (mut idle_socket, _) = idle_listener.accept().await?;
    let idle_service = tokio::spawn(async move {
        let mut byte = [0];
        tokio::select! {
            _=host_guard.wait_stopped()=>{},
            _=idle_socket.read(&mut byte)=>{},
        }
        drop(idle_socket);
        drop(host_guard);
    });
    let revoke_started = std::time::Instant::now();
    sdk.revoke_node(&node_id).await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        controller_guard.wait_stopped().await;
        let mut byte = [0];
        assert_eq!(idle_client.read(&mut byte).await?, 0);
        idle_service.await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert!(revoke_started.elapsed() < Duration::from_secs(2));
    assert!(controller_guard.admit(1, || Ok(())).is_err());
    drop(controller_guard);
    assert_eq!(control.counters()?.closed_connections, 2);
    assert!(
        sdk.reserve_relay_allocation(&controller, &permit, &allocation_id, &node_id)
            .await
            .is_err()
    );
    assert_eq!(sdk.relay_reservations().await?.held_allocations, 1);
    sdk.revoke_remote(&request.id).await?;
    assert!(
        sdk.reserve_relay_allocation(&controller, &permit, &allocation_id, &node_id)
            .await
            .is_err()
    );
    assert_eq!(sdk.relay_reservations().await?.held_allocations, 1);
    Ok(())
}
