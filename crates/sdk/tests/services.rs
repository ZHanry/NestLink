//! Typed SDK -> actual HTTP -> registry -> locally selected installation proof.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::{PermitSigner, nodes::NodeIdentity};
use nestlink_protocol::{NodeRole, api::*};
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk, services::LocalServiceTargetConsent};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Server(Option<tokio::task::JoinHandle<std::io::Result<()>>>);
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}
#[tokio::test]
async fn local_choice_typed_api_approves_configuration_and_never_claims_running() -> Result {
    let deployment = random_id();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", "service-sdk-test-password")?;
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([4; 32]),
        signer,
        origin.clone(),
        false,
    )?);
    let (stop, stop_rx) = tokio::sync::oneshot::channel();
    let mut server = Server(Some(tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await
    })));
    let mut sdk = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment,
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    sdk.login(
        "admin".into(),
        Secret::from_text("service-sdk-test-password".into()),
        None,
    )
    .await?;
    let host = DeviceIdentity::generate();
    sdk.enroll(
        &host,
        "sdk service host".into(),
        "windows".into(),
        vec!["host".into(), "vp8".into()],
        "direct_only".into(),
    )
    .await?;
    let node = random_id();
    let node_identity = NodeIdentity::generate();
    sdk.register_node(NodeRegistration {
        id: node.clone(),
        name: "edge-only".into(),
        public_key: URL_SAFE_NO_PAD.encode(node_identity.public_key()),
        roles: vec![NodeRole::NodeEdge as i32],
        max_connections: 8,
        bytes_per_second: 1048576,
    })
    .await?;
    let create = ServiceCreate {
        id: random_id(),
        definition: ServiceDefinition {
            name: "explicit SDK choice".into(),
            host_device_id: host.device_id.clone(),
            edge_node_id: node,
            requested_ingress: ServiceIngress::Tcp { port: 29100 },
            allowed_sources: vec![],
            limits: ServiceLimits {
                maximum_connections: 8,
                bytes_per_second: 1048576,
                maximum_bytes: 1073741824,
                idle_timeout_seconds: 60,
            },
        },
    };
    let view = sdk.create_service(&create).await?;
    let consent =
        LocalServiceTargetConsent::from_local_choice(&view, "tcp", "127.0.0.1:8080".parse()?)?;
    assert_eq!(
        consent.address(),
        "127.0.0.1:8080".parse::<std::net::SocketAddr>()?
    );
    assert!(
        sdk.approve_service_target(&host, &consent, 60000)
            .await
            .is_err()
    );
    sdk.set_policy(PolicyUpdate {
        expected_revision: 1,
        policy: NetworkPolicy {
            server_forwarding: "allow".into(),
            peer_path_mode: "direct_only".into(),
            public_ingress: "enabled".into(),
        },
    })
    .await?;
    let approved = sdk.approve_service_target(&host, &consent, 60000).await?;
    assert_eq!(approved.approval, ServiceApprovalState::ApprovedTarget);
    assert_eq!(approved.publication, ServicePublicationStatus::NotPublished);
    assert_eq!(approved.target_id.as_deref(), Some(consent.target_id()));
    assert!(
        sdk.approve_service_target(&host, &consent, 60000)
            .await
            .is_err()
    );
    let page = sdk.services(None, 100).await?;
    assert_eq!(page.services.len(), 1);
    assert_eq!(page.services[0].revision, approved.revision);
    assert_eq!(
        sdk.service(&view.id).await?.approval,
        ServiceApprovalState::ApprovedTarget
    );
    let revoked = sdk.revoke_service(&view.id, approved.revision).await?;
    assert_eq!(revoked.approval, ServiceApprovalState::Revoked);
    let _ = stop.send(());
    if let Some(task) = server.0.take() {
        task.await??;
    }
    Ok(())
}
