//! Real HTTP two-account offline consent and the original QUIC Session queues.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_identity::offline::OfflineProcess;
use nestlink_protocol::{
    Path, Permission,
    api::*,
    network::SpaceRole,
    offline::{OfflineDirectTransport, OfflineRemoteOperation, management::*},
};
use nestlink_remote::SessionLifecycle;
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk};
use nestlink_session::{EndpointRole, SessionBinding};
use nestlink_transport_stream::Channel;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn wall() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn password() -> Secret {
    Secret::from_text("offline-original-remote-test-password".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_remote_actual_http_then_expired_original_quic_view_budget_and_process_stop()
-> Result {
    tokio::time::timeout(Duration::from_secs(60), async {
        let deployment = random_id();
        let signer = PermitSigner::generate();
        let issuer = signer.public_key();
        let mut store = nestlink_storage::Store::in_memory(&deployment)?;
        store.bootstrap_admin("admin", password().expose())?;
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = http.local_addr()?;
        let origin = format!("http://{address}");
        let app = nestlink_server::router(nestlink_server::AppState::new(
            store,
            VaultKey::from_bytes([71; 32]),
            signer,
            origin.clone(),
            false,
        )?);
        let server = tokio::spawn(async move { axum::serve(http, app).await });
        let mut controller_sdk = Sdk::connect(
            &origin,
            DeploymentTrust {
                deployment_id: deployment.clone(),
                permit_issuer: issuer,
            },
            true,
        )
        .await?;
        controller_sdk
            .login("admin".into(), password(), None)
            .await?;
        controller_sdk
            .create_account("host-owner".into(), password())
            .await?;
        let mut host_sdk = Sdk::connect(
            &origin,
            DeploymentTrust {
                deployment_id: deployment,
                permit_issuer: issuer,
            },
            true,
        )
        .await?;
        host_sdk
            .login("host-owner".into(), password(), None)
            .await?;
        let controller = Arc::new(DeviceIdentity::generate());
        let host = Arc::new(DeviceIdentity::generate());
        for (sdk, identity, role) in [
            (&controller_sdk, &controller, "controller"),
            (&host_sdk, &host, "host"),
        ] {
            sdk.enroll(
                identity,
                role.into(),
                "linux-x11".into(),
                vec![
                    role.into(),
                    "vp8".into(),
                    nestlink_protocol::remote_budget::CAPABILITY.into(),
                ],
                "direct_only".into(),
            )
            .await?;
        }
        let request = || RemoteRequest {
            id: random_id(),
            controller_device_id: controller.device_id.clone(),
            host_device_id: host.device_id.clone(),
            permissions: vec![Permission::View as i32, Permission::Input as i32],
            path_mode: "direct_only".into(),
        };
        let pending = controller_sdk.create_remote(request()).await?;
        host_sdk
            .approve(
                &host,
                &pending,
                ApprovalChoice {
                    approved: true,
                    permissions: vec![Permission::View as i32, Permission::Input as i32],
                    paths: vec![Path::Direct as i32],
                },
            )
            .await?;
        let initial = controller_sdk.permit(&pending.id).await?;
        host_sdk
            .trust_remote(
                &host,
                &initial,
                TrustChoice {
                    expected_revision: 0,
                    expires_at_unix_ms: wall()? + 120_000,
                },
            )
            .await?;
        let trusted = controller_sdk.create_trusted_remote(request()).await?;
        let original = controller_sdk.permit(&trusted.id).await?;
        let host_original = host_sdk.host_permit(&host, &trusted.id).await?;
        let space = random_id();
        let policy = controller_sdk
            .configure_network_authority(&space, 0)
            .await?;
        let authority: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&policy.authority_public_key)?
            .try_into()
            .map_err(|_| "authority length")?;
        for (revision, identity) in [(1, &controller), (2, &host)] {
            controller_sdk
                .set_network_member(
                    &space,
                    &identity.device_id,
                    NetworkMemberRequest {
                        expected_policy_revision: revision,
                        expected_membership_epoch: 0,
                        role: SpaceRole::Member,
                    },
                )
                .await?;
        }
        let policy = controller_sdk
            .set_offline_enabled(
                &space,
                &OfflineEnableUpdate {
                    expected_revision: 0,
                    enabled: true,
                },
            )
            .await?;
        let mut source_process = OfflineProcess::new(
            controller.device_id.clone(),
            controller.identity.public_key(),
            wall()?,
            policy.highest_revocation_epoch,
        )?;
        let mut host_process = OfflineProcess::new(
            host.device_id.clone(),
            host.identity.public_key(),
            wall()?,
            policy.highest_revocation_epoch,
        )?;
        let draft = controller_sdk
            .create_offline_remote_draft(
                &space,
                &OfflineRemoteDraftRequest {
                    session_id: trusted.id,
                    expected_policy_revision: 3,
                    expected_connection_generation: original.claims().connection_generation,
                    expected_lease_sequence: original.claims().lease_sequence,
                    process_nonces: [source_process.nonce(), host_process.nonce()],
                    operations: vec![OfflineRemoteOperation::View],
                    direct_transports: vec![OfflineDirectTransport::Quic],
                    maximum_bytes: 4096,
                    maximum_file_write_bytes: 0,
                    maximum_connections: 4,
                    expires_at_ms: wall()? + 45_000,
                },
            )
            .await?;
        assert!(
            host_sdk
                .create_offline_remote_draft(
                    &space,
                    &OfflineRemoteDraftRequest {
                        session_id: original.claims().session_id.clone(),
                        expected_policy_revision: 3,
                        expected_connection_generation: original.claims().connection_generation,
                        expected_lease_sequence: original.claims().lease_sequence,
                        process_nonces: [source_process.nonce(), host_process.nonce()],
                        operations: vec![OfflineRemoteOperation::View],
                        direct_transports: vec![OfflineDirectTransport::Quic],
                        maximum_bytes: 4096,
                        maximum_file_write_bytes: 0,
                        maximum_connections: 4,
                        expires_at_ms: wall()? + 45_000,
                    }
                )
                .await
                .is_err()
        );
        controller_sdk
            .approve_offline_bundle(
                &controller,
                &source_process,
                &draft,
                &authority,
                0,
                draft.draft_digest,
            )
            .await?;
        let signed = host_sdk
            .approve_offline_bundle(
                &host,
                &host_process,
                &draft,
                &authority,
                1,
                draft.draft_digest,
            )
            .await?;
        let source = controller_sdk
            .activate_offline_bundle(
                &controller,
                &mut source_process,
                &signed,
                &authority,
                0,
                signed.draft_digest,
            )
            .await?;
        let target = host_sdk
            .activate_offline_bundle(
                &host,
                &mut host_process,
                &signed,
                &authority,
                1,
                signed.draft_digest,
            )
            .await?;
        assert!(
            controller_sdk
                .activate_offline_bundle(
                    &controller,
                    &mut source_process,
                    &signed,
                    &authority,
                    0,
                    signed.draft_digest
                )
                .await
                .is_err()
        );
        let c = original.claims();
        let binding = SessionBinding {
            deployment_id: c.deployment_id.clone(),
            security_epoch: c.security_epoch,
            session_id: c.session_id.clone(),
            account_id: c.account_id.clone(),
            controller_device_id: c.controller_device_id.clone(),
            host_device_id: c.host_device_id.clone(),
            controller_key_sha256: controller.identity.fingerprint(),
            host_key_sha256: host.identity.fingerprint(),
            resource_id: c.resource_id.clone(),
            policy_revision: c.policy_revision,
            connection_generation: c.connection_generation,
            capability_sha256: c.capability_sha256.as_slice().try_into()?,
            granted_permissions: vec![Permission::View, Permission::Input],
            supported_capabilities: c.required_capabilities.clone(),
            local_paths: nestlink_policy::PathSet::DIRECT,
            media: None,
        };
        let online_expiry = c.expires_at_unix_ms;
        let controller_sdk = Arc::new(controller_sdk);
        let host_sdk = Arc::new(host_sdk);
        let source = controller_sdk.prepare_offline_remote(
            controller.clone(),
            source,
            original.clone(),
            binding.clone(),
            EndpointRole::Controller,
        )?;
        let target = host_sdk.prepare_offline_remote(
            host.clone(),
            target,
            host_original,
            binding,
            EndpointRole::Host,
        )?;
        server.abort();
        let _ = server.await;
        let proof = tokio::net::TcpListener::bind(address).await?;
        drop(proof);
        tokio::time::sleep(Duration::from_millis(
            online_expiry.saturating_sub(wall()?) + 20,
        ))
        .await;
        assert!(wall()? >= original.claims().expires_at_unix_ms);
        let listener = target.listen("127.0.0.1:0".parse()?)?;
        let peer = listener.address()?;
        let (_source_stop, source_stop) = watch::channel(None);
        let (_host_stop, host_stop) = watch::channel(None);
        let (host_runtime, source_runtime) = tokio::join!(
            listener.accept(SessionLifecycle::new(host_stop)),
            source.connect(peer, SessionLifecycle::new(source_stop))
        );
        let mut host_runtime = host_runtime?;
        let mut source_runtime = source_runtime?;
        assert!(
            source_runtime
                .channels()
                .lease_control()
                .current_native_permit()
                .is_err()
        );
        assert!(
            source_runtime
                .channels()
                .send(Channel::Input, b"not approved offline")
                .await
                .is_err()
        );
        host_runtime
            .channels()
            .send(Channel::Video, b"original remote offline frame")
            .await?;
        assert_eq!(
            source_runtime.channels().receive().await?.payload,
            b"original remote offline frame"
        );
        assert!(source.status()?.remaining_bytes < 4096);
        assert_eq!(source.status()?.connection_attempts, 1);
        source_process.stop();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), source_runtime.channels().receive())
                .await?
                .is_err()
        );
        source_runtime.wait_stopped().await?;
        host_runtime.wait_stopped().await?;
        let released = std::net::UdpSocket::bind(peer)?;
        drop(released);
        assert!(
            source
                .connect(peer, SessionLifecycle::new(watch::channel(None).1))
                .await
                .is_err()
        );
        target.stop();
        drop(host_process);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?
}
