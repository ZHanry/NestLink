use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_policy::PathSet;
use nestlink_protocol::{
    Path, Permission,
    api::{ApprovalChoice, RemoteRequest},
};
use nestlink_remote::{RuntimeClock, SessionLifecycle, SessionSetup, TransportMode};
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk, SdkError};
use nestlink_server::{AppState, router};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use nestlink_storage::Store;
use nestlink_transport_quic::{connect, connector, listener};
use nestlink_transport_stream::Channel;
use std::time::Duration;
use tokio::sync::watch;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Running(tokio::task::JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn password() -> Secret {
    Secret::from_text("sdk-integration-password".into())
}
fn trust(deployment_id: &str, issuer: [u8; 32]) -> DeploymentTrust {
    DeploymentTrust {
        deployment_id: deployment_id.into(),
        permit_issuer: issuer,
    }
}

#[tokio::test]
async fn real_http_sdk_registration_approval_native_quic_and_revoke() -> Result {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", password().expose())?;
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", http.local_addr()?);
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([12; 32]),
        signer,
        origin.clone(),
        false,
    )?);
    let _service = Running(tokio::spawn(async move {
        let _ = axum_serve(http, app).await;
    }));
    assert!(matches!(
        Sdk::connect(&origin, trust(&random_id(), issuer), true).await,
        Err(SdkError::Trust)
    ));
    let mut controller_sdk = Sdk::connect(&origin, trust(&deployment, issuer), true).await?;
    controller_sdk
        .login("admin".into(), password(), None)
        .await?;
    controller_sdk
        .create_account("host-owner".into(), password())
        .await?;
    let mut host_sdk = Sdk::connect(&origin, trust(&deployment, issuer), true).await?;
    host_sdk
        .login("host-owner".into(), password(), None)
        .await?;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    controller_sdk
        .enroll(
            &controller,
            "Controller".into(),
            "windows".into(),
            vec!["controller".into(), "vp8".into()],
            "direct_preferred".into(),
        )
        .await?;
    host_sdk
        .enroll(
            &host,
            "Host".into(),
            "linux-x11".into(),
            vec!["host".into(), "vp8".into()],
            "direct_preferred".into(),
        )
        .await?;
    let controller_devices = controller_sdk.devices().await?;
    assert_eq!(controller_devices.len(), 1);
    assert_eq!(
        controller_devices[0].device.capabilities,
        vec!["controller".to_owned(), "vp8".to_owned()],
        "registration must preserve the caller's explicit codec capabilities"
    );
    assert_eq!(host_sdk.devices().await?.len(), 1);
    let view = controller_sdk
        .create_remote(RemoteRequest {
            id: random_id(),
            controller_device_id: controller.device_id.clone(),
            host_device_id: host.device_id.clone(),
            permissions: vec![Permission::View as i32, Permission::Input as i32],
            path_mode: "direct_preferred".into(),
        })
        .await?;
    assert!(controller_sdk.permit(&view.id).await.is_err());
    let pending = host_sdk.pending_remote().await?;
    assert_eq!(pending.len(), 1);
    host_sdk
        .approve(
            &host,
            &view,
            ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32],
                paths: vec![Path::Direct as i32],
            },
        )
        .await?;
    let initial = controller_sdk.permit(&view.id).await?;
    let approved = controller_sdk.remote(&view.id).await?;
    let host_signature = host_sdk.renewal_signature(&host, &approved, &initial)?;
    let permit = controller_sdk
        .renew_permit(&controller, &approved, &initial, host_signature)
        .await?;
    assert_eq!(permit.claims().lease_sequence, 2);
    assert!(
        controller_sdk
            .renew_permit(
                &controller,
                &approved,
                &initial,
                host_sdk.renewal_signature(&host, &approved, &initial)?
            )
            .await
            .is_err()
    );
    let host_permit = host_sdk.host_permit(&host, &view.id).await?;
    assert_eq!(permit.digest(), host_permit.digest());
    assert!(matches!(
        controller_sdk.connect_relay(&controller, &permit).await,
        Err(SdkError::Api(
            _,
            nestlink_protocol::ErrorCode::RelayDisabled
        ))
    ));
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use nestlink_protocol::api::{
        Candidate, CandidateKind, SignalPayload, SignalSubmission, SignalView, Transport,
    };
    use nestlink_sdk::{SignalCursor, verify_peer_signal};
    let payload = SignalPayload {
        ice: None,
        connection_generation: 1,
        lease_sequence: 2,
        network_generation: 1,
        sequence: 1,
        candidates: vec![Candidate {
            address: "192.168.1.20:28743".parse()?,
            transport: Transport::Quic,
            kind: CandidateKind::Lan,
            generation: 1,
        }],
        description: None,
    };
    host_sdk
        .publish_signal(&host, &host_permit, payload.clone())
        .await?;
    let mut cursor = SignalCursor::new(&permit, &controller)?;
    assert_eq!(
        controller_sdk
            .peer_signals(&controller, &permit, &mut cursor)
            .await?,
        vec![payload.clone()]
    );
    assert!(
        controller_sdk
            .peer_signals(&controller, &permit, &mut cursor)
            .await?
            .is_empty()
    );
    let account = &host_sdk.principal().ok_or("host signed out")?.account_id;
    let proof =
        nestlink_identity::signal_transcript(permit.claims(), account, &host.device_id, &payload)?;
    let envelope = SignalView {
        account_id: account.clone(),
        public_key: URL_SAFE_NO_PAD.encode(host.identity.public_key()),
        submission: SignalSubmission {
            device_id: host.device_id.clone(),
            payload: payload.clone(),
            signature: URL_SAFE_NO_PAD.encode(host.identity.sign_action(&proof)?),
        },
    };
    let mut forged = envelope.clone();
    forged.submission.payload.candidates[0]
        .address
        .set_port(12345);
    assert!(verify_peer_signal(&permit, &controller, forged, &mut cursor).is_err());
    assert!(verify_peer_signal(&initial, &controller, envelope, &mut cursor).is_err());
    let claims = permit.claims();
    let binding = SessionBinding {
        media: None,
        deployment_id: claims.deployment_id.clone(),
        security_epoch: claims.security_epoch,
        session_id: claims.session_id.clone(),
        account_id: claims.account_id.clone(),
        controller_device_id: claims.controller_device_id.clone(),
        host_device_id: claims.host_device_id.clone(),
        controller_key_sha256: controller.identity.fingerprint(),
        host_key_sha256: host.identity.fingerprint(),
        resource_id: claims.resource_id.clone(),
        policy_revision: claims.policy_revision,
        connection_generation: claims.connection_generation,
        capability_sha256: claims.capability_sha256.as_slice().try_into()?,
        granted_permissions: vec![Permission::View],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::DIRECT,
    };
    let server = listener(
        "127.0.0.1:0".parse()?,
        &host.identity,
        controller.identity.fingerprint(),
    )?;
    let client = connector(
        "127.0.0.1:0".parse()?,
        &controller.identity,
        host.identity.fingerprint(),
    )?;
    let address = server.local_addr()?;
    let host_key = host.identity.public_key();
    let controller_key = controller.identity.public_key();
    let (revoke, stop) = watch::channel(None);
    let host_binding = binding.clone();
    let task = tokio::spawn(async move {
        let connection = server.accept().await.ok_or("no incoming QUIC")?.await?;
        let clock = RuntimeClock::default();
        let session =
            Session::activate(host_permit, host_binding, Path::Direct, 0, clock.sample()?)?;
        let mut channel = nestlink_remote::quic::authorize(
            connection,
            Some(server),
            SessionSetup {
                session,
                path: Path::Direct,
                role: EndpointRole::Host,
                clock,
                lifecycle: SessionLifecycle::new(stop),
            },
            &host.identity,
            &controller_key,
        )
        .await?;
        channel
            .send(Channel::Video, b"authenticated-data-channel")
            .await?;
        assert!(channel.receive().await.is_err());
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let connection = connect(&client, address, Duration::from_secs(3)).await?;
    let clock = RuntimeClock::default();
    let session = Session::activate(permit, binding, Path::Direct, 0, clock.sample()?)?;
    let (_keep, stop) = watch::channel(None);
    let mut channel = nestlink_remote::quic::authorize(
        connection,
        Some(client),
        SessionSetup {
            session,
            path: Path::Direct,
            role: EndpointRole::Controller,
            clock,
            lifecycle: SessionLifecycle::new(stop),
        },
        &controller.identity,
        &host_key,
    )
    .await?;
    assert_eq!(channel.mode(), TransportMode::QuicStreamsAndDatagrams);
    assert_eq!(
        channel.receive().await?.payload,
        b"authenticated-data-channel"
    );
    assert!(channel.send(Channel::Input, b"not-approved").await.is_err());
    host_sdk.revoke_remote(&view.id).await?;
    assert!(controller_sdk.permit(&view.id).await.is_err());
    revoke.send(Some(StopReason::Revoked))?;
    tokio::time::timeout(Duration::from_secs(2), task).await???;
    controller_sdk.refresh().await?;
    controller_sdk.logout().await?;
    assert!(controller_sdk.principal().is_none());
    assert!(matches!(
        controller_sdk.devices().await,
        Err(SdkError::SignIn)
    ));
    channel.wait_stopped().await?;
    Ok(())
}
async fn axum_serve(listener: tokio::net::TcpListener, app: axum::Router) -> std::io::Result<()> {
    axum::serve(listener, app).await
}

#[tokio::test]
async fn audit_http_sdk_pages_live_roles_retention_and_running_service_maintenance() -> Result {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", password().expose())?;
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", http.local_addr()?);
    let state = AppState::new(
        store,
        VaultKey::from_bytes([21; 32]),
        signer,
        origin.clone(),
        false,
    )?;
    let app = router(state.clone());
    let _service = Running(tokio::spawn(async move {
        let _ = axum_serve(http, app).await;
    }));
    let _maintenance = Running(tokio::spawn(async move {
        let _ = state.run_audit_maintenance().await;
    }));
    let mut admin = Sdk::connect(&origin, trust(&deployment, issuer), true).await?;
    admin.login("admin".into(), password(), None).await?;
    admin
        .create_account("auditor-member".into(), password())
        .await?;
    let mut member = Sdk::connect(&origin, trust(&deployment, issuer), true).await?;
    member
        .login("auditor-member".into(), password(), None)
        .await?;
    assert!(matches!(
        member.audit_page(0, 100).await,
        Err(SdkError::Api(reqwest::StatusCode::FORBIDDEN, _))
    ));
    assert!(member.audit_retention().await.is_err());
    assert!(
        member
            .set_audit_retention(nestlink_protocol::api::AuditRetentionUpdate {
                expected_revision: 1,
                retention_seconds: 3600
            })
            .await
            .is_err()
    );
    let initial = admin.audit_retention().await?;
    assert_eq!(initial.retention_seconds, 2_592_000);
    let changed = admin
        .set_audit_retention(nestlink_protocol::api::AuditRetentionUpdate {
            expected_revision: initial.revision,
            retention_seconds: 3600,
        })
        .await?;
    assert_eq!(changed.revision, initial.revision + 1);
    assert!(matches!(
        admin
            .set_audit_retention(nestlink_protocol::api::AuditRetentionUpdate {
                expected_revision: initial.revision,
                retention_seconds: 7200
            })
            .await,
        Err(SdkError::Api(reqwest::StatusCode::CONFLICT, _))
    ));
    let first = admin.audit_page(0, 2).await?;
    assert_eq!(first.entries.len(), 2);
    assert_eq!(
        first.entries[0].actor,
        nestlink_protocol::api::AuditActor::LocalOperator
    );
    let actor = admin.principal().ok_or("admin signed out")?;
    let expected = nestlink_protocol::api::AuditActor::Management {
        account_id: actor.account_id.clone(),
        session_id: actor.session_id.clone(),
    };
    assert_eq!(first.entries[1].actor, expected);
    assert!(first.more);
    let rest = admin.audit_page(first.next_sequence, 100).await?;
    assert!(
        rest.entries
            .iter()
            .all(|entry| entry.sequence > first.next_sequence)
    );
    assert_eq!(
        rest.entries
            .iter()
            .find(|entry| entry.event == "audit_retention_changed")
            .ok_or("missing retention event")?
            .actor,
        expected
    );
    assert!(!serde_json::to_string(&rest)?.contains(password().expose()));
    assert_eq!(rest.high_watermark, changed.high_watermark);
    assert!(matches!(
        admin.audit_page(rest.high_watermark + 1, 1).await,
        Err(SdkError::Api(reqwest::StatusCode::CONFLICT, _))
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if admin.audit_retention().await?.last_cleanup_at_unix_ms > 0 {
                return Ok::<(), SdkError>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn opaque_websocket_relay_inner_mutual_tls_and_server_revocation() -> Result {
    relay_roundtrip(RelayRevocation::Session).await
}
#[tokio::test]
async fn trusted_device_access_over_inner_tls_relay_stops_after_trust_revocation() -> Result {
    relay_roundtrip(RelayRevocation::RemoveTrust).await
}
#[tokio::test]
async fn replacing_trust_revokes_the_live_old_revision_relay() -> Result {
    relay_roundtrip(RelayRevocation::ReplaceTrust).await
}
#[tokio::test]
async fn fixed_password_authority_revocation_closes_both_live_relay_endpoints() -> Result {
    relay_roundtrip(RelayRevocation::RemovePassword).await
}
#[tokio::test]
async fn fixed_password_rotation_closes_the_old_revision_relay() -> Result {
    relay_roundtrip(RelayRevocation::ReplacePassword).await
}
#[tokio::test]
async fn persistent_quota_change_closes_live_relay_and_denies_new_admission() -> Result {
    relay_roundtrip(RelayRevocation::Quota).await
}
#[derive(Clone, Copy, PartialEq)]
enum RelayRevocation {
    Session,
    Quota,
    RemoveTrust,
    ReplaceTrust,
    RemovePassword,
    ReplacePassword,
}
async fn relay_roundtrip(revocation: RelayRevocation) -> Result {
    let trusted = matches!(
        revocation,
        RelayRevocation::RemoveTrust | RelayRevocation::ReplaceTrust
    );
    let password_access = matches!(
        revocation,
        RelayRevocation::RemovePassword | RelayRevocation::ReplacePassword
    );
    use nestlink_protocol::api::{NetworkPolicy, PolicyUpdate};
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", password().expose())?;
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", http.local_addr()?);
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([14; 32]),
        signer,
        origin.clone(),
        false,
    )?);
    let _service = Running(tokio::spawn(async move {
        let _ = axum_serve(http, app).await;
    }));
    let mut controller_sdk = Sdk::connect(&origin, trust(&deployment, issuer), true).await?;
    controller_sdk
        .login("admin".into(), password(), None)
        .await?;
    controller_sdk
        .create_account("host-owner".into(), password())
        .await?;
    controller_sdk
        .set_policy(PolicyUpdate {
            expected_revision: 1,
            policy: NetworkPolicy {
                server_forwarding: "allow".into(),
                peer_path_mode: "direct_preferred".into(),
                public_ingress: "disabled".into(),
            },
        })
        .await?;
    let mut host_sdk = Sdk::connect(&origin, trust(&deployment, issuer), true).await?;
    host_sdk
        .login("host-owner".into(), password(), None)
        .await?;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    controller_sdk
        .enroll(
            &controller,
            "controller".into(),
            "windows".into(),
            vec!["controller".into(), "vp8".into()],
            "direct_preferred".into(),
        )
        .await?;
    host_sdk
        .enroll(
            &host,
            "host".into(),
            "linux-x11".into(),
            vec!["host".into(), "vp8".into()],
            "direct_preferred".into(),
        )
        .await?;
    let request = controller_sdk
        .create_remote(RemoteRequest {
            id: random_id(),
            controller_device_id: controller.device_id.clone(),
            host_device_id: host.device_id.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "relay_only".into(),
        })
        .await?;
    if !password_access {
        host_sdk
            .approve(
                &host,
                &request,
                ApprovalChoice {
                    approved: true,
                    permissions: vec![Permission::View as i32],
                    paths: vec![Path::Relay as i32],
                },
            )
            .await?;
    }
    let request = if trusted {
        let next = RemoteRequest {
            id: random_id(),
            controller_device_id: controller.device_id.clone(),
            host_device_id: host.device_id.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "relay_only".into(),
        };
        assert!(
            controller_sdk
                .create_trusted_remote(next.clone())
                .await
                .is_err()
        );
        let _initial = controller_sdk.permit(&request.id).await?;
        let source = host_sdk.host_permit(&host, &request.id).await?;
        assert_eq!(
            host_sdk
                .trust_remote(
                    &host,
                    &source,
                    nestlink_protocol::api::TrustChoice {
                        expected_revision: 0,
                        expires_at_unix_ms: source.claims().issued_at_unix_ms + 60_000,
                    }
                )
                .await?,
            1
        );
        assert!(
            controller_sdk
                .trusted_devices(&host.device_id)
                .await
                .is_err()
        );
        let list = host_sdk.trusted_devices(&host.device_id).await?;
        assert_eq!(list.len(), 1);
        assert!(list[0].active);
        let approved = controller_sdk.create_trusted_remote(next).await?;
        assert_eq!(approved.status, "approved");
        assert_eq!(approved.trust_revision, Some(1));
        assert!(host_sdk.pending_remote().await?.is_empty());
        approved
    } else if password_access {
        assert!(!host_sdk.remote_password(&host.device_id).await?.active);
        assert!(
            !controller_sdk
                .remote_password_offer(&request.id)
                .await?
                .active
        );
        assert!(
            controller_sdk
                .remote_password(&host.device_id)
                .await
                .is_err()
        );
        assert_eq!(
            host_sdk
                .configure_remote_password(
                    &host,
                    nestlink_protocol::api::RemotePasswordSettings {
                        expected_revision: 0,
                        permissions: vec![Permission::View as i32],
                        paths: vec![Path::Relay as i32],
                        expires_at_unix_ms: request.expires_at_unix_ms + 60_000,
                    },
                    Secret::from_text("remote-password-test-only".into())
                )
                .await?,
            1
        );
        let offer = controller_sdk.remote_password_offer(&request.id).await?;
        assert!(offer.active);
        assert!(
            controller_sdk
                .authorize_remote_password(
                    &controller,
                    &request,
                    offer.revision,
                    Secret::from_text("incorrect-password".into())
                )
                .await
                .is_err()
        );
        controller_sdk.refresh().await?;
        let approved = controller_sdk
            .authorize_remote_password(
                &controller,
                &request,
                offer.revision,
                Secret::from_text("remote-password-test-only".into()),
            )
            .await?;
        assert_eq!(approved.password_revision, Some(1));
        assert_eq!(approved.trust_revision, None);
        assert!(
            controller_sdk
                .authorize_remote_password(
                    &controller,
                    &request,
                    offer.revision,
                    Secret::from_text("remote-password-test-only".into())
                )
                .await
                .is_err()
        );
        approved
    } else {
        request
    };
    let permit = controller_sdk.permit(&request.id).await?;
    let host_permit = host_sdk.host_permit(&host, &request.id).await?;
    let stun = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let stun_address = stun.local_addr()?;
    let (_direct_endpoint, discovery) = nestlink_transport_quic::discovery_endpoint(
        "0.0.0.0:0".parse()?,
        &controller.identity,
        host.identity.fingerprint(),
        vec![stun_address],
    )?;
    let candidates =
        nestlink_sdk::discovery::gather(&permit, discovery, vec![stun_address]).await?;
    assert!(candidates.candidates.is_empty());
    let mut probe = [0; 512];
    assert!(
        tokio::time::timeout(Duration::from_millis(50), stun.recv_from(&mut probe))
            .await
            .is_err()
    );
    use nestlink_protocol::api::{Candidate, CandidateKind, Transport};
    use nestlink_sdk::native::{AddressPolicy, NativeEndpoint, NativeTransport};
    let controller_endpoint = NativeEndpoint::new(
        "127.0.0.1:0".parse()?,
        &controller,
        &host.identity.public_key(),
        permit.clone(),
        vec![stun_address],
        AddressPolicy::new(&[])?,
    )?;
    let host_endpoint = NativeEndpoint::new(
        "127.0.0.1:0".parse()?,
        &host,
        &controller.identity.public_key(),
        host_permit.clone(),
        vec![],
        AddressPolicy::new(&[])?,
    )?;
    assert!(controller_endpoint.discovery_socket().is_none());
    assert!(host_endpoint.discovery_socket().is_none());
    let c_route = controller_sdk.relay_route(&permit).await?;
    let h_route = host_sdk.relay_route(&host_permit).await?;
    let hostile = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let direct = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut c_candidates = c_route.candidates(4);
    c_candidates.push(Candidate {
        address: hostile.local_addr()?,
        kind: CandidateKind::Relay,
        transport: Transport::Wss,
        generation: 4,
    });
    c_candidates.push(Candidate {
        address: direct.local_addr()?,
        kind: CandidateKind::Lan,
        transport: Transport::Tls,
        generation: 4,
    });
    let (_c_cancel, c_cancel) = watch::channel(false);
    let (_h_cancel, h_cancel) = watch::channel(false);
    let (c_connected, h_connected) = tokio::time::timeout(Duration::from_secs(8), async {
        tokio::try_join!(
            controller_endpoint.dial_native(&controller, Some(&c_route), 4, c_candidates, c_cancel),
            host_endpoint.dial_native(&host, Some(&h_route), 4, h_route.candidates(4), h_cancel)
        )
    })
    .await??;
    assert_eq!(c_connected.candidate.path(), Path::Relay);
    assert_eq!(
        c_connected.candidate.address,
        c_route.candidates(4)[0].address
    );
    assert!(
        c_connected
            .failures
            .iter()
            .any(|f| f.stage == "relay-authority")
    );
    assert!(
        c_connected
            .failures
            .iter()
            .any(|f| f.stage == "path-policy")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), hostile.accept())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), direct.accept())
            .await
            .is_err()
    );
    assert!(matches!(&c_connected.transport, NativeTransport::Wss(_)));
    assert!(matches!(&h_connected.transport, NativeTransport::Wss(_)));
    drop(c_route);
    drop(h_route);
    let claims = permit.claims();
    let binding = SessionBinding {
        media: None,
        deployment_id: claims.deployment_id.clone(),
        security_epoch: claims.security_epoch,
        session_id: claims.session_id.clone(),
        account_id: claims.account_id.clone(),
        controller_device_id: claims.controller_device_id.clone(),
        host_device_id: claims.host_device_id.clone(),
        controller_key_sha256: controller.identity.fingerprint(),
        host_key_sha256: host.identity.fingerprint(),
        resource_id: claims.resource_id.clone(),
        policy_revision: claims.policy_revision,
        connection_generation: claims.connection_generation,
        capability_sha256: claims.capability_sha256.as_slice().try_into()?,
        granted_permissions: vec![Permission::View],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::RELAY,
    };
    let c_clock = RuntimeClock::default();
    let h_clock = RuntimeClock::default();
    let c_session = Session::activate(
        permit.clone(),
        binding.clone(),
        Path::Relay,
        0,
        c_clock.sample()?,
    )?;
    let h_session = Session::activate(host_permit, binding, Path::Relay, 0, h_clock.sample()?)?;
    let host_key = host.identity.public_key();
    let controller_key = controller.identity.public_key();
    let (_c_keep, c_stop) = watch::channel(None);
    let (_h_keep, h_stop) = watch::channel(None);
    let (c, h) = tokio::try_join!(
        c_connected.authorize(
            SessionSetup {
                session: c_session,
                path: Path::Relay,
                role: EndpointRole::Controller,
                clock: c_clock.clone(),
                lifecycle: SessionLifecycle::new(c_stop)
            },
            &controller,
            &host_key
        ),
        h_connected.authorize(
            SessionSetup {
                session: h_session,
                path: Path::Relay,
                role: EndpointRole::Host,
                clock: h_clock.clone(),
                lifecycle: SessionLifecycle::new(h_stop)
            },
            &host,
            &controller_key
        )
    )?;
    let mut c = c.channels;
    let mut h = h.channels;
    assert_eq!(c.mode(), TransportMode::ReliableByteStream);
    let bytes = vec![42; 512 * 1024];
    let (sent, received) = tokio::join!(h.send(Channel::Video, &bytes), c.receive());
    sent?;
    assert_eq!(received?.payload, bytes);
    // Refresh rotates HTTP tokens without killing an authorized relay login session.
    controller_sdk.refresh().await?;
    let approved = controller_sdk.remote(&request.id).await?;
    let host_signature = host_sdk.renewal_signature(&host, &approved, &permit)?;
    let started_c = c_clock.monotonic_ms();
    let started_h = h_clock.monotonic_ms();
    let renewed = controller_sdk
        .renew_permit(&controller, &approved, &permit, host_signature)
        .await?;
    c.lease_control().renew(renewed.clone(), started_c.max(1))?;
    h.lease_control().renew(renewed, started_h.max(1))?;
    let (sent, received) = tokio::join!(h.send(Channel::Video, b"after-renewal"), c.receive());
    sent?;
    assert_eq!(received?.payload, b"after-renewal");
    if revocation == RelayRevocation::Quota {
        use nestlink_protocol::api::RelayQuotaUpdate;
        assert!(host_sdk.relay_quota().await.is_err());
        assert!(host_sdk.relay_usage().await.is_err());
        let quota = controller_sdk.relay_quota().await?;
        assert!(
            host_sdk
                .set_relay_quota(RelayQuotaUpdate {
                    expected_revision: quota.revision,
                    limits: quota.limits
                })
                .await
                .is_err()
        );
        let usage = controller_sdk.relay_usage().await?;
        assert!(nestlink_protocol::valid_id(&usage.runtime_id));
        assert_eq!((usage.allocations, usage.endpoints), (1, 2));
        assert!(usage.admitted_bytes >= bytes.len() as u64);
        let mut limits = quota.limits;
        limits.max_allocations = 0;
        let updated = controller_sdk
            .set_relay_quota(RelayQuotaUpdate {
                expected_revision: quota.revision,
                limits,
            })
            .await?;
        assert_eq!(updated.revision, quota.revision + 1);
        assert!(matches!(
            controller_sdk
                .set_relay_quota(RelayQuotaUpdate {
                    expected_revision: quota.revision,
                    limits
                })
                .await,
            Err(SdkError::Api(reqwest::StatusCode::CONFLICT, _))
        ));
        let closed = controller_sdk.relay_usage().await?;
        assert_eq!(closed.runtime_id, usage.runtime_id);
        assert_eq!((closed.allocations, closed.endpoints), (0, 0));
        assert_eq!(closed.admitted_bytes, usage.admitted_bytes);
        assert!(closed.report_sequence > usage.report_sequence);
        assert_eq!(closed.closed_allocations, 1);
        assert_eq!(controller_sdk.relay_usage().await?, closed);
    } else if revocation == RelayRevocation::ReplacePassword {
        assert_eq!(
            host_sdk
                .configure_remote_password(
                    &host,
                    nestlink_protocol::api::RemotePasswordSettings {
                        expected_revision: 1,
                        permissions: vec![Permission::View as i32],
                        paths: vec![Path::Relay as i32],
                        expires_at_unix_ms: request.expires_at_unix_ms + 60_000,
                    },
                    Secret::from_text("replacement-test-only-password".into())
                )
                .await?,
            2
        );
        assert_eq!(host_sdk.remote_password(&host.device_id).await?.revision, 2);
    } else if password_access {
        host_sdk.revoke_remote_password(&host.device_id, 1).await?;
        assert!(!host_sdk.remote_password(&host.device_id).await?.active);
    } else if revocation == RelayRevocation::ReplaceTrust {
        let current = host_sdk.host_permit(&host, &request.id).await?;
        assert_eq!(
            host_sdk
                .trust_remote(
                    &host,
                    &current,
                    nestlink_protocol::api::TrustChoice {
                        expected_revision: 1,
                        expires_at_unix_ms: current.claims().issued_at_unix_ms + 60_000,
                    }
                )
                .await?,
            2
        );
        let list = host_sdk.trusted_devices(&host.device_id).await?;
        assert!(list[0].active);
        assert_eq!(list[0].revision, 2);
    } else if trusted {
        host_sdk
            .revoke_device_trust(&host.device_id, &controller.device_id, 1)
            .await?;
        assert!(!host_sdk.trusted_devices(&host.device_id).await?[0].active);
    } else {
        host_sdk.revoke_remote(&request.id).await?;
    }
    // No local stop notification: the server itself must stop the existing relay.
    assert!(
        tokio::time::timeout(Duration::from_secs(2), c.receive())
            .await?
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), h.receive())
            .await?
            .is_err()
    );
    assert!(
        controller_sdk
            .connect_relay(&controller, &permit)
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let held = controller_sdk.relay_reservations().await?;
            if held.held_allocations == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok::<(), SdkError>(())
    })
    .await??;
    Ok(())
}
