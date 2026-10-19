use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password, random_id};
use nestlink_identity::{InstallationIdentity, PermitSigner, digest, verify_permit};
use nestlink_protocol::{
    Permission,
    api::{
        ApprovalChoice, BrowserEndpointRegistration, DeviceDescriptor, DeviceRegistration,
        RemoteRequest, RenewalSubmission,
    },
};
use nestlink_storage::{StorageError, Store, accounts::Principal};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const PASSWORD: &str = "integration-only-password";
#[path = "control/auditing.rs"]
mod auditing;
#[path = "control/browser_readiness.rs"]
mod browser_readiness;
#[path = "control/quotas.rs"]
mod quotas;
#[path = "control/reconnection.rs"]
mod reconnection;
#[path = "control/remote_password.rs"]
mod remote_password;
#[path = "control/trusted.rs"]
mod trusted;

fn fixture() -> Result<(Store, VaultKey, String, Principal, Principal)> {
    let mut s = Store::in_memory(&random_id())?;
    let vault = VaultKey::from_bytes([7; 32]);
    let dummy = hash_password("dummy-only-password")?;
    s.bootstrap_admin("Admin", PASSWORD)?;
    let admin = s
        .login("admin", PASSWORD, None, 1000, &vault, &dummy)?
        .principal;
    s.create_member(&admin, "member", PASSWORD)?;
    let member = s
        .login("member", PASSWORD, None, 1000, &vault, &dummy)?
        .principal;
    Ok((s, vault, dummy, admin, member))
}
fn enroll(
    s: &mut Store,
    p: &Principal,
    identity: &InstallationIdentity,
    name: &str,
) -> Result<String> {
    let challenge = s.enrollment_challenge(p, 1000)?;
    let mut registration = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: random_id(),
            name: name.into(),
            platform: "windows".into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            capabilities: vec!["controller".into(), "host".into(), "vp8".into()],
            path_mode: "direct_preferred".into(),
        },
        signature: String::new(),
    };
    registration.signature = URL_SAFE_NO_PAD
        .encode(identity.sign_action(&s.registration_transcript(p, &registration, 1000)?)?);
    let id = registration.device.id.clone();
    s.register_device(p, registration, 1000)?;
    Ok(id)
}
fn enroll_browser(
    s: &mut Store,
    p: &Principal,
    identity: &InstallationIdentity,
    now: u64,
) -> Result<nestlink_protocol::api::BrowserEndpointLease> {
    let challenge = s.enrollment_challenge(p, now)?;
    let mut registration = BrowserEndpointRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: random_id(),
            name: "browser controller".into(),
            platform: "web".into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            capabilities: vec!["controller".into(), "vp8".into()],
            path_mode: "direct_only".into(),
        },
        signature: String::new(),
    };
    registration.signature = URL_SAFE_NO_PAD
        .encode(identity.sign_action(&s.browser_endpoint_transcript(p, &registration, now)?)?);
    Ok(s.register_browser_endpoint(p, registration, now)?)
}
#[test]
fn concurrent_account_logins_refresh_and_logout_independently() -> Result {
    let (mut store, vault, dummy, _, _) = fixture()?;
    let desktop = store.login("admin", PASSWORD, None, 1001, &vault, &dummy)?;
    let web = store.login("admin", PASSWORD, None, 1002, &vault, &dummy)?;
    let phone = store.login("admin", PASSWORD, None, 1003, &vault, &dummy)?;
    assert_ne!(desktop.principal.session_id, web.principal.session_id);
    assert_ne!(web.principal.session_id, phone.principal.session_id);
    let desktop = store.refresh_login(desktop.refresh_token.expose(), desktop.generation, 1010)?;
    assert!(store.authenticate(web.access_token.expose(), 1010).is_ok());
    assert!(
        store
            .authenticate(phone.access_token.expose(), 1010)
            .is_ok()
    );
    store.logout(&web.principal)?;
    assert!(store.authenticate(web.access_token.expose(), 1011).is_err());
    assert!(
        store
            .authenticate(desktop.access_token.expose(), 1011)
            .is_ok()
    );
    assert!(
        store
            .authenticate(phone.access_token.expose(), 1011)
            .is_ok()
    );
    let phone = store.refresh_login(phone.refresh_token.expose(), phone.generation, 1012)?;
    store.change_password(
        &desktop.principal,
        PASSWORD,
        "replacement-password-050",
        None,
        1013,
        &vault,
    )?;
    assert!(
        store
            .authenticate(desktop.access_token.expose(), 1013)
            .is_err()
    );
    assert!(
        store
            .authenticate(phone.access_token.expose(), 1013)
            .is_err()
    );
    Ok(())
}

#[test]
fn token_refresh_is_single_consumer_and_old_access_is_dead() -> Result {
    let (mut s, vault, dummy, admin, member) = fixture()?;
    assert!(matches!(
        s.bootstrap_admin("second", PASSWORD),
        Err(StorageError::Conflict)
    ));
    assert!(matches!(
        s.create_member(&member, "forbidden", PASSWORD),
        Err(StorageError::Forbidden)
    ));
    let first = s.login("admin", PASSWORD, None, 1001, &vault, &dummy)?;
    let second = s.refresh_login(first.refresh_token.expose(), first.generation, 1002)?;
    assert!(s.authenticate(first.access_token.expose(), 1002).is_err());
    assert!(
        s.refresh_login(first.refresh_token.expose(), first.generation, 1002)
            .is_err()
    );
    assert!(s.authenticate(second.access_token.expose(), 1002).is_ok());
    s.logout(&second.principal)?;
    assert!(
        s.refresh_login(second.refresh_token.expose(), second.generation, 1003)
            .is_err()
    );
    assert!(s.disable_account(&member, &admin.account_id).is_err());
    s.disable_account(&admin, &member.account_id)?;
    assert!(
        s.login("member", PASSWORD, None, 1004, &vault, &dummy)
            .is_err()
    );
    Ok(())
}
#[test]
fn enrollment_requires_key_possession_and_challenge_is_account_bound() -> Result {
    let (mut s, _, _, admin, member) = fixture()?;
    let identity = InstallationIdentity::generate();
    let challenge = s.enrollment_challenge(&admin, 1000)?;
    let mut body = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: random_id(),
            name: "test".into(),
            platform: "windows".into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            capabilities: vec!["vp8".into(), "host".into()],
            path_mode: "direct_only".into(),
        },
        signature: String::new(),
    };
    assert!(s.registration_transcript(&member, &body, 1000).is_err());
    let proof = s.registration_transcript(&admin, &body, 1000)?;
    body.signature = URL_SAFE_NO_PAD.encode(InstallationIdentity::generate().sign_action(&proof)?);
    assert!(s.register_device(&admin, body, 1000).is_err());
    let id = enroll(&mut s, &admin, &identity, "actual")?;
    assert_eq!(s.devices(&admin)?[0].device.id, id);
    assert_eq!(s.devices_at(&admin, 1_000_000)?.len(), 1);
    assert!(s.devices(&member)?.is_empty());
    Ok(())
}
#[test]
fn browser_endpoint_is_controller_only_and_server_expiry_bounds_permits() -> Result {
    let (mut s, _, _, admin, member) = fixture()?;
    let browser = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let host_id = enroll(&mut s, &member, &host, "host")?;
    let lease = enroll_browser(&mut s, &admin, &browser, 1000)?;
    assert_eq!(lease.expires_at_unix_ms, 1_600_000);
    assert_eq!(lease.device_id, s.devices_at(&admin, 1599)?[0].device.id);
    assert!(s.devices_at(&admin, 1600)?.is_empty());
    let credential_id = random_id();
    assert!(
        s.register_credential(&credential_id, &lease.device_id, "management", &[3; 32])
            .is_err()
    );

    // The expired identity cannot be used to create a fresh remote request.
    assert!(
        s.create_remote(
            &admin,
            RemoteRequest {
                id: random_id(),
                controller_device_id: lease.device_id.clone(),
                host_device_id: host_id.clone(),
                permissions: vec![Permission::View as i32],
                path_mode: "direct_only".into(),
            },
            1600,
        )
        .is_err()
    );

    // The last permit issued before expiry is itself capped at the device lease,
    // and all permit lookups stop working at that exact boundary.
    let browser = InstallationIdentity::generate();
    let lease = enroll_browser(&mut s, &admin, &browser, 2000)?;
    let view = s.create_remote(
        &admin,
        RemoteRequest {
            id: random_id(),
            controller_device_id: lease.device_id,
            host_device_id: host_id,
            permissions: vec![Permission::View as i32],
            path_mode: "direct_only".into(),
        },
        2599,
    )?;
    let choice = ApprovalChoice {
        approved: true,
        permissions: vec![Permission::View as i32],
        paths: vec![1],
    };
    let proof = s.approval_transcript(&member, &view.id, &choice, 2599)?;
    let signature = URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?);
    s.approve_remote(&member, &view.id, choice, &signature, 2599)?;
    let proof = s.browser_host_readiness_transcript(&member, &view.id, 2599)?;
    s.mark_browser_host_ready(
        &member,
        &view.id,
        nestlink_protocol::api::BrowserHostReadinessSubmission {
            signature: URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
        },
        2599,
    )?;
    let permit = s.initial_permit(&admin, &view.id, 2599)?;
    assert_eq!(permit.expires_at_unix_ms, 2_600_000);
    assert!(s.session_is_active_at(&view.id, 2599)?);
    assert!(s.lease_is_active_at(&view.id, 2599)?);
    assert!(!s.session_is_active_at(&view.id, 2600)?);
    assert!(!s.lease_is_active_at(&view.id, 2600)?);
    assert!(s.current_permit(&admin, &view.id, 2600).is_err());
    assert!(
        s.renewal_transcript(&admin, &view.id, 2, false, 2600)
            .is_err()
    );
    Ok(())
}
#[test]
fn browser_endpoint_account_cap_counts_only_live_leases() -> Result {
    let (mut s, _, _, admin, _) = fixture()?;
    let mut last = None;
    for _ in 0..nestlink_storage::control::MAX_ACTIVE_BROWSER_ENDPOINTS_PER_ACCOUNT {
        last = Some(enroll_browser(
            &mut s,
            &admin,
            &InstallationIdentity::generate(),
            1_000,
        )?);
    }
    let over_limit = enroll_browser(&mut s, &admin, &InstallationIdentity::generate(), 1_000);
    assert!(matches!(
        over_limit,
        Err(error)
            if matches!(error.downcast_ref::<StorageError>(), Some(StorageError::RateLimited))
    ));

    // The cap is on active leases; an endpoint expiring at this exact second
    // no longer occupies a slot for a fresh browser session.
    assert!(last.is_some());
    let replacement = enroll_browser(&mut s, &admin, &InstallationIdentity::generate(), 1_600)?;
    assert!(!replacement.device_id.is_empty());
    Ok(())
}
#[test]
fn approval_shrinks_permissions_and_revocation_prevents_renewal() -> Result {
    let (mut s, vault, dummy, admin, member) = fixture()?;
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let c = enroll(&mut s, &admin, &controller, "controller")?;
    let h = enroll(&mut s, &member, &host, "host")?;
    let request = RemoteRequest {
        id: random_id(),
        controller_device_id: c,
        host_device_id: h,
        permissions: vec![Permission::View as i32, Permission::Input as i32],
        path_mode: "direct_only".into(),
    };
    let view = s.create_remote(&admin, request.clone(), 1000)?;
    let mut changed = request.clone();
    changed.path_mode = "direct_preferred".into();
    assert!(matches!(
        s.create_remote(&admin, changed, 1000),
        Err(StorageError::Conflict)
    ));
    assert_eq!(s.create_remote(&admin, request, 1000)?.id, view.id);
    let choice = ApprovalChoice {
        approved: true,
        permissions: vec![Permission::View as i32],
        paths: vec![1],
    };
    assert!(
        s.approval_transcript(&admin, &view.id, &choice, 1001)
            .is_err()
    );
    let proof = s.approval_transcript(&member, &view.id, &choice, 1001)?;
    let signature = URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?);
    s.approve_remote(&member, &view.id, choice.clone(), &signature, 1001)?;
    assert!(
        s.approve_remote(&member, &view.id, choice, &signature, 1001)
            .is_err()
    );
    let initial = s.initial_permit(&admin, &view.id, 1002)?;
    let retry = s.initial_permit(&admin, &view.id, 1003)?;
    assert_eq!(initial, retry);
    // Each account can obtain only the keys of the peer in its approved session.
    // A third management account and a subsequently revoked request cannot.
    assert!(
        s.devices(&admin)?
            .iter()
            .all(|d| d.device.id != initial.host_device_id)
    );
    let controller_keys = s.remote_peer_keys(&admin, &view.id, 1003)?;
    let host_keys = s.remote_peer_keys(&member, &view.id, 1003)?;
    assert_eq!(
        controller_keys.controller_public_key,
        URL_SAFE_NO_PAD.encode(controller.public_key())
    );
    assert_eq!(
        controller_keys.host_public_key,
        URL_SAFE_NO_PAD.encode(host.public_key())
    );
    assert_eq!(
        host_keys.controller_public_key,
        controller_keys.controller_public_key
    );
    assert_eq!(host_keys.host_public_key, controller_keys.host_public_key);
    s.create_member(&admin, "stranger", PASSWORD)?;
    let stranger = s
        .login("stranger", PASSWORD, None, 1003, &vault, &dummy)?
        .principal;
    assert!(s.remote_peer_keys(&stranger, &view.id, 1003).is_err());
    let signer = PermitSigner::generate();
    use prost::Message;
    let verified = verify_permit(
        &signer.sign(&initial)?.encode_to_vec(),
        &signer.public_key(),
    )?;
    assert_eq!(verified.claims().permissions, vec![Permission::View as i32]);
    let cp = s.renewal_transcript(&admin, &view.id, 2, false, 1007)?;
    let hp = s.renewal_transcript(&admin, &view.id, 2, true, 1007)?;
    let renewal = RenewalSubmission {
        lease_sequence: 2,
        controller_signature: URL_SAFE_NO_PAD.encode(controller.sign_action(&cp)?),
        host_signature: URL_SAFE_NO_PAD.encode(host.sign_action(&hp)?),
    };
    let renewed = s.renew_permit(&admin, &view.id, renewal, 1007)?;
    assert_eq!(renewed.lease_sequence, 2);
    s.revoke_remote(&member, &view.id)?;
    assert!(s.remote_peer_keys(&admin, &view.id, 1008).is_err());
    assert!(s.remote_peer_keys(&member, &view.id, 1008).is_err());
    assert!(
        s.renewal_transcript(&admin, &view.id, 3, false, 1008)
            .is_err()
    );
    assert!(!s.session_is_active(&view.id)?);
    Ok(())
}

#[test]
fn audio_codec_requirement_tracks_approved_permission_and_survives_renewal() -> Result {
    let (mut s, _, _, admin, member) = fixture()?;
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let controller_id = enroll(&mut s, &admin, &controller, "controller")?;
    let host_id = enroll(&mut s, &member, &host, "host")?;

    let audio_request = RemoteRequest {
        id: random_id(),
        controller_device_id: controller_id.clone(),
        host_device_id: host_id.clone(),
        permissions: vec![Permission::View as i32, Permission::Audio as i32],
        path_mode: "direct_only".into(),
    };
    let audio_view = s.create_remote(&admin, audio_request, 1000)?;
    let audio_choice = ApprovalChoice {
        approved: true,
        permissions: vec![Permission::View as i32, Permission::Audio as i32],
        paths: vec![1],
    };
    let audio_proof = s.approval_transcript(&member, &audio_view.id, &audio_choice, 1001)?;
    let audio_signature = URL_SAFE_NO_PAD.encode(host.sign_action(&audio_proof)?);
    s.approve_remote(
        &member,
        &audio_view.id,
        audio_choice,
        &audio_signature,
        1001,
    )?;

    let audio_permit = s.initial_permit(&admin, &audio_view.id, 1002)?;
    assert_eq!(
        audio_permit.permissions,
        vec![Permission::View as i32, Permission::Audio as i32]
    );
    assert_eq!(audio_permit.required_capabilities, vec!["vp8", "opus"]);

    // Browser and native hosts consume the same signed permit. Renewal must
    // preserve its codec requirements as well as the approved permissions.
    let controller_proof = s.renewal_transcript(&admin, &audio_view.id, 2, false, 1003)?;
    let host_proof = s.renewal_transcript(&admin, &audio_view.id, 2, true, 1003)?;
    let renewed_audio_permit = s.renew_permit(
        &admin,
        &audio_view.id,
        RenewalSubmission {
            lease_sequence: 2,
            controller_signature: URL_SAFE_NO_PAD
                .encode(controller.sign_action(&controller_proof)?),
            host_signature: URL_SAFE_NO_PAD.encode(host.sign_action(&host_proof)?),
        },
        1003,
    )?;
    assert_eq!(renewed_audio_permit.lease_sequence, 2);
    assert_eq!(renewed_audio_permit.permissions, audio_permit.permissions);
    assert_eq!(
        renewed_audio_permit.required_capabilities,
        audio_permit.required_capabilities
    );
    assert_eq!(
        s.current_permit(&admin, &audio_view.id, 1003)?,
        renewed_audio_permit
    );

    let view_request = RemoteRequest {
        id: random_id(),
        controller_device_id: controller_id,
        host_device_id: host_id,
        permissions: vec![Permission::View as i32, Permission::Audio as i32],
        path_mode: "direct_only".into(),
    };
    let view = s.create_remote(&admin, view_request, 1004)?;
    let view_choice = ApprovalChoice {
        approved: true,
        permissions: vec![Permission::View as i32],
        paths: vec![1],
    };
    let view_proof = s.approval_transcript(&member, &view.id, &view_choice, 1005)?;
    let view_signature = URL_SAFE_NO_PAD.encode(host.sign_action(&view_proof)?);
    s.approve_remote(&member, &view.id, view_choice, &view_signature, 1005)?;
    let view_permit = s.initial_permit(&admin, &view.id, 1006)?;
    assert_eq!(view_permit.permissions, vec![Permission::View as i32]);
    assert_eq!(view_permit.required_capabilities, vec!["vp8"]);
    Ok(())
}

#[test]
fn lockout_and_restore_invalidate_login() -> Result {
    let (mut s, vault, dummy, _, _) = fixture()?;
    for _ in 0..5 {
        assert!(
            s.login("admin", "wrong-password", None, 1001, &vault, &dummy)
                .is_err()
        );
    }
    assert!(matches!(
        s.login("admin", PASSWORD, None, 1002, &vault, &dummy),
        Err(StorageError::RateLimited)
    ));
    let grant = s.login("admin", PASSWORD, None, 1032, &vault, &dummy)?;
    s.invalidate_after_restore()?;
    assert!(s.authenticate(grant.access_token.expose(), 1032).is_err());
    assert!(
        s.refresh_login(grant.refresh_token.expose(), grant.generation, 1032)
            .is_err()
    );
    Ok(())
}

#[test]
fn persisted_scope_limits_cannot_be_bypassed_by_session_request() -> Result {
    use nestlink_policy::{NetworkPolicy, PeerPathMode, PublicIngress, ServerForwarding};
    let (mut s, _, _, admin, member) = fixture()?;
    let c = enroll(
        &mut s,
        &admin,
        &InstallationIdentity::generate(),
        "controller",
    )?;
    let h = enroll(&mut s, &member, &InstallationIdentity::generate(), "host")?;
    let mut revision = s.apply_policy(
        1,
        NetworkPolicy {
            server_forwarding: ServerForwarding::Allow,
            peer_path_mode: PeerPathMode::DirectPreferred,
            public_ingress: PublicIngress::Disabled,
        },
    )?;
    for (scope, id) in [
        ("account", admin.account_id.clone()),
        ("device", c.clone()),
        ("resource", h.clone()),
        ("login_session", admin.session_id.clone()),
    ] {
        assert!(
            s.set_path_limit(&member, scope, &id, "direct_only", revision)
                .is_err()
        );
        revision = s.set_path_limit(&admin, scope, &id, "direct_only", revision)?;
        let request = RemoteRequest {
            id: random_id(),
            controller_device_id: c.clone(),
            host_device_id: h.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "direct_preferred".into(),
        };
        assert_eq!(
            s.create_remote(&admin, request.clone(), 1000)?.paths,
            vec![1]
        );
        let mut relay = request;
        relay.id = random_id();
        relay.path_mode = "relay_only".into();
        assert!(s.create_remote(&admin, relay, 1000).is_err());
        revision = s.set_path_limit(&admin, scope, &id, "direct_preferred", revision)?;
    }
    Ok(())
}

#[test]
fn another_login_and_password_change_cannot_reuse_remote_approval() -> Result {
    let (mut s, vault, dummy, admin, member) = fixture()?;
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let c = enroll(&mut s, &admin, &controller, "controller")?;
    let h = enroll(&mut s, &member, &host, "host")?;
    let view = s.create_remote(
        &admin,
        RemoteRequest {
            id: random_id(),
            controller_device_id: c,
            host_device_id: h,
            permissions: vec![Permission::View as i32],
            path_mode: "direct_only".into(),
        },
        1000,
    )?;
    let choice = ApprovalChoice {
        approved: true,
        permissions: vec![Permission::View as i32],
        paths: vec![1],
    };
    let proof = s.approval_transcript(&member, &view.id, &choice, 1001)?;
    let signature = URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?);
    s.approve_remote(&member, &view.id, choice, &signature, 1001)?;
    let other = s
        .login("admin", PASSWORD, None, 1002, &vault, &dummy)?
        .principal;
    assert!(s.initial_permit(&other, &view.id, 1002).is_err());
    let permit = s.initial_permit(&admin, &view.id, 1002)?;
    assert_eq!(s.current_permit(&member, &view.id, 1003)?, permit);
    assert!(
        s.renewal_transcript(&other, &view.id, 2, false, 1003)
            .is_err()
    );
    s.change_password(
        &admin,
        PASSWORD,
        "replacement-only-password",
        None,
        1004,
        &vault,
    )?;
    let replacement = s
        .login(
            "admin",
            "replacement-only-password",
            None,
            1005,
            &vault,
            &dummy,
        )?
        .principal;
    assert!(s.initial_permit(&replacement, &view.id, 1005).is_err());
    assert!(s.current_permit(&member, &view.id, 1005).is_err());
    assert!(
        s.renewal_transcript(&replacement, &view.id, 2, false, 1005)
            .is_err()
    );
    Ok(())
}

#[test]
fn signal_possession_generation_paths_and_live_authorization_are_enforced() -> Result {
    use nestlink_protocol::api::{
        Candidate, CandidateKind, SignalPayload, SignalSubmission, Transport, WebRtcDescription,
    };
    use nestlink_protocol::{DeviceAction, DeviceActionClaims};
    use prost::Message;
    let (mut s, _, _, admin, member) = fixture()?;
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let c = enroll(&mut s, &admin, &controller, "controller")?;
    let h = enroll(&mut s, &member, &host, "host")?;
    let view = s.create_remote(
        &admin,
        RemoteRequest {
            id: random_id(),
            controller_device_id: c.clone(),
            host_device_id: h.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "direct_only".into(),
        },
        1000,
    )?;
    assert!(s.remote_signals(&member, &view.id, 1000).is_err());
    let choice = ApprovalChoice {
        approved: true,
        permissions: vec![Permission::View as i32],
        paths: vec![1],
    };
    let proof = s.approval_transcript(&member, &view.id, &choice, 1001)?;
    s.approve_remote(
        &member,
        &view.id,
        choice,
        &URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
        1001,
    )?;
    let permit = s.initial_permit(&admin, &view.id, 1002)?;
    let payload = SignalPayload {
        connection_generation: 1,
        lease_sequence: 1,
        network_generation: 1,
        sequence: 1,
        candidates: vec![Candidate {
            address: "192.168.1.10:28743".parse()?,
            transport: Transport::Quic,
            kind: CandidateKind::Lan,
            generation: 1,
        }],
        description: None,
    };
    let sign = |payload: SignalPayload| -> Result<SignalSubmission> {
        let proof = nestlink_identity::signal_transcript(&permit, &admin.account_id, &c, &payload)?;
        Ok(SignalSubmission {
            device_id: c.clone(),
            payload,
            signature: URL_SAFE_NO_PAD.encode(controller.sign_action(&proof)?),
        })
    };
    let body = sign(payload.clone())?;
    let mut tampered = body.clone();
    tampered.payload.candidates[0].address.set_port(28744);
    assert!(s.submit_signal(&admin, &view.id, tampered, 1003).is_err());
    assert!(
        s.submit_signal(&member, &view.id, body.clone(), 1003)
            .is_err()
    );
    s.submit_signal(&admin, &view.id, body.clone(), 1003)?;
    s.submit_signal(&admin, &view.id, body, 1003)?;
    assert_eq!(s.remote_signals(&member, &view.id, 1003)?.len(), 1);
    assert_eq!(s.ready_native_remote(&member, &h, 1003)?.len(), 1);
    assert!(s.ready_native_remote(&admin, &h, 1003).is_err());
    assert!(s.ready_native_remote(&member, &c, 1003).is_err());
    let mut next = payload.clone();
    next.network_generation = 2;
    next.sequence = 2;
    next.candidates[0].generation = 2;
    s.submit_signal(&admin, &view.id, sign(next)?, 1004)?;
    let mut stale = payload.clone();
    stale.sequence = 3;
    assert!(
        s.submit_signal(&admin, &view.id, sign(stale)?, 1005)
            .is_err()
    );

    let fingerprint = vec![0xab; 32];
    let fingerprint_text = std::iter::repeat_n("AB", 32).collect::<Vec<_>>().join(":");
    let sdp = format!(
        "v=0\r\na=fingerprint:sha-256 {fingerprint_text}\r\na=candidate:1 1 UDP 2122260223 192.168.1.10 28743 typ host\r\n"
    );
    let offer_sequence = 3;
    let offer = SignalPayload {
        connection_generation: 1,
        lease_sequence: 1,
        network_generation: 3,
        sequence: offer_sequence,
        candidates: vec![],
        description: Some(WebRtcDescription {
            kind: "offer".into(),
            sdp: sdp.clone(),
            dtls_sha256: fingerprint.clone(),
            in_reply_to_sequence: None,
        }),
    };
    s.submit_signal(&admin, &view.id, sign(offer)?, 1006)?;
    // A browser SDP offer must never wake a native host session.
    assert!(s.ready_native_remote(&member, &h, 1006)?.is_empty());
    let sign_answer = |sequence: u64, in_reply_to_sequence: u64| -> Result<SignalSubmission> {
        let payload = SignalPayload {
            connection_generation: 1,
            lease_sequence: 1,
            network_generation: 1,
            sequence,
            candidates: vec![],
            description: Some(WebRtcDescription {
                kind: "answer".into(),
                sdp: sdp.clone(),
                dtls_sha256: fingerprint.clone(),
                in_reply_to_sequence: Some(in_reply_to_sequence),
            }),
        };
        let proof =
            nestlink_identity::signal_transcript(&permit, &member.account_id, &h, &payload)?;
        Ok(SignalSubmission {
            device_id: h.clone(),
            payload,
            signature: URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
        })
    };
    assert!(
        s.submit_signal(&member, &view.id, sign_answer(1, 2)?, 1007)
            .is_err()
    );
    s.submit_signal(&member, &view.id, sign_answer(1, offer_sequence)?, 1007)?;
    let newer_offer = SignalPayload {
        connection_generation: 1,
        lease_sequence: 1,
        network_generation: 4,
        sequence: 4,
        candidates: vec![],
        description: Some(WebRtcDescription {
            kind: "offer".into(),
            sdp: sdp.clone(),
            dtls_sha256: fingerprint.clone(),
            in_reply_to_sequence: None,
        }),
    };
    s.submit_signal(&admin, &view.id, sign(newer_offer.clone())?, 1008)?;
    assert!(
        s.submit_signal(&member, &view.id, sign_answer(2, offer_sequence)?, 1009)
            .is_err()
    );

    let mut unsafe_address = payload.clone();
    unsafe_address.candidates[0].address = "169.254.169.254:80".parse()?;
    assert!(sign(unsafe_address).is_err());
    let mut denied = payload.clone();
    denied.candidates[0].kind = CandidateKind::Relay;
    assert!(sign(denied).is_err());
    let mut denied = payload.clone();
    denied.network_generation = 5;
    denied.sequence = 5;
    denied.candidates[0].kind = CandidateKind::Relay;
    denied.candidates[0].generation = 5;
    let proof = DeviceActionClaims {
        schema_version: nestlink_protocol::SCHEMA_VERSION,
        action: DeviceAction::Signal as i32,
        deployment_id: permit.deployment_id.clone(),
        security_epoch: permit.security_epoch,
        account_id: admin.account_id.clone(),
        device_id: c.clone(),
        resource_id: permit.session_id.clone(),
        challenge: digest(&permit.encode_to_vec()).to_vec(),
        payload_sha256: digest(&serde_json::to_vec(&denied)?).to_vec(),
        expires_at_unix_ms: permit.expires_at_unix_ms,
    };
    assert!(
        s.submit_signal(
            &admin,
            &view.id,
            SignalSubmission {
                device_id: c.clone(),
                payload: denied,
                signature: URL_SAFE_NO_PAD.encode(controller.sign_action(&proof)?),
            },
            1017,
        )
        .is_err()
    );
    assert!(s.remote_signals(&member, &view.id, 1017).is_err());
    s.revoke_remote(&member, &view.id)?;
    assert!(s.remote_signals(&member, &view.id, 1005).is_err());
    Ok(())
}

#[test]
fn password_work_snapshots_cannot_commit_after_password_refresh_logout_or_restore() -> Result {
    let (mut s, vault, dummy, admin, _) = fixture()?;
    let delayed = s.login_snapshot("admin", 1001, &dummy)?.verify(PASSWORD);
    s.change_password(
        &admin,
        PASSWORD,
        "snapshot-new-password",
        None,
        1001,
        &vault,
    )?;
    assert!(s.complete_login(delayed, None, 1002, &vault).is_err());
    let fresh = s.login("admin", "snapshot-new-password", None, 1002, &vault, &dummy)?;
    let proof = s
        .password_snapshot(&fresh.principal)?
        .verify("snapshot-new-password")?;
    let refreshed = s.refresh_login(fresh.refresh_token.expose(), fresh.generation, 1003)?;
    assert!(
        s.complete_password_change(
            proof.replacement("another-test-password")?,
            None,
            1003,
            &vault
        )
        .is_err()
    );
    let proof = s
        .password_snapshot(&refreshed.principal)?
        .verify("snapshot-new-password")?;
    s.logout(&refreshed.principal)?;
    assert!(
        s.complete_password_change(
            proof.replacement("another-test-password")?,
            None,
            1004,
            &vault
        )
        .is_err()
    );
    let delayed = s
        .login_snapshot("admin", 1004, &dummy)?
        .verify("snapshot-new-password");
    s.invalidate_after_restore()?;
    assert!(s.complete_login(delayed, None, 1005, &vault).is_err());
    Ok(())
}
