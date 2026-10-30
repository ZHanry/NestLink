use super::*;
use nestlink_protocol::{
    Path,
    api::{BrowserHostReadinessSubmission, NativeIceParameters, SignalPayload},
    native_ice::CAPABILITY,
};

pub(super) fn enroll_capabilities(
    store: &mut Store,
    account: &Principal,
    identity: &InstallationIdentity,
    role: &str,
    platform: &str,
    native_ice: bool,
) -> Result<String> {
    let challenge = store.enrollment_challenge(account, 1000)?;
    let mut capabilities = vec![role.into(), "vp8".into()];
    if native_ice {
        capabilities.push(CAPABILITY.into());
    }
    let mut submission = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: random_id(),
            name: role.into(),
            platform: platform.into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            capabilities,
            path_mode: "direct_preferred".into(),
        },
        signature: String::new(),
    };
    submission.signature = URL_SAFE_NO_PAD.encode(
        identity.sign_action(&store.registration_transcript(account, &submission, 1000)?)?,
    );
    let id = submission.device.id.clone();
    store.register_device(account, submission, 1000)?;
    Ok(id)
}

#[test]
fn native_ice_requires_both_signed_device_capabilities_and_direct_permission_and_survives_renewal()
-> Result {
    for (controller_supports, host_supports) in
        [(false, false), (false, true), (true, false), (true, true)]
    {
        for path in [Path::Direct, Path::Relay] {
            let (mut store, _, _, controller_account, host_account) = fixture()?;
            store.apply_policy(
                1,
                nestlink_policy::NetworkPolicy {
                    server_forwarding: nestlink_policy::ServerForwarding::Allow,
                    peer_path_mode: nestlink_policy::PeerPathMode::DirectPreferred,
                    public_ingress: nestlink_policy::PublicIngress::Disabled,
                },
            )?;
            let controller = InstallationIdentity::generate();
            let host = InstallationIdentity::generate();
            let controller_id = enroll_capabilities(
                &mut store,
                &controller_account,
                &controller,
                "controller",
                "windows",
                controller_supports,
            )?;
            let host_id = enroll_capabilities(
                &mut store,
                &host_account,
                &host,
                "host",
                "linux-x11",
                host_supports,
            )?;
            let request = store.create_remote(
                &controller_account,
                RemoteRequest {
                    id: random_id(),
                    controller_device_id: controller_id.clone(),
                    host_device_id: host_id,
                    permissions: vec![Permission::View as i32],
                    path_mode: if path == Path::Direct {
                        "direct_only"
                    } else {
                        "relay_only"
                    }
                    .into(),
                },
                1000,
            )?;
            let choice = ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32],
                paths: vec![path as i32],
            };
            let proof = store.approval_transcript(&host_account, &request.id, &choice, 1001)?;
            store.approve_remote(
                &host_account,
                &request.id,
                choice,
                &URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
                1001,
            )?;
            let initial = store.initial_permit(&controller_account, &request.id, 1002)?;
            let negotiated = controller_supports && host_supports && path == Path::Direct;
            let expected = if negotiated {
                vec!["vp8".to_owned(), CAPABILITY.into()]
            } else {
                vec!["vp8".to_owned()]
            };
            assert_eq!(initial.required_capabilities, expected);
            let payload = SignalPayload {
                connection_generation: initial.connection_generation,
                lease_sequence: initial.lease_sequence,
                network_generation: 1,
                sequence: 1,
                candidates: Vec::new(),
                description: None,
                ice: None,
                rendezvous: None,
                native_ice: Some(NativeIceParameters {
                    version: nestlink_protocol::native_ice::VERSION,
                    username_fragment: "abcdefgh".into(),
                    password: "abcdefghijklmnopqrstuvwx".into(),
                    candidate: "1234 1 udp 2130706431 203.0.113.7 45678 typ host".into(),
                }),
            };
            assert_eq!(
                nestlink_identity::signal_transcript(
                    &initial,
                    &controller_account.account_id,
                    &controller_id,
                    &payload
                )
                .is_ok(),
                negotiated
            );
            let controller_proof =
                store.renewal_transcript(&controller_account, &request.id, 2, false, 1003)?;
            let host_proof =
                store.renewal_transcript(&controller_account, &request.id, 2, true, 1003)?;
            let renewed = store.renew_permit(
                &controller_account,
                &request.id,
                RenewalSubmission {
                    lease_sequence: 2,
                    controller_signature: URL_SAFE_NO_PAD
                        .encode(controller.sign_action(&controller_proof)?),
                    host_signature: URL_SAFE_NO_PAD.encode(host.sign_action(&host_proof)?),
                },
                1003,
            )?;
            assert_eq!(renewed.lease_sequence, 2);
            assert_eq!(renewed.required_capabilities, initial.required_capabilities);
            assert_eq!(renewed.capability_sha256, initial.capability_sha256);
        }
    }
    Ok(())
}

#[test]
fn browser_declaration_cannot_negotiate_the_native_quic_dialect() -> Result {
    let (mut store, _, _, controller_account, host_account) = fixture()?;
    store.apply_policy(
        1,
        nestlink_policy::NetworkPolicy {
            server_forwarding: nestlink_policy::ServerForwarding::Allow,
            peer_path_mode: nestlink_policy::PeerPathMode::DirectPreferred,
            public_ingress: nestlink_policy::PublicIngress::Disabled,
        },
    )?;
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let controller_id = enroll_capabilities(
        &mut store,
        &controller_account,
        &controller,
        "controller",
        "web",
        true,
    )?;
    let host_id = enroll_capabilities(&mut store, &host_account, &host, "host", "windows", true)?;
    let request = store.create_remote(
        &controller_account,
        RemoteRequest {
            id: random_id(),
            controller_device_id: controller_id,
            host_device_id: host_id,
            permissions: vec![Permission::View as i32],
            path_mode: "direct_only".into(),
        },
        1000,
    )?;
    let choice = ApprovalChoice {
        approved: true,
        permissions: vec![Permission::View as i32],
        paths: vec![Path::Direct as i32],
    };
    let proof = store.approval_transcript(&host_account, &request.id, &choice, 1001)?;
    store.approve_remote(
        &host_account,
        &request.id,
        choice,
        &URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
        1001,
    )?;
    let ready = store.browser_host_readiness_transcript(&host_account, &request.id, 1002)?;
    store.mark_browser_host_ready(
        &host_account,
        &request.id,
        BrowserHostReadinessSubmission {
            protocol_features: Vec::new(),
            signature: URL_SAFE_NO_PAD.encode(host.sign_action(&ready)?),
        },
        1002,
    )?;
    let permit = store.initial_permit(&controller_account, &request.id, 1003)?;
    assert_eq!(permit.required_capabilities, vec!["vp8".to_owned()]);
    Ok(())
}
