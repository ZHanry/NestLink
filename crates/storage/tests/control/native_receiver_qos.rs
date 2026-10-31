use super::*;
use nestlink_protocol::{Path, api::BrowserHostReadinessSubmission, native_qos::CAPABILITY};

fn enroll_qos(
    store: &mut Store,
    account: &Principal,
    identity: &InstallationIdentity,
    host: bool,
    platform: &str,
    supports: bool,
) -> Result<String> {
    let challenge = store.enrollment_challenge(account, 1000)?;
    let mut capabilities = vec![
        if host { "host" } else { "controller" }.into(),
        "vp8".into(),
    ];
    if supports {
        capabilities.push(CAPABILITY.into());
    }
    let mut body = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: random_id(),
            name: "QoS negotiation fixture".into(),
            platform: platform.into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            capabilities,
            path_mode: "direct_only".into(),
        },
        signature: String::new(),
    };
    body.signature = URL_SAFE_NO_PAD
        .encode(identity.sign_action(&store.registration_transcript(account, &body, 1000)?)?);
    let id = body.device.id.clone();
    store.register_device(account, body, 1000)?;
    Ok(id)
}

#[test]
fn receiver_qos_requires_both_signed_native_declarations_and_keeps_original_permit_scope() -> Result
{
    for (controller_supports, host_supports, browser) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, false),
        (true, true, true),
    ] {
        let (mut store, _, _, controller_account, host_account) = fixture()?;
        let controller = InstallationIdentity::generate();
        let host = InstallationIdentity::generate();
        let controller_id = enroll_qos(
            &mut store,
            &controller_account,
            &controller,
            false,
            if browser { "web" } else { "windows" },
            controller_supports,
        )?;
        let host_id = enroll_qos(
            &mut store,
            &host_account,
            &host,
            true,
            "linux-x11",
            host_supports,
        )?;
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
        if browser {
            let proof =
                store.browser_host_readiness_transcript(&host_account, &request.id, 1002)?;
            store.mark_browser_host_ready(
                &host_account,
                &request.id,
                BrowserHostReadinessSubmission {
                    protocol_features: Vec::new(),
                    signature: URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
                },
                1002,
            )?;
        }
        let initial = store.initial_permit(&controller_account, &request.id, 1003)?;
        assert_eq!(
            initial
                .required_capabilities
                .iter()
                .any(|value| value == CAPABILITY),
            controller_supports && host_supports && !browser
        );
        assert_eq!(initial.permissions, vec![Permission::View as i32]);
        assert_eq!(initial.paths, vec![Path::Direct as i32]);
        let controller_proof =
            store.renewal_transcript(&controller_account, &request.id, 2, false, 1004)?;
        let host_proof =
            store.renewal_transcript(&controller_account, &request.id, 2, true, 1004)?;
        let renewed = store.renew_permit(
            &controller_account,
            &request.id,
            RenewalSubmission {
                lease_sequence: 2,
                controller_signature: URL_SAFE_NO_PAD
                    .encode(controller.sign_action(&controller_proof)?),
                host_signature: URL_SAFE_NO_PAD.encode(host.sign_action(&host_proof)?),
            },
            1004,
        )?;
        assert_eq!(renewed.required_capabilities, initial.required_capabilities);
        assert_eq!(renewed.permissions, initial.permissions);
        assert_eq!(renewed.capability_sha256, initial.capability_sha256);
    }
    Ok(())
}
