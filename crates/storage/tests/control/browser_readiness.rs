use super::*;
use nestlink_protocol::api::BrowserHostReadinessSubmission;

#[test]
fn signed_setup_features_get_a_bounded_setup_then_normal_dual_signed_renewal() -> Result {
    use nestlink_protocol::ice::{SETUP_CAPABILITY, TRICKLE_CAPABILITY, readiness_payload};
    for (path_mode, paths) in [
        ("direct_only", vec![1]),
        ("direct_preferred", vec![1, 2]),
        ("relay_only", vec![2]),
    ] {
        let (mut store, _, _, controller, host_account) = fixture()?;
        store.apply_policy(
            1,
            nestlink_policy::NetworkPolicy {
                server_forwarding: nestlink_policy::ServerForwarding::Allow,
                peer_path_mode: nestlink_policy::PeerPathMode::DirectPreferred,
                public_ingress: nestlink_policy::PublicIngress::Disabled,
            },
        )?;
        let browser_key = InstallationIdentity::generate();
        let host = InstallationIdentity::generate();
        let host_id = enroll(&mut store, &host_account, &host, "host")?;
        let browser = enroll_browser_with_features_and_mode(
            &mut store,
            &controller,
            &browser_key,
            1000,
            &[SETUP_CAPABILITY, TRICKLE_CAPABILITY],
            "direct_preferred",
        )?;
        let request = store.create_remote(
            &controller,
            RemoteRequest {
                id: random_id(),
                controller_device_id: browser.device_id,
                host_device_id: host_id,
                permissions: vec![Permission::View as i32],
                path_mode: path_mode.into(),
            },
            1001,
        )?;
        let choice = ApprovalChoice {
            approved: true,
            permissions: vec![1],
            paths,
        };
        let proof = store.approval_transcript(&host_account, &request.id, &choice, 1002)?;
        store.approve_remote(
            &host_account,
            &request.id,
            choice,
            &URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
            1002,
        )?;
        let mut proof =
            store.browser_host_readiness_transcript(&host_account, &request.id, 1003)?;
        let features = vec![SETUP_CAPABILITY.to_owned(), TRICKLE_CAPABILITY.to_owned()];
        // A v0.6 signature must never authorize server-injected features.
        assert!(
            store
                .mark_browser_host_ready(
                    &host_account,
                    &request.id,
                    BrowserHostReadinessSubmission {
                        protocol_features: features.clone(),
                        signature: URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
                    },
                    1003
                )
                .is_err()
        );
        proof.payload_sha256 = nestlink_identity::digest(&readiness_payload(
            request.connection_generation,
            &features,
        )?)
        .to_vec();
        store.mark_browser_host_ready(
            &host_account,
            &request.id,
            BrowserHostReadinessSubmission {
                protocol_features: features,
                signature: URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
            },
            1003,
        )?;
        // The request expires at 1061. A late attempt must report the distinct
        // budget error, leave sequence 0 and never silently shorten or extend it.
        assert!(matches!(
            store.initial_permit(&controller, &request.id, 1032),
            Err(StorageError::Proof(error))
                if error.code == nestlink_protocol::ErrorCode::SetupBudgetExhausted
        ));
        assert_eq!(store.remote(&controller, &request.id)?.lease_sequence, 0);
        let setup = store.initial_permit(&controller, &request.id, 1004)?;
        assert!(setup.is_setup());
        assert_eq!(setup.expires_at_unix_ms - setup.issued_at_unix_ms, 30_000);
        assert!(
            setup
                .required_capabilities
                .iter()
                .any(|value| value == TRICKLE_CAPABILITY)
        );
        // The old 15-second cutoff no longer rejects a still-live setup permit.
        let c = store.renewal_transcript(&controller, &request.id, 2, false, 1022)?;
        let h = store.renewal_transcript(&controller, &request.id, 2, true, 1022)?;
        let running = store.renew_permit(
            &controller,
            &request.id,
            RenewalSubmission {
                lease_sequence: 2,
                controller_signature: URL_SAFE_NO_PAD.encode(browser_key.sign_action(&c)?),
                host_signature: URL_SAFE_NO_PAD.encode(host.sign_action(&h)?),
            },
            1022,
        )?;
        assert!(!running.is_setup());
        assert_eq!(
            running.expires_at_unix_ms - running.issued_at_unix_ms,
            15_000
        );
        assert_eq!(running.required_capabilities, setup.required_capabilities);
        assert!(
            store
                .renewal_transcript(&controller, &request.id, 3, false, 1037)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn browser_waits_for_host_consent_then_gets_a_fresh_short_lease() -> Result {
    let (mut store, _, _, controller, host_account) = fixture()?;
    let browser = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let host_id = enroll(&mut store, &host_account, &host, "host")?;
    let browser = enroll_browser(&mut store, &controller, &browser, 1000)?;
    let request = store.create_remote(
        &controller,
        RemoteRequest {
            id: random_id(),
            controller_device_id: browser.device_id,
            host_device_id: host_id.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "direct_only".into(),
        },
        1001,
    )?;
    assert!(
        store
            .ready_browser_remote(&host_account, &host_id, 1001)?
            .is_empty()
    );
    let choice = ApprovalChoice {
        approved: true,
        permissions: vec![1],
        paths: vec![1],
    };
    let proof = store.approval_transcript(&host_account, &request.id, &choice, 1002)?;
    store.approve_remote(
        &host_account,
        &request.id,
        choice,
        &URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
        1002,
    )?;
    assert_eq!(
        store
            .ready_browser_remote(&host_account, &host_id, 1002)?
            .len(),
        1
    );
    assert!(
        store
            .ready_browser_remote(&controller, &host_id, 1002)
            .is_err()
    );
    assert!(
        !store
            .browser_host_readiness(&controller, &request.id, 1002)?
            .ready
    );
    assert!(matches!(
        store.initial_permit(&controller, &request.id, 1002),
        Err(StorageError::Conflict)
    ));
    // More than one old 15-second lease has passed, but none was consumed.
    assert_eq!(store.remote(&controller, &request.id)?.lease_sequence, 0);
    assert!(
        store
            .initial_permit(&controller, &request.id, 1020)
            .is_err()
    );
    assert!(
        store
            .browser_host_readiness_transcript(&controller, &request.id, 1020)
            .is_err()
    );
    let proof = store.browser_host_readiness_transcript(&host_account, &request.id, 1020)?;
    let wrong = InstallationIdentity::generate();
    assert!(
        store
            .mark_browser_host_ready(
                &host_account,
                &request.id,
                BrowserHostReadinessSubmission {
                    protocol_features: Vec::new(),
                    signature: URL_SAFE_NO_PAD.encode(wrong.sign_action(&proof)?),
                },
                1020
            )
            .is_err()
    );
    store.mark_browser_host_ready(
        &host_account,
        &request.id,
        BrowserHostReadinessSubmission {
            protocol_features: Vec::new(),
            signature: URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
        },
        1020,
    )?;
    let permit = store.initial_permit(&controller, &request.id, 1021)?;
    assert_eq!(permit.issued_at_unix_ms, 1_021_000);
    assert_eq!(
        permit.expires_at_unix_ms - permit.issued_at_unix_ms,
        nestlink_protocol::SESSION_LEASE_MS
    );
    assert!(
        store
            .ready_browser_remote(&host_account, &host_id, 1021)?
            .is_empty()
    );
    store.revoke_remote(&controller, &request.id)?;
    assert!(
        store
            .browser_host_readiness(&controller, &request.id, 1022)
            .is_err()
    );
    assert!(
        store
            .current_permit(&controller, &request.id, 1022)
            .is_err()
    );
    Ok(())
}
