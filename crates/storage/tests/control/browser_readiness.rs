use super::*;
use nestlink_protocol::api::BrowserHostReadinessSubmission;

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
