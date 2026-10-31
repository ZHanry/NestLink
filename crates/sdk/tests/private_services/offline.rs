//! Actual HTTP/SDK approval, durable quota, one-process activation and recovery.
//! Business carriers are qualified separately; no fake I/O is called a transport.
#[path = "offline/carrier.rs"]
mod carrier;
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::offline::OfflineProcess;
use nestlink_protocol::offline::{OfflineDirectTransport, management::*};

#[tokio::test]
async fn offline_http_sdk_approval_exact_process_consume_budget_and_recovery() -> Result {
    let f = Fixture::new("tcp", "127.0.0.1:8080".parse()?).await?;
    let space = &f.exposure.space_id;
    let disabled = f.sdk.offline_policy(space).await?;
    assert!(!disabled.enabled);
    let enabled = f
        .sdk
        .set_offline_enabled(
            space,
            &OfflineEnableUpdate {
                expected_revision: disabled.revision,
                enabled: true,
            },
        )
        .await?;
    let policy = f.sdk.network_policy(space).await?;
    let authority: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&policy.authority_public_key)?
        .try_into()
        .map_err(|_| "authority key length")?;
    let mut consumer = OfflineProcess::new(
        f.consumer.device_id.clone(),
        f.consumer.identity.public_key(),
        wall_ms()?,
        enabled.highest_revocation_epoch,
    )?;
    let mut host = OfflineProcess::new(
        f.host.device_id.clone(),
        f.host.identity.public_key(),
        wall_ms()?,
        enabled.highest_revocation_epoch,
    )?;
    let request = OfflinePrivateDraftRequest {
        consumer_device_id: f.consumer.device_id.clone(),
        service_id: f.view.id.clone(),
        process_nonces: [consumer.nonce(), host.nonce()],
        expected_policy_revision: policy.revision,
        expected_service_revision: f.view.revision,
        expected_exposure_revision: f.exposure.revision,
        direct_transports: vec![OfflineDirectTransport::Quic, OfflineDirectTransport::Tls],
        maximum_bytes: 4096,
        maximum_connections: 2,
        expires_at_ms: wall_ms()? + 20_000,
    };
    let draft = f.sdk.create_offline_private_draft(space, &request).await?;
    assert!(draft.signed.is_none());
    assert!(
        f.sdk
            .activate_offline_bundle(
                &f.consumer,
                &mut consumer,
                &draft,
                &authority,
                0,
                draft.draft_digest
            )
            .await
            .is_err()
    );
    let mut wrong = draft.draft_digest;
    wrong[0] ^= 1;
    assert!(
        f.sdk
            .approve_offline_bundle(&f.consumer, &consumer, &draft, &authority, 0, wrong)
            .await
            .is_err()
    );
    assert!(
        f.sdk
            .approve_offline_bundle(
                &f.outsider,
                &consumer,
                &draft,
                &authority,
                0,
                draft.draft_digest
            )
            .await
            .is_err()
    );
    f.sdk
        .approve_offline_bundle(
            &f.consumer,
            &consumer,
            &draft,
            &authority,
            0,
            draft.draft_digest,
        )
        .await?;
    let signed = f
        .sdk
        .approve_offline_bundle(&f.host, &host, &draft, &authority, 1, draft.draft_digest)
        .await?;
    assert_eq!(signed.approved, [true, true]);
    assert!(signed.signed.is_some());
    let quota = f
        .sdk
        .service_quota_usage(ServiceQuotaUsageQuery {
            scope: ServiceQuotaScope::Resource,
            scope_key: f.view.id.clone(),
        })
        .await?;
    assert_eq!(quota.spent_bytes, 4096);
    assert_eq!(quota.outstanding_bytes, 0);
    let mut restarted = OfflineProcess::new(
        f.consumer.device_id.clone(),
        f.consumer.identity.public_key(),
        wall_ms()?,
        enabled.highest_revocation_epoch,
    )?;
    assert!(
        f.sdk
            .activate_offline_bundle(
                &f.consumer,
                &mut restarted,
                &signed,
                &authority,
                0,
                signed.draft_digest
            )
            .await
            .is_err()
    );
    let mut owner = f
        .sdk
        .activate_offline_bundle(
            &f.consumer,
            &mut consumer,
            &signed,
            &authority,
            0,
            signed.draft_digest,
        )
        .await?;
    let mut host_owner = f
        .sdk
        .activate_offline_bundle(
            &f.host,
            &mut host,
            &signed,
            &authority,
            1,
            signed.draft_digest,
        )
        .await?;
    assert!(
        f.sdk
            .activate_offline_bundle(
                &f.consumer,
                &mut consumer,
                &signed,
                &authority,
                0,
                signed.draft_digest
            )
            .await
            .is_err()
    );
    owner.admit_connection(
        wall_ms()?,
        OfflineDirectTransport::Quic,
        &f.host.identity.public_key(),
    )?;
    host_owner.admit_connection(
        wall_ms()?,
        OfflineDirectTransport::Quic,
        &f.consumer.identity.public_key(),
    )?;
    f.sdk
        .synchronize_offline_bundle(&mut owner, &authority)
        .await?;
    let revoked = f
        .sdk
        .revoke_offline_bundle(space, &signed.claims.bundle_id)
        .await?;
    assert!(!revoked.live);
    assert!(revoked.highest_revocation_epoch > signed.highest_revocation_epoch);
    assert!(
        f.sdk
            .synchronize_offline_bundle(&mut owner, &authority)
            .await
            .is_err()
    );
    assert!(owner.is_stopped());
    assert!(
        f.sdk
            .synchronize_offline_bundle(&mut host_owner, &authority)
            .await
            .is_err()
    );
    assert!(host_owner.is_stopped());
    assert_eq!(
        f.sdk
            .service_quota_usage(ServiceQuotaUsageQuery {
                scope: ServiceQuotaScope::Resource,
                scope_key: f.view.id.clone()
            })
            .await?
            .spent_bytes,
        4096
    );
    std::fs::remove_dir_all(f.usage)?;
    Ok(())
}

#[tokio::test]
async fn offline_http_sdk_administrator_enable_and_direct_policy_boundaries() -> Result {
    let f = Fixture::with_path_policy("tcp", "127.0.0.1:8080".parse()?, "relay_only").await?;
    let space = &f.exposure.space_id;
    let policy = f.sdk.network_policy(space).await?;
    let request = OfflinePrivateDraftRequest {
        consumer_device_id: f.consumer.device_id.clone(),
        service_id: f.view.id.clone(),
        process_nonces: [[21; 32], [22; 32]],
        expected_policy_revision: policy.revision,
        expected_service_revision: f.view.revision,
        expected_exposure_revision: f.exposure.revision,
        direct_transports: vec![OfflineDirectTransport::Quic],
        maximum_bytes: 4096,
        maximum_connections: 1,
        expires_at_ms: wall_ms()? + 20_000,
    };
    assert!(
        f.sdk
            .create_offline_private_draft(space, &request)
            .await
            .is_err()
    );
    f.sdk
        .set_offline_enabled(
            space,
            &OfflineEnableUpdate {
                expected_revision: 0,
                enabled: true,
            },
        )
        .await?;
    assert!(
        f.sdk
            .create_offline_private_draft(space, &request)
            .await
            .is_err()
    );
    assert!(
        f.sdk
            .set_offline_enabled(
                space,
                &OfflineEnableUpdate {
                    expected_revision: 0,
                    enabled: true
                }
            )
            .await
            .is_err()
    );
    let http = reqwest::Client::new();
    let response = http
        .put(format!(
            "{}/api/v3/network/spaces/{space}/offline",
            f.origin
        ))
        .json(&OfflineEnableUpdate {
            expected_revision: 1,
            enabled: true,
        })
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        f.sdk
            .service_quota_usage(ServiceQuotaUsageQuery {
                scope: ServiceQuotaScope::Resource,
                scope_key: f.view.id.clone()
            })
            .await?
            .spent_bytes,
        0
    );
    std::fs::remove_dir_all(f.usage)?;
    Ok(())
}
