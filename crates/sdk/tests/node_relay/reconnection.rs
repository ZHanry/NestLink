use super::*;
use nestlink_sdk::{NativeReconnectionConfig, ReconnectedPermit, SdkError};
fn endpoint(
    sdk: &Sdk,
    receipt: &ReconnectedPermit,
    local: &DeviceIdentity,
    peer: &DeviceIdentity,
) -> Result<NativeEndpoint> {
    Ok(sdk.reconnection_endpoint(
        receipt,
        local,
        &peer.identity.public_key(),
        NativeReconnectionConfig {
            bound: "0.0.0.0:0".parse()?,
            stun_servers: vec![],
            address_policy: AddressPolicy::new(&[])?,
            monitor: None,
        },
    )?)
}
async fn actual_reconnection(quic: bool) -> Result {
    let mut f = Fixture::new().await?;
    let mut host_sdk = Sdk::connect(
        &f.control_origin,
        DeploymentTrust {
            deployment_id: f.permit.claims().deployment_id.clone(),
            permit_issuer: f.permit.issuer(),
        },
        true,
    )
    .await?;
    host_sdk
        .login(
            "admin".into(),
            Secret::from_text("independent-relay-fixture-password".into()),
            None,
        )
        .await?;
    let (mut c, mut h, _keep) = if quic {
        f.quic_channels().await?
    } else {
        f.channels().await?
    };
    let (sent, received) = tokio::join!(
        c.send(Channel::Video, b"before carrier replacement"),
        h.receive()
    );
    sent?;
    assert_eq!(received?.payload, b"before carrier replacement");
    let attempt = f.sdk.prepare_reconnection(&f.controller, &f.permit)?;
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    let (controller, host) = tokio::try_join!(
        f.sdk
            .coordinate_reconnection_controller(&attempt, &host_key, || false),
        host_sdk.coordinate_reconnection_host(&f.host, &f.permit, &controller_key, || false)
    )?;
    assert_eq!(controller.permit().claims(), host.permit().claims());
    assert_eq!(controller.permit().claims().connection_generation, 2);
    assert_eq!(
        controller.permit().claims().expires_at_unix_ms,
        f.permit.claims().expires_at_unix_ms
    );
    let start = Instant::now();
    let (c_result, h_result) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(c_result?.is_err());
    assert!(h_result?.is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
    drop(c);
    drop(h);
    f.closed().await?;
    f.receipts(1, 0).await?;
    let old_allocation = f.allocation.clone();
    f.permit = controller.permit().clone();
    assert!(
        f.sdk
            .reserve_relay_allocation(
                &f.controller,
                &f.permit,
                &old_allocation.claims().allocation_id,
                &f.node_id
            )
            .await
            .is_err()
    );
    f.allocation = f
        .sdk
        .reserve_relay_allocation(&f.controller, &f.permit, &random_id(), &f.node_id)
        .await?;
    assert_ne!(
        f.allocation.claims().allocation_id,
        old_allocation.claims().allocation_id
    );
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
    f.endpoints = [
        endpoint(&f.sdk, &controller, &f.controller, &f.host)?,
        endpoint(&host_sdk, &host, &f.host, &f.controller)?,
    ];
    f.reconnected_clocks = Some([controller.runtime_clock()?, host.runtime_clock()?]);
    let (mut c, mut h, _keep) = if quic {
        f.quic_channels().await?
    } else {
        f.channels().await?
    };
    let payload = vec![37; 256 * 1024];
    let (sent, received) = tokio::join!(h.send(Channel::Video, &payload), c.receive());
    sent?;
    assert_eq!(received?.payload, payload);
    let (sent, received) = tokio::join!(
        c.send(Channel::Video, b"new generation reverse"),
        h.receive()
    );
    sent?;
    assert_eq!(received?.payload, b"new generation reverse");
    Ok(())
}
#[tokio::test]
async fn coordinated_reconnection_retires_real_wss_and_rebuilds_new_uuid_with_both_proofs() -> Result
{
    actual_reconnection(false).await
}
#[tokio::test]
async fn coordinated_reconnection_retires_outer_inner_quic_and_rebuilds_new_uuid() -> Result {
    actual_reconnection(true).await
}
#[tokio::test]
async fn reconnect_sdk_rejects_other_issuer_login_peer_and_cancel_before_commit() -> Result {
    let mut f = Fixture::new().await?;
    let attempt = f.sdk.prepare_reconnection(&f.controller, &f.permit)?;
    assert!(matches!(
        f.sdk
            .coordinate_reconnection_controller(&attempt, &f.host.identity.public_key(), || true)
            .await,
        Err(SdkError::Timeout)
    ));
    let mut other = Sdk::connect(
        &f.control_origin,
        DeploymentTrust {
            deployment_id: f.permit.claims().deployment_id.clone(),
            permit_issuer: f.permit.issuer(),
        },
        true,
    )
    .await?;
    other
        .login(
            "admin".into(),
            Secret::from_text("independent-relay-fixture-password".into()),
            None,
        )
        .await?;
    assert!(matches!(
        other.offer_reconnection(&attempt).await,
        Err(SdkError::Trust)
    ));
    let rogue = PermitSigner::generate();
    use prost::Message;
    let wrong = nestlink_identity::verify_permit(
        &rogue.sign(f.permit.claims())?.encode_to_vec(),
        &rogue.public_key(),
    )?;
    assert!(matches!(
        f.sdk.prepare_reconnection(&f.controller, &wrong),
        Err(SdkError::Trust)
    ));
    assert!(
        f.sdk
            .commit_reconnection(&attempt, &[0; 32], URL_SAFE_NO_PAD.encode([0; 64]))
            .await
            .is_err()
    );
    assert_eq!(
        f.sdk.permit(&f.permit.claims().session_id).await?.claims(),
        f.permit.claims()
    );
    f.sdk.logout().await?;
    assert!(f.sdk.offer_reconnection(&attempt).await.is_err());
    Ok(())
}
#[tokio::test]
async fn coordinator_recovers_real_http_body_loss_after_commit_and_ignores_prior_receipt_on_next_exchange()
-> Result {
    let f = Fixture::with_response_fault(None, "127.0.0.1:0", "127.0.0.1:0", true).await?;
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    let attempt = f.sdk.prepare_reconnection(&f.controller, &f.permit)?;
    let (c, h) = tokio::try_join!(
        f.sdk
            .coordinate_reconnection_controller(&attempt, &host_key, || false),
        f.sdk
            .coordinate_reconnection_host(&f.host, &f.permit, &controller_key, || false)
    )?;
    assert_eq!(
        f.lost_commit_responses
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(c.permit().claims(), h.permit().claims());
    assert_eq!(c.permit().claims().connection_generation, 2);
    let state = f
        .sdk
        .reconnection_state(&f.permit.claims().session_id)
        .await?;
    let signature = state.host_signature.ok_or("missing host proof")?;
    let retry = f
        .sdk
        .commit_reconnection(&attempt, &host_key, signature)
        .await?;
    assert_eq!(retry.permit().claims(), c.permit().claims());
    let attempt = f.sdk.prepare_reconnection(&f.controller, c.permit())?;
    let controller = async {
        tokio::time::sleep(Duration::from_millis(150)).await;
        f.sdk
            .coordinate_reconnection_controller(&attempt, &host_key, || false)
            .await
    };
    let (c2, h2) = tokio::try_join!(
        controller,
        f.sdk
            .coordinate_reconnection_host(&f.host, c.permit(), &controller_key, || false)
    )?;
    assert_eq!(c2.permit().claims(), h2.permit().claims());
    assert_eq!(c2.permit().claims().connection_generation, 3);
    assert_eq!(
        c2.permit().claims().expires_at_unix_ms,
        f.permit.claims().expires_at_unix_ms
    );
    Ok(())
}
#[tokio::test]
async fn native_reconnect_entry_consumes_stopped_committed_sessions_and_preserves_original_clock()
-> Result {
    let f = Fixture::new().await?;
    let route = f
        .sdk
        .node_relay_route(&f.origin, true, &f.permit, &f.allocation)
        .await?;
    let (c, mut h, _keep, _clocks) = f
        .native_sessions_on_route(NativeRelayRoute::Wss(&route))
        .await?;
    let (sent, received) = tokio::join!(
        c.channels.send(Channel::Video, b"committed transport"),
        h.channels.receive()
    );
    sent?;
    assert_eq!(received?.payload, b"committed transport");
    let c_sender = c.channels.sender();
    let h_sender = h.channels.sender();
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    let (next, host) = tokio::try_join!(
        f.sdk
            .reconnect_native_controller(&f.controller, &f.permit, &host_key, c, || false),
        f.sdk
            .reconnect_native_host(&f.host, &f.permit, &controller_key, h, || false)
    )?;
    assert_eq!(next.permit().claims(), host.permit().claims());
    assert!(
        c_sender
            .send(Channel::Video, b"old queue must not survive")
            .await
            .is_err()
    );
    assert!(
        h_sender
            .send(Channel::Video, b"old queue must not survive")
            .await
            .is_err()
    );
    let first = next.runtime_clock()?.monotonic_ms();
    let remaining = next.remaining_ms()?;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(next.runtime_clock()?.monotonic_ms() >= first + 20);
    assert!(next.remaining_ms()? <= remaining - 20);
    f.closed().await?;
    f.receipts(1, 0).await?;
    Ok(())
}
