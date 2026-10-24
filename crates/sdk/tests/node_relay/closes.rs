use super::*;
use std::sync::atomic::Ordering;
impl Fixture {
    pub(super) async fn receipts(&self, acknowledged: u64, held: u32) -> Result {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.control.close_report_status()?.acknowledged_receipts < acknowledged {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(), nestlink_node::control::Error>(())
        })
        .await
        .map_err(|error| {
            format!(
                "fixture close receipt was not acknowledged: {error}; status={:?}; counters={:?}; pending_candidates={:?}",
                self.control.close_report_status(),
                self.control.counters(),
                self.selector.pending_candidates(),
            )
        })??;
        assert_eq!(
            self.control.close_report_status()?.acknowledged_receipts,
            acknowledged
        );
        assert_eq!(self.sdk.relay_reservations().await?.held_allocations, held);
        Ok(())
    }
}
async fn real_close(quic: bool, lose_response: bool) -> Result {
    let f = Fixture::new().await?;
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
    let (mut c, mut h, keep) = if quic {
        f.quic_channels().await?
    } else {
        f.channels().await?
    };
    let (sent, received) = tokio::join!(
        c.send(Channel::Video, b"close receipt actual business"),
        h.receive()
    );
    sent?;
    assert_eq!(received?.payload, b"close receipt actual business");
    f.close_faults
        .lose_next
        .store(lose_response, Ordering::SeqCst);
    keep.send(Some(nestlink_session::StopReason::ExplicitExit))?;
    let (a, b) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive()),
    );
    assert!(a?.is_err());
    assert!(b?.is_err());
    drop(c);
    drop(h);
    f.closed().await?;
    f.receipts(1, 0).await?;
    assert_eq!(
        f.close_faults.lost_responses.load(Ordering::SeqCst),
        usize::from(lose_response)
    );
    assert_eq!(f.control.close_report_status()?.pending_receipts, 0);
    assert!(f.control.authorize(NodeRole::NodeRelay, false).is_ok());
    assert!(
        f.sdk
            .reserve_relay_allocation(
                &f.controller,
                &f.permit,
                &f.allocation.claims().allocation_id,
                &f.node_id
            )
            .await
            .is_err()
    );
    let new = f
        .sdk
        .reserve_relay_allocation(&f.controller, &f.permit, &random_id(), &f.node_id)
        .await?;
    assert_ne!(
        new.claims().allocation_id,
        f.allocation.claims().allocation_id
    );
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
    Ok(())
}
#[tokio::test]
async fn actual_wss_close_releases_capacity_and_lost_response_retries_same_fact() -> Result {
    real_close(false, true).await
}
#[tokio::test]
async fn actual_quic_close_waits_for_socket_driver_idle_then_releases_capacity() -> Result {
    real_close(true, false).await
}
#[tokio::test]
async fn another_live_quic_allocation_prevents_unproven_early_capacity_release() -> Result {
    let mut f = Fixture::new().await?;
    let (mut first_c, mut first_h, stop_first) = f.quic_channels().await?;
    f.allocation = f
        .sdk
        .reserve_relay_allocation(&f.controller, &f.permit, &random_id(), &f.node_id)
        .await?;
    let (mut second_c, mut second_h, stop_second) = f.quic_channels().await?;
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 2);
    stop_first.send(Some(nestlink_session::StopReason::ExplicitExit))?;
    let (a, b) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), first_c.receive()),
        tokio::time::timeout(Duration::from_secs(2), first_h.receive()),
    );
    assert!(a?.is_err());
    assert!(b?.is_err());
    drop(first_c);
    drop(first_h);
    tokio::time::timeout(Duration::from_secs(3), async {
        while f.control.close_report_status()?.active_allocations != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<(), nestlink_node::control::Error>(())
    })
    .await??;
    let status = f.control.close_report_status()?;
    assert_eq!(status.acknowledged_receipts, 0);
    assert_eq!(status.pending_receipts, 0);
    assert_eq!(f.control.counters()?.closed_connections, 2);
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 2);
    let (sent, received) = tokio::join!(
        second_c.send(Channel::Video, b"other allocation remains authorized"),
        second_h.receive(),
    );
    sent?;
    assert_eq!(received?.payload, b"other allocation remains authorized");
    stop_second.send(Some(nestlink_session::StopReason::ExplicitExit))?;
    let (a, b) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), second_c.receive()),
        tokio::time::timeout(Duration::from_secs(2), second_h.receive()),
    );
    assert!(a?.is_err());
    assert!(b?.is_err());
    drop(second_c);
    drop(second_h);
    f.closed().await?;
    f.receipts(1, 1).await?; // Only the actually drained second allocation releases.
    Ok(())
}
#[tokio::test]
async fn corrupted_close_ack_retains_pending_receipt_until_exact_verified_retry() -> Result {
    let f = Fixture::new().await?;
    let (c, h, keep) = f.channels().await?;
    f.close_faults.corrupt_ack.store(true, Ordering::SeqCst);
    keep.send(Some(nestlink_session::StopReason::ExplicitExit))?;
    drop(c);
    drop(h);
    f.closed().await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        while f.close_faults.corrupt_responses.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let status = f.control.close_report_status()?;
    assert_eq!(status.pending_receipts, 1);
    assert_eq!(status.acknowledged_receipts, 0);
    // The server committed the genuine signed fact. The node still retains
    // its exact retry bytes because the received ACK signatures were invalid.
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 0);
    f.close_faults.corrupt_ack.store(false, Ordering::SeqCst);
    f.receipts(1, 0).await?;
    Ok(())
}
#[tokio::test]
async fn business_stop_keeps_bounded_close_reporter_alive_for_last_wss_guards() -> Result {
    let f = Fixture::new().await?;
    let (mut c, mut h, _keep) = f.channels().await?;
    f.control.stop();
    let (a, b) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive()),
    );
    assert!(a?.is_err());
    assert!(b?.is_err());
    drop(c);
    drop(h);
    f.closed().await?;
    f.receipts(1, 0).await?;
    assert!(f.control.authorize(NodeRole::NodeRelay, false).is_err());
    Ok(())
}
#[tokio::test]
async fn close_api_rejects_unsigned_wrong_node_and_oversized_metadata_without_refund() -> Result {
    let f = Fixture::new().await?;
    let client = reqwest::Client::new();
    let url = format!("{}/api/v3/nodes/{}/close", f.control_origin, f.node_id);
    assert_eq!(
        client
            .post(&url)
            .json(&serde_json::json!({}))
            .send()
            .await?
            .status(),
        422
    );
    let g = f.allocation.claims();
    let claims = nestlink_protocol::RelayCloseClaims {
        schema_version: nestlink_protocol::SCHEMA_VERSION,
        deployment_id: g.deployment_id.clone(),
        security_epoch: g.security_epoch,
        node_id: g.node_id.clone(),
        runtime_id: g.runtime_id.clone(),
        runtime_generation: g.runtime_generation,
        allocation_id: g.allocation_id.clone(),
        allocation_binding_sha256: nestlink_identity::relay::allocation_binding(g)?.to_vec(),
        observed_grant_sequence: g.grant_sequence,
        opened_connections: 2,
        closed_connections: 2,
        admitted_bytes: 0,
        closed_at_unix_ms: g.issued_at_unix_ms,
    };
    use prost::Message;
    let mut request = nestlink_protocol::SignedRelayClose {
        claims: claims.encode_to_vec(),
        signature: vec![0; 64],
    };
    assert_eq!(client.post(&url).json(&request).send().await?.status(), 403);
    let wrong_url = format!("{}/api/v3/nodes/{}/close", f.control_origin, random_id());
    assert_eq!(
        client.post(wrong_url).json(&request).send().await?.status(),
        403
    );
    request.claims = vec![0; nestlink_protocol::RELAY_CLOSE_MESSAGE_BYTES as usize + 1];
    assert_eq!(client.post(&url).json(&request).send().await?.status(), 400);
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);
    assert_eq!(f.control.counters()?.opened_connections, 0);
    Ok(())
}
