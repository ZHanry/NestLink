mod support;
use nestlink_protocol::NodeRole;
use std::time::{Duration, Instant};
use support::{Mode, Result, peer};

fn deadline_expired(error: &nestlink_node::control::Error) -> bool {
    match error {
        nestlink_node::control::Error::Phase { cause, .. } => deadline_expired(cause),
        nestlink_node::control::Error::Authorization(error) => {
            error.code == nestlink_protocol::ErrorCode::LeaseExpired
                && error.reason == "node local lease deadline expired"
        }
        _ => false,
    }
}

async fn ready(
    control: nestlink_node::control::NodeControl,
) -> Result<nestlink_node::control::NodeControl> {
    let activation = tokio::time::timeout(Duration::from_secs(2), async {
        while control.current_lease().is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if activation.is_err() {
        let stopped = *control.stopped().borrow();
        let completion =
            tokio::time::timeout(Duration::from_millis(100), control.wait_finished()).await;
        return Err(format!(
            "node fixture did not activate within two seconds; stopped={stopped}, completion={completion:?}"
        )
        .into());
    }
    Ok(control)
}

#[tokio::test]
async fn dropping_control_before_its_first_poll_publishes_stop_to_existing_observers() -> Result {
    let (control, _fixture) = peer(Mode::Valid).await?;
    let stopped = control.stopped();
    drop(control);
    assert!(
        *stopped.borrow(),
        "drop must synchronously stop observers even if the pump never ran"
    );
    Ok(())
}
#[tokio::test]
async fn stalled_open_control_socket_expires_authority_without_waiting_for_io() -> Result {
    let (control, _server) = peer(Mode::Valid).await?;
    let control = ready(control).await?;
    assert!(control.authorize(NodeRole::NodeRelay, false).is_ok());
    let started = Instant::now();
    let mut stopped = control.stopped();
    tokio::time::timeout(Duration::from_secs(11), async {
        while !*stopped.borrow() {
            stopped.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await??;
    let elapsed = started.elapsed();
    assert!(control.authorize(NodeRole::NodeRelay, false).is_err());
    let completion =
        tokio::time::timeout(Duration::from_millis(100), control.wait_finished()).await;
    assert!(
        elapsed >= Duration::from_secs(8),
        "stalled control stopped before its lease deadline: elapsed={elapsed:?}, completion={completion:?}"
    );
    assert!(
        matches!(&completion, Ok(Err(error)) if deadline_expired(error)),
        "stalled control must expire its original lease: completion={completion:?}"
    );
    Ok(())
}
#[tokio::test]
async fn untrusted_policy_issuer_never_activates_the_node() -> Result {
    let (control, _server) = peer(Mode::WrongIssuer).await?;
    let mut stopped = control.stopped();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !*stopped.borrow() {
            stopped.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await??;
    assert!(control.current_lease().is_err());
    assert!(control.authorize(NodeRole::NodeRelay, false).is_err());
    Ok(())
}

#[tokio::test]
async fn transient_control_close_reconnects_without_resetting_runtime_or_usage() -> Result {
    let (control, fixture) = peer(Mode::Reconnect).await?;
    let control = ready(control).await?;
    let original = control.current_lease()?;
    let allocation = control.reserve_capacity(NodeRole::NodeRelay, false)?;
    allocation.admit(512, || Ok(()))?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let lease = control.current_lease()?;
            if lease.lease_sequence > original.lease_sequence && fixture.reports()?.len() >= 2 {
                assert_eq!(lease.runtime_id, original.runtime_id);
                assert_eq!(lease.runtime_generation, original.runtime_generation);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert_eq!(fixture.connections(), 2);
    assert!(!*control.stopped().borrow());
    assert_eq!(control.counters()?.admitted_bytes, 512);
    allocation.admit(1, || Ok(()))?;
    let reports = fixture.reports()?;
    let last: nestlink_protocol::NodeUsageClaims = nestlink_protocol::decode_bounded(
        reports.last().ok_or("missing resumed report")?,
        nestlink_protocol::nodes::NODE_MESSAGE_BYTES,
    )?;
    assert_eq!(last.report_sequence, 2);
    assert_eq!(last.opened_connections, 1);
    assert_eq!(last.admitted_bytes, 512);
    Ok(())
}

#[tokio::test]
async fn reconnect_cannot_extend_an_unrenewed_lease_deadline() -> Result {
    let (control, fixture) = peer(Mode::ReconnectUnavailable).await?;
    let control = ready(control).await?;
    let started = Instant::now();
    let mut stopped = control.stopped();
    tokio::time::timeout(Duration::from_secs(11), async {
        while !*stopped.borrow() {
            stopped.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await??;
    assert!(fixture.connections() >= 2);
    assert!(started.elapsed() >= Duration::from_secs(8));
    assert!(control.authorize(NodeRole::NodeRelay, false).is_err());
    assert_eq!(fixture.reports()?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn reconnect_with_an_untrusted_lease_is_terminal() -> Result {
    let (control, fixture) = peer(Mode::ReconnectWrongIssuer).await?;
    let control = ready(control).await?;
    let mut stopped = control.stopped();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !*stopped.borrow() {
            stopped.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await??;
    assert_eq!(fixture.connections(), 2);
    assert!(control.current_lease().is_err());
    assert!(
        control
            .reserve_capacity(NodeRole::NodeRelay, false)
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn lost_report_confirmation_retries_exact_bytes_and_local_capacity_is_released_once() -> Result
{
    let (control, fixture) = peer(Mode::LostFirstAck).await?;
    let control = ready(control).await?;
    let reports = fixture.reports()?;
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0], reports[1]);
    let allocation = control.reserve_capacity(NodeRole::NodeRelay, false)?;
    assert!(
        control
            .reserve_capacity(NodeRole::NodeRelay, false)
            .is_err()
    );
    assert!(
        allocation
            .admit(1, || Err::<(), _>(nestlink_protocol::ContractError::new(
                nestlink_protocol::ErrorCode::CapacityExceeded,
                "test full queue"
            )))
            .is_err()
    );
    assert_eq!(control.counters()?.admitted_bytes, 0);
    allocation.admit(1024, || Ok(()))?;
    assert!(allocation.admit(1025, || Ok(())).is_err());
    drop(allocation);
    let allocation = control.reserve_capacity(NodeRole::NodeRelay, false)?;
    assert_eq!(control.counters()?.opened_connections, 2);
    assert_eq!(control.counters()?.closed_connections, 1);
    let mut stopped = allocation.stopped();
    drop(control);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !*stopped.borrow() {
            stopped.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await??;
    assert!(allocation.admit(1, || Ok(())).is_err());
    Ok(())
}
#[tokio::test]
async fn transient_report_overload_retries_the_same_signature_before_activating() -> Result {
    let (control, fixture) = peer(Mode::RecoveringReport).await?;
    let control = ready(control).await?;
    let reports = fixture.reports()?;
    assert_eq!(reports.len(), 3);
    assert!(reports.windows(2).all(|pair| pair[0] == pair[1]));
    let signed = fixture.signed_reports()?;
    assert_eq!(signed.len(), reports.len());
    assert!(signed.windows(2).all(|pair| pair[0] == pair[1]));
    let claims: nestlink_protocol::NodeUsageClaims = nestlink_protocol::decode_bounded(
        &reports[0],
        nestlink_protocol::nodes::NODE_MESSAGE_BYTES,
    )?;
    assert_eq!(claims.report_sequence, 1);
    assert_eq!(
        claims.lease_sequence,
        control.current_lease()?.lease_sequence
    );
    assert_eq!(fixture.connections(), 1);
    assert!(!*control.stopped().borrow());
    assert!(control.reserve_capacity(NodeRole::NodeRelay, false).is_ok());
    Ok(())
}

#[tokio::test]
async fn timed_out_report_confirmation_reuses_the_original_signature() -> Result {
    let (control, fixture) = peer(Mode::DelayedFirstAck).await?;
    let control = ready(control).await?;
    let signed = fixture.signed_reports()?;
    assert_eq!(signed.len(), 2);
    assert_eq!(signed[0], signed[1]);
    assert_eq!(fixture.connections(), 1);
    assert!(!*control.stopped().borrow());
    Ok(())
}

#[tokio::test]
async fn sustained_report_overload_expires_the_same_lease_and_stops_existing_capacity() -> Result {
    let (control, fixture) = peer(Mode::RenewalReportOverload).await?;
    let control = ready(control).await?;
    let allocation = control.reserve_capacity(NodeRole::NodeRelay, false)?;
    allocation.admit(1, || Ok(()))?;
    tokio::time::timeout(Duration::from_secs(3), async {
        while fixture.reports()?.len() < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    let lease = control.current_lease()?;
    assert_eq!(lease.lease_sequence, 2);
    let started = Instant::now();
    assert!(!*control.stopped().borrow());
    let mut stopped = control.stopped();
    let mut capacity_stopped = allocation.stopped();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !*stopped.borrow() {
            stopped.changed().await?;
        }
        while !*capacity_stopped.borrow() {
            capacity_stopped.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await??;
    assert!(started.elapsed() >= Duration::from_secs(8));
    assert!(control.current_lease().is_err());
    assert!(allocation.admit(1, || Ok(())).is_err());
    let reports = fixture.reports()?;
    assert!(reports.len() >= 4 && reports.len() < 20);
    assert!(reports[1..].windows(2).all(|pair| pair[0] == pair[1]));
    let signed = fixture.signed_reports()?;
    assert_eq!(signed.len(), reports.len());
    assert!(signed[1..].windows(2).all(|pair| pair[0] == pair[1]));
    let claims: nestlink_protocol::NodeUsageClaims = nestlink_protocol::decode_bounded(
        &reports[1],
        nestlink_protocol::nodes::NODE_MESSAGE_BYTES,
    )?;
    assert_eq!(claims.report_sequence, 2);
    assert_eq!(claims.lease_sequence, lease.lease_sequence);
    assert_eq!(fixture.connections(), 2);
    let completion =
        tokio::time::timeout(Duration::from_millis(100), control.wait_finished()).await;
    assert!(
        matches!(&completion, Ok(Err(error)) if deadline_expired(error)),
        "report retries must expire the original lease: completion={completion:?}"
    );
    Ok(())
}

#[tokio::test]
async fn unavailable_report_never_activates_or_extends_the_initial_confirmation_budget() -> Result {
    let (control, fixture) = peer(Mode::UnavailableReport).await?;
    let started = Instant::now();
    let mut stopped = control.stopped();
    tokio::time::timeout(Duration::from_secs(7), async {
        while !*stopped.borrow() {
            stopped.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await??;
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert!(control.current_lease().is_err());
    assert!(
        control
            .reserve_capacity(NodeRole::NodeRelay, false)
            .is_err()
    );
    let signed = fixture.signed_reports()?;
    assert!(signed.len() >= 3 && signed.len() < 12);
    assert!(signed.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(fixture.connections(), 1);
    Ok(())
}

#[tokio::test]
async fn invalid_or_rejected_meter_ack_prevents_activation_without_retrying() -> Result {
    for mode in [
        Mode::WrongAck,
        Mode::WrongAckIssuer,
        Mode::WrongAckSequence,
        Mode::RejectedReport,
    ] {
        let (control, fixture) = peer(mode).await?;
        let mut stopped = control.stopped();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !*stopped.borrow() {
                stopped.changed().await?;
            }
            Ok::<(), tokio::sync::watch::error::RecvError>(())
        })
        .await??;
        assert_eq!(fixture.reports()?.len(), 1);
        assert!(control.current_lease().is_err());
        assert!(
            control
                .reserve_capacity(NodeRole::NodeRelay, false)
                .is_err()
        );
    }
    Ok(())
}
