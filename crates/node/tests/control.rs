mod support;
use nestlink_protocol::NodeRole;
use std::time::{Duration, Instant};
use support::{Mode, Result, peer};

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
async fn invalid_or_unavailable_meter_ack_prevents_activation_and_stops_control() -> Result {
    for mode in [Mode::WrongAck, Mode::UnavailableReport] {
        let (control, _fixture) = peer(mode).await?;
        let mut stopped = control.stopped();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !*stopped.borrow() {
                stopped.changed().await?;
            }
            Ok::<(), tokio::sync::watch::error::RecvError>(())
        })
        .await??;
        assert!(control.current_lease().is_err());
        assert!(
            control
                .reserve_capacity(NodeRole::NodeRelay, false)
                .is_err()
        );
    }
    Ok(())
}
