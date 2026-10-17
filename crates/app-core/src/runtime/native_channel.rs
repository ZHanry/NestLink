//! A receive can itself publish the terminal lease report before returning.
use super::*;
use nestlink_remote::RemoteError;
use nestlink_transport_stream::Frame;

pub(super) fn completed_stop(stopped: &watch::Receiver<Option<StopReport>>) -> bool {
    stopped.borrow().is_some_and(|report| {
        matches!(
            report.cleanup,
            CleanupStatus::NotAttached | CleanupStatus::Succeeded
        )
    })
}

fn terminal_error(error: &RemoteError, stopped: &watch::Receiver<Option<StopReport>>) -> bool {
    completed_stop(stopped)
        && matches!(
            error,
            RemoteError::Stopped
                | RemoteError::Authorization(nestlink_protocol::ContractError {
                    code: nestlink_protocol::ErrorCode::LeaseExpired
                        | nestlink_protocol::ErrorCode::PolicyRevoked,
                    ..
                })
        )
}

pub(super) fn terminal_io_error(
    error: &io::Error,
    stopped: &watch::Receiver<Option<StopReport>>,
) -> bool {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RemoteError>())
        .is_some_and(|error| terminal_error(error, stopped))
}

pub(super) async fn receive(
    receive: impl Future<Output = Result<Frame, RemoteError>>,
    stopped: &mut watch::Receiver<Option<StopReport>>,
) -> io::Result<Option<Frame>> {
    if stopped.borrow().is_some() {
        return Ok(None);
    }
    let received = tokio::select! { biased;
        _ = stopped.changed() => return Ok(None),
        received = receive => received,
    };
    match received {
        // The receive branch can stop the lease during its own poll, after
        // the biased watch branch was already polled. Recheck its receipt.
        Err(error) if terminal_error(&error, stopped) => Ok(None),
        Err(error) => Err(io::Error::other(error)),
        Ok(mut frame) if stopped.borrow().is_some() => {
            frame.payload.zeroize();
            Ok(None)
        }
        Ok(frame) => Ok(Some(frame)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> StopReport {
        StopReport {
            reason: StopReason::NetworkChanged,
            effects: nestlink_session::StopEffects {
                cancel_channels: true,
                release_inputs: true,
                discard_queues: true,
                close_allocations: true,
            },
            cleanup: CleanupStatus::Succeeded,
        }
    }

    #[tokio::test]
    async fn receive_that_publishes_its_own_stop_is_clean() -> io::Result<()> {
        let (sender, mut stopped) = watch::channel(None);
        let received = receive(
            async move {
                sender.send_replace(Some(report()));
                Err(RemoteError::Authorization(
                    nestlink_protocol::ContractError::new(
                        nestlink_protocol::ErrorCode::LeaseExpired,
                        "session is terminal",
                    ),
                ))
            },
            &mut stopped,
        )
        .await?;
        assert!(received.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn terminal_notifications_do_not_hide_protocol_or_unreported_failures() {
        for (publish, failed_cleanup) in [(false, false), (true, false), (true, true)] {
            let (sender, mut stopped) = watch::channel(None);
            let result = receive(
                async move {
                    if publish {
                        let mut report = report();
                        if failed_cleanup {
                            report.cleanup = CleanupStatus::Failed(io::ErrorKind::Other);
                        }
                        sender.send_replace(Some(report));
                        if failed_cleanup {
                            Err(RemoteError::Stopped)
                        } else {
                            Err(RemoteError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "malformed frame",
                            )))
                        }
                    } else {
                        Err(RemoteError::Stopped)
                    }
                },
                &mut stopped,
            )
            .await;
            assert!(result.is_err());
        }
    }
}
