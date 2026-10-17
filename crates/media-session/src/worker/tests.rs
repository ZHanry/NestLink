use super::Worker;
use nestlink_session::StopReason;
use std::{io, sync::mpsc, thread, time::Duration};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_authorization_race_is_completion_but_device_errors_still_veto_recovery() -> Result
{
    for platform_failure in [false, true] {
        let mut pair = crate::tests::pair().await?;
        let lease = pair.host.lease_control();
        let authority = lease.clone();
        let (release, wait) = mpsc::channel();
        let mut worker = Worker::spawn(
            "nestlink-terminal-authority-fixture",
            lease.clone(),
            move |_| {
                wait.recv().map_err(io::Error::other)?;
                if platform_failure {
                    Err(io::Error::other(
                        "device failed during stopped-session cleanup",
                    ))
                } else {
                    authority
                        .check_media_binding(nestlink_transport_stream::Channel::Audio, 9)
                        .map_err(io::Error::other)
                }
            },
        )?;
        lease.stop(StopReason::TransportLost)?;
        tokio::time::timeout(Duration::from_secs(2), pair.host.wait_stopped()).await??;
        let original = lease.reconnection_budget()?;
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !worker.monitor().status().finished {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await?;
        assert_eq!(worker.monitor().status().error.is_some(), platform_failure);
        assert_eq!(worker.cleanup()?, crate::ShutdownReport::Joined);
        if platform_failure {
            assert!(lease.reconnection_budget().is_err());
        } else {
            let after = lease.reconnection_budget()?;
            assert_eq!(after.deadline(), original.deadline());
            assert_eq!(after.permit().digest(), original.permit().digest());
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_worker_cleanup_preserves_recovery_but_a_platform_failure_vetoes_it() -> Result {
    for failed in [false, true] {
        let mut pair = crate::tests::pair().await?;
        let lease = pair.host.lease_control();
        let (release, wait) = mpsc::channel();
        let worker = Worker::spawn(
            "nestlink-recovery-cleanup-fixture",
            lease.clone(),
            move |_| {
                wait.recv().map_err(io::Error::other)?;
                if failed {
                    Err(io::Error::other("platform cleanup fixture failed"))
                } else {
                    Ok(())
                }
            },
        )?;
        let monitor = worker.monitor();
        lease.stop(StopReason::TransportLost)?;
        tokio::time::timeout(Duration::from_secs(2), pair.host.wait_stopped()).await??;
        let original = lease.reconnection_budget()?;
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !monitor.status().finished {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await?;
        drop(worker);
        assert_eq!(monitor.status().error.is_some(), failed);
        if failed {
            assert!(lease.reconnection_budget().is_err());
        } else {
            let after_cleanup = lease.reconnection_budget()?;
            assert_eq!(after_cleanup.deadline(), original.deadline());
            assert_eq!(after_cleanup.permit().digest(), original.permit().digest());
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_live_worker_still_stops_the_session_and_prohibits_recovery() -> Result {
    let mut pair = crate::tests::pair().await?;
    let lease = pair.host.lease_control();
    let worker = Worker::spawn(
        "nestlink-live-owner-drop-fixture",
        lease.clone(),
        |stopped| {
            while !super::stopped(&stopped) {
                thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        },
    )?;
    let monitor = worker.monitor();
    drop(worker);
    let report = tokio::time::timeout(Duration::from_secs(2), pair.host.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::ExplicitExit);
    assert!(monitor.status().finished);
    assert!(monitor.status().error.is_none());
    assert!(lease.reconnection_budget().is_err());
    Ok(())
}
