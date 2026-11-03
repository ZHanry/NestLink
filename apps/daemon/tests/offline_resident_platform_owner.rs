//! Exercise ownership around the original real platform fixture lifecycle.
#![cfg(any(target_os = "linux", windows))]

#[path = "offline_remote_resident/support.rs"]
pub mod support;

use std::time::Duration;
use support::{Platform, Result};

#[tokio::test]
async fn original_platform_owner_is_exclusive_cancel_safe_and_released_after_shutdown_or_drop()
-> Result {
    let first_area = tempfile::tempdir()?;
    let waiting_area = tempfile::tempdir()?;
    let after_shutdown_area = tempfile::tempdir()?;
    let after_drop_area = tempfile::tempdir()?;
    let first = Platform::new(first_area.path()).await?;
    #[cfg(target_os = "linux")]
    let first_children = first
        .children
        .iter()
        .filter_map(|child| child.id())
        .collect::<Vec<_>>();

    // A second real platform must stay queued before creating any OS owner.
    // Cancelling that queued future must not take or poison the held permit.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            Platform::new(waiting_area.path()),
        )
        .await
        .is_err(),
        "a second original platform overlapped the live desktop owner"
    );
    first.shutdown().await;
    #[cfg(target_os = "linux")]
    assert!(
        !first_children.is_empty()
            && first_children.iter().all(|pid| {
                std::fs::symlink_metadata(format!("/proc/{pid}"))
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            }),
        "explicit shutdown left an original platform process alive or unreaped"
    );

    let after_shutdown = tokio::time::timeout(
        Duration::from_secs(30),
        Platform::new(after_shutdown_area.path()),
    )
    .await??;
    #[cfg(target_os = "linux")]
    let dropped_children = after_shutdown
        .children
        .iter()
        .filter_map(|child| child.id())
        .collect::<Vec<_>>();
    drop(after_shutdown);
    #[cfg(target_os = "linux")]
    assert!(
        !dropped_children.is_empty()
            && dropped_children.iter().all(|pid| {
                std::fs::symlink_metadata(format!("/proc/{pid}"))
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            }),
        "Drop left an original platform process alive or unreaped"
    );
    let after_drop = tokio::time::timeout(
        Duration::from_secs(30),
        Platform::new(after_drop_area.path()),
    )
    .await??;
    after_drop.shutdown().await;
    #[cfg(target_os = "linux")]
    for stage in ["dbus", "seed-xauth", "xvfb", "keyring", "dbus-owner", "xsetroot"] {
        construction_terminal_reaps_before_reentry(stage, true).await?;
        construction_terminal_reaps_before_reentry(stage, false).await?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn construction_terminal_reaps_before_reentry(stage: &'static str, cancel: bool) -> Result {
    let area = tempfile::tempdir()?;
    let waiting_area = tempfile::tempdir()?;
    let reentry_area = tempfile::tempdir()?;
    let (spawned, observed) = tokio::sync::oneshot::channel();
    let (resume, continued) = tokio::sync::oneshot::channel();
    let mut construction = Box::pin(Platform::new_observed(
        area.path(),
        Some(support::ConstructionProbe {
            stage,
            spawned,
            resume: continued,
        }),
    ));
    // Observe the actual original spawned PIDs while construction is paused
    // before its first pipe/read/write/wait await at the selected boundary.
    let owned = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            result = construction.as_mut() => {
                result?;
                Err(std::io::Error::other("original constructor did not reach its observed spawn").into())
            }
            result = observed => Ok::<_, Box<dyn std::error::Error + Send + Sync>>(result?),
        }
    })
    .await??;
    assert!(!owned.is_empty(), "real constructor spawn had no owned PID");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), Platform::new(waiting_area.path()))
            .await
            .is_err(),
        "construction admitted a second original desktop owner"
    );
    if cancel {
        drop(construction);
        drop(resume);
    } else {
        resume
            .send(Err(std::io::Error::other(
                "independent original constructor failure",
            )))
            .map_err(|_| "original constructor stopped before the injected failure")?;
        let failed = tokio::time::timeout(Duration::from_secs(30), construction.as_mut()).await?;
        assert!(
            failed.is_err_and(|error| error.to_string() == "independent original constructor failure"),
            "original constructor did not retain its injected error"
        );
        drop(construction);
    }
    assert!(
        owned.iter().all(|pid| {
            std::fs::symlink_metadata(format!("/proc/{pid}"))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        }),
        "cancelled or failed construction left an original PID alive or unreaped"
    );
    let reentered = tokio::time::timeout(
        Duration::from_secs(30),
        Platform::new(reentry_area.path()),
    )
    .await??;
    reentered.shutdown().await;
    Ok(())
}
