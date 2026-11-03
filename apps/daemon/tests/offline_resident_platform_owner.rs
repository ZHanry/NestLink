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
    Ok(())
}
