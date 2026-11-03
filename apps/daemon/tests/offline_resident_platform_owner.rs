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

    let after_shutdown = tokio::time::timeout(
        Duration::from_secs(30),
        Platform::new(after_shutdown_area.path()),
    )
    .await??;
    drop(after_shutdown);
    let after_drop = tokio::time::timeout(
        Duration::from_secs(30),
        Platform::new(after_drop_area.path()),
    )
    .await??;
    after_drop.shutdown().await;
    Ok(())
}
