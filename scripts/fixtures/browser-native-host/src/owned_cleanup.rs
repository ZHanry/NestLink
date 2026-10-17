//! Physical cleanup of this fixture's generated temporary deployment.
use serde_json::json;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
    time::{Duration, Instant},
};

/// Called only after both management server JoinHandles have completed.
/// Axum can signal connection completion before dropping its connection future
/// and the Router/AppState it contains. Keep the owned directory until Windows
/// confirms the actual handles have closed and the directory is gone.
pub async fn close(scratch: tempfile::TempDir, evidence: &Path) -> io::Result<()> {
    let verified = (|| {
        let metadata = std::fs::symlink_metadata(scratch.path())?;
        let target = std::fs::canonicalize(scratch.path())?;
        let parent = std::fs::canonicalize(std::env::temp_dir())?;
        #[cfg(windows)]
        let reparse_point = metadata.file_attributes() & 0x400 != 0;
        #[cfg(not(windows))]
        let reparse_point = false;
        if metadata.file_type().is_symlink()
            || reparse_point
            || !metadata.is_dir()
            || !target.is_absolute()
            || target.parent() != Some(parent.as_path())
            || !target.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("nestlink-browser-native-")
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owned deployment cleanup escaped its generated temporary directory",
            ));
        }
        Ok(target)
    })();
    let target = match verified {
        Ok(target) => target,
        Err(error) => {
            let _ = scratch.keep();
            return Err(error);
        }
    };
    let started = Instant::now();
    let mut attempts = 0_u32;
    let mut sharing_retries = Vec::new();
    let outcome = loop {
        attempts += 1;
        match std::fs::remove_dir_all(&target) {
            Ok(()) => break Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound && !target.exists() => {
                break Ok(());
            }
            Err(error)
                if cfg!(windows)
                    && matches!(error.raw_os_error(), Some(5 | 32 | 33))
                    && started.elapsed() < Duration::from_secs(5) =>
            {
                sharing_retries.push(error.raw_os_error());
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => break Err(error),
        }
    };
    // Success has already removed the verified directory. On failure retain
    // its exact path for investigation instead of an unreported Drop retry.
    let _ = scratch.keep();
    let removed = !target.try_exists()?;
    let report = json!({
        "scope":"Fixture-owned temporary deployment physical cleanup",
        "servers_joined":true,"verified_owned_tempdir":true,
        "owned_temporary_database_removed":outcome.is_ok() && removed,
        "cleanup_attempts":attempts,"sharing_retries":sharing_retries,
        "elapsed_ms":started.elapsed().as_millis(),
        "cleanup_error":outcome.as_ref().err().map(|error| error.to_string()),
        "cleanup_error_code":outcome.as_ref().err().and_then(io::Error::raw_os_error)
    });
    let mut receipt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence.join("database-cleanup.json"))?;
    receipt.write_all(&serde_json::to_vec_pretty(&report)?)?;
    receipt.write_all(b"\n")?;
    outcome?;
    if !removed {
        return Err(io::Error::other(
            "owned deployment still exists after cleanup",
        ));
    }
    Ok(())
}
