use nestlink_app_ipc::{
    Client,
    wire::{Command, ExitResult, Reply},
};
use std::{
    io,
    path::Path,
    process::{Child, Command as Process, Stdio},
    time::Duration,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn daemon(root: &Path) -> Result<OwnedChild> {
    Ok(OwnedChild(
        Process::new(env!("CARGO_BIN_EXE_nestlink-daemon"))
            .arg("--state-dir")
            .arg(root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    ))
}
async fn connect(root: &Path, child: &mut OwnedChild) -> Result<Client> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(client) = Client::connect(root).await {
                return Ok(client);
            }
            if child.0.try_wait()?.is_some() {
                return Err(io::Error::other("daemon exited during startup"));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?
    .map_err(Into::into)
}
async fn exit(client: &mut Client, child: &mut OwnedChild) -> Result {
    let generation = client
        .request(0, Command::Snapshot)
        .await?
        .snapshot
        .generation;
    assert!(matches!(
        client.request(generation, Command::Exit).await?.result,
        Reply::Exited {
            result: ExitResult::Complete
        }
    ));
    let status = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(status) = child.0.try_wait()? {
                return Ok::<_, io::Error>(status);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    assert!(status.success());
    Ok(())
}
#[tokio::test]
async fn actual_user_daemon_singleton_identity_restart_and_explicit_exit() -> Result {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("new-v15-state");
    let mut first = daemon(&root)?;
    let mut client = connect(&root, &mut first).await?;
    let first_runtime = client.runtime_id().to_owned();
    let first_identity = client
        .request(0, Command::Snapshot)
        .await?
        .snapshot
        .installation
        .clone()
        .ok_or("installation identity not published")?;
    let mut duplicate = daemon(&root)?;
    let status = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(status) = duplicate.0.try_wait()? {
                return Ok::<_, io::Error>(status);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    assert!(!status.success());
    assert_eq!(
        client.request(0, Command::Snapshot).await?.runtime_id,
        first_runtime
    );
    exit(&mut client, &mut first).await?;
    drop(client);
    assert!(!root.join("daemon-endpoint.json").exists());
    assert!(root.join("installation-device.key").is_file());
    let mut replacement = daemon(&root)?;
    let mut client = connect(&root, &mut replacement).await?;
    assert_ne!(client.runtime_id(), first_runtime);
    let replacement_identity = client
        .request(0, Command::Snapshot)
        .await?
        .snapshot
        .installation
        .clone()
        .ok_or("replacement identity missing")?;
    assert_eq!(first_identity.device_id, replacement_identity.device_id);
    assert_eq!(
        first_identity.public_key_sha256,
        replacement_identity.public_key_sha256
    );
    exit(&mut client, &mut replacement).await?;
    Ok(())
}

#[tokio::test]
async fn actual_daemon_rejects_interrupted_quota_metadata_without_resetting_it() -> Result {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("interrupted-quota-state");
    nestlink_platform_security::new_private_directory(&root)?;
    drop(
        nestlink_platform_files::upload::WriteQuota::open_private_ledger(
            &root,
            nestlink_protocol::FILE_SIZE_BYTES,
            nestlink_app_core::NATIVE_FILE_TASK_HISTORY_LIMIT as u64,
        )?,
    );
    let ledger_path = root.join("native-file-write-quota.ledger");
    let original_ledger = std::fs::read(&ledger_path)?;
    let pending_path = root.join("native-file-write-quota.pending");
    nestlink_platform_security::create_private(&pending_path, b"interrupted quota replacement")?;

    for _ in 0..2 {
        let mut child = daemon(&root)?;
        let status = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = child.0.try_wait()? {
                    return Ok::<_, io::Error>(status);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??;
        assert!(!status.success());
        assert!(Client::connect(&root).await.is_err());
        assert_eq!(std::fs::read(&ledger_path)?, original_ledger);
        assert_eq!(
            std::fs::read(&pending_path)?,
            b"interrupted quota replacement"
        );
        assert!(!root.join("installation-device.key").exists());
    }
    Ok(())
}

async fn quota_command(root: &Path, action: &str) -> Result<std::process::Output> {
    let mut child = OwnedChild(
        Process::new(env!("CARGO_BIN_EXE_nestlink-daemon"))
            .args(["file-quota", action, "--state-dir"])
            .arg(root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let status = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = child.0.try_wait()? {
                return Ok::<_, io::Error>(status);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    use std::io::Read;
    let mut stdout = Vec::new();
    child
        .0
        .stdout
        .take()
        .ok_or("missing quota command stdout")?
        .take(16 * 1024)
        .read_to_end(&mut stdout)?;
    let mut stderr = Vec::new();
    child
        .0
        .stderr
        .take()
        .ok_or("missing quota command stderr")?
        .take(16 * 1024)
        .read_to_end(&mut stderr)?;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

#[tokio::test]
async fn actual_quota_cli_refuses_live_owners_exports_original_bytes_and_recovers_conservatively()
-> Result {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("offline-quota-maintenance");
    nestlink_platform_security::new_private_directory(&root)?;
    let maximum_bytes = nestlink_protocol::FILE_SIZE_BYTES;
    let maximum_artifacts = nestlink_app_core::NATIVE_FILE_TASK_HISTORY_LIMIT as u64;
    let owner = nestlink_platform_files::upload::WriteQuota::open_private_ledger(
        &root,
        maximum_bytes,
        maximum_artifacts,
    )?;
    for action in ["inspect", "export", "recover"] {
        assert!(
            !quota_command(&root, action).await?.status.success(),
            "{action} admitted an active quota owner"
        );
    }
    assert!(!root.join("native-file-write-quota.snapshot").exists());
    drop(owner);
    let ledger = root.join("native-file-write-quota.ledger");
    let pending = root.join("native-file-write-quota.pending");
    let original = std::fs::read(&ledger)?;
    let marker = std::fs::read(root.join("native-file-write-quota.lock"))?;
    nestlink_platform_security::create_private(
        &pending,
        b"interrupted replacement with unknown charged usage",
    )?;
    let inspected = quota_command(&root, "inspect").await?;
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&inspected.stdout)?;
    assert_eq!(summary["lock_marker_valid"], true);
    assert_eq!(summary["pending"]["record_valid"], false);
    assert_eq!(std::fs::read(&ledger)?, original);
    assert_eq!(
        std::fs::read(&pending)?,
        b"interrupted replacement with unknown charged usage"
    );
    let exported = quota_command(&root, "export").await?;
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let archive = std::fs::read(root.join("native-file-write-quota.snapshot"))?;
    assert!(archive.starts_with(b"NLWQEXP1\x03"));
    assert!(
        archive
            .windows(original.len())
            .any(|bytes| bytes == original)
    );
    assert!(
        archive
            .windows(b"interrupted replacement with unknown charged usage".len())
            .any(|bytes| bytes == b"interrupted replacement with unknown charged usage")
    );
    assert!(!quota_command(&root, "export").await?.status.success());
    assert_eq!(
        std::fs::read(root.join("native-file-write-quota.snapshot"))?,
        archive
    );

    let recovered = quota_command(&root, "recover").await?;
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(
        String::from_utf8_lossy(&recovered.stdout).contains("unknown_usage_saturated_limits=true")
    );
    assert!(!pending.exists());
    let inspected = quota_command(&root, "inspect").await?;
    assert!(inspected.status.success());
    let summary: serde_json::Value = serde_json::from_slice(&inspected.stdout)?;
    assert_eq!(summary["ledger"]["charged_bytes"], maximum_bytes);
    assert_eq!(summary["ledger"]["charged_artifacts"], maximum_artifacts);
    assert_eq!(
        std::fs::read(root.join("native-file-write-quota.lock"))?,
        marker
    );
    assert_eq!(
        std::fs::read(root.join("native-file-write-quota.snapshot"))?,
        archive
    );

    let mut child = daemon(&root)?;
    let mut client = connect(&root, &mut child).await?;
    exit(&mut client, &mut child).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn quota_cli_refuses_nonprivate_pending_without_mutating_original_bytes() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("nonprivate-quota-pending");
    nestlink_platform_security::new_private_directory(&root)?;
    drop(
        nestlink_platform_files::upload::WriteQuota::open_private_ledger(
            &root,
            nestlink_protocol::FILE_SIZE_BYTES,
            nestlink_app_core::NATIVE_FILE_TASK_HISTORY_LIMIT as u64,
        )?,
    );
    let pending = root.join("native-file-write-quota.pending");
    nestlink_platform_security::create_private(&pending, b"untrusted pending quota record")?;
    std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o644))?;
    let ledger = root.join("native-file-write-quota.ledger");
    let original = std::fs::read(&ledger)?;
    for action in ["inspect", "export", "recover"] {
        let response = quota_command(&root, action).await?;
        assert!(
            !response.status.success(),
            "{action} accepted nonprivate quota metadata"
        );
        assert!(String::from_utf8_lossy(&response.stderr).contains("not owner-private"));
        assert_eq!(std::fs::read(&ledger)?, original);
        assert_eq!(std::fs::read(&pending)?, b"untrusted pending quota record");
        assert_eq!(
            std::fs::metadata(&pending)?.permissions().mode() & 0o777,
            0o644
        );
        assert!(!root.join("native-file-write-quota.snapshot").exists());
    }
    Ok(())
}
