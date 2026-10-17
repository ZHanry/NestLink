#![cfg(not(target_arch = "wasm32"))]
#[path = "file_restart/support.rs"]
mod support;
use nestlink_auth::random_id;
use nestlink_platform_files::{
    ApprovedReadRoot, FileRoots,
    download::recovery::{DownloadRecoveryStore, PersistentDownloadSelection},
};
use nestlink_protocol::FILE_SIZE_BYTES;
use nestlink_remote::files::FileReadServer;
use nestlink_sdk::files::{NativeDownloadPhase, NativeDownloadRequest, NativeFileDownload};
use nestlink_session::StopReason;
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use support::*;

fn private_state(path: &Path) -> Result {
    // SDK test dependency is the platform adapter. Creating a fresh store's
    // private state goes through the same publicly selected private area API.
    fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        // Use the native package's platform-security helper via a test-only
        // dependency, never shell ACL commands or a production profile.
        fs::remove_dir(path)?;
        nestlink_platform_security::new_private_directory(path)?;
    }
    Ok(())
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn child_root() -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os("NESTLINK_RESTART_FIXTURE") else {
        return Ok(None);
    };
    let root = PathBuf::from(value);
    let parent = std::env::temp_dir().canonicalize()?;
    if root.parent() != Some(parent.as_path())
        || !root
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("nestlink-sdk-files-"))
        || root.canonicalize()? != root
    {
        return Err("restart fixture path is not the exact owned temporary directory".into());
    }
    Ok(Some(root))
}

/// Helper executed in a real separate process by the tests below. The parent
/// kills it with live worker/file handles, rather than mocking a restart flag.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_child_fixture() -> Result {
    let Some(root) = child_root()? else {
        return Ok(());
    };
    let quic = std::env::var("NESTLINK_RESTART_QUIC").as_deref() == Ok("true");
    let store = DownloadRecoveryStore::open(&root.join("state"), FILE_SIZE_BYTES, 128)?;
    let root_id = store.approved_read_root_id(&root.join("source"), &random_id())?;
    let (selected_root, _read_consent) =
        ApprovedReadRoot::open(&root_id, &root.join("source"), FILE_SIZE_BYTES)?;
    let mut sessions = Sessions::new(quic).await?;
    let _server = FileReadServer::start(&mut sessions.h, 9, FileRoots::new(vec![selected_root])?)?;
    let (selected, _save_consent) =
        PersistentDownloadSelection::new(store, &random_id(), &root.join("area"), "done")?;
    let mut download = NativeFileDownload::attach(
        &mut sessions.c,
        9,
        NativeDownloadRequest::new(&root_id, "source")?,
        selected,
    )?;
    download.ready().await?;
    download.pull().await?;
    download.pull().await?;
    let status = download.status();
    let checkpoint = status
        .destination
        .ok_or("missing child destination")?
        .destination
        .confirmed_bytes;
    if checkpoint == 0 || status.source_verified {
        return Err("child fixture must hold a non-complete real partial".into());
    }
    fs::write(root.join("ready"), checkpoint.to_string())?;
    // Keep every scope, consent and actual worker alive until external kill.
    std::future::pending::<()>().await;
    Ok(())
}

async fn kill_partial(root: &Path, quic: bool) -> Result<u64> {
    let mut child = ChildGuard(
        Command::new(std::env::current_exe()?)
            .args(["--exact", "restart_child_fixture", "--nocapture"])
            .env("NESTLINK_RESTART_FIXTURE", root)
            .env("NESTLINK_RESTART_QUIC", quic.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let checkpoint = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if root.join("ready").exists() {
                return Ok::<u64, Box<dyn std::error::Error + Send + Sync>>(
                    fs::read_to_string(root.join("ready"))?.parse()?,
                );
            }
            if child.0.try_wait()?.is_some() {
                return Err("restart fixture child exited before checkpoint".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    assert_eq!(
        DownloadRecoveryStore::open(&root.join("state"), FILE_SIZE_BYTES, 128)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    child.0.kill()?;
    child.0.wait()?;
    Ok(checkpoint)
}
fn prepare() -> Result<(TempDirectory, Vec<u8>)> {
    let temp = TempDirectory::new()?;
    private_state(&temp.path().join("state"))?;
    fs::create_dir(temp.path().join("source"))?;
    let bytes: Vec<_> = (0..240 * 1024 + 37)
        .map(|index| (index % 239) as u8)
        .collect();
    fs::write(temp.path().join("source/source"), &bytes)?;
    Ok((temp, bytes))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn killed_process_resumes_only_under_new_tls_quic_proofs_and_truncates_unconfirmed_tail()
-> Result {
    for quic in [false, true] {
        let (temp, bytes) = prepare()?;
        let checkpoint = kill_partial(temp.path(), quic).await?;
        let staged = fs::read_dir(temp.path().join("area"))?
            .next()
            .ok_or("missing actual staged object")??
            .path();
        fs::OpenOptions::new()
            .append(true)
            .open(&staged)?
            .write_all(b"uncheckpointed tail")?;
        let store = DownloadRecoveryStore::open(&temp.path().join("state"), FILE_SIZE_BYTES, 128)?;
        let (tasks, charged) = store.list()?;
        assert_eq!(tasks.len(), 1);
        assert_eq!(charged, bytes.len() as u64);
        assert_eq!(tasks[0].phase, "waiting_for_approval");
        assert!(!tasks[0].owner_active);
        assert_eq!(tasks[0].checkpoint_bytes, checkpoint);
        let recovery = store.resume_facts(&tasks[0].task_id)?;
        let root_id = store.approved_read_root_id(&temp.path().join("source"), &random_id())?;
        assert_eq!(root_id, recovery.facts.root_id);
        let (root, _source_consent) =
            ApprovedReadRoot::open(&root_id, &temp.path().join("source"), FILE_SIZE_BYTES)?;
        // This creates a fresh permit with a fresh session ID and performs both
        // endpoint proofs over a new real transport. Only stable facts match.
        let mut fresh = Sessions::new(quic).await?;
        let mut server = FileReadServer::start(&mut fresh.h, 9, FileRoots::new(vec![root])?)?;
        let (selection, _new_local_consent) =
            PersistentDownloadSelection::recover(store.clone(), &tasks[0].task_id)?;
        let mut resumed = NativeFileDownload::attach(
            &mut fresh.c,
            9,
            NativeDownloadRequest::recover(recovery)?,
            selection,
        )?;
        let ready = resumed.ready().await?;
        assert_eq!(ready.phase, NativeDownloadPhase::Ready);
        assert_eq!(
            ready
                .destination
                .ok_or("missing reopened destination")?
                .destination
                .confirmed_bytes,
            checkpoint
        );
        assert_eq!(fs::metadata(&staged)?.len(), checkpoint);
        resumed.download_to_end().await?;
        resumed.monitor().wait_finished().await;
        assert_eq!(fs::read(temp.path().join("area/done"))?, bytes);
        assert_eq!(store.list()?.1, 0);
        assert!(store.list()?.0[0].published && store.list()?.0[0].temporary_removed);
        resumed.release_client().await?;
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restarted_task_rejects_other_scope_and_revoked_new_local_consent_without_disk_changes()
-> Result {
    let (temp, bytes) = prepare()?;
    kill_partial(temp.path(), false).await?;
    let store = DownloadRecoveryStore::open(&temp.path().join("state"), FILE_SIZE_BYTES, 128)?;
    let tasks = store.list()?.0;
    let original = store.resume_facts(&tasks[0].task_id)?;
    let mut incorrect = original.clone();
    incorrect.facts.scope.resource_id = random_id();
    let mut fresh = Sessions::new(false).await?;
    let (selection, _new_consent) =
        PersistentDownloadSelection::recover(store.clone(), &tasks[0].task_id)?;
    let mut refused = NativeFileDownload::attach(
        &mut fresh.c,
        9,
        NativeDownloadRequest::recover(incorrect)?,
        selection,
    )?;
    assert!(refused.ready().await.is_err());
    refused.monitor().wait_finished().await;
    assert_eq!(store.list()?.1, bytes.len() as u64);
    assert_eq!(store.resume_facts(&tasks[0].task_id)?, original);
    refused.release_client().await?;

    let root_id = original.facts.root_id.clone();
    let (root, _source_consent) =
        ApprovedReadRoot::open(&root_id, &temp.path().join("source"), FILE_SIZE_BYTES)?;
    let mut fresh = Sessions::new(false).await?;
    let mut server = FileReadServer::start(&mut fresh.h, 9, FileRoots::new(vec![root])?)?;
    let (selection, consent) =
        PersistentDownloadSelection::recover(store.clone(), &tasks[0].task_id)?;
    consent.revoke();
    let mut refused = NativeFileDownload::attach(
        &mut fresh.c,
        9,
        NativeDownloadRequest::recover(original.clone())?,
        selection,
    )?;
    assert!(refused.ready().await.is_err());
    refused.monitor().wait_finished().await;
    assert_eq!(store.resume_facts(&tasks[0].task_id)?, original);
    assert_eq!(store.list()?.1, bytes.len() as u64);
    refused.release_client().await?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
