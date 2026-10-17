use super::*;
use nestlink_remote::files::{
    FileDestination, FileDestinationFactory, FileDestinationStatus, FileDownloadSnapshot,
    FileReadConsent,
};
use std::{
    io,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Default)]
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
}
impl Gate {
    fn block(&self) -> io::Result<()> {
        let mut released = self
            .released
            .lock()
            .map_err(|_| io::Error::other("test gate poisoned"))?;
        self.entered.store(true, Ordering::Release);
        while !*released {
            released = self
                .changed
                .wait(released)
                .map_err(|_| io::Error::other("test gate poisoned"))?;
        }
        Ok(())
    }
    fn release(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = true;
        self.changed.notify_all();
    }
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct Factory {
    selected: LocalDownloadSelection,
    gate: Arc<Gate>,
}
impl FileDestinationFactory for Factory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.selected.consent()
    }
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        Ok(Box::new(Blocked {
            destination: Box::new(self.selected).build(source)?,
            gate: self.gate,
        }))
    }
}
struct Blocked {
    destination: Box<dyn FileDestination>,
    gate: Arc<Gate>,
}
impl FileDestination for Blocked {
    fn status(&self) -> FileDestinationStatus {
        self.destination.status()
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.destination.prepare(authorized)
    }
    fn write(
        &mut self,
        source: &FileDownloadSnapshot,
        chunk: &FileReadChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        authorized()?;
        self.gate.block()?;
        self.destination.write(source, chunk, authorized)
    }
    fn resume(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.resume(source, authorized)
    }
    fn finish(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.finish(source, authorized)
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.destination.cleanup()
    }
}

#[tokio::test]
async fn sdk_blocked_disk_cancel_reports_timeout_and_preserves_later_actual_cleanup() -> Result {
    let source = TempDirectory::new()?;
    let output = TempDirectory::new()?;
    fs::write(source.path().join("source"), b"blocked disk bytes")?;
    let root = random_id();
    let (provider, _keep) = roots(source.path(), &root)?;
    let mut sessions = Sessions::new(false).await?;
    let mut server = FileReadServer::start(&mut sessions.h, 9, provider)?;
    let area = output.path().join("blocked");
    let (selected, _save_keep) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
    let gate = Arc::new(Gate::default());
    let release = Release(gate.clone());
    let mut download = NativeFileDownload::attach(
        &mut sessions.c,
        9,
        NativeDownloadRequest::new(&root, "source")?,
        Factory {
            selected,
            gate: gate.clone(),
        },
    )?;
    download.ready().await?;
    let monitor = download.monitor();
    let mut pull = Box::pin(download.pull());
    tokio::select! {
        result = &mut pull => return Err(format!("disk operation completed before test release: {result:?}").into()),
        result = tokio::time::timeout(Duration::from_secs(2), async {
            while !gate.entered.load(Ordering::Acquire) { tokio::time::sleep(Duration::from_millis(1)).await; }
        }) => result?,
    }
    drop(pull);
    let stopped = tokio::time::timeout(Duration::from_secs(1), download.cancel()).await?;
    assert!(stopped.local_stopped);
    assert_eq!(stopped.destination_shutdown, Some(FileShutdown::TimedOut));
    let still_owned = stopped.destination.ok_or("missing blocked destination")?;
    assert!(still_owned.cleanup_timed_out && !still_owned.finished);
    assert!(
        !still_owned.destination.published
            && !still_owned.destination.file_closed
            && !still_owned.destination.temporary_removed
    );
    assert_eq!(still_owned.destination.confirmed_bytes, 0);
    let retired = download.release_client().await?;
    assert!(retired.source_cancel_acknowledged);
    assert_eq!(retired.client_retirement, Some(Ok(())));
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    drop(release);
    let actual = tokio::time::timeout(Duration::from_secs(2), monitor.wait_finished()).await?;
    let actual = actual.destination.ok_or("missing final destination")?;
    assert!(
        actual.finished
            && actual.cleanup_timed_out
            && actual.destination.file_closed
            && actual.destination.temporary_removed
    );
    assert!(!actual.destination.published);
    assert_eq!(actual.destination.confirmed_bytes, 0);
    assert!(!area.join("done").exists());
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn sdk_cancel_interrupts_a_pause_barrier_behind_a_blocked_write() -> Result {
    let source = TempDirectory::new()?;
    let output = TempDirectory::new()?;
    fs::write(source.path().join("source"), b"pause then cancel")?;
    let root = random_id();
    let (provider, _keep) = roots(source.path(), &root)?;
    let mut sessions = Sessions::new(false).await?;
    let mut server = FileReadServer::start(&mut sessions.h, 9, provider)?;
    let area = output.path().join("paused-blocked");
    let (selected, _save_keep) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
    let gate = Arc::new(Gate::default());
    let release = Release(gate.clone());
    let mut download = NativeFileDownload::attach(
        &mut sessions.c,
        9,
        NativeDownloadRequest::new(&root, "source")?,
        Factory {
            selected,
            gate: gate.clone(),
        },
    )?;
    download.ready().await?;
    let monitor = download.monitor();
    let mut pull = Box::pin(download.pull());
    tokio::select! {
        result = &mut pull => return Err(format!("write completed before gate release: {result:?}").into()),
        result = tokio::time::timeout(Duration::from_secs(2), async {
            while !gate.entered.load(Ordering::Acquire) { tokio::time::sleep(Duration::from_millis(1)).await; }
        }) => result?,
    }
    drop(pull);
    download.control().pause();
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut changes = monitor.subscribe();
        loop {
            if changes.borrow_and_update().phase == NativeDownloadPhase::Pausing {
                break;
            }
            changes.changed().await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    let stopped = tokio::time::timeout(Duration::from_secs(1), download.cancel()).await?;
    assert!(stopped.local_stopped);
    assert_eq!(stopped.destination_shutdown, Some(FileShutdown::TimedOut));
    let held = stopped.destination.ok_or("missing blocked destination")?;
    assert!(held.cleanup_timed_out && !held.finished);
    assert_eq!(stopped.pause_ack_revision, 0);
    let retired = download.release_client().await?;
    assert!(retired.source_cancel_acknowledged);
    assert_eq!(retired.client_retirement, Some(Ok(())));
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    drop(release);
    let actual = tokio::time::timeout(Duration::from_secs(2), monitor.wait_finished()).await?;
    let actual = actual.destination.ok_or("missing cleaned destination")?;
    assert!(
        actual.finished
            && actual.cleanup_timed_out
            && actual.destination.file_closed
            && actual.destination.temporary_removed
    );
    assert!(!actual.destination.published && !area.join("done").exists());
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
