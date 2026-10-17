use super::*;
use nestlink_remote::files::{
    FileDestination, FileDestinationFactory, FileDestinationStatus, FileDownloadSnapshot,
    FileReadConsent,
};
use std::{
    io,
    sync::{Arc, Condvar, Mutex, atomic::AtomicBool},
};

#[derive(Default)]
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
}
impl Gate {
    fn block(&self) {
        // Test teardown must still unblock a worker if an assertion poisoned the gate.
        let mut released = match self.released.lock() {
            Ok(released) => released,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.entered
            .store(true, std::sync::atomic::Ordering::Release);
        self.changed.notify_all();
        while !*released {
            released = match self.changed.wait(released) {
                Ok(released) => released,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }
    fn release(&self) {
        let mut released = match self.released.lock() {
            Ok(released) => released,
            Err(poisoned) => poisoned.into_inner(),
        };
        *released = true;
        self.changed.notify_all();
    }
}
struct ReleaseOnDrop(Arc<Gate>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct BlockingConsent {
    inner: Arc<dyn FileReadConsent>,
    drop_gate: Arc<Gate>,
}
impl FileReadConsent for BlockingConsent {
    fn check(&self) -> io::Result<()> {
        self.inner.check()
    }
}
impl Drop for BlockingConsent {
    fn drop(&mut self) {
        self.drop_gate.block();
    }
}

struct GatedFactory {
    selected: LocalDownloadSelection,
    consent: Arc<BlockingConsent>,
    cleanup_gate: Arc<Gate>,
    provider_dropped: Arc<AtomicBool>,
}
impl FileDestinationFactory for GatedFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.consent.clone()
    }
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        let Self {
            selected,
            cleanup_gate,
            provider_dropped,
            ..
        } = *self;
        Ok(Box::new(BlockingCleanup {
            inner: Box::new(selected).build(source)?,
            gate: cleanup_gate,
            provider_dropped,
        }))
    }
}

struct BlockingCleanup {
    inner: Box<dyn FileDestination>,
    gate: Arc<Gate>,
    provider_dropped: Arc<AtomicBool>,
}
impl Drop for BlockingCleanup {
    fn drop(&mut self) {
        self.provider_dropped
            .store(true, std::sync::atomic::Ordering::Release);
    }
}
impl FileDestination for BlockingCleanup {
    fn status(&self) -> FileDestinationStatus {
        self.inner.status()
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.inner.prepare(authorized)
    }
    fn write(
        &mut self,
        source: &FileDownloadSnapshot,
        chunk: &FileReadChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.write(source, chunk, authorized)
    }
    fn resume(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.resume(source, authorized)
    }
    fn finish(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.finish(source, authorized)
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.inner.cleanup()?;
        self.gate.block();
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destination_finished_waits_for_captured_consent_drop_and_preserves_timeout() -> Result {
    let source = TempDirectory::new()?;
    let output = TempDirectory::new()?;
    fs::write(source.path().join("source"), b"consent drop gate")?;
    let root = random_id();
    let (provider, _keep) = roots(source.path(), &root)?;
    let mut sessions = Sessions::new(false).await?;
    let mut server = FileReadServer::start(&mut sessions.h, 9, provider)?;
    let area = output.path().join("consent-drop");
    let (selected, _save_consent) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
    let cleanup_gate = Arc::new(Gate::default());
    let drop_gate = Arc::new(Gate::default());
    let _cleanup_release = ReleaseOnDrop(cleanup_gate.clone());
    let _drop_release = ReleaseOnDrop(drop_gate.clone());
    let provider_dropped = Arc::new(AtomicBool::new(false));
    let consent = Arc::new(BlockingConsent {
        inner: selected.consent(),
        drop_gate: drop_gate.clone(),
    });
    let consent_weak = Arc::downgrade(&consent);
    let mut download = NativeFileDownload::attach(
        &mut sessions.c,
        9,
        NativeDownloadRequest::new(&root, "source")?,
        GatedFactory {
            selected,
            consent: consent.clone(),
            cleanup_gate: cleanup_gate.clone(),
            provider_dropped: provider_dropped.clone(),
        },
    )?;
    drop(consent);
    download.ready().await?;
    let monitor = download.monitor();

    let stopped = tokio::time::timeout(Duration::from_secs(2), download.cancel()).await?;
    assert_eq!(stopped.destination_shutdown, Some(FileShutdown::TimedOut));
    assert!(
        cleanup_gate
            .entered
            .load(std::sync::atomic::Ordering::Acquire)
    );
    tokio::time::timeout(Duration::from_secs(2), download.release_client()).await??;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !monitor.status().actor_finished || consent_weak.strong_count() != 1 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;

    cleanup_gate.release();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !drop_gate.entered.load(std::sync::atomic::Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;
    assert!(provider_dropped.load(std::sync::atomic::Ordering::Acquire));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(destination) = monitor.status().destination
                && destination.cleanup_timed_out
            {
                assert!(!destination.finished);
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;

    drop_gate.release();
    let final_status =
        tokio::time::timeout(Duration::from_secs(2), monitor.wait_finished()).await?;
    let destination = final_status
        .destination
        .ok_or("missing final destination")?;
    assert!(destination.finished && destination.cleanup_timed_out);
    assert!(destination.destination.file_closed && destination.destination.temporary_removed);
    assert!(!destination.destination.published && !area.join("done").exists());

    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
