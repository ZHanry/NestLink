#![cfg(not(target_arch = "wasm32"))]
#[path = "files/support.rs"]
#[allow(dead_code)]
mod support;
use nestlink_auth::random_id;
use nestlink_identity::digest;
use nestlink_platform_files::upload::{LocalUploadSelection, WriteRootSelection, WriteRoots};
use nestlink_protocol::{FILE_SIZE_BYTES, FileReadManifest};
use nestlink_remote::{
    files::{FileReadConsent, FileReadSource, FileShutdown},
    upload::{FileUploadSourceFactory, FileWriteServer},
};
use nestlink_sdk::upload::{NativeFileUpload, NativeUploadPhase, NativeUploadRequest};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{
    fs, io,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use support::*;

#[tokio::test]
async fn sdk_uploads_actual_files_and_reuses_the_exact_idle_writer_before_safe_retirement() -> Result
{
    for quic in [false, true] {
        let temporary = TempDirectory::new()?;
        let area = temporary.path().join("received");
        let local = temporary.path().join("selected");
        let bytes: Vec<_> = (0..3 * 61440 + 7).map(|i| (i % 241) as u8).collect();
        fs::write(&local, &bytes)?;
        let root = random_id();
        let (selection, _keep_write) =
            WriteRootSelection::new(&root, &area, FILE_SIZE_BYTES, FILE_SIZE_BYTES)?;
        let mut sessions = Sessions::new_upload(quic).await?;
        let mut server =
            FileWriteServer::start(&mut sessions.h, 9, WriteRoots::new(vec![selection])?)?;
        let (source, _keep_read) = LocalUploadSelection::new(&local, FILE_SIZE_BYTES)?;
        let upload = NativeFileUpload::attach(
            &mut sessions.c,
            9,
            NativeUploadRequest::new(&root, "first")?,
            source,
        )?;
        let monitor = upload.monitor();
        let mut outcome = tokio::time::timeout(Duration::from_secs(5), upload.finish()).await??;
        let receipt = outcome.result?;
        assert_eq!(receipt.sha256, digest(&bytes));
        assert_eq!(fs::read(area.join("first"))?, bytes);
        assert_eq!(monitor.status().phase, NativeUploadPhase::Completed);
        assert!(
            monitor.status().finished
                && monitor.status().actor_finished
                && monitor.status().remote_closed
        );
        assert_eq!(monitor.status().confirmed_bytes, bytes.len() as u64);
        assert_eq!(
            monitor
                .status()
                .source
                .ok_or("actual source facts missing")?
                .error,
            None
        );
        assert!(
            monitor
                .status()
                .source
                .ok_or("actual source facts missing")?
                .source_closed
        );
        let returned = outcome
            .client
            .take()
            .ok_or("exact idle writer was not returned")?;
        let (second, _keep_read_second) = LocalUploadSelection::new(&local, FILE_SIZE_BYTES)?;
        let upload = returned.start(NativeUploadRequest::new(&root, "second")?, second)?;
        let mut outcome = tokio::time::timeout(Duration::from_secs(5), upload.finish()).await??;
        outcome.result?;
        assert_eq!(fs::read(area.join("second"))?, bytes);
        outcome
            .client
            .take()
            .ok_or("writer was not reclaimed after second upload")?
            .retire()?;
        sessions
            .c
            .send(Channel::Video, b"viewing survives both uploads")
            .await?;
        assert_eq!(
            sessions.h.receive().await?.payload,
            b"viewing survives both uploads"
        );
        assert!(fs::read_dir(&area)?.all(|entry| entry.is_ok_and(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".nestlink-upload-")
        })));
        server.shutdown(StopReason::ExplicitExit).await?;
        sessions.c.shutdown(StopReason::ExplicitExit).await?;
        sessions.h.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sdk_cancellation_before_begin_preserves_viewing_and_returns_a_clean_writer() -> Result {
    let temporary = TempDirectory::new()?;
    let area = temporary.path().join("received");
    let local = temporary.path().join("selected");
    fs::write(&local, vec![7; 8 * 61440])?;
    let root = random_id();
    let (selection, _keep_write) =
        WriteRootSelection::new(&root, &area, FILE_SIZE_BYTES, FILE_SIZE_BYTES)?;
    let mut sessions = Sessions::new_upload(false).await?;
    let mut server = FileWriteServer::start(&mut sessions.h, 9, WriteRoots::new(vec![selection])?)?;
    let (source, _keep_read) = LocalUploadSelection::new(&local, FILE_SIZE_BYTES)?;
    let mut upload = NativeFileUpload::attach(
        &mut sessions.c,
        9,
        NativeUploadRequest::new(&root, "cancelled")?,
        source,
    )?;
    let monitor = upload.monitor();
    let _ = upload.cancel().await;
    let mut outcome = tokio::time::timeout(Duration::from_secs(5), upload.finish()).await??;
    assert!(outcome.result.is_err());
    assert_eq!(monitor.status().phase, NativeUploadPhase::Cancelled);
    assert!(monitor.status().finished);
    assert!(!area.join("cancelled").exists());
    drop(
        outcome
            .client
            .take()
            .ok_or("cancelled clean writer was not returned")?,
    );
    sessions
        .c
        .send(Channel::Video, b"viewing after upload cancellation")
        .await?;
    assert_eq!(
        sessions.h.receive().await?.payload,
        b"viewing after upload cancellation"
    );
    if area.exists() {
        assert!(fs::read_dir(&area)?.next().is_none());
    }
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

struct SourceGate {
    entered: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
}
impl SourceGate {
    fn block(&self) {
        self.entered.store(true, Ordering::Release);
        let mut released = self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = self
                .wake
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
    fn release(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.wake.notify_all();
    }
}
struct ReleaseSource(Arc<SourceGate>);
impl Drop for ReleaseSource {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct SlowSourceFactory {
    selected: LocalUploadSelection,
    gate: Arc<SourceGate>,
}
struct SlowSource {
    source: Box<dyn FileReadSource>,
    gate: Arc<SourceGate>,
}
impl FileUploadSourceFactory for SlowSourceFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.selected.consent()
    }
    fn open(
        self: Box<Self>,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileReadSource>> {
        Ok(Box::new(SlowSource {
            source: Box::new(self.selected).open(authorized)?,
            gate: self.gate,
        }))
    }
}
impl FileReadSource for SlowSource {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.source.consent()
    }
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        self.source.describe(authorized)
    }
    fn read_chunk(
        &mut self,
        offset: u64,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        if offset != 0 {
            self.gate.block();
        }
        self.source.read_chunk(offset, maximum, authorized)
    }
    fn verify(
        &mut self,
        manifest: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.source.verify(manifest, authorized)
    }
}
#[tokio::test]
async fn sdk_cancels_an_active_destination_while_a_source_call_is_blocked_and_reports_late_cleanup()
-> Result {
    let temporary = TempDirectory::new()?;
    let area = temporary.path().join("received");
    let local = temporary.path().join("selected");
    fs::write(&local, vec![5; 3 * 61440])?;
    let root = random_id();
    let (selection, _keep_write) =
        WriteRootSelection::new(&root, &area, FILE_SIZE_BYTES, FILE_SIZE_BYTES)?;
    let (selected, _keep_read) = LocalUploadSelection::new(&local, FILE_SIZE_BYTES)?;
    let gate = Arc::new(SourceGate {
        entered: AtomicBool::new(false),
        released: Mutex::new(false),
        wake: Condvar::new(),
    });
    let _release = ReleaseSource(gate.clone());
    let mut sessions = Sessions::new_upload(false).await?;
    let mut server = FileWriteServer::start(&mut sessions.h, 9, WriteRoots::new(vec![selection])?)?;
    let mut upload = NativeFileUpload::attach(
        &mut sessions.c,
        9,
        NativeUploadRequest::new(&root, "cancelled")?,
        SlowSourceFactory {
            selected,
            gate: gate.clone(),
        },
    )?;
    let monitor = upload.monitor();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !gate.entered.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;
    assert_eq!(monitor.status().confirmed_bytes, 61440);
    assert_eq!(upload.cancel().await, FileShutdown::TimedOut);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !monitor.status().actor_finished {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;
    assert!(monitor.status().actor_finished && monitor.status().remote_closed);
    assert!(!monitor.status().finished);
    assert!(monitor.status().cleanup_timed_out);
    let partial = monitor
        .status()
        .destination
        .ok_or("cancel actual destination facts missing")?;
    assert!(partial.file_closed && partial.temporary_removed && !partial.published);
    assert!(fs::read_dir(&area)?.next().is_none());
    assert!(
        !monitor
            .status()
            .source
            .ok_or("owned source facts missing")?
            .source_closed
    );
    let finished = upload.finish();
    tokio::pin!(finished);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut finished)
            .await
            .is_err(),
        "a blocked source cannot release its writer for a replacement worker"
    );
    let subscribed = monitor.subscribe();
    gate.release();
    let mut outcome = tokio::time::timeout(Duration::from_secs(2), finished).await??;
    assert!(outcome.result.is_err());
    tokio::time::timeout(Duration::from_secs(2), async {
        while !monitor.status().finished {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;
    assert!(subscribed.borrow().finished);
    assert!(monitor.status().cleanup_timed_out);
    assert!(
        monitor
            .status()
            .source
            .ok_or("late actual source facts missing")?
            .source_closed
    );
    outcome
        .client
        .take()
        .ok_or("cancelled exact writer was not returned")?
        .retire()?;
    sessions
        .c
        .send(Channel::Video, b"viewing after active upload cancellation")
        .await?;
    assert_eq!(
        sessions.h.receive().await?.payload,
        b"viewing after active upload cancellation"
    );
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
