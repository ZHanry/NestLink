#![cfg(not(target_arch = "wasm32"))]
use nestlink_sdk::{download_queue, files};
#[allow(dead_code)]
#[path = "files/support.rs"]
mod support;
use download_queue::*;
use files::NativeDownloadRequest;
use nestlink_auth::random_id;
use nestlink_identity::digest;
use nestlink_platform_files::{
    ApprovedReadRoot, FileRoots,
    download::{LocalDownloadConsent, LocalDownloadSelection},
};
use nestlink_protocol::{
    FILE_SIZE_BYTES, FileReadChunk, FileReadManifest, NativeFileRead, native_file_read::Action,
};
use nestlink_remote::{
    ChannelRuntime,
    files::{
        FileDestination, FileDestinationFactory, FileDestinationStatus, FileDownloadSnapshot,
        FileReadClient, FileReadConsent, FileReadServer, FileShutdown,
    },
};
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

async fn receive(host: &mut ChannelRuntime) -> Result<NativeFileRead> {
    let frame = tokio::time::timeout(Duration::from_secs(2), host.receive()).await??;
    Ok(NativeFileRead::decode_validated(&frame.payload)?)
}
async fn reply(host: &mut ChannelRuntime, mut request: NativeFileRead, action: Action) -> Result {
    request.action = Some(action);
    host.send(Channel::FileRead, &request.encode_validated()?)
        .await?;
    Ok(())
}
async fn manifest(host: &mut ChannelRuntime, request: NativeFileRead, data: &[u8]) -> Result {
    assert!(matches!(request.action, Some(Action::Open(_))));
    reply(
        host,
        request,
        Action::Manifest(FileReadManifest {
            size: data.len() as u64,
            sha256: digest(data).to_vec(),
            offset: 0,
        }),
    )
    .await
}
async fn cancelled(host: &mut ChannelRuntime) -> Result {
    let request = receive(host).await?;
    assert_eq!(request.action, Some(Action::Cancel(true)));
    reply(host, request, Action::Cancelled(true)).await
}
fn submit(
    queue: &NativeDownloadQueue,
    sessions: &mut Sessions,
    output: &TempDirectory,
    name: &str,
    maximum: u64,
) -> Result<(NativeDownloadTask, LocalDownloadConsent)> {
    let (selection, consent) =
        LocalDownloadSelection::new(&output.path().join(name), "done", FILE_SIZE_BYTES)?;
    let task = queue.submit(
        FileReadClient::attach(&mut sessions.c, 9)?,
        NativeDownloadRequest::new(&random_id(), "source")?,
        maximum,
        selection,
    )?;
    Ok((task, consent))
}

#[tokio::test]
async fn queue_caps_fifo_reservations_pending_cancel_and_safe_admission_rejection() -> Result {
    let output = TempDirectory::new()?;
    let queue = NativeDownloadQueue::new(NativeDownloadQueueLimits {
        active: 2,
        tasks: 3,
        reserved_bytes: 8,
    })?;
    let mut a = Sessions::new(false).await?;
    let (first, _first_consent) = submit(&queue, &mut a, &output, "a", 8)?;
    let open = receive(&mut a.h).await?;
    assert_eq!(queue.status().reserved_bytes, 8);
    manifest(&mut a.h, open, b"data").await?;
    let next = receive(&mut a.h).await?;
    assert!(matches!(next.action, Some(Action::Next(_))));
    assert_eq!(queue.status().reserved_bytes, 4);

    let mut b = Sessions::new(false).await?;
    let (second, _second_consent) = submit(&queue, &mut b, &output, "b", 8)?;
    let mut c = Sessions::new(false).await?;
    let (third, _third_consent) = submit(&queue, &mut c, &output, "c", 4)?;
    assert!(
        tokio::time::timeout(Duration::from_millis(40), b.h.receive())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(40), c.h.receive())
            .await
            .is_err(),
        "a smaller task cannot bypass the FIFO head awaiting its full reservation"
    );
    assert_eq!(queue.status().active, 1);
    assert_eq!(queue.status().queued, 2);
    assert_eq!(queue.status().reserved_bytes, 4);
    assert!(!output.path().join("b").exists() && !output.path().join("c").exists());
    let mut d = Sessions::new(false).await?;
    let (selection, _d_consent) = LocalDownloadSelection::new(&output.path().join("d"), "done", 4)?;
    let rejected = queue.submit(
        FileReadClient::attach(&mut d.c, 9)?,
        NativeDownloadRequest::new(&random_id(), "source")?,
        4,
        selection,
    );
    let rejected = match rejected {
        Err(error) => error,
        Ok(_) => return Err("fourth task exceeded the total owner cap".into()),
    };
    assert_eq!(rejected.cause, NativeDownloadQueueError::Full);
    assert_eq!(rejected.client_retirement, Ok(()));
    d.c.lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    second.cancel();
    let stopped = tokio::time::timeout(Duration::from_secs(1), second.wait_finished()).await?;
    assert_eq!(stopped.phase, NativeDownloadTaskPhase::Cancelled);
    assert!(stopped.native.is_none());
    assert_eq!(stopped.client_retirement, Some(Ok(())));
    b.c.lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    let open = receive(&mut c.h).await?;
    assert!(matches!(open.action, Some(Action::Open(_))));
    assert_eq!(queue.status().active, 2);
    assert_eq!(queue.status().reserved_bytes, 8);
    first.cancel();
    third.cancel();
    let task_monitor = first.monitor();
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut state = task_monitor.subscribe();
        while !state
            .borrow_and_update()
            .native
            .as_ref()
            .is_some_and(|native| native.local_stopped)
        {
            state.changed().await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert_eq!(queue.status().reserved_bytes, 8);
    reply(
        &mut a.h,
        next,
        Action::Chunk(FileReadChunk {
            offset: 0,
            data: b"data".to_vec(),
            sha256: digest(b"data").to_vec(),
        }),
    )
    .await?;
    cancelled(&mut a.h).await?;
    manifest(&mut c.h, open, b"data").await?;
    cancelled(&mut c.h).await?;
    for task in [&first, &third] {
        let stopped = tokio::time::timeout(Duration::from_secs(1), task.wait_finished()).await?;
        assert_eq!(stopped.phase, NativeDownloadTaskPhase::Cancelled);
        assert_eq!(stopped.client_retirement, Some(Ok(())));
        assert_eq!(stopped.reserved_bytes, 0);
    }
    let idle = tokio::time::timeout(Duration::from_secs(1), queue.monitor().wait_idle()).await?;
    assert_eq!(idle.tasks, 0);
    assert_eq!(idle.active, 0);
    assert_eq!(idle.queued, 0);
    assert_eq!(idle.reserved_bytes, 0);
    a.c.lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    c.c.lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    Ok(())
}

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
            .map_err(|_| io::Error::other("gate poisoned"))?;
        self.entered.store(true, Ordering::Release);
        while !*released {
            released = self
                .changed
                .wait(released)
                .map_err(|_| io::Error::other("gate poisoned"))?;
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
    gate: Option<Arc<Gate>>,
    built: Arc<AtomicBool>,
}
impl FileDestinationFactory for Factory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.selected.consent()
    }
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        self.built.store(true, Ordering::Release);
        Ok(Box::new(Controlled {
            destination: Box::new(self.selected).build(source)?,
            gate: self.gate,
        }))
    }
}
struct Controlled {
    destination: Box<dyn FileDestination>,
    gate: Option<Arc<Gate>>,
}
impl FileDestination for Controlled {
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
        if let Some(gate) = &self.gate {
            gate.block()?;
        }
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
async fn queue_holds_budget_through_bounded_shutdown_dropped_wait_and_late_actual_cleanup() -> Result
{
    let source = TempDirectory::new()?;
    let output = TempDirectory::new()?;
    fs::write(source.path().join("source"), b"data")?;
    let queue = NativeDownloadQueue::new(NativeDownloadQueueLimits {
        active: 1,
        tasks: 2,
        reserved_bytes: 4,
    })?;
    let root = random_id();
    let (read_root, _read_consent) = ApprovedReadRoot::open(&root, source.path(), 4)?;
    let mut a = Sessions::new(false).await?;
    let mut server_a = FileReadServer::start(&mut a.h, 9, FileRoots::new(vec![read_root])?)?;
    let (selected, _save_consent) =
        LocalDownloadSelection::new(&output.path().join("a"), "done", 4)?;
    let gate = Arc::new(Gate::default());
    let release = Release(gate.clone());
    let first = queue.submit(
        FileReadClient::attach(&mut a.c, 9)?,
        NativeDownloadRequest::new(&root, "source")?,
        4,
        Factory {
            selected,
            gate: Some(gate.clone()),
            built: Arc::default(),
        },
    )?;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !gate.entered.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    let (read_root, _second_read_consent) = ApprovedReadRoot::open(&root, source.path(), 4)?;
    let mut b = Sessions::new(false).await?;
    let mut server_b = FileReadServer::start(&mut b.h, 9, FileRoots::new(vec![read_root])?)?;
    let (selected, _second_save_consent) =
        LocalDownloadSelection::new(&output.path().join("b"), "done", 4)?;
    let second = queue.submit(
        FileReadClient::attach(&mut b.c, 9)?,
        NativeDownloadRequest::new(&root, "source")?,
        4,
        selected,
    )?;
    let first_monitor = first.monitor();
    first.control().cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut state = first_monitor.subscribe();
        while !state
            .borrow_and_update()
            .native
            .as_ref()
            .is_some_and(|native| native.actor_finished)
        {
            state.changed().await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    let held = first_monitor.status();
    let native = held.native.ok_or("missing native owner status")?;
    assert_eq!(native.destination_shutdown, Some(FileShutdown::TimedOut));
    assert!(native.actor_finished && !native.destination.ok_or("missing disk")?.finished);
    assert!(!held.finished);
    assert_eq!(queue.status().active, 1);
    assert_eq!(queue.status().reserved_bytes, 4);
    assert_eq!(queue.status().tasks, 2);
    assert_eq!(second.status().phase, NativeDownloadTaskPhase::Queued);
    assert!(second.status().native.is_none() && !output.path().join("b").exists());
    assert!(
        tokio::time::timeout(Duration::from_millis(40), first_monitor.wait_finished())
            .await
            .is_err()
    );
    drop(first);
    assert_eq!(queue.status().reserved_bytes, 4);
    drop(release);
    let stopped =
        tokio::time::timeout(Duration::from_secs(2), first_monitor.wait_finished()).await?;
    assert_eq!(stopped.phase, NativeDownloadTaskPhase::Cancelled);
    let disk = stopped
        .native
        .ok_or("missing final native state")?
        .destination
        .ok_or("missing final disk")?;
    assert!(disk.finished && disk.destination.file_closed && disk.destination.temporary_removed);
    let complete = tokio::time::timeout(Duration::from_secs(2), second.wait_finished()).await?;
    assert_eq!(complete.phase, NativeDownloadTaskPhase::Completed);
    assert_eq!(complete.client_retirement, Some(Ok(())));
    assert_eq!(fs::read(output.path().join("b/done"))?, b"data");
    assert_eq!(queue.monitor().wait_idle().await.reserved_bytes, 0);
    assert_eq!(queue.status().tasks, 0);
    // Repeated cancellation and observation cannot deduct either permit again.
    second.cancel();
    second.wait_finished().await;
    assert_eq!(queue.status().reserved_bytes, 0);
    a.c.lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    b.c.lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    server_a.shutdown(StopReason::ExplicitExit).await?;
    server_b.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn queue_rejects_a_manifest_over_budget_before_destination_construction_and_returns_permits()
-> Result {
    let source = TempDirectory::new()?;
    let output = TempDirectory::new()?;
    fs::write(source.path().join("source"), b"oversized")?;
    let root = random_id();
    let (read_root, _read_consent) = ApprovedReadRoot::open(&root, source.path(), FILE_SIZE_BYTES)?;
    let mut sessions = Sessions::new(true).await?;
    let mut server = FileReadServer::start(&mut sessions.h, 9, FileRoots::new(vec![read_root])?)?;
    let queue = NativeDownloadQueue::new(NativeDownloadQueueLimits {
        active: 1,
        tasks: 1,
        reserved_bytes: 4,
    })?;
    let area = output.path().join("oversized");
    let (selected, _save_consent) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
    let built = Arc::new(AtomicBool::new(false));
    let task = queue.submit(
        FileReadClient::attach(&mut sessions.c, 9)?,
        NativeDownloadRequest::new(&root, "source")?,
        4,
        Factory {
            selected,
            gate: None,
            built: built.clone(),
        },
    )?;
    let failed = tokio::time::timeout(Duration::from_secs(2), task.wait_finished()).await?;
    assert_eq!(failed.phase, NativeDownloadTaskPhase::Failed);
    assert_eq!(failed.error, Some(NativeDownloadQueueError::ManifestBudget));
    assert!(
        failed
            .native
            .ok_or("missing rejected source")?
            .source_cancel_acknowledged
    );
    assert_eq!(failed.client_retirement, Some(Ok(())));
    assert!(!built.load(Ordering::Acquire) && !area.exists());
    assert_eq!(queue.status().reserved_bytes, 0);
    assert_eq!(queue.status().active, 0);
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn last_queue_owner_drop_cancels_all_tasks_without_releasing_a_pending_rpc_early() -> Result {
    let output = TempDirectory::new()?;
    let queue = NativeDownloadQueue::new(NativeDownloadQueueLimits {
        active: 1,
        tasks: 2,
        reserved_bytes: 4,
    })?;
    let clone = queue.clone();
    let queue_monitor = queue.monitor();
    let mut a = Sessions::new(false).await?;
    let (first, _a_consent) = submit(&queue, &mut a, &output, "owner-a", 4)?;
    let open = receive(&mut a.h).await?;
    let mut b = Sessions::new(false).await?;
    let (second, _b_consent) = submit(&queue, &mut b, &output, "owner-b", 4)?;
    drop(queue);
    assert!(!queue_monitor.status().closed);
    drop(clone);
    assert!(queue_monitor.status().closed);
    let stopped =
        tokio::time::timeout(Duration::from_secs(1), second.monitor().wait_finished()).await?;
    assert_eq!(stopped.phase, NativeDownloadTaskPhase::Cancelled);
    assert!(stopped.native.is_none());
    assert_eq!(queue_monitor.status().tasks, 1);
    assert_eq!(queue_monitor.status().reserved_bytes, 4);
    assert!(!output.path().join("owner-a").exists() && !output.path().join("owner-b").exists());
    manifest(&mut a.h, open, b"data").await?;
    cancelled(&mut a.h).await?;
    let stopped = tokio::time::timeout(Duration::from_secs(1), first.wait_finished()).await?;
    assert_eq!(stopped.phase, NativeDownloadTaskPhase::Cancelled);
    assert_eq!(stopped.client_retirement, Some(Ok(())));
    assert_eq!(queue_monitor.wait_idle().await.reserved_bytes, 0);
    assert!(queue_monitor.status().closed);
    a.c.lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    b.c.lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    Ok(())
}

#[test]
fn queue_limits_are_hard_and_checked() {
    for limits in [
        NativeDownloadQueueLimits {
            active: 0,
            ..Default::default()
        },
        NativeDownloadQueueLimits {
            active: NATIVE_DOWNLOAD_ACTIVE_MAX + 1,
            ..Default::default()
        },
        NativeDownloadQueueLimits {
            tasks: NATIVE_DOWNLOAD_TASKS_MAX + 1,
            ..Default::default()
        },
        NativeDownloadQueueLimits {
            active: 2,
            tasks: 1,
            ..Default::default()
        },
        NativeDownloadQueueLimits {
            reserved_bytes: 0,
            ..Default::default()
        },
        NativeDownloadQueueLimits {
            reserved_bytes: NATIVE_DOWNLOAD_RESERVED_MAX + 1,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            NativeDownloadQueue::new(limits),
            Err(NativeDownloadQueueError::InvalidLimits)
        ));
    }
}
