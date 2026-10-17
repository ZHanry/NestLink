use super::*;
use nestlink_platform_files::download::{LocalDownloadSelection, LocalDownloadStatus};
use nestlink_remote::files::{
    FileDestination, FileDestinationFactory, FileDownloadMonitor, FileDownloadPhase,
    FileDownloadSnapshot, FileDownloadView, FileDownloadWorker,
};

async fn finished(monitor: &FileDownloadMonitor) -> Result {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut state = monitor.subscribe();
        while !state.borrow_and_update().finished {
            state.changed().await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn owned_tls_and_quic_workers_verify_and_publish_without_stopping_view_permission() -> Result
{
    for quic in [false, true] {
        let source = tempfile::tempdir()?;
        let output = tempfile::tempdir()?;
        let bytes: Vec<_> = (0..180 * 1024 + 73).map(|i| (i % 251) as u8).collect();
        fs::write(source.path().join("source"), &bytes)?;
        fs::write(source.path().join("empty"), b"")?;
        let (id, provider, _keep) = roots(source.path())?;
        let mut s = Sessions::new(quic, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        for (name, expected) in [("source", bytes.as_slice()), ("empty", &[])] {
            let mut download = client.open(&random_id(), &id, name, 0, None).await?;
            let area = output.path().join(name);
            let (selection, _consent) =
                LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
            assert!(
                !area.exists(),
                "local selection itself must not perform disk I/O"
            );
            let mut worker = FileDownloadWorker::start(&client, &download, selection)?;
            let monitor = worker.monitor();
            worker.ready().await?;
            assert!(
                worker.ready().await.is_err(),
                "initial reply cannot be consumed twice"
            );
            let mut earlier_view = download.snapshot();
            while let Some(chunk) = client.next(&mut download).await? {
                earlier_view = download.snapshot();
                let offset = download.offset();
                assert_eq!(
                    worker.write(&download, chunk).await?.confirmed_bytes,
                    offset
                );
                assert!(!area.join("done").exists());
            }
            assert!(
                !earlier_view.source_verified(),
                "an old chunk view cannot later become a verified End"
            );
            let saved = worker.finish(&download).await?;
            assert!(
                saved.published && saved.file_closed && saved.temporary_removed && !saved.poisoned
            );
            assert_eq!(worker.shutdown().await?, FileShutdown::Finished);
            assert_eq!(monitor.status().phase, FileDownloadPhase::Completed);
            assert!(monitor.status().finished && monitor.status().error.is_none());
            s.c.lease_control()
                .check_channel_binding(Channel::Video, 9)?;
            assert_eq!(fs::read(area.join("done"))?, expected);
        }
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[tokio::test]
async fn source_cancel_invalidates_queued_views_before_the_remote_cancel_ack() -> Result {
    let output = tempfile::tempdir()?;
    let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let transfer = random_id();
    let root = random_id();
    let open_peer = async {
        let request = s.h.receive().await?;
        let mut reply = NativeFileRead::decode_validated(&request.payload)?;
        reply.action = Some(Action::Manifest(FileReadManifest {
            size: 4,
            sha256: digest(b"data").to_vec(),
            offset: 0,
        }));
        s.h.send(Channel::FileRead, &reply.encode_validated()?)
            .await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (download, peer) =
        tokio::join!(client.open(&transfer, &root, "source", 0, None), open_peer);
    peer?;
    let mut download = download?;
    let (selection, _consent) =
        LocalDownloadSelection::new(&output.path().join("cancelled"), "done", 4)?;
    let mut worker = FileDownloadWorker::start(&client, &download, selection)?;
    worker.ready().await?;
    let cached = download.snapshot();
    let mut cancel = Box::pin(client.cancel(&mut download));
    let received = tokio::select! {
        result = &mut cancel => return Err(format!("cancel completed without a source reply: {result:?}").into()),
        request = s.h.receive() => request?,
    };
    assert!(cached.finished() && !cached.source_verified());
    let partial = worker.pause().await?;
    assert_eq!(partial.confirmed_bytes, 0);
    assert_eq!(worker.shutdown().await?, FileShutdown::Finished);
    let mut reply = NativeFileRead::decode_validated(&received.payload)?;
    assert_eq!(reply.action, Some(Action::Cancel(true)));
    reply.action = Some(Action::Cancelled(true));
    s.h.send(Channel::FileRead, &reply.encode_validated()?)
        .await?;
    cancel.await?;
    s.c.lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    assert!(!output.path().join("cancelled/done").exists());
    Ok(())
}

#[tokio::test]
async fn paused_worker_rebinds_only_the_actual_prefix_of_the_same_proven_scope() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    let bytes: Vec<_> = (0..190 * 1024).map(|i| (i % 239) as u8).collect();
    fs::write(source.path().join("source"), &bytes)?;
    fs::write(source.path().join("other"), &bytes)?;
    let (id, provider, _keep) = roots(source.path())?;
    let permissions = vec![Permission::View, Permission::FileRead];
    let mut s = Sessions::new(true, permissions.clone()).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut first = client.open(&random_id(), &id, "source", 0, None).await?;
    let hash: [u8; 32] = first.manifest().sha256.as_slice().try_into()?;
    let area = output.path().join("resumed");
    let (selection, _consent) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
    let mut worker = FileDownloadWorker::start(&client, &first, selection)?;
    worker.ready().await?;
    let chunk = client.next(&mut first).await?.ok_or("missing chunk")?;
    let offset = worker.write(&first, chunk).await?.confirmed_bytes;
    assert_eq!(worker.pause().await?.confirmed_bytes, offset);
    client.cancel(&mut first).await?;
    let mut wrong_path = client
        .open(&random_id(), &id, "other", offset, Some(hash))
        .await?;
    assert!(
        worker.resume(&client, &wrong_path).await.is_err(),
        "matching content cannot change source scope"
    );
    client.cancel(&mut wrong_path).await?;
    let mut second = client
        .open(&random_id(), &id, "source", offset, Some(hash))
        .await?;
    worker.resume(&client, &second).await?;
    let chunk = client
        .next(&mut second)
        .await?
        .ok_or("missing resumed chunk")?;
    let offset = worker.write(&second, chunk).await?.confirmed_bytes;
    // A fresh, mutually proven successor connection to the same signed resource.
    // This fixture is not evidence of production reconnection consent/UI gates.
    s.c.lease_control().stop(StopReason::NetworkChanged)?;
    worker.pause().await?;
    server.shutdown(StopReason::NetworkChanged).await?;
    let (root, _new_keep) = ApprovedReadRoot::open(&id, source.path(), FILE_SIZE_BYTES)?;
    let mut next = Sessions::with_scope(false, permissions.clone(), Some(&s.scope), 10).await?;
    let mut next_server = FileReadServer::start(&mut next.h, 10, FileRoots::new(vec![root])?)?;
    let mut next_client = FileReadClient::attach(&mut next.c, 10)?;
    let mut successor = next_client
        .open(&random_id(), &id, "source", offset, Some(hash))
        .await?;
    worker.resume(&next_client, &successor).await?;
    assert!(
        worker
            .write(
                &second,
                FileReadChunk {
                    offset,
                    data: vec![0],
                    sha256: digest(&[0]).to_vec()
                }
            )
            .await
            .is_err()
    );
    while let Some(chunk) = next_client.next(&mut successor).await? {
        worker.write(&successor, chunk).await?;
    }
    worker.finish(&successor).await?;
    assert_eq!(worker.shutdown().await?, FileShutdown::Finished);
    assert_eq!(fs::read(area.join("done"))?, bytes);
    next_server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn another_proven_resource_and_idle_local_or_session_revocation_cannot_save() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), b"same content")?;
    for revoke_session in [false, true] {
        let (id, provider, _keep) = roots(source.path())?;
        let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        let mut first = client.open(&random_id(), &id, "source", 0, None).await?;
        let area = output.path().join(random_id());
        let (selection, consent) = LocalDownloadSelection::new(&area, "done", 30)?;
        let mut worker = FileDownloadWorker::start(&client, &first, selection)?;
        let monitor = worker.monitor();
        worker.ready().await?;
        worker.pause().await?;
        let (root, _other_keep) = ApprovedReadRoot::open(&id, source.path(), FILE_SIZE_BYTES)?;
        let mut other = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
        let mut other_server = FileReadServer::start(&mut other.h, 9, FileRoots::new(vec![root])?)?;
        let mut other_client = FileReadClient::attach(&mut other.c, 9)?;
        let mut same_bytes = other_client
            .open(&random_id(), &id, "source", 0, None)
            .await?;
        assert!(worker.resume(&other_client, &same_bytes).await.is_err());
        other_client.cancel(&mut same_bytes).await?;
        other_server.shutdown(StopReason::ExplicitExit).await?;
        if revoke_session {
            s.c.lease_control().stop(StopReason::Revoked)?;
        } else {
            consent.revoke();
        }
        finished(&monitor).await?;
        let status = monitor.status();
        assert_eq!(status.phase, FileDownloadPhase::Stopped);
        assert!(status.destination.file_closed && status.destination.temporary_removed);
        assert!(!status.destination.published);
        assert!(!area.join("done").exists());
        assert_eq!(worker.shutdown().await?, FileShutdown::Finished);
        if !revoke_session {
            s.c.lease_control()
                .check_channel_binding(Channel::Video, 9)?;
            client.cancel(&mut first).await?;
        }
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum BlockAt {
    Prepare,
    Write,
    Resume,
    Finish,
    Cleanup,
}
struct DelayedFactory {
    inner: LocalDownloadSelection,
    gate: Arc<Gate>,
    at: BlockAt,
    disk_full: bool,
    fail_cleanup: bool,
}
impl FileDestinationFactory for DelayedFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.inner.consent()
    }
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        Ok(Box::new(DelayedDestination {
            inner: Box::new(self.inner).build(source)?,
            gate: self.gate,
            at: self.at,
            disk_full: self.disk_full,
            fail_cleanup: self.fail_cleanup,
        }))
    }
}
struct DelayedDestination {
    inner: Box<dyn FileDestination>,
    gate: Arc<Gate>,
    at: BlockAt,
    disk_full: bool,
    fail_cleanup: bool,
}
impl DelayedDestination {
    fn block(&self) -> io::Result<()> {
        self.gate.entered.store(true, Ordering::Release);
        let guard = self
            .gate
            .released
            .lock()
            .map_err(|_| io::Error::other("test gate poisoned"))?;
        let (guard, timeout) = self
            .gate
            .changed
            .wait_timeout_while(guard, Duration::from_secs(4), |released| !*released)
            .map_err(|_| io::Error::other("test gate poisoned"))?;
        if timeout.timed_out() && !*guard {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "test gate was not released",
            ));
        }
        Ok(())
    }
}
impl Drop for DelayedDestination {
    fn drop(&mut self) {
        self.gate.dropped.fetch_add(1, Ordering::AcqRel);
    }
}
impl FileDestination for DelayedDestination {
    fn status(&self) -> LocalDownloadStatus {
        self.inner.status()
    }
    fn prepare(&mut self, check: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.inner.prepare(check)?;
        if matches!(self.at, BlockAt::Prepare) {
            self.block()?;
        }
        check()
    }
    fn write(
        &mut self,
        source: &FileDownloadSnapshot,
        chunk: &FileReadChunk,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.disk_full {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "injected disk full",
            ));
        }
        self.inner.write(source, chunk, check)?;
        if matches!(self.at, BlockAt::Write) {
            self.block()?;
        }
        check()
    }
    fn resume(
        &mut self,
        source: &FileDownloadSnapshot,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.resume(source, check)?;
        if matches!(self.at, BlockAt::Resume) {
            self.block()?;
        }
        check()
    }
    fn finish(
        &mut self,
        source: &FileDownloadSnapshot,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.finish(source, check)?;
        if matches!(self.at, BlockAt::Finish) {
            self.block()?;
        }
        check()
    }
    fn cleanup(&mut self) -> io::Result<()> {
        if matches!(self.at, BlockAt::Cleanup) {
            self.block()?;
        }
        self.inner.cleanup()?;
        if self.fail_cleanup {
            return Err(io::Error::other("injected cleanup failure"));
        }
        Ok(())
    }
}
fn delayed(
    area: &FsPath,
    gate: &Arc<Gate>,
    at: BlockAt,
) -> Result<(
    DelayedFactory,
    nestlink_platform_files::download::LocalDownloadConsent,
)> {
    let (inner, consent) = LocalDownloadSelection::new(area, "done", FILE_SIZE_BYTES)?;
    Ok((
        DelayedFactory {
            inner,
            gate: gate.clone(),
            at,
            disk_full: false,
            fail_cleanup: false,
        },
        consent,
    ))
}

#[tokio::test]
async fn cancelled_disk_wait_has_no_late_ack_and_resume_wait_cannot_unpause_itself() -> Result {
    for at in [BlockAt::Write, BlockAt::Resume] {
        let source = tempfile::tempdir()?;
        let output = tempfile::tempdir()?;
        fs::write(source.path().join("source"), vec![7; 100 * 1024])?;
        let (id, provider, _keep) = roots(source.path())?;
        let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
        let hash: [u8; 32] = download.manifest().sha256.as_slice().try_into()?;
        let gate = Arc::new(Gate::default());
        let area = output.path().join("paused");
        let (factory, _consent) = delayed(&area, &gate, at)?;
        let mut worker = FileDownloadWorker::start(&client, &download, factory)?;
        let monitor = worker.monitor();
        worker.ready().await?;
        if matches!(at, BlockAt::Write) {
            let chunk = client.next(&mut download).await?.ok_or("missing chunk")?;
            let mut write = Box::pin(worker.write(&download, chunk));
            tokio::select! {
                result = &mut write => return Err(format!("blocked write completed early: {result:?}").into()),
                result = gate.entered() => result?,
            }
            drop(write);
        } else {
            worker.pause().await?;
            let mut resume = Box::pin(worker.resume(&client, &download));
            tokio::select! {
                result = &mut resume => return Err(format!("blocked resume completed early: {result:?}").into()),
                result = gate.entered() => result?,
            }
            drop(resume);
        }
        let mut second = client
            .open(&random_id(), &id, "source", 0, Some(hash))
            .await?;
        assert!(
            worker.resume(&client, &second).await.is_err(),
            "unacknowledged wait cannot be replaced"
        );
        gate.release();
        let partial = worker.pause().await?;
        assert_eq!(monitor.status().phase, FileDownloadPhase::Paused);
        client.cancel(&mut second).await?;
        second = client
            .open(
                &random_id(),
                &id,
                "source",
                partial.confirmed_bytes,
                Some(hash),
            )
            .await?;
        worker.resume(&client, &second).await?;
        while let Some(chunk) = client.next(&mut second).await? {
            worker.write(&second, chunk).await?;
        }
        worker.finish(&second).await?;
        worker.shutdown().await?;
        assert_eq!(fs::read(area.join("done"))?, vec![7; 100 * 1024]);
        assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
        client.cancel(&mut download).await?;
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[tokio::test]
async fn blocked_initialization_write_publication_and_cleanup_report_actual_late_effects() -> Result
{
    for at in [
        BlockAt::Prepare,
        BlockAt::Write,
        BlockAt::Finish,
        BlockAt::Cleanup,
    ] {
        let source = tempfile::tempdir()?;
        let output = tempfile::tempdir()?;
        fs::write(source.path().join("source"), b"exact original")?;
        let (id, provider, _keep) = roots(source.path())?;
        let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
        let gate = Arc::new(Gate::default());
        let area = output.path().join("late");
        let (factory, consent) = delayed(&area, &gate, at)?;
        let mut worker = FileDownloadWorker::start(&client, &download, factory)?;
        let monitor = worker.monitor();
        if matches!(at, BlockAt::Prepare) {
            let mut ready = Box::pin(worker.ready());
            tokio::select! { result = &mut ready => return Err(format!("initialization completed early: {result:?}").into()), result = gate.entered() => result? }
            consent.revoke();
            assert_eq!(
                tokio::time::timeout(Duration::from_millis(300), ready)
                    .await?
                    .err()
                    .ok_or("revoked initialization unexpectedly succeeded")?
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        } else {
            worker.ready().await?;
            let chunk = client.next(&mut download).await?.ok_or("missing chunk")?;
            if matches!(at, BlockAt::Write) {
                let mut write = Box::pin(worker.write(&download, chunk));
                tokio::select! { result = &mut write => return Err(format!("write completed early: {result:?}").into()), result = gate.entered() => result? }
                consent.revoke();
                assert_eq!(
                    tokio::time::timeout(Duration::from_millis(300), write)
                        .await?
                        .err()
                        .ok_or("revoked write unexpectedly succeeded")?
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
            } else {
                worker.write(&download, chunk).await?;
                if matches!(at, BlockAt::Finish) {
                    assert!(client.next(&mut download).await?.is_none());
                    let mut finish = Box::pin(worker.finish(&download));
                    tokio::select! { result = &mut finish => return Err(format!("finish completed early: {result:?}").into()), result = gate.entered() => result? }
                    consent.revoke();
                    assert_eq!(
                        tokio::time::timeout(Duration::from_millis(300), finish)
                            .await?
                            .err()
                            .ok_or("revoked publication unexpectedly succeeded")?
                            .kind(),
                        io::ErrorKind::PermissionDenied
                    );
                }
            }
        }
        let start = Instant::now();
        assert_eq!(worker.shutdown().await?, FileShutdown::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));
        gate.entered().await?;
        assert!(monitor.status().cleanup_timed_out && !monitor.status().finished);
        assert_eq!(gate.dropped.load(Ordering::Acquire), 0);
        gate.release();
        finished(&monitor).await?;
        let status = monitor.status();
        assert!(status.finished && status.cleanup_timed_out);
        assert!(status.destination.file_closed && status.destination.temporary_removed);
        assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
        if matches!(at, BlockAt::Finish) {
            assert!(status.destination.published);
            assert_eq!(fs::read(area.join("done"))?, b"exact original");
        } else {
            assert!(!status.destination.published && !area.join("done").exists());
        }
        assert_eq!(worker.shutdown().await?, FileShutdown::Finished);
        s.c.lease_control()
            .check_channel_binding(Channel::Video, 9)?;
        if !download.finished() {
            client.cancel(&mut download).await?;
        }
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[tokio::test]
async fn disk_full_and_cleanup_error_are_preserved_without_ending_the_viewing_session() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), b"incoming file")?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
    let area = output.path().join("full");
    let (mut factory, _consent) = delayed(&area, &Arc::new(Gate::default()), BlockAt::Write)?;
    factory.disk_full = true;
    factory.fail_cleanup = true;
    let mut worker = FileDownloadWorker::start(&client, &download, factory)?;
    let monitor = worker.monitor();
    worker.ready().await?;
    let chunk = client.next(&mut download).await?.ok_or("missing chunk")?;
    assert_eq!(
        worker
            .write(&download, chunk)
            .await
            .err()
            .ok_or("disk-full operation unexpectedly succeeded")?
            .kind(),
        io::ErrorKind::StorageFull
    );
    finished(&monitor).await?;
    let status = monitor.status();
    assert_eq!(status.error, Some(io::ErrorKind::StorageFull));
    assert_eq!(status.cleanup_error, Some(io::ErrorKind::Other));
    assert!(status.destination.file_closed && status.destination.temporary_removed);
    assert!(!area.join("done").exists());
    worker.shutdown().await?;
    s.c.lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    client.cancel(&mut download).await?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
