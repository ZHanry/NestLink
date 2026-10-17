use super::*;
use nestlink_platform_files::download::{LocalDownloadSelection, LocalDownloadStatus};
use nestlink_remote::files::{
    FileDestination, FileDestinationFactory, FileDownloadMonitor, FileDownloadPhase,
    FileDownloadSnapshot, FileDownloadWorker,
};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

async fn destination_finished(monitor: &FileDownloadMonitor) -> Result {
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

fn block(gate: &Gate) -> io::Result<()> {
    gate.entered.store(true, Ordering::Release);
    let guard = gate
        .released
        .lock()
        .map_err(|_| io::Error::other("test gate poisoned"))?;
    let (guard, timeout) = gate
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

struct ReleaseGate(Arc<Gate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[derive(Clone, Copy)]
enum AckAt {
    Ready,
    Write,
    Finish,
}

#[derive(Default)]
struct AckWitness {
    operation_returned: AtomicBool,
    status_reads: AtomicUsize,
    idle_after_reply: AtomicBool,
}

struct WitnessConsent {
    inner: Arc<dyn FileReadConsent>,
    witness: Arc<AckWitness>,
}
impl FileReadConsent for WitnessConsent {
    fn check(&self) -> io::Result<()> {
        self.inner.check()?;
        // For successful prepare/write, the owning thread reads status twice,
        // sends the exact oneshot reply, then checks consent in its idle loop.
        // This observer never performs I/O or changes authorization. The async
        // action is deliberately not polled during this interval.
        if std::thread::current().name() == Some("nestlink-file-download")
            && self.witness.operation_returned.load(Ordering::Acquire)
            && self.witness.status_reads.load(Ordering::Acquire) >= 2
        {
            self.witness.idle_after_reply.store(true, Ordering::Release);
        }
        Ok(())
    }
}

struct WitnessFactory {
    inner: LocalDownloadSelection,
    at: AckAt,
    gate: Arc<Gate>,
    witness: Arc<AckWitness>,
}
impl FileDestinationFactory for WitnessFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(WitnessConsent {
            inner: self.inner.consent(),
            witness: self.witness.clone(),
        })
    }
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        Ok(Box::new(WitnessDestination {
            inner: Box::new(self.inner).build(source)?,
            at: self.at,
            gate: self.gate,
            witness: self.witness,
        }))
    }
}
struct WitnessDestination {
    inner: Box<dyn FileDestination>,
    at: AckAt,
    gate: Arc<Gate>,
    witness: Arc<AckWitness>,
}
impl WitnessDestination {
    fn await_release(&self) -> io::Result<()> {
        // Ignore earlier setup status reads: only this operation's two reads
        // followed by the worker idle loop can witness its reply being sent.
        self.witness.status_reads.store(0, Ordering::Release);
        block(&self.gate)?;
        self.witness
            .operation_returned
            .store(true, Ordering::Release);
        Ok(())
    }
}
impl FileDestination for WitnessDestination {
    fn status(&self) -> LocalDownloadStatus {
        self.witness.status_reads.fetch_add(1, Ordering::AcqRel);
        self.inner.status()
    }
    fn prepare(&mut self, check: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.inner.prepare(check)?;
        if matches!(self.at, AckAt::Ready) {
            self.await_release()?;
        }
        Ok(())
    }
    fn write(
        &mut self,
        source: &FileDownloadSnapshot,
        chunk: &FileReadChunk,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.write(source, chunk, check)?;
        if matches!(self.at, AckAt::Write) {
            self.await_release()?;
        }
        Ok(())
    }
    fn resume(
        &mut self,
        source: &FileDownloadSnapshot,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.resume(source, check)
    }
    fn finish(
        &mut self,
        source: &FileDownloadSnapshot,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.finish(source, check)?;
        if matches!(self.at, AckAt::Finish) {
            self.await_release()?;
        }
        Ok(())
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.inner.cleanup()
    }
}

async fn delayed_ack(at: AckAt) -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    let bytes = b"on-time original bytes";
    fs::write(source.path().join("source"), bytes)?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
    let area = output.path().join("late-ack");
    let (inner, _consent) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
    let gate = Arc::new(Gate::default());
    let _release = ReleaseGate(gate.clone());
    let witness = Arc::new(AckWitness::default());
    let budget = Duration::from_secs(2);
    let mut worker = FileDownloadWorker::with_operation_budget(
        &client,
        &download,
        WitnessFactory {
            inner,
            at,
            gate: gate.clone(),
            witness: witness.clone(),
        },
        budget,
    )?;
    let monitor = worker.monitor();
    let started_after_construction = Instant::now();
    let mut chunk = None;
    if !matches!(at, AckAt::Ready) {
        worker.ready().await?;
        chunk = Some(client.next(&mut download).await?.ok_or("missing chunk")?);
        if matches!(at, AckAt::Finish) {
            worker
                .write(&download, chunk.take().ok_or("missing disk chunk")?)
                .await?;
            assert!(client.next(&mut download).await?.is_none());
        }
    }
    let submitted = if matches!(at, AckAt::Ready) {
        started_after_construction
    } else {
        Instant::now()
    };
    let mut action: Pin<Box<dyn Future<Output = io::Result<LocalDownloadStatus>> + '_>> = match at {
        AckAt::Ready => Box::pin(worker.ready()),
        AckAt::Write => Box::pin(worker.write(&download, chunk.ok_or("missing disk chunk")?)),
        AckAt::Finish => Box::pin(worker.finish(&download)),
    };
    assert!(matches!(
        action
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    gate.entered().await?;
    gate.release();
    tokio::time::timeout_at((submitted + budget).into(), async {
        loop {
            let sent = if matches!(at, AckAt::Finish) {
                // Completed destruction is published only after the reply send.
                monitor.status().finished
            } else {
                witness.idle_after_reply.load(Ordering::Acquire)
            };
            if sent {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;
    let before_late_consumption = monitor.status();
    assert!(before_late_consumption.error.is_none());
    assert_eq!(
        before_late_consumption.destination.confirmed_bytes,
        if matches!(at, AckAt::Ready) {
            0
        } else {
            bytes.len() as u64
        }
    );
    assert_eq!(
        before_late_consumption.destination.published,
        matches!(at, AckAt::Finish)
    );
    // Keep the action alive, without polling it: its original ACK was sent on
    // time, but this caller must not consume it successfully after its budget.
    tokio::time::sleep_until((submitted + budget + Duration::from_millis(100)).into()).await;
    let result = match action
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => return Err("expired reply consumption remained pending".into()),
    };
    assert_eq!(
        result
            .err()
            .ok_or("late reply consumption unexpectedly succeeded")?
            .kind(),
        io::ErrorKind::TimedOut
    );
    drop(action);
    let shutdown = worker.shutdown().await?;
    if shutdown == FileShutdown::TimedOut {
        // The 250 ms shutdown budget observes cleanup; it cannot guarantee OS
        // completion or executor scheduling under the full concurrent suite.
        // Keep that observed timeout even after actual handle removal finishes.
        assert!(monitor.status().cleanup_timed_out);
        destination_finished(&monitor).await?;
    }
    let after = monitor.status();
    assert!(after.finished && after.destination.file_closed && after.destination.temporary_removed);
    assert_eq!(after.cleanup_timed_out, shutdown == FileShutdown::TimedOut);
    assert_eq!(after.destination.published, matches!(at, AckAt::Finish));
    if matches!(at, AckAt::Finish) {
        assert_eq!(after.phase, FileDownloadPhase::Completed);
        assert_eq!(fs::read(area.join("done"))?, bytes);
    } else {
        assert!(!area.join("done").exists());
        client.cancel(&mut download).await?;
    }
    s.c.lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn on_time_initialization_ack_is_rejected_when_consumed_after_original_deadline() -> Result {
    delayed_ack(AckAt::Ready).await
}

#[tokio::test]
async fn on_time_write_ack_preserves_confirmed_bytes_but_cannot_outlive_its_deadline() -> Result {
    delayed_ack(AckAt::Write).await
}

#[tokio::test]
async fn on_time_publication_ack_preserves_saved_file_but_cannot_outlive_its_deadline() -> Result {
    delayed_ack(AckAt::Finish).await
}

#[derive(Clone, Copy)]
enum LaterStop {
    Revoked,
    ObserverClosed,
    Suspended,
}

#[tokio::test]
async fn network_paused_partial_is_cleaned_after_later_revoke_closed_observer_or_suspend() -> Result
{
    for later in [
        LaterStop::Revoked,
        LaterStop::ObserverClosed,
        LaterStop::Suspended,
    ] {
        let source = tempfile::tempdir()?;
        let output = tempfile::tempdir()?;
        fs::write(source.path().join("source"), b"paused actual bytes")?;
        let (id, provider, _keep) = roots(source.path())?;
        let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
        let area = output.path().join("paused");
        let (selection, _consent) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
        let mut worker = FileDownloadWorker::start(&client, &download, selection)?;
        let monitor = worker.monitor();
        worker.ready().await?;
        let chunk = client.next(&mut download).await?.ok_or("missing chunk")?;
        let confirmed = worker.write(&download, chunk).await?.confirmed_bytes;
        assert!(confirmed > 0);
        let lease = s.c.lease_control();
        lease.stop(StopReason::NetworkChanged)?;
        assert_eq!(worker.pause().await?.confirmed_bytes, confirmed);
        assert_eq!(monitor.status().phase, FileDownloadPhase::Paused);
        assert!(!monitor.status().finished);
        let [controller_stop, _host_stop] = s.stops;
        match later {
            LaterStop::Revoked => {
                controller_stop.send_replace(Some(StopReason::Revoked));
            }
            LaterStop::ObserverClosed => drop(controller_stop),
            LaterStop::Suspended => {
                controller_stop.send_replace(Some(StopReason::Suspended));
            }
        }
        destination_finished(&monitor).await?;
        let status = monitor.status();
        assert_eq!(status.phase, FileDownloadPhase::Stopped);
        assert_eq!(status.destination.confirmed_bytes, confirmed);
        assert!(status.destination.file_closed && status.destination.temporary_removed);
        assert!(!status.destination.published && !area.join("done").exists());
        assert_eq!(
            lease
                .subscribe_stopped()
                .borrow()
                .as_ref()
                .ok_or("missing original report")?
                .reason,
            StopReason::NetworkChanged,
            "later facts must not rewrite the original stop receipt"
        );
        assert_eq!(worker.shutdown().await?, FileShutdown::Finished);
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

// A separate short-lived, signed and mutually proven duplex fixture keeps this
// precise expiry test independent of the shared 15-second TLS/QUIC fixture. It
// exercises the actual channel and storage lifecycle, not transport acceptance.
struct ShortChannels {
    controller: ChannelRuntime,
    host: ChannelRuntime,
    _stops: [watch::Sender<Option<StopReason>>; 2],
}
fn short_lived_channels(lifetime: Duration) -> Result<ShortChannels> {
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let signer = PermitSigner::generate();
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let binding = SessionBinding {
        deployment_id: random_id(),
        security_epoch: 1,
        session_id: random_id(),
        account_id: random_id(),
        controller_device_id: random_id(),
        host_device_id: random_id(),
        controller_key_sha256: controller.fingerprint(),
        host_key_sha256: host.fingerprint(),
        resource_id: random_id(),
        policy_revision: 1,
        connection_generation: 9,
        capability_sha256: [7; 32],
        granted_permissions: vec![Permission::View, Permission::FileRead],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::DIRECT,
    };
    let claims = PermitClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: binding.deployment_id.clone(),
        security_epoch: binding.security_epoch,
        session_id: binding.session_id.clone(),
        account_id: binding.account_id.clone(),
        controller_device_id: binding.controller_device_id.clone(),
        host_device_id: binding.host_device_id.clone(),
        controller_key_sha256: controller.fingerprint().to_vec(),
        host_key_sha256: host.fingerprint().to_vec(),
        resource_id: binding.resource_id.clone(),
        permissions: vec![Permission::View as i32, Permission::FileRead as i32],
        paths: vec![Path::Direct as i32],
        policy_revision: binding.policy_revision,
        connection_generation: binding.connection_generation,
        lease_sequence: 1,
        issued_at_unix_ms: now.unix_ms,
        expires_at_unix_ms: now.unix_ms + u64::try_from(lifetime.as_millis())?,
        capability_sha256: binding.capability_sha256.to_vec(),
        required_capabilities: vec!["vp8".into()],
    };
    let permit = verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?;
    let active = || -> Result<Session> {
        let mut session = Session::activate(
            permit.clone(),
            binding.clone(),
            Path::Direct,
            now.monotonic_ms,
            now,
        )?;
        let transcript = session.proof_transcript();
        for (role, identity) in [
            (EndpointRole::Controller, &controller),
            (EndpointRole::Host, &host),
        ] {
            session.confirm_endpoint(
                role,
                &identity.public_key(),
                &identity.prove(&transcript)?,
                clock.monotonic_ms(),
            )?;
        }
        Ok(session)
    };
    let (controller_io, host_io) = tokio::io::duplex(65536);
    let (controller_read, controller_write) = tokio::io::split(controller_io);
    let (host_read, host_write) = tokio::io::split(host_io);
    let (controller_stop, controller_facts) = watch::channel(None);
    let (host_stop, host_facts) = watch::channel(None);
    let controller_runtime = AuthorizedConnection::new(
        controller_read,
        controller_write,
        active()?,
        Path::Direct,
        clock.clone(),
        controller_facts,
    )?
    .into_channels();
    let host_runtime = AuthorizedConnection::new(
        host_read,
        host_write,
        active()?,
        Path::Direct,
        clock,
        host_facts,
    )?
    .into_channels();
    Ok(ShortChannels {
        controller: controller_runtime,
        host: host_runtime,
        _stops: [controller_stop, host_stop],
    })
}

#[tokio::test]
async fn network_paused_partial_is_cleaned_when_the_original_signed_lease_expires() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), b"expired actual prefix")?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut channels = short_lived_channels(Duration::from_secs(2))?;
    let mut server = FileReadServer::start(&mut channels.host, 9, provider)?;
    let mut client = FileReadClient::attach(&mut channels.controller, 9)?;
    let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
    let area = output.path().join("expired");
    let (selection, _consent) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
    let mut worker = FileDownloadWorker::start(&client, &download, selection)?;
    let monitor = worker.monitor();
    worker.ready().await?;
    let chunk = client.next(&mut download).await?.ok_or("missing chunk")?;
    let confirmed = worker.write(&download, chunk).await?.confirmed_bytes;
    let lease = channels.controller.lease_control();
    lease.stop(StopReason::NetworkChanged)?;
    assert_eq!(worker.pause().await?.confirmed_bytes, confirmed);
    let deadline = lease.reconnection_budget()?.deadline();
    assert!(Instant::now() < deadline && !monitor.status().finished);
    tokio::time::sleep_until(deadline.into()).await;
    destination_finished(&monitor).await?;
    assert!(lease.reconnection_budget().is_err());
    let status = monitor.status();
    assert_eq!(status.phase, FileDownloadPhase::Stopped);
    assert_eq!(status.destination.confirmed_bytes, confirmed);
    assert!(
        confirmed > 0 && status.destination.file_closed && status.destination.temporary_removed
    );
    assert!(!status.destination.published && !area.join("done").exists());
    assert_eq!(
        lease
            .subscribe_stopped()
            .borrow()
            .as_ref()
            .ok_or("missing original report")?
            .reason,
        StopReason::NetworkChanged
    );
    assert_eq!(worker.shutdown().await?, FileShutdown::Finished);
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

struct FatalFactory {
    inner: LocalDownloadSelection,
    gate: Arc<Gate>,
    error: io::ErrorKind,
}
impl FileDestinationFactory for FatalFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.inner.consent()
    }
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        Ok(Box::new(FatalDestination {
            inner: Box::new(self.inner).build(source)?,
            gate: self.gate,
            error: self.error,
        }))
    }
}
struct FatalDestination {
    inner: Box<dyn FileDestination>,
    gate: Arc<Gate>,
    error: io::ErrorKind,
}
impl FileDestination for FatalDestination {
    fn status(&self) -> LocalDownloadStatus {
        self.inner.status()
    }
    fn prepare(&mut self, check: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.inner.prepare(check)
    }
    fn write(
        &mut self,
        _: &FileDownloadSnapshot,
        _: &FileReadChunk,
        _: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        block(&self.gate)?;
        // A real filesystem error must remain fatal even if async cancellation
        // requested a pause while this already-issued disk call was blocked.
        Err(io::Error::new(
            self.error,
            "injected late fatal disk result",
        ))
    }
    fn resume(
        &mut self,
        source: &FileDownloadSnapshot,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.resume(source, check)
    }
    fn finish(
        &mut self,
        source: &FileDownloadSnapshot,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.finish(source, check)
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.inner.cleanup()
    }
}

#[tokio::test]
async fn paused_wait_cannot_turn_late_provider_disk_errors_into_a_resumable_partial() -> Result {
    for error in [
        io::ErrorKind::StorageFull,
        io::ErrorKind::Other,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::Interrupted,
    ] {
        let source = tempfile::tempdir()?;
        let output = tempfile::tempdir()?;
        fs::write(source.path().join("source"), b"fatal disk operation")?;
        let (id, provider, _keep) = roots(source.path())?;
        let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
        let area = output.path().join("fatal");
        let (inner, _consent) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
        let gate = Arc::new(Gate::default());
        let _release = ReleaseGate(gate.clone());
        let mut worker = FileDownloadWorker::start(
            &client,
            &download,
            FatalFactory {
                inner,
                gate: gate.clone(),
                error,
            },
        )?;
        let monitor = worker.monitor();
        worker.ready().await?;
        let chunk = client.next(&mut download).await?.ok_or("missing chunk")?;
        let mut write = Box::pin(worker.write(&download, chunk));
        assert!(matches!(
            write.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
        gate.entered().await?;
        drop(write);
        gate.release();
        if let Err(wait_error) = destination_finished(&monitor).await {
            return Err(format!(
                "late provider error {error:?} did not stop and clean the worker: {wait_error}; actual status={:?}",
                monitor.status()
            ).into());
        }
        let status = monitor.status();
        assert_eq!(status.phase, FileDownloadPhase::Stopped);
        assert_eq!(status.error, Some(error));
        assert!(status.destination.file_closed && status.destination.temporary_removed);
        assert!(!status.destination.published && !area.join("done").exists());
        assert!(
            worker.pause().await.is_err(),
            "terminal disk failure cannot acknowledge a resumable pause"
        );
        assert_eq!(worker.shutdown().await?, FileShutdown::Finished);
        s.c.lease_control()
            .check_channel_binding(Channel::Video, 9)?;
        client.cancel(&mut download).await?;
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}
