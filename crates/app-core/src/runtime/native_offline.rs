//! Independent product owner for online-consumed finite offline remote control.
//! The existing data routes retain their original delivery checks and platform
//! cleanup. No management actor, renewable online permit or relay is created.
use super::*;
use nestlink_protocol::offline::OfflineRemoteOperation;
use nestlink_sdk::offline_remote::{
    OfflineRemoteBinding, OfflineRemoteListener, OfflineRemoteOwner, OfflineRemoteRuntime,
    OfflineRemoteTlsListener,
};
use nestlink_session::EndpointRole;

use crate::{NativeOfflineBudget, NativeOfflineStop, NativeOfflineTransport, NativeOfflineView};

#[derive(Debug, thiserror::Error)]
pub enum NativeOfflineError {
    #[error("invalid offline product limits")]
    Limits,
    #[error("the original offline owner already has a listener or live session")]
    Active,
    #[error(transparent)]
    Sdk(#[from] nestlink_sdk::SdkError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

struct Owner {
    sdk: OfflineRemoteOwner,
    limits: Limits,
    active: Arc<Semaphore>,
    stop: watch::Sender<Option<StopReason>>,
    next_generation: AtomicU64,
}

/// Retain this original owner in the same resident that consumed the bundle.
/// A transport failure can spend another signed attempt; explicit stop ends
/// this authority permanently. There is only one active local data lifecycle.
#[derive(Clone)]
pub struct NativeOfflineRemote(Arc<Owner>);

struct Pending {
    remote: NativeOfflineRemote,
    armed: bool,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if self.armed {
            self.remote.stop();
        }
    }
}

enum Listener {
    Quic(OfflineRemoteListener),
    Tls(OfflineRemoteTlsListener),
}

pub struct NativeOfflineListener {
    listener: Listener,
    transport: NativeOfflineTransport,
    pending: Pending,
    permit: OwnedSemaphorePermit,
}

/// The public data handle supports the existing video/display, input, audio,
/// clipboard and file APIs, including their local platform consent. Its
/// Snapshot remains disconnected from management; only the exact local stop
/// action is accepted, and it completes after the actual cleanup receipt.
/// Drop requests stop while the retained worker joins the original resources.
pub struct NativeOfflineSession {
    remote: NativeOfflineRemote,
    data: CoreHandle,
    view: watch::Receiver<Arc<NativeOfflineView>>,
    finished: watch::Receiver<Option<NativeOfflineStop>>,
    task: Option<JoinHandle<()>>,
    carrier: LeaseControl,
}

impl NativeOfflineRemote {
    pub fn new(owner: OfflineRemoteOwner, limits: Limits) -> Result<Self, NativeOfflineError> {
        if !limits.valid() {
            return Err(NativeOfflineError::Limits);
        }
        owner.binding()?;
        let (stop, _) = watch::channel(None);
        Ok(Self(Arc::new(Owner {
            sdk: owner,
            limits,
            active: Arc::new(Semaphore::new(1)),
            stop,
            next_generation: AtomicU64::new(1),
        })))
    }
    pub fn binding(&self) -> Result<OfflineRemoteBinding, NativeOfflineError> {
        Ok(self.0.sdk.binding()?)
    }
    pub fn budget(&self) -> Result<NativeOfflineBudget, NativeOfflineError> {
        let value = self.0.sdk.status()?;
        Ok(NativeOfflineBudget {
            remaining_bytes: value.remaining_bytes,
            remaining_file_write_bytes: value.remaining_file_write_bytes,
            connection_attempts: value.connection_attempts,
            remaining_lifetime_ms: value
                .remaining_lifetime
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            stopped: value.stopped,
        })
    }
    // A direct read, including authenticated IPC Snapshot, must observe the
    // original cumulative meter after a completed delivery. The periodic watch
    // is only a notification cadence and cannot be the accounting read source.
    pub(super) fn refresh_budget(&self, view: &mut NativeOfflineView) {
        match self.budget() {
            Ok(budget) => view.budget = budget,
            Err(_) => {
                view.budget.remaining_bytes = 0;
                view.budget.remaining_file_write_bytes = 0;
                view.budget.remaining_lifetime_ms = 0;
                view.budget.stopped = true;
            }
        }
    }
    pub fn stop(&self) {
        self.0.sdk.stop();
        self.0.stop.send_replace(Some(StopReason::ExplicitExit));
    }
    /// Stops original offline deliveries before reading the latest management
    /// state. Continuing online requires the ordinary fresh online path.
    pub async fn synchronize_online(
        &self,
    ) -> Result<nestlink_protocol::offline::management::OfflineBundleView, NativeOfflineError> {
        self.stop();
        Ok(self.0.sdk.synchronize_online().await?)
    }
    fn pending(&self) -> Result<(Pending, OwnedSemaphorePermit), NativeOfflineError> {
        let permit = self
            .0
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| NativeOfflineError::Active)?;
        Ok((
            Pending {
                remote: self.clone(),
                armed: true,
            },
            permit,
        ))
    }
    pub async fn listen(
        &self,
        transport: NativeOfflineTransport,
        address: std::net::SocketAddr,
    ) -> Result<NativeOfflineListener, NativeOfflineError> {
        let (mut pending, permit) = self.pending()?;
        let listener = match transport {
            NativeOfflineTransport::Quic => self.0.sdk.listen(address).map(Listener::Quic),
            NativeOfflineTransport::Tls => self.0.sdk.listen_tls(address).await.map(Listener::Tls),
        };
        let listener = match listener {
            Ok(listener) => listener,
            Err(error) => {
                pending.armed = false;
                return Err(error.into());
            }
        };
        Ok(NativeOfflineListener {
            listener,
            transport,
            pending,
            permit,
        })
    }
    pub async fn connect(
        &self,
        transport: NativeOfflineTransport,
        peer: std::net::SocketAddr,
    ) -> Result<NativeOfflineSession, NativeOfflineError> {
        let (mut pending, permit) = self.pending()?;
        let lifecycle = nestlink_remote::SessionLifecycle::new(self.0.stop.subscribe());
        let runtime = match transport {
            NativeOfflineTransport::Quic => self.0.sdk.connect(peer, lifecycle).await,
            NativeOfflineTransport::Tls => self.0.sdk.connect_tls(peer, lifecycle).await,
        };
        let runtime = match runtime {
            Ok(runtime) => runtime,
            Err(error) => {
                // Returned setup failures have released their original carrier.
                // Cancellation still drops an armed guard and ends authority.
                pending.armed = false;
                return Err(error.into());
            }
        };
        let session =
            NativeOfflineSession::attach(self.clone(), runtime, transport, permit).await?;
        pending.armed = false;
        Ok(session)
    }
}

impl NativeOfflineListener {
    pub fn address(&self) -> Result<std::net::SocketAddr, NativeOfflineError> {
        Ok(match &self.listener {
            Listener::Quic(listener) => listener.address()?,
            Listener::Tls(listener) => listener.address()?,
        })
    }
    pub async fn accept(self) -> Result<NativeOfflineSession, NativeOfflineError> {
        let Self {
            listener,
            transport,
            mut pending,
            permit,
        } = self;
        let lifecycle = nestlink_remote::SessionLifecycle::new(pending.remote.0.stop.subscribe());
        let runtime = match listener {
            Listener::Quic(listener) => listener.accept(lifecycle).await,
            Listener::Tls(listener) => listener.accept(lifecycle).await,
        };
        let runtime = match runtime {
            Ok(runtime) => runtime,
            Err(error) => {
                pending.armed = false;
                return Err(error.into());
            }
        };
        let session =
            NativeOfflineSession::attach(pending.remote.clone(), runtime, transport, permit)
                .await?;
        pending.armed = false;
        Ok(session)
    }
}

fn key(scope: &OfflineRemoteBinding) -> NativeSessionKey {
    let is_host = scope.role == EndpointRole::Host;
    let has = |operation| scope.operations.contains(&operation);
    NativeSessionKey {
        request_id: scope.session_id.clone(),
        connection_generation: scope.connection_generation,
        lease_sequence: scope.lease_sequence,
        is_host,
        host_view_authorized: is_host && has(OfflineRemoteOperation::View),
        controller_view_authorized: !is_host && has(OfflineRemoteOperation::View),
        input_authorized: has(OfflineRemoteOperation::Input),
        audio_authorized: has(OfflineRemoteOperation::Audio),
        file_read_authorized: has(OfflineRemoteOperation::FileRead),
        file_write_authorized: has(OfflineRemoteOperation::FileWrite),
        clipboard_read_authorized: has(OfflineRemoteOperation::ClipboardRead),
        clipboard_write_authorized: has(OfflineRemoteOperation::ClipboardWrite),
        path: nestlink_protocol::Path::Direct as i32,
    }
}

#[derive(Default)]
struct Routes {
    video: Option<VideoReceiver>,
    feedback: Option<JoinHandle<io::Result<()>>>,
    audio: Option<Arc<NativeAudioRoute>>,
    clipboard: Option<Arc<NativeClipboardRoute>>,
    files: Option<Arc<NativeFilesRoute>>,
    input: Option<Arc<NativeInputRoute>>,
}
impl Routes {
    fn attach(
        &mut self,
        shared: &Arc<Shared>,
        channels: &mut ChannelRuntime,
        key: &NativeSessionKey,
    ) -> io::Result<()> {
        let generation = shared.generation.load(Ordering::Acquire);
        let timing = SessionMediaTiming::default();
        if key.controller_view_authorized {
            let receiver = VideoReceiver::attach_advertised_channel_timed(
                channels,
                key.connection_generation,
                timing.playout.clone(),
            )
            .map_err(io::Error::other)?;
            shared.set_native_video_presentation(Some(Arc::new(NativeVideoPresentationRoute {
                request_id: key.request_id.clone(),
                connection_generation: key.connection_generation,
                generation,
                presentation: receiver.presentation(),
            })));
            self.video = Some(receiver);
        }
        if key.host_view_authorized {
            shared.set_native_video_route(Some(NativeVideoRoute::attach(
                channels,
                key,
                timing.clone(),
            )));
        }
        if key.audio_authorized {
            self.audio = Some(
                NativeAudioRoute::attach(shared, channels, key, generation, timing)
                    .map_err(io::Error::other)?,
            );
            shared.set_native_audio_route(self.audio.clone());
        }
        if key.clipboard_read_authorized || key.clipboard_write_authorized {
            self.clipboard = Some(
                NativeClipboardRoute::attach(shared, channels, key, generation)
                    .map_err(io::Error::other)?,
            );
            shared.set_native_clipboard_route(self.clipboard.clone());
        }
        if key.file_read_authorized || key.file_write_authorized {
            self.files = Some(
                NativeFilesRoute::attach(shared, channels, key, generation)
                    .map_err(io::Error::other)?,
            );
            shared.set_native_files_route(self.files.clone());
        }
        if key.input_authorized {
            self.input = Some(
                NativeInputRoute::attach(channels, key, generation).map_err(io::Error::other)?,
            );
            shared.set_native_input_route(self.input.clone());
        }
        if key.host_view_authorized || key.controller_view_authorized {
            let (route, worker) = NativeDisplayRoute::attach(shared, channels, key, generation)?;
            self.feedback = Some(worker);
            shared.set_native_display_route(Some(route));
        }
        Ok(())
    }
    async fn shutdown(mut self, shared: &Arc<Shared>, reason: StopReason) -> (bool, bool) {
        shared.closing.store(true, Ordering::Release);
        shared.set_native_video_route(None);
        shared.set_native_video_presentation(None);
        shared.set_native_display_route(None);
        shared.set_native_audio_route(None);
        shared.set_native_clipboard_route(None);
        shared.set_native_files_route(None);
        shared.set_native_input_route(None);
        let (mut cleanup_failed, mut worker_failed) = (false, false);
        if let Some(route) = self.audio {
            let outcome = route.shutdown(reason).await;
            cleanup_failed |= outcome.cleanup_failed;
            worker_failed |= outcome.worker_failed;
            if outcome.owner_pending {
                shared.retain_native_audio_owner(route);
            }
        }
        if let Some(route) = self.clipboard {
            let outcome = route.shutdown(reason).await;
            cleanup_failed |= outcome.cleanup_failed;
            worker_failed |= outcome.worker_failed;
            if outcome.owner_pending {
                shared.retain_native_clipboard_owner(route);
            }
        }
        if let Some(route) = self.files {
            let outcome = route.shutdown(reason).await;
            cleanup_failed |= outcome.cleanup_failed;
            worker_failed |= outcome.worker_failed;
            if outcome.owner_pending {
                shared.retain_native_files_owner(route);
            }
        }
        if let Some(route) = self.input {
            cleanup_failed |= route.shutdown().await.is_err();
        }
        if let Some(mut receiver) = self.video {
            let (cleanup, worker) = tokio::task::spawn_blocking(move || {
                let result = receiver.shutdown(reason);
                let status = receiver.monitor().status();
                (
                    !matches!(result, Ok(nestlink_media_session::ShutdownReport::Joined))
                        || status.cleanup_timed_out
                        || !status.finished,
                    status.error.is_some(),
                )
            })
            .await
            .unwrap_or((true, true));
            cleanup_failed |= cleanup;
            worker_failed |= worker;
        }
        if let Some(mut worker) = self.feedback.take() {
            match tokio::time::timeout(Duration::from_millis(250), &mut worker).await {
                Ok(Ok(Ok(()))) => {}
                Ok(_) => worker_failed = true,
                Err(_) => {
                    cleanup_failed = true;
                    worker.abort();
                    let _ = worker.await;
                }
            }
        }
        (cleanup_failed, worker_failed)
    }
}

impl NativeOfflineSession {
    async fn attach(
        remote: NativeOfflineRemote,
        mut runtime: OfflineRemoteRuntime,
        transport: NativeOfflineTransport,
        permit: OwnedSemaphorePermit,
    ) -> Result<Self, NativeOfflineError> {
        let scope = remote.binding()?;
        let initial_budget = remote.budget()?;
        let key = key(&scope);
        let generation = remote
            .0
            .next_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1).filter(|next| *next <= i64::MAX as u64)
            })
            .map_err(|_| NativeOfflineError::Limits)?;
        let shared = Shared::new(remote.0.limits);
        shared.generation.store(generation, Ordering::Release);
        let mut routes = Routes::default();
        if let Err(error) = routes.attach(&shared, runtime.channels(), &key) {
            let _ = runtime
                .channels()
                .lease_control()
                .stop(StopReason::PlatformChanged);
            let _ = runtime.wait_stopped().await;
            routes.shutdown(&shared, StopReason::PlatformChanged).await;
            return Err(error.into());
        }
        let carrier = runtime.channels().lease_control();
        let mut snapshot = Snapshot {
            generation,
            ..Snapshot::default()
        };
        snapshot.native_session.replace(NativeSessionView {
            request_id: key.request_id.clone(),
            connection_generation: key.connection_generation,
            lease_sequence: key.lease_sequence,
            status: NativeSessionStatus::Connected,
            host_view_authorized: key.host_view_authorized,
            path: Some(key.path),
            quality: None,
            recovery_chain_origin_generation: None,
            stop_reason: None,
            stop_effects: None,
            cleanup: None,
            failure: None,
        });
        let (snapshots, watching) = watch::channel(Arc::new(snapshot.clone()));
        let (commands, mut requests) = mpsc::channel::<Envelope>(remote.0.limits.operations);
        let (controls, _) = mpsc::channel(1);
        let data = CoreHandle {
            commands,
            controls,
            shared: shared.clone(),
            view: watching,
            offline: Some(remote.clone()),
        };
        let initial = NativeOfflineView {
            space_id: scope.space_id,
            bundle_id: scope.bundle_id,
            request_id: key.request_id,
            connection_generation: key.connection_generation,
            is_host: key.is_host,
            operations: scope.operations,
            transport,
            status: NativeSessionStatus::Connected,
            budget: initial_budget,
            stop_reason: None,
            cleanup: None,
            failure: None,
        };
        let (views, view) = watch::channel(Arc::new(initial.clone()));
        snapshot.native_offline = Some(initial.clone());
        snapshots.send_replace(Arc::new(snapshot.clone()));
        let (finished_sender, finished) = watch::channel(None);
        let original = remote.clone();
        let task = tokio::spawn(async move {
            let _permit = permit;
            let mut view = initial;
            let mut stop_requests = Vec::new();
            let mut requests_open = true;
            let stopped = {
                let stopped = runtime.wait_stopped();
                tokio::pin!(stopped);
                let mut tick = tokio::time::interval(Duration::from_millis(250));
                loop {
                    tokio::select! { biased;
                        result = &mut stopped => break result,
                        request = requests.recv(), if requests_open => if let Some(request) = request {
                            let current = request.generation == snapshot.generation;
                            let exact_stop = matches!(&request.action,
                                Some(Action::StopNativeSession { request_id, connection_generation })
                                if request_id == &view.request_id && *connection_generation == view.connection_generation);
                            if current && exact_stop {
                                shared.closing.store(true, Ordering::Release);
                                original.stop();
                                stop_requests.push(request);
                                view.status = NativeSessionStatus::Stopping;
                                if let Some(session) = snapshot.native_session.data.as_ref() {
                                    let mut session = session.as_ref().clone();
                                    session.status = NativeSessionStatus::Stopping;
                                    session.host_view_authorized = false;
                                    snapshot.native_session.replace(session);
                                }
                            } else {
                                complete(&shared, &mut snapshot, request,
                                    if current { OperationStatus::Failed } else { OperationStatus::Superseded },
                                    Some(Failure::local(if current { FailureKind::SignInRequired } else { FailureKind::StaleGeneration })),
                                    original.0.limits.history);
                            }
                            snapshot.native_offline = Some(view.clone());
                            snapshot.revision += 1;
                            snapshots.send_replace(Arc::new(snapshot.clone()));
                            views.send_replace(Arc::new(view.clone()));
                        } else { requests_open = false; },
                        _ = tick.tick() => {
                            if let Ok(budget) = original.budget() {
                                view.budget = budget;
                                views.send_replace(Arc::new(view.clone()));
                                snapshot.native_offline = Some(view.clone());
                                snapshot.revision += 1;
                                snapshots.send_replace(Arc::new(snapshot.clone()));
                            }
                        }
                    }
                }
            };
            let reason = stopped
                .as_ref()
                .map_or(StopReason::PlatformChanged, |report| report.reason);
            let (cleanup_failed, worker_failed) = routes.shutdown(&shared, reason).await;
            // A timed-out platform join keeps its original owner in Shared.
            // Hold the single-lifecycle permit until that actual reaper ends;
            // callers can observe Pending through the bounded shutdown API.
            while shared.native_audio_cleanup_pending()
                || shared.native_clipboard_cleanup_pending()
                || shared.native_files_cleanup_pending()
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let transport_failed = stopped.as_ref().map_or(true, |report| {
                map_report_cleanup(report.cleanup) == NativeSessionCleanup::Failed
            });
            let cleanup = if cleanup_failed || transport_failed {
                NativeSessionCleanup::Failed
            } else {
                NativeSessionCleanup::Succeeded
            };
            let failure = (cleanup == NativeSessionCleanup::Failed || worker_failed)
                .then(|| Failure::local(FailureKind::NativeSessionUnavailable));
            let report = NativeOfflineStop {
                reason: map_stop_reason(reason),
                cleanup,
                failure: failure.clone(),
            };
            if let Some(session) = snapshot.native_session.data.as_ref() {
                let mut session = session.as_ref().clone();
                session.status = if failure.is_some() {
                    NativeSessionStatus::Failed
                } else {
                    NativeSessionStatus::Stopped
                };
                session.host_view_authorized = false;
                session.stop_reason = Some(report.reason);
                session.cleanup = Some(cleanup);
                session.failure = failure.clone();
                session.stop_effects = stopped.as_ref().ok().map(|report| {
                    map_report_effects(
                        report.effects.cancel_channels,
                        report.effects.release_inputs,
                        report.effects.discard_queues,
                        report.effects.close_allocations,
                    )
                });
                snapshot.native_session.replace(session);
            }
            snapshot.lifecycle = Lifecycle::Stopped;
            snapshot.revision += 1;
            view.status = if failure.is_some() {
                NativeSessionStatus::Failed
            } else {
                NativeSessionStatus::Stopped
            };
            if let Ok(budget) = original.budget() {
                view.budget = budget;
            }
            view.stop_reason = Some(report.reason);
            view.cleanup = Some(cleanup);
            view.failure = failure;
            for request in stop_requests {
                complete(
                    &shared,
                    &mut snapshot,
                    request,
                    if report.failure.is_some() {
                        OperationStatus::Failed
                    } else {
                        OperationStatus::Succeeded
                    },
                    report.failure.clone(),
                    original.0.limits.history,
                );
            }
            snapshot.native_offline = Some(view.clone());
            snapshots.send_replace(Arc::new(snapshot));
            views.send_replace(Arc::new(view));
            finished_sender.send_replace(Some(report));
        });
        Ok(Self {
            remote,
            data,
            view,
            finished,
            task: Some(task),
            carrier,
        })
    }
    pub fn handle(&self) -> CoreHandle {
        self.data.clone()
    }
    pub fn view(&self) -> Arc<NativeOfflineView> {
        let mut view = self.view.borrow().clone();
        self.remote.refresh_budget(Arc::make_mut(&mut view));
        view
    }
    pub fn observe(&self) -> watch::Receiver<Arc<NativeOfflineView>> {
        self.view.clone()
    }
    pub fn request_stop(&self) {
        self.data.shared.closing.store(true, Ordering::Release);
        self.remote.stop();
    }
    /// Retire only this carrier after a network change. The original owner,
    /// deadline and cumulative reservations remain unchanged; a later explicit
    /// connect/listen spends another signed attempt after actual cleanup.
    pub fn request_carrier_rebuild(&self) -> Result<(), NativeOfflineError> {
        if self.view().status != NativeSessionStatus::Connected {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "offline carrier is not connected",
            )
            .into());
        }
        self.data.shared.closing.store(true, Ordering::Release);
        self.carrier
            .stop(StopReason::NetworkChanged)
            .map_err(io::Error::other)?;
        Ok(())
    }
    pub async fn wait_stopped(&mut self) -> Result<NativeOfflineStop, NativeOfflineError> {
        loop {
            let report = self.finished.borrow().clone();
            if let Some(report) = report {
                if let Some(task) = self.task.take() {
                    task.await.map_err(io::Error::other)?;
                }
                return Ok(report);
            }
            self.finished.changed().await.map_err(|_| {
                io::Error::other("offline product worker ended without a cleanup receipt")
            })?;
        }
    }
    pub async fn shutdown(&mut self, timeout: Duration) -> ShutdownState {
        self.request_stop();
        match tokio::time::timeout(timeout, self.wait_stopped()).await {
            Err(_) => ShutdownState::Pending,
            Ok(Err(_)) => ShutdownState::Failed,
            Ok(Ok(report))
                if report.cleanup == NativeSessionCleanup::Failed || report.failure.is_some() =>
            {
                ShutdownState::Failed
            }
            Ok(Ok(_)) => ShutdownState::Complete,
        }
    }
}

fn complete(
    shared: &Shared,
    snapshot: &mut Snapshot,
    request: Envelope,
    status: OperationStatus,
    failure: Option<Failure>,
    history: usize,
) {
    let result = request.result(status, RemoteEffect::None, failure, PublicOutput::None);
    snapshot.event_sequence += 1;
    snapshot.events.push(Event {
        sequence: snapshot.event_sequence,
        result: result.clone(),
    });
    snapshot.operations.push(result.clone());
    if snapshot.events.len() > history {
        snapshot.events.remove(0);
    }
    if snapshot.operations.len() > history {
        snapshot.operations.remove(0);
    }
    let _ = request.reply.send(Completion {
        result,
        sensitive: None,
        generation: shared.generation.clone(),
    });
}
impl Drop for NativeOfflineSession {
    fn drop(&mut self) {
        if self.finished.borrow().is_none() {
            self.request_stop();
        }
    }
}
