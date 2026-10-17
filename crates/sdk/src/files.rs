//! Application-owned native downloads. The actor consumes every source reply,
//! even when its caller stops waiting. File cancellation stops local saving
//! before it waits for remote cleanup and never stops the viewing lease.
use nestlink_auth::random_id;
use nestlink_protocol::{
    ContractError, ErrorCode, FILE_READ_TRANSFERS, FileReadErrorCode, FileReadManifest, valid_id,
};
use nestlink_remote::{
    ChannelRuntime, RemoteError,
    files::{
        FileDestinationFactory, FileDownload, FileDownloadMonitor, FileDownloadPhase,
        FileDownloadWorker, FileDownloadWorkerStatus, FileReadClient, FileReadError, FileShutdown,
    },
};
use std::io;
use tokio::sync::{mpsc, oneshot, watch};

/// Remote root and portable relative name selected by the application. The
/// destination factory separately owns the local user's save-area approval.
#[derive(Clone, Debug)]
pub struct NativeDownloadRequest {
    root_id: String,
    relative_path: String,
    recovery: Option<nestlink_protocol::file_recovery::DownloadRecoveryResume>,
}
impl NativeDownloadRequest {
    pub fn new(root_id: &str, relative_path: &str) -> Result<Self, ContractError> {
        if !valid_id(root_id) {
            return Err(ContractError::new(
                ErrorCode::InvalidMessage,
                "invalid download root",
            ));
        }
        nestlink_protocol::files::validate_relative_path(relative_path)?;
        Ok(Self {
            root_id: root_id.into(),
            relative_path: relative_path.into(),
            recovery: None,
        })
    }
    /// Only task facts cross restart. Actual client scope is rechecked by the
    /// actor and the destination independently verifies source/prefix bytes.
    pub fn recover(
        facts: nestlink_protocol::file_recovery::DownloadRecoveryResume,
    ) -> Result<Self, ContractError> {
        facts.validate()?;
        let mut request = Self::new(&facts.facts.root_id, &facts.facts.relative_path)?;
        request.recovery = Some(facts);
        Ok(request)
    }
    pub fn root_id(&self) -> &str {
        &self.root_id
    }
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NativeDownloadPhase {
    #[default]
    Opening,
    Preparing,
    Ready,
    Pulling,
    Saving,
    SourceVerified,
    Finalizing,
    Completed,
    Pausing,
    Paused,
    Cancelling,
    Cancelled,
    Failed,
}

/// Bounded error facts suitable for progress/UI state. Peer paths and OS error
/// strings are deliberately absent; authorization's exact contract is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeDownloadError {
    #[error("remote file source rejected the operation: {0:?}")]
    Source(FileReadErrorCode),
    #[error("remote file transport failed: {0:?}")]
    Transport(io::ErrorKind),
    #[error("remote file platform cleanup failed: {0:?}")]
    Cleanup(io::ErrorKind),
    #[error("remote file authorization failed ({code:?}): {reason}")]
    Authorization {
        code: ErrorCode,
        reason: &'static str,
    },
    #[error("remote file connection stopped")]
    Stopped,
    #[error("local download storage failed: {0:?}")]
    Destination(io::ErrorKind),
    #[error("download operation unavailable: {0}")]
    State(&'static str),
    #[error("download was cancelled")]
    Cancelled,
}
impl From<FileReadError> for NativeDownloadError {
    fn from(error: FileReadError) -> Self {
        match error {
            FileReadError::Source(code) => Self::Source(code),
            FileReadError::Remote(RemoteError::Io(error)) => Self::Transport(error.kind()),
            FileReadError::Remote(RemoteError::Cleanup(error)) => Self::Cleanup(error.kind()),
            FileReadError::Remote(RemoteError::Authorization(error)) => Self::Authorization {
                code: error.code,
                reason: error.reason,
            },
            FileReadError::Remote(RemoteError::Stopped) => Self::Stopped,
        }
    }
}
impl From<RemoteError> for NativeDownloadError {
    fn from(error: RemoteError) -> Self {
        FileReadError::Remote(error).into()
    }
}
fn source_error(error: &FileReadError) -> NativeDownloadError {
    match error {
        FileReadError::Source(code) => NativeDownloadError::Source(*code),
        FileReadError::Remote(RemoteError::Io(error)) => {
            NativeDownloadError::Transport(error.kind())
        }
        FileReadError::Remote(RemoteError::Cleanup(error)) => {
            NativeDownloadError::Cleanup(error.kind())
        }
        FileReadError::Remote(RemoteError::Authorization(error)) => {
            NativeDownloadError::Authorization {
                code: error.code,
                reason: error.reason,
            }
        }
        FileReadError::Remote(RemoteError::Stopped) => NativeDownloadError::Stopped,
    }
}
fn disk(error: io::Error) -> NativeDownloadError {
    NativeDownloadError::Destination(error.kind())
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NativeDownloadSourceAttempt {
    pub transfer_id: String,
    pub start_offset: u64,
    pub manifest: Option<FileReadManifest>,
    pub received_bytes: u64,
    pub verified_end: bool,
    pub cancel_requested: bool,
    pub cancel_acknowledged: bool,
    pub error: Option<NativeDownloadError>,
    pub cancel_error: Option<NativeDownloadError>,
    pub client_retirement: Option<Result<(), NativeDownloadError>>,
}
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NativeDownloadStatus {
    pub phase: NativeDownloadPhase,
    /// A pause is acknowledged only after its exact source and worker barriers.
    /// A previous Paused phase cannot acknowledge a newer pause request.
    pub pause_ack_revision: u64,
    pub manifest: Option<FileReadManifest>,
    /// Source bytes received can exceed confirmed disk bytes when pausing.
    pub received_bytes: u64,
    pub source_verified: bool,
    pub source_cancel_requested: bool,
    pub source_cancel_acknowledged: bool,
    pub source_cancel_error: Option<NativeDownloadError>,
    pub source_request_pending: bool,
    /// At most FILE_READ_TRANSFERS attempts, including rejected successors.
    /// Old End/Cancel/error facts remain here after a successful resumption.
    pub source_attempts: Vec<NativeDownloadSourceAttempt>,
    pub active_attempt: Option<usize>,
    pub client_retirement: Option<Result<(), NativeDownloadError>>,
    pub retired_clients: u64,
    pub retirement_error: Option<NativeDownloadError>,
    /// None means no destination worker was constructed.
    pub destination: Option<FileDownloadWorkerStatus>,
    /// The bounded shutdown result is distinct from actual eventual completion.
    pub destination_shutdown: Option<FileShutdown>,
    /// Saving has stopped or was never started. A timed-out disk call may still
    /// own handles; inspect destination.finished and its actual effects.
    pub local_stopped: bool,
    pub actor_finished: bool,
    pub error: Option<NativeDownloadError>,
}

#[derive(Clone)]
pub struct NativeDownloadMonitor(watch::Sender<NativeDownloadStatus>);
impl NativeDownloadMonitor {
    pub fn status(&self) -> NativeDownloadStatus {
        self.0.borrow().clone()
    }
    pub fn subscribe(&self) -> watch::Receiver<NativeDownloadStatus> {
        self.0.subscribe()
    }
    /// Remote cleanup may take longer than local saving cancellation. This also
    /// waits for the destination's actual owned-thread completion, if present.
    pub async fn wait_finished(&self) -> NativeDownloadStatus {
        let mut state = self.subscribe();
        loop {
            let current = state.borrow_and_update().clone();
            if current.actor_finished && current.destination.is_none_or(|disk| disk.finished) {
                return current;
            }
            if state.changed().await.is_err() {
                return self.status();
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Requested {
    #[default]
    Running,
    Pause,
    Cancel,
}
#[derive(Clone, Copy, Debug, Default)]
struct Control {
    request: Requested,
    revision: u64,
}
/// A UI may retain this while the owning download awaits a chunk or disk call.
/// Cancellation is sticky; this handle carries no session-stop authority.
#[derive(Clone)]
pub struct NativeDownloadControl(watch::Sender<Control>);
impl NativeDownloadControl {
    pub fn pause(&self) {
        let _ = self.request_pause();
    }
    fn request_pause(&self) -> Result<u64, NativeDownloadError> {
        let mut revision = None;
        self.0.send_modify(|state| {
            if state.request != Requested::Cancel {
                if let Some(next) = state.revision.checked_add(1) {
                    state.request = Requested::Pause;
                    state.revision = next;
                    revision = Some(next);
                } else {
                    // Never reuse an acknowledgement identity after overflow.
                    state.request = Requested::Cancel;
                }
            }
        });
        revision.ok_or(NativeDownloadError::Cancelled)
    }
    pub fn cancel(&self) {
        self.0.send_modify(|state| {
            state.request = Requested::Cancel;
            state.revision = state.revision.saturating_add(1);
        });
    }
}

type Reply = oneshot::Sender<Result<NativeDownloadStatus, NativeDownloadError>>;
enum Command {
    Pull(Reply),
    Finish(Reply),
    Resume(u64, Option<NativeDownloadClient>, Reply),
}

enum RetirementTarget {
    Owner,
    Auxiliary(Option<usize>),
}
/// An exact idle FileRead client returned after this transfer's source cleanup.
/// Dropping this guard safely retires only FileRead; it preserves live viewing.
pub struct NativeDownloadClient {
    client: Option<FileReadClient>,
    monitor: NativeDownloadMonitor,
    target: RetirementTarget,
}
impl NativeDownloadClient {
    fn new(
        client: FileReadClient,
        monitor: NativeDownloadMonitor,
        target: RetirementTarget,
    ) -> Self {
        Self {
            client: Some(client),
            monitor,
            target,
        }
    }
    fn take(&mut self) -> Result<FileReadClient, NativeDownloadError> {
        self.client
            .take()
            .ok_or(NativeDownloadError::State("file client already consumed"))
    }
    pub fn start(
        mut self,
        request: NativeDownloadRequest,
        destination: impl FileDestinationFactory,
    ) -> Result<NativeFileDownload, NativeDownloadError> {
        Ok(NativeFileDownload::start(
            self.take()?,
            request,
            destination,
        ))
    }
    /// Advanced callers may take the original client for another owner. Its
    /// ordinary Drop still stops the lease; use this guard for safe retirement.
    pub fn into_client(mut self) -> Result<FileReadClient, NativeDownloadError> {
        self.take()
    }
    pub fn retire(mut self) -> Result<(), NativeDownloadError> {
        self.retire_owned()
    }
    fn retire_owned(&mut self) -> Result<(), NativeDownloadError> {
        let Some(client) = self.client.take() else {
            return Ok(());
        };
        let result = client.retire().map_err(NativeDownloadError::from);
        self.monitor.0.send_modify(|state| {
            state.retired_clients = state.retired_clients.saturating_add(1);
            if let Err(error) = result {
                state.retirement_error.get_or_insert(error);
            }
            match self.target {
                RetirementTarget::Owner => state.client_retirement = Some(result),
                RetirementTarget::Auxiliary(Some(index)) => {
                    state.source_attempts[index].client_retirement = Some(result)
                }
                RetirementTarget::Auxiliary(None) => {}
            }
        });
        result
    }
}
impl Drop for NativeDownloadClient {
    fn drop(&mut self) {
        let _ = self.retire_owned();
    }
}

/// One bounded transfer on one claimed FileRead channel. The owning task keeps
/// protocol requests alive when an application future is dropped. Further data
/// operations then require an acknowledged pause, preventing late acknowledgments
/// from answering a replacement request.
pub struct NativeFileDownload {
    commands: mpsc::Sender<Command>,
    control: NativeDownloadControl,
    monitor: NativeDownloadMonitor,
    in_flight: bool,
    client_return: Option<oneshot::Receiver<NativeDownloadClient>>,
}
impl NativeFileDownload {
    pub fn attach(
        runtime: &mut ChannelRuntime,
        generation: u64,
        request: NativeDownloadRequest,
        destination: impl FileDestinationFactory,
    ) -> Result<Self, RemoteError> {
        Ok(Self::start(
            FileReadClient::attach(runtime, generation)?,
            request,
            destination,
        ))
    }
    /// Requires a Tokio runtime. Local directory/file operations execute only
    /// on FileDownloadWorker's owned std thread, including initialization.
    pub fn start(
        client: FileReadClient,
        request: NativeDownloadRequest,
        destination: impl FileDestinationFactory,
    ) -> Self {
        let (commands, inbox) = mpsc::channel(1);
        let (control, signals) = watch::channel(Control::default());
        let (status, _) = watch::channel(NativeDownloadStatus::default());
        let monitor = NativeDownloadMonitor(status);
        let (return_client, client_return) = oneshot::channel();
        let actor = Actor {
            client,
            request,
            source: None,
            worker: None,
            signals,
            control: NativeDownloadControl(control.clone()),
            monitor: monitor.clone(),
        };
        tokio::spawn(async move {
            actor.run(destination, inbox, return_client).await;
        });
        Self {
            commands,
            control: NativeDownloadControl(control),
            monitor,
            in_flight: false,
            client_return: Some(client_return),
        }
    }
    pub fn monitor(&self) -> NativeDownloadMonitor {
        self.monitor.clone()
    }
    pub fn control(&self) -> NativeDownloadControl {
        self.control.clone()
    }
    pub fn status(&self) -> NativeDownloadStatus {
        self.monitor.status()
    }
    pub async fn ready(&self) -> Result<NativeDownloadStatus, NativeDownloadError> {
        self.wait_state(|s| {
            !matches!(
                s.phase,
                NativeDownloadPhase::Opening | NativeDownloadPhase::Preparing
            )
        })
        .await
    }
    /// Pull one bounded source block and acknowledge its actual disk write.
    /// SourceVerified means End was checked; publication still requires finish.
    pub async fn pull(&mut self) -> Result<NativeDownloadStatus, NativeDownloadError> {
        self.command(Command::Pull).await
    }
    pub async fn finish(&mut self) -> Result<NativeDownloadStatus, NativeDownloadError> {
        self.command(Command::Finish).await
    }
    pub async fn download_to_end(&mut self) -> Result<NativeDownloadStatus, NativeDownloadError> {
        self.ready().await?;
        while !self.status().source_verified {
            self.pull().await?;
        }
        self.finish().await
    }
    /// Retains only the worker's actual confirmed prefix. The old source's
    /// outstanding reply and Cancel are consumed before Paused is acknowledged.
    pub async fn pause(&mut self) -> Result<NativeDownloadStatus, NativeDownloadError> {
        let revision = self.control.request_pause()?;
        let status = self
            .wait_state(|s| {
                s.phase == NativeDownloadPhase::Paused && s.pause_ack_revision >= revision
            })
            .await?;
        self.in_flight = false;
        Ok(status)
    }
    /// Explicitly reopens the same root/path/content at the confirmed disk
    /// prefix. None reuses the live connection; Some is a freshly proved client.
    /// The worker checks complete signed scope, generation and actual prefix.
    pub async fn resume(
        &mut self,
        successor: Option<FileReadClient>,
    ) -> Result<NativeDownloadStatus, NativeDownloadError> {
        // Capture at submission, before the actor can observe a later pause.
        let revision = self.control.0.borrow().revision;
        let successor = successor.map(|client| {
            NativeDownloadClient::new(
                client,
                self.monitor.clone(),
                RetirementTarget::Auxiliary(None),
            )
        });
        self.command(|reply| Command::Resume(revision, successor, reply))
            .await
    }
    /// Wait for exact source cleanup and take the original client to reuse its
    /// sequence/owner for another file. A cancelled wait keeps this slot intact.
    pub async fn take_client(&mut self) -> Result<NativeDownloadClient, NativeDownloadError> {
        let status = self.status();
        if !status.actor_finished
            && !matches!(
                status.phase,
                NativeDownloadPhase::Cancelling
                    | NativeDownloadPhase::Cancelled
                    | NativeDownloadPhase::Failed
                    | NativeDownloadPhase::Completed
            )
        {
            return Err(NativeDownloadError::State(
                "client return requires a completed or cancelled transfer",
            ));
        }
        let receiver = self
            .client_return
            .as_mut()
            .ok_or(NativeDownloadError::State("file client already taken"))?;
        let client = receiver.await.map_err(|_| {
            NativeDownloadError::State("file owner ended without returning the client")
        })?;
        self.client_return.take();
        Ok(client)
    }
    pub async fn release_client(&mut self) -> Result<NativeDownloadStatus, NativeDownloadError> {
        self.take_client().await?.retire()?;
        Ok(self.status())
    }
    /// Returns after bounded destination shutdown, without waiting for a slow
    /// remote Cancel reply. Retain the monitor to observe actual late cleanup.
    pub async fn cancel(&mut self) -> NativeDownloadStatus {
        self.control.cancel();
        let mut state = self.monitor.subscribe();
        loop {
            let current = state.borrow_and_update().clone();
            if current.local_stopped || current.actor_finished {
                return current;
            }
            if state.changed().await.is_err() {
                return self.status();
            }
        }
    }
    async fn wait_state(
        &self,
        predicate: impl Fn(&NativeDownloadStatus) -> bool,
    ) -> Result<NativeDownloadStatus, NativeDownloadError> {
        let mut state = self.monitor.subscribe();
        loop {
            let current = state.borrow_and_update().clone();
            if matches!(
                current.phase,
                NativeDownloadPhase::Cancelled
                    | NativeDownloadPhase::Cancelling
                    | NativeDownloadPhase::Failed
            ) {
                return Err(current.error.unwrap_or(NativeDownloadError::Cancelled));
            }
            if predicate(&current) {
                return Ok(current);
            }
            if current.actor_finished {
                return Err(current.error.unwrap_or(NativeDownloadError::State(
                    "download owner already finished",
                )));
            }
            state
                .changed()
                .await
                .map_err(|_| NativeDownloadError::State("download monitor closed"))?;
        }
    }
    async fn command(
        &mut self,
        make: impl FnOnce(Reply) -> Command,
    ) -> Result<NativeDownloadStatus, NativeDownloadError> {
        if self.in_flight {
            return Err(NativeDownloadError::State(
                "an abandoned operation requires an acknowledged pause",
            ));
        }
        if self.monitor.status().actor_finished
            || self.control.0.borrow().request == Requested::Cancel
        {
            return Err(NativeDownloadError::Cancelled);
        }
        let (reply, result) = oneshot::channel();
        self.commands
            .try_send(make(reply))
            .map_err(|_| NativeDownloadError::State("download command slot unavailable"))?;
        self.in_flight = true;
        let result = result.await.map_err(|_| {
            self.status().error.unwrap_or(NativeDownloadError::State(
                "download actor ended without the exact response",
            ))
        })?;
        self.in_flight = false;
        result
    }
}
impl Drop for NativeFileDownload {
    fn drop(&mut self) {
        self.control.cancel();
    }
}

struct Actor {
    client: FileReadClient,
    request: NativeDownloadRequest,
    source: Option<FileDownload>,
    worker: Option<FileDownloadWorker>,
    signals: watch::Receiver<Control>,
    control: NativeDownloadControl,
    monitor: NativeDownloadMonitor,
}
struct ActorCompletion(NativeDownloadMonitor);
impl Drop for ActorCompletion {
    fn drop(&mut self) {
        self.0.0.send_modify(|state| {
            if !state.actor_finished {
                state.actor_finished = true;
                state.phase = NativeDownloadPhase::Failed;
                state.error.get_or_insert(NativeDownloadError::State(
                    "download owner ended unexpectedly",
                ));
            }
        });
    }
}
fn observe_destination(source: FileDownloadMonitor, target: NativeDownloadMonitor) {
    // This observer outlives the actor after a bounded cleanup timeout and keeps
    // actual publication, handle close and temporary removal facts observable.
    // Thread exit itself does not notify a watch channel; polling status drives
    // the monitor's exact-handle join before exposing `finished`.
    tokio::spawn(async move {
        let mut updates = source.subscribe();
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(50));
        loop {
            let actual = source.status();
            let _ = updates.borrow_and_update();
            target.0.send_if_modified(|state| {
                let mut changed = false;
                if state.destination != Some(actual) {
                    state.destination = Some(actual);
                    changed = true;
                }
                if actual.finished && !state.local_stopped {
                    state.local_stopped = true;
                    changed = true;
                }
                changed
            });
            if actual.finished {
                break;
            }
            tokio::select! {
                changed = updates.changed() => if changed.is_err() { break; },
                _ = tick.tick() => {},
            }
        }
    });
}
async fn shutdown_destination(
    worker: &mut Option<FileDownloadWorker>,
    monitor: &NativeDownloadMonitor,
) {
    monitor
        .0
        .send_modify(|state| state.phase = NativeDownloadPhase::Cancelling);
    let result = match worker.as_mut() {
        Some(worker) => Some(worker.shutdown().await),
        None => None,
    };
    monitor.0.send_modify(|state| {
        match result {
            Some(Ok(receipt)) => state.destination_shutdown = Some(receipt),
            Some(Err(ref error)) => {
                state
                    .error
                    .get_or_insert(NativeDownloadError::Destination(error.kind()));
            }
            None => {}
        }
        if let Some(worker) = worker {
            state.destination = Some(worker.monitor().status());
        }
        state.local_stopped = true;
    });
}
async fn pause_destination(
    worker: &mut Option<FileDownloadWorker>,
    signals: &mut watch::Receiver<Control>,
    monitor: &NativeDownloadMonitor,
) -> Result<(), NativeDownloadError> {
    if signals.borrow().request == Requested::Cancel {
        shutdown_destination(worker, monitor).await;
        return Ok(());
    }
    let mut pending = Box::pin(
        worker
            .as_mut()
            .ok_or(NativeDownloadError::State("missing paused destination"))?
            .pause(),
    );
    let result = loop {
        tokio::select! { biased;
            changed = signals.changed() => {
                if changed.is_err() || signals.borrow().request == Requested::Cancel {
                    break None;
                }
            }
            result = &mut pending => break Some(result),
        }
    };
    drop(pending);
    match result {
        Some(result) => result.map(|_| ()).map_err(disk),
        None => {
            shutdown_destination(worker, monitor).await;
            Ok(())
        }
    }
}
async fn cancel_remote(
    client: &mut FileReadClient,
    source: &mut FileDownload,
    worker: &mut Option<FileDownloadWorker>,
    signals: &mut watch::Receiver<Control>,
    monitor: &NativeDownloadMonitor,
    attempt: Option<usize>,
) -> Result<(), NativeDownloadError> {
    monitor.0.send_modify(|state| {
        state.source_request_pending = true;
        if let Some(index) = attempt {
            state.source_attempts[index].cancel_requested = true;
        }
    });
    let mut pending = Box::pin(client.cancel(source));
    let mut locally_stopped = monitor.status().local_stopped;
    let result = loop {
        tokio::select! { biased;
            changed = signals.changed(), if !locally_stopped => {
                if changed.is_err() || signals.borrow().request == Requested::Cancel {
                    shutdown_destination(worker, monitor).await;
                    locally_stopped = true;
                }
            }
            result = &mut pending => break result.map_err(NativeDownloadError::from),
        }
    };
    drop(pending);
    monitor.0.send_modify(|state| {
        state.source_request_pending = false;
        if let Some(index) = attempt {
            match result {
                Ok(()) => state.source_attempts[index].cancel_acknowledged = true,
                Err(error) => state.source_attempts[index].cancel_error = Some(error),
            }
        }
    });
    result
}
impl Actor {
    fn begin_attempt(&self, offset: u64) -> Result<(String, usize), NativeDownloadError> {
        let id = random_id();
        let mut index = None;
        self.monitor.0.send_modify(|state| {
            if state.source_attempts.len() < FILE_READ_TRANSFERS as usize {
                index = Some(state.source_attempts.len());
                state.source_attempts.push(NativeDownloadSourceAttempt {
                    transfer_id: id.clone(),
                    start_offset: offset,
                    received_bytes: offset,
                    ..NativeDownloadSourceAttempt::default()
                });
            }
        });
        Ok((
            id,
            index.ok_or(NativeDownloadError::State(
                "download source-attempt budget exhausted",
            ))?,
        ))
    }
    fn phase(&self, phase: NativeDownloadPhase) {
        self.monitor.0.send_modify(|state| state.phase = phase);
    }
    fn requested(&self) -> Requested {
        self.signals.borrow().request
    }
    fn failure(&self, error: NativeDownloadError) {
        self.monitor.0.send_modify(|state| {
            state.error.get_or_insert(error);
            state.phase = NativeDownloadPhase::Failed;
        });
    }
    async fn run(
        mut self,
        factory: impl FileDestinationFactory,
        mut inbox: mpsc::Receiver<Command>,
        return_client: oneshot::Sender<NativeDownloadClient>,
    ) {
        let _completed = ActorCompletion(self.monitor.clone());
        if let Err(error) = self.initialize(factory).await {
            self.failure(error);
            self.stop_local().await;
            self.cancel_source().await;
            self.monitor.0.send_modify(|state| {
                state.actor_finished = true;
                state.phase = if self.requested() == Requested::Cancel {
                    NativeDownloadPhase::Cancelled
                } else {
                    NativeDownloadPhase::Failed
                };
            });
            self.return_client(return_client);
            return;
        }
        if self.monitor.status().phase == NativeDownloadPhase::Cancelled {
            self.monitor
                .0
                .send_modify(|state| state.actor_finished = true);
            self.return_client(return_client);
            return;
        }
        let mut destination = self
            .worker
            .as_ref()
            .map(|worker| worker.monitor().subscribe());
        loop {
            if self.requested() == Requested::Cancel {
                self.cancel_all().await;
                break;
            }
            if self.requested() == Requested::Pause
                && (self.monitor.status().phase != NativeDownloadPhase::Paused
                    || self.monitor.status().pause_ack_revision != self.signals.borrow().revision)
                && let Err(error) = self.pause_all().await
            {
                self.failure(error);
                self.stop_local().await;
                self.cancel_source().await;
                self.phase(NativeDownloadPhase::Failed);
                break;
            }
            let actual = destination.as_mut().map(|state| *state.borrow_and_update());
            if let Some(actual) = actual {
                if actual.finished && actual.phase != FileDownloadPhase::Completed {
                    self.failure(NativeDownloadError::Destination(
                        actual.error.unwrap_or(io::ErrorKind::Interrupted),
                    ));
                    self.stop_local().await;
                    self.cancel_source().await;
                    self.phase(NativeDownloadPhase::Failed);
                    break;
                }
                if actual.phase == FileDownloadPhase::Paused
                    && self.requested() == Requested::Running
                {
                    self.control.pause();
                    continue;
                }
            }
            let command = tokio::select! { biased;
                result = self.signals.changed() => {
                    if result.is_err() { self.cancel_all().await; break; }
                    continue;
                }
                _ = async { if let Some(destination) = destination.as_mut() { let _ = destination.changed().await; } else { std::future::pending::<()>().await; } } => continue,
                command = inbox.recv() => match command { Some(command) => command, None => { self.cancel_all().await; break; } },
            };
            let (reply, result) = match command {
                Command::Pull(reply) => (reply, self.pull().await),
                Command::Finish(reply) => (reply, self.finish().await),
                Command::Resume(revision, client, reply) => {
                    let mut result = self.resume(revision, client).await;
                    if self.requested() == Requested::Pause
                        && self.monitor.status().phase == NativeDownloadPhase::Pausing
                        && let Err(error) = self.pause_all().await
                    {
                        self.failure(error);
                        result = Err(error);
                    }
                    (reply, result)
                }
            };
            let _ = reply.send(result);
            if matches!(
                self.monitor.status().phase,
                NativeDownloadPhase::Completed
                    | NativeDownloadPhase::Cancelled
                    | NativeDownloadPhase::Failed
            ) {
                if self.monitor.status().phase == NativeDownloadPhase::Failed {
                    self.stop_local().await;
                    self.cancel_source().await;
                    self.phase(NativeDownloadPhase::Failed);
                }
                break;
            }
        }
        self.monitor
            .0
            .send_modify(|state| state.actor_finished = true);
        self.return_client(return_client);
    }
    fn return_client(self, sender: oneshot::Sender<NativeDownloadClient>) {
        let _ = sender.send(NativeDownloadClient::new(
            self.client,
            self.monitor,
            RetirementTarget::Owner,
        ));
    }
    async fn initialize(
        &mut self,
        factory: impl FileDestinationFactory,
    ) -> Result<(), NativeDownloadError> {
        if self.requested() == Requested::Cancel {
            self.cancel_all().await;
            return Ok(());
        }
        // Reject an unrelated fresh scope before claiming a pending RPC.
        let (offset, expected) = match &self.request.recovery {
            Some(recovery) => {
                if self.client.recovery_scope()? != recovery.facts.scope {
                    return Err(NativeDownloadError::State(
                        "fresh session does not match saved download principals/resource",
                    ));
                }
                (recovery.checkpoint_bytes, Some(recovery.facts.sha256))
            }
            None => (0, None),
        };
        let (transfer, attempt) = self.begin_attempt(offset)?;
        self.monitor
            .0
            .send_modify(|state| state.source_request_pending = true);
        // Initial Open is also consumed exactly, even if cancellation arrives.
        let mut pending = Box::pin(self.client.open(
            &transfer,
            &self.request.root_id,
            &self.request.relative_path,
            offset,
            expected,
        ));
        let mut interrupted = false;
        let result = loop {
            tokio::select! { biased;
                changed = self.signals.changed(), if !interrupted => {
                    if changed.is_err() || self.signals.borrow().request == Requested::Cancel {
                        interrupted = true;
                        self.monitor.0.send_modify(|state| { state.local_stopped = true; state.phase = NativeDownloadPhase::Cancelling; });
                    }
                }
                result = &mut pending => break result,
            }
        };
        drop(pending);
        self.monitor
            .0
            .send_modify(|state| state.source_request_pending = false);
        let source = result.map_err(|error| {
            let error = NativeDownloadError::from(error);
            self.monitor
                .0
                .send_modify(|state| state.source_attempts[attempt].error = Some(error));
            error
        })?;
        self.monitor.0.send_modify(|state| {
            state.manifest = Some(source.manifest().clone());
            state.active_attempt = Some(attempt);
            state.source_attempts[attempt].manifest = Some(source.manifest().clone());
        });
        self.source = Some(source);
        if let Some(recovery) = &self.request.recovery {
            let actual = self
                .source
                .as_ref()
                .ok_or(NativeDownloadError::State("missing recovery source"))?;
            if actual.manifest().size != recovery.facts.size
                || actual.snapshot().recovery_facts().map_err(disk)? != recovery.facts
            {
                return Err(NativeDownloadError::State(
                    "fresh source differs from saved size/digest/scope",
                ));
            }
            self.monitor
                .0
                .send_modify(|state| state.received_bytes = offset);
        }
        if self.requested() == Requested::Cancel {
            self.cancel_all().await;
            return Ok(());
        }
        self.phase(NativeDownloadPhase::Preparing);
        let source = self
            .source
            .as_ref()
            .ok_or(NativeDownloadError::State("missing initial source"))?;
        let worker = FileDownloadWorker::start(&self.client, source, factory).map_err(disk)?;
        self.monitor
            .0
            .send_modify(|state| state.destination = Some(worker.monitor().status()));
        observe_destination(worker.monitor(), self.monitor.clone());
        self.worker = Some(worker);
        let mut future = Box::pin(
            self.worker
                .as_mut()
                .ok_or(NativeDownloadError::State("missing destination"))?
                .ready(),
        );
        let result = loop {
            tokio::select! { biased;
                change = self.signals.changed() => {
                    if change.is_err() || self.signals.borrow().request == Requested::Cancel { break None; }
                }
                result = &mut future => break Some(result),
            }
        };
        drop(future);
        match result {
            Some(result) => {
                result.map_err(disk)?;
                self.phase(NativeDownloadPhase::Ready);
            }
            None => self.cancel_all().await,
        }
        Ok(())
    }
    async fn stop_local(&mut self) {
        shutdown_destination(&mut self.worker, &self.monitor).await;
    }
    async fn cancel_source(&mut self) {
        let Some(source) = self.source.as_mut().filter(|source| !source.finished()) else {
            return;
        };
        self.monitor.0.send_modify(|state| {
            state.source_cancel_requested = true;
            state.source_request_pending = true;
        });
        let result = cancel_remote(
            &mut self.client,
            source,
            &mut self.worker,
            &mut self.signals,
            &self.monitor,
            self.monitor.status().active_attempt,
        )
        .await;
        self.monitor.0.send_modify(|state| {
            state.source_request_pending = false;
            match result {
                Ok(()) => state.source_cancel_acknowledged = true,
                Err(error) => state.source_cancel_error = Some(error),
            }
        });
    }
    async fn cancel_all(&mut self) {
        self.stop_local().await;
        self.cancel_source().await;
        self.phase(NativeDownloadPhase::Cancelled);
    }
    async fn pause_all(&mut self) -> Result<(), NativeDownloadError> {
        self.phase(NativeDownloadPhase::Pausing);
        pause_destination(&mut self.worker, &mut self.signals, &self.monitor).await?;
        self.cancel_source().await;
        if self.requested() == Requested::Running {
            self.control.pause();
        }
        let control = *self.signals.borrow();
        if control.request == Requested::Cancel {
            self.cancel_all().await;
        } else {
            self.monitor.0.send_modify(|state| {
                state.phase = NativeDownloadPhase::Paused;
                state.pause_ack_revision = control.revision;
            });
        }
        Ok(())
    }
    async fn pull(&mut self) -> Result<NativeDownloadStatus, NativeDownloadError> {
        if self.requested() != Requested::Running
            || self.monitor.status().phase != NativeDownloadPhase::Ready
        {
            return Err(NativeDownloadError::State(
                "pull requires an active ready download",
            ));
        }
        self.phase(NativeDownloadPhase::Pulling);
        self.monitor
            .0
            .send_modify(|state| state.source_request_pending = true);
        let source = self
            .source
            .as_mut()
            .ok_or(NativeDownloadError::State("missing download source"))?;
        let mut pending = Box::pin(self.client.next(source));
        let mut interruption = Requested::Running;
        let result = loop {
            tokio::select! { biased;
                change = self.signals.changed(), if interruption != Requested::Cancel => {
                    if change.is_err() || self.signals.borrow().request != Requested::Running {
                        let request = self.signals.borrow().request;
                        if request == Requested::Pause && interruption != Requested::Pause {
                            interruption = Requested::Pause;
                            self.monitor.0.send_modify(|state| state.phase = NativeDownloadPhase::Pausing);
                            let _ = pause_destination(&mut self.worker, &mut self.signals, &self.monitor).await;
                            if self.monitor.status().local_stopped { interruption = Requested::Cancel; }
                        } else if request == Requested::Cancel || change.is_err() {
                            interruption = Requested::Cancel;
                            shutdown_destination(&mut self.worker, &self.monitor).await;
                        }
                    }
                }
                result = &mut pending => break result,
            }
        };
        drop(pending);
        let source = self
            .source
            .as_ref()
            .ok_or(NativeDownloadError::State("missing received source"))?;
        self.monitor.0.send_modify(|state| {
            state.source_request_pending = false;
            state.received_bytes = source.offset();
            state.source_verified = source.source_verified();
            if let Some(index) = state.active_attempt {
                state.source_attempts[index].received_bytes = source.offset();
                state.source_attempts[index].verified_end = source.source_verified();
                if let Err(error) = &result {
                    state.source_attempts[index].error = Some(source_error(error));
                }
            }
        });
        if self.requested() == Requested::Cancel {
            self.cancel_all().await;
            return Err(NativeDownloadError::Cancelled);
        }
        if self.requested() == Requested::Pause {
            self.pause_all().await?;
            return Ok(self.monitor.status());
        }
        let chunk = match result {
            Ok(Some(chunk)) => chunk,
            Ok(None) => {
                self.phase(NativeDownloadPhase::SourceVerified);
                return Ok(self.monitor.status());
            }
            Err(error) => {
                let error = NativeDownloadError::from(error);
                self.monitor.0.send_modify(|state| {
                    state.error.get_or_insert(error);
                });
                // A source/transport failure can retain an authorized local
                // prefix only after the worker itself acknowledges idle pause.
                if self.pause_all().await.is_err() {
                    self.failure(error);
                }
                return Err(error);
            }
        };
        self.phase(NativeDownloadPhase::Saving);
        let source = self
            .source
            .as_ref()
            .ok_or(NativeDownloadError::State("missing source for disk write"))?;
        let mut pending = Box::pin(
            self.worker
                .as_mut()
                .ok_or(NativeDownloadError::State("missing destination"))?
                .write(source, chunk),
        );
        let result = loop {
            tokio::select! { biased;
                change = self.signals.changed() => {
                    if change.is_err() || self.signals.borrow().request != Requested::Running { break None; }
                }
                result = &mut pending => break Some(result),
            }
        };
        drop(pending);
        match result {
            Some(Ok(_)) => {
                let actual = self
                    .worker
                    .as_ref()
                    .ok_or(NativeDownloadError::State(
                        "missing acknowledged destination",
                    ))?
                    .monitor()
                    .status();
                self.monitor
                    .0
                    .send_modify(|state| state.destination = Some(actual));
                self.phase(NativeDownloadPhase::Ready);
                Ok(self.monitor.status())
            }
            Some(Err(error)) => {
                let error = disk(error);
                self.failure(error);
                Err(error)
            }
            None if self.requested() == Requested::Pause => {
                self.pause_all().await?;
                Ok(self.monitor.status())
            }
            None => {
                self.cancel_all().await;
                Err(NativeDownloadError::Cancelled)
            }
        }
    }
    async fn finish(&mut self) -> Result<NativeDownloadStatus, NativeDownloadError> {
        if self.requested() != Requested::Running
            || !self.monitor.status().source_verified
            || self.monitor.status().phase != NativeDownloadPhase::SourceVerified
        {
            return Err(NativeDownloadError::State(
                "finish requires the exact verified source End",
            ));
        }
        self.phase(NativeDownloadPhase::Finalizing);
        let source = self
            .source
            .as_ref()
            .ok_or(NativeDownloadError::State("missing verified source"))?;
        let mut pending = Box::pin(
            self.worker
                .as_mut()
                .ok_or(NativeDownloadError::State("missing destination"))?
                .finish(source),
        );
        let result = loop {
            tokio::select! { biased;
                change = self.signals.changed() => {
                    if change.is_err() || self.signals.borrow().request != Requested::Running { break None; }
                }
                result = &mut pending => break Some(result),
            }
        };
        drop(pending);
        match result {
            Some(Ok(_)) => {
                let worker = self
                    .worker
                    .as_mut()
                    .ok_or(NativeDownloadError::State("missing finalized destination"))?;
                let receipt = worker.shutdown().await.map_err(disk)?;
                let actual = worker.monitor().status();
                self.monitor.0.send_modify(|state| {
                    state.destination_shutdown = Some(receipt);
                    state.destination = Some(actual);
                    state.local_stopped = true;
                    state.phase = NativeDownloadPhase::Completed;
                });
                Ok(self.monitor.status())
            }
            Some(Err(error)) => {
                let error = disk(error);
                self.failure(error);
                Err(error)
            }
            None if self.requested() == Requested::Pause => {
                self.pause_all().await?;
                Ok(self.monitor.status())
            }
            None => {
                self.cancel_all().await;
                Err(NativeDownloadError::Cancelled)
            }
        }
    }
    async fn resume(
        &mut self,
        revision: u64,
        client: Option<NativeDownloadClient>,
    ) -> Result<NativeDownloadStatus, NativeDownloadError> {
        if self.requested() != Requested::Pause
            || self.monitor.status().phase != NativeDownloadPhase::Paused
            || self.signals.borrow().revision != revision
            || self.monitor.status().pause_ack_revision != revision
        {
            return Err(NativeDownloadError::State(
                "resume requires an acknowledged pause",
            ));
        }
        let status = self.monitor.status();
        let manifest = status
            .manifest
            .as_ref()
            .ok_or(NativeDownloadError::State("missing resume manifest"))?;
        let hash: [u8; 32] = manifest
            .sha256
            .as_slice()
            .try_into()
            .map_err(|_| NativeDownloadError::State("invalid resume hash"))?;
        let offset = self
            .worker
            .as_ref()
            .ok_or(NativeDownloadError::State("missing resume destination"))?
            .monitor()
            .status()
            .destination
            .confirmed_bytes;
        let (transfer, attempt) = self.begin_attempt(offset)?;
        self.monitor.0.send_modify(|state| {
            state.phase = NativeDownloadPhase::Pausing;
            state.source_request_pending = true;
        });
        let mut replacement = client;
        if let Some(client) = replacement.as_mut() {
            client.target = RetirementTarget::Auxiliary(Some(attempt));
        }
        let successor = match replacement.as_mut() {
            Some(client) => client
                .client
                .as_mut()
                .ok_or(NativeDownloadError::State("empty successor client"))?,
            None => &mut self.client,
        };
        let mut pending = Box::pin(successor.open(
            &transfer,
            &self.request.root_id,
            &self.request.relative_path,
            offset,
            Some(hash),
        ));
        let mut locally_stopped = false;
        let result = loop {
            tokio::select! { biased;
                changed = self.signals.changed(), if !locally_stopped => {
                    if changed.is_err() || self.signals.borrow().request == Requested::Cancel {
                        shutdown_destination(&mut self.worker, &self.monitor).await;
                        locally_stopped = true;
                    }
                }
                result = &mut pending => break result,
            }
        };
        drop(pending);
        self.monitor
            .0
            .send_modify(|state| state.source_request_pending = false);
        let mut source = result.map_err(|error| {
            let error = NativeDownloadError::from(error);
            self.monitor
                .0
                .send_modify(|state| state.source_attempts[attempt].error = Some(error));
            error
        })?;
        self.monitor.0.send_modify(|state| {
            state.source_attempts[attempt].manifest = Some(source.manifest().clone())
        });
        if self.signals.borrow().request == Requested::Cancel
            || self.signals.borrow().revision != revision
        {
            let _ = cancel_remote(
                successor,
                &mut source,
                &mut self.worker,
                &mut self.signals,
                &self.monitor,
                Some(attempt),
            )
            .await;
            return Err(NativeDownloadError::Cancelled);
        }
        let mut pending = Box::pin(
            self.worker
                .as_mut()
                .ok_or(NativeDownloadError::State("missing resume destination"))?
                .resume(successor, &source),
        );
        let result = loop {
            tokio::select! { biased;
                changed = self.signals.changed() => {
                    if changed.is_err() || self.signals.borrow().request == Requested::Cancel { break None; }
                }
                result = &mut pending => break Some(result),
            }
        };
        drop(pending);
        let resume_error = match result {
            Some(Ok(_)) => None,
            Some(Err(error)) => Some(disk(error)),
            None => {
                shutdown_destination(&mut self.worker, &self.monitor).await;
                Some(NativeDownloadError::Cancelled)
            }
        };
        if let Some(error) = resume_error {
            self.monitor
                .0
                .send_modify(|state| state.source_attempts[attempt].error = Some(error));
            let _ = cancel_remote(
                successor,
                &mut source,
                &mut self.worker,
                &mut self.signals,
                &self.monitor,
                Some(attempt),
            )
            .await;
            return Err(error);
        }
        if let Some(mut replacement) = replacement {
            let old = std::mem::replace(&mut self.client, replacement.take()?);
            let mut retired = NativeDownloadClient::new(
                old,
                self.monitor.clone(),
                RetirementTarget::Auxiliary(self.monitor.status().active_attempt),
            );
            let _ = retired.retire_owned();
        }
        self.source = Some(source);
        self.monitor.0.send_modify(|state| {
            state.active_attempt = Some(attempt);
            state.received_bytes = offset;
            state.source_verified = false;
            state.source_cancel_requested = false;
            state.source_cancel_acknowledged = false;
            state.source_cancel_error = None;
        });
        if self.requested() == Requested::Cancel || self.signals.borrow().revision != revision {
            self.pause_all().await?;
            return Err(NativeDownloadError::Cancelled);
        }
        let resumed = self.control.0.send_if_modified(|state| {
            if state.request == Requested::Pause && state.revision == revision {
                state.request = Requested::Running;
                true
            } else {
                false
            }
        });
        if !resumed {
            self.pause_all().await?;
            return Err(NativeDownloadError::Cancelled);
        }
        self.signals.borrow_and_update();
        self.monitor.0.send_modify(|state| {
            state.phase = NativeDownloadPhase::Ready;
            state.received_bytes = offset;
            state.source_verified = false;
            state.source_cancel_requested = false;
            state.source_cancel_acknowledged = false;
            state.source_cancel_error = None;
        });
        Ok(self.monitor.status())
    }
}
