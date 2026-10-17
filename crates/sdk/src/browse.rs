//! Application-owned directory pagination on one proved FileRead claimant.
//! Wire cursors stay inside the actor; pages contain metadata, never authority.
use nestlink_auth::random_id;
use nestlink_protocol::{
    ContractError, DIRECTORY_PAGE_ENTRIES, DIRECTORY_SNAPSHOT_MS, DirectoryBrowseBegin,
    DirectoryBrowsePage, DirectoryEntry, ErrorCode, FILE_OPERATION_MS, FileReadErrorCode,
};
use nestlink_remote::{
    ChannelRuntime, LeaseControl, RemoteError,
    files::{DirectoryBrowse, FileDestinationFactory, FileReadClient, FileReadError},
};
use nestlink_transport_stream::Channel;
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, watch};

#[derive(Clone, Debug)]
pub struct NativeBrowseRequest {
    root_id: String,
    directory: String,
    maximum: u32,
    operation_budget: Duration,
    snapshot_lifetime: Duration,
}
impl NativeBrowseRequest {
    pub fn new(
        root_id: &str,
        directory: Option<&str>,
        maximum: u32,
    ) -> Result<Self, ContractError> {
        let begin = DirectoryBrowseBegin {
            root_id: root_id.into(),
            directory: directory.unwrap_or_default().into(),
            maximum,
        };
        begin.validate()?;
        Ok(Self {
            root_id: begin.root_id,
            directory: begin.directory,
            maximum,
            operation_budget: Duration::from_millis(FILE_OPERATION_MS),
            snapshot_lifetime: Duration::from_millis(DIRECTORY_SNAPSHOT_MS),
        })
    }
    /// Lower SDK delivery bounds. These do not alter the remote root's limits.
    pub fn with_budgets(
        mut self,
        operation_budget: Duration,
        snapshot_lifetime: Duration,
    ) -> Result<Self, ContractError> {
        if operation_budget.is_zero()
            || operation_budget > Duration::from_millis(FILE_OPERATION_MS)
            || snapshot_lifetime.is_zero()
            || snapshot_lifetime > Duration::from_millis(DIRECTORY_SNAPSHOT_MS)
        {
            return Err(ContractError::new(
                ErrorCode::InvalidMessage,
                "invalid SDK browse budget",
            ));
        }
        self.operation_budget = operation_budget;
        self.snapshot_lifetime = snapshot_lifetime;
        Ok(self)
    }
    pub fn root_id(&self) -> &str {
        &self.root_id
    }
    pub fn directory(&self) -> Option<&str> {
        (!self.directory.is_empty()).then_some(self.directory.as_str())
    }
    pub fn maximum(&self) -> u32 {
        self.maximum
    }
}

/// Already delivered metadata. No local BrowseCursor or network continuation
/// token is exposed or serialized; this value cannot initiate a source request.
#[derive(Clone, Debug, PartialEq)]
pub struct NativeDirectoryPage {
    pub root_id: String,
    pub directory: String,
    pub snapshot_id: Vec<u8>,
    pub offset: u32,
    pub total_entries: u32,
    pub entries: Vec<DirectoryEntry>,
    pub has_more: bool,
}
impl From<DirectoryBrowsePage> for NativeDirectoryPage {
    fn from(page: DirectoryBrowsePage) -> Self {
        Self {
            root_id: page.root_id,
            directory: page.directory,
            snapshot_id: page.snapshot_id,
            offset: page.offset,
            total_entries: page.total_entries,
            entries: page.entries,
            has_more: !page.next_cursor.is_empty(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeBrowseError {
    #[error("directory source rejected the operation: {0:?}")]
    Source(FileReadErrorCode),
    #[error("directory transport failed: {0:?}")]
    Transport(io::ErrorKind),
    #[error("directory platform cleanup failed: {0:?}")]
    Cleanup(io::ErrorKind),
    #[error("directory authorization failed ({code:?}): {reason}")]
    Authorization {
        code: ErrorCode,
        reason: &'static str,
    },
    #[error("directory connection stopped")]
    Stopped,
    #[error("directory delivery or snapshot expired")]
    Expired,
    #[error("directory operation unavailable: {0}")]
    State(&'static str),
    #[error("directory browse was cancelled")]
    Cancelled,
}
impl From<FileReadError> for NativeBrowseError {
    fn from(error: FileReadError) -> Self {
        match error {
            FileReadError::Source(code) => Self::Source(code),
            FileReadError::Remote(error) => error.into(),
        }
    }
}
impl From<RemoteError> for NativeBrowseError {
    fn from(error: RemoteError) -> Self {
        match error {
            RemoteError::Io(error) => Self::Transport(error.kind()),
            RemoteError::Cleanup(error) => Self::Cleanup(error.kind()),
            RemoteError::Authorization(error) => Self::Authorization {
                code: error.code,
                reason: error.reason,
            },
            RemoteError::Stopped => Self::Stopped,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NativeBrowsePhase {
    #[default]
    Beginning,
    Ready,
    Reading,
    Completed,
    Cancelling,
    Cancelled,
    Failed,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NativeBrowseStatus {
    pub phase: NativeBrowsePhase,
    pub transfer_id: String,
    pub pages_received: u32,
    pub pages_delivered: u32,
    pub entries_received: u32,
    pub total_entries: Option<u32>,
    pub source_request_pending: bool,
    /// Exact final page, business failure or Cancel response was consumed.
    /// A stopped transport alone does not certify remote source cleanup.
    pub source_closed: bool,
    pub source_error: Option<NativeBrowseError>,
    pub source_cancel_requested: bool,
    pub source_cancel_acknowledged: bool,
    pub source_cancel_error: Option<NativeBrowseError>,
    pub delivery_stopped: bool,
    pub actor_finished: bool,
    pub client_retirement: Option<Result<(), NativeBrowseError>>,
    pub error: Option<NativeBrowseError>,
}
#[derive(Clone, Default)]
struct State {
    status: NativeBrowseStatus,
    stop: Option<NativeBrowseError>,
}
#[derive(Clone)]
pub struct NativeBrowseMonitor(watch::Sender<State>);
impl NativeBrowseMonitor {
    pub fn status(&self) -> NativeBrowseStatus {
        self.0.borrow().status.clone()
    }
    pub async fn wait_finished(&self) -> NativeBrowseStatus {
        let mut updates = self.0.subscribe();
        loop {
            let current = updates.borrow_and_update().status.clone();
            if current.actor_finished || updates.changed().await.is_err() {
                return current;
            }
        }
    }
}
/// Sticky local cancellation, without session-stop authority. May be retained
/// while the owning browse waits for its first page or a continuation.
#[derive(Clone)]
pub struct NativeBrowseControl(NativeBrowseMonitor);
impl NativeBrowseControl {
    pub fn cancel(&self) {
        self.stop(NativeBrowseError::Cancelled);
    }
    fn stop(&self, error: NativeBrowseError) {
        self.0.0.send_modify(|state| {
            if state.stop.is_none() {
                state.stop = Some(error);
                state.status.delivery_stopped = true;
                state.status.error.get_or_insert(error);
                if !state.status.actor_finished {
                    state.status.phase = if error == NativeBrowseError::Cancelled {
                        NativeBrowsePhase::Cancelling
                    } else {
                        NativeBrowsePhase::Failed
                    };
                }
            }
        });
    }
    fn error(&self) -> Option<NativeBrowseError> {
        self.0.0.borrow().stop
    }
}
struct PageReply {
    page: NativeDirectoryPage,
    operation_deadline: Instant,
    snapshot_deadline: Instant,
}
type PageResult = Result<PageReply, NativeBrowseError>;
enum Command {
    Next {
        maximum: u32,
        deadline: Instant,
        reply: oneshot::Sender<PageResult>,
    },
}
struct PageWait<'a> {
    busy: &'a AtomicBool,
    control: NativeBrowseControl,
    armed: bool,
}
impl<'a> PageWait<'a> {
    fn acquire(
        busy: &'a AtomicBool,
        control: NativeBrowseControl,
    ) -> Result<Self, NativeBrowseError> {
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| NativeBrowseError::State("a directory page is already pending"))?;
        Ok(Self {
            busy,
            control,
            armed: true,
        })
    }
    fn complete(&mut self) {
        self.armed = false;
    }
}
impl Drop for PageWait<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.control.cancel();
        }
        self.busy.store(false, Ordering::Release);
    }
}

/// One fixed snapshot with one outstanding page slot. Requires a Tokio runtime.
/// The owned actor drains an issued RPC even after an application wait is dropped.
pub struct NativeDirectoryBrowse {
    commands: mpsc::Sender<Command>,
    monitor: NativeBrowseMonitor,
    control: NativeBrowseControl,
    lease: LeaseControl,
    generation: u64,
    operation_budget: Duration,
    snapshot_deadline: Instant,
    first_deadline: Instant,
    first: Option<oneshot::Receiver<PageResult>>,
    first_consumed: bool,
    busy: AtomicBool,
    client_return: Option<oneshot::Receiver<NativeBrowseClient>>,
}
impl NativeDirectoryBrowse {
    pub fn attach(
        runtime: &mut ChannelRuntime,
        generation: u64,
        request: NativeBrowseRequest,
    ) -> Result<Self, RemoteError> {
        let lease = runtime.lease_control();
        let client = FileReadClient::attach(runtime, generation)?;
        Ok(Self::start(client, lease, generation, request))
    }
    fn start(
        client: FileReadClient,
        lease: LeaseControl,
        generation: u64,
        request: NativeBrowseRequest,
    ) -> Self {
        let started = Instant::now();
        let first_deadline = started + request.operation_budget;
        let snapshot_deadline = started + request.snapshot_lifetime;
        let (commands, inbox) = mpsc::channel(1);
        let (first_reply, first) = oneshot::channel();
        let (return_client, client_return) = oneshot::channel();
        let id = random_id();
        let (state, _) = watch::channel(State {
            status: NativeBrowseStatus {
                transfer_id: id.clone(),
                ..NativeBrowseStatus::default()
            },
            stop: None,
        });
        let monitor = NativeBrowseMonitor(state);
        let control = NativeBrowseControl(monitor.clone());
        let actor = Actor {
            client,
            lease: lease.clone(),
            generation,
            request: request.clone(),
            source: None,
            client_idle: true,
            monitor: monitor.clone(),
            control: control.clone(),
            snapshot_deadline,
        };
        tokio::spawn(actor.run(id, first_deadline, first_reply, inbox, return_client));
        Self {
            commands,
            monitor,
            control,
            lease,
            generation,
            operation_budget: request.operation_budget,
            snapshot_deadline,
            first_deadline,
            first: Some(first),
            first_consumed: false,
            busy: AtomicBool::new(false),
            client_return: Some(client_return),
        }
    }
    pub fn status(&self) -> NativeBrowseStatus {
        self.monitor.status()
    }
    pub fn monitor(&self) -> NativeBrowseMonitor {
        self.monitor.clone()
    }
    pub fn control(&self) -> NativeBrowseControl {
        self.control.clone()
    }
    /// Consume the first page once. Delaying this consume cannot renew its budget.
    pub async fn ready(&mut self) -> Result<NativeDirectoryPage, NativeBrowseError> {
        if self.first.is_none() {
            return Err(NativeBrowseError::State(
                "first directory page already consumed",
            ));
        }
        let mut wait = PageWait::acquire(&self.busy, self.control.clone())?;
        let result = wait_page(
            self.first.as_mut().ok_or(NativeBrowseError::State(
                "first directory page already consumed",
            ))?,
            &self.control,
            &self.lease,
            self.generation,
            self.first_deadline.min(self.snapshot_deadline),
        )
        .await;
        wait.complete();
        self.first.take();
        self.first_consumed = result.is_ok();
        result
    }
    /// Concurrent calls are rejected before any extra request enters the actor.
    /// An abandoned wait cancels this browse; refresh needs a fresh source UUID.
    pub async fn next_page(
        &self,
        maximum: u32,
    ) -> Result<Option<NativeDirectoryPage>, NativeBrowseError> {
        if maximum == 0 || u64::from(maximum) > DIRECTORY_PAGE_ENTRIES {
            return Err(NativeBrowseError::State("invalid directory page maximum"));
        }
        check_live(
            &self.control,
            &self.lease,
            self.generation,
            self.snapshot_deadline,
        )?;
        if !self.first_consumed {
            return Err(NativeBrowseError::State(
                "consume the first directory page first",
            ));
        }
        let mut wait = PageWait::acquire(&self.busy, self.control.clone())?;
        if self.status().source_closed {
            wait.complete();
            return Ok(None);
        }
        let deadline = Instant::now() + self.operation_budget;
        let (reply, mut result) = oneshot::channel();
        if self
            .commands
            .try_send(Command::Next {
                maximum,
                deadline,
                reply,
            })
            .is_err()
        {
            wait.complete();
            return Err(self
                .status()
                .error
                .unwrap_or(NativeBrowseError::State("directory owner is unavailable")));
        }
        let result = wait_page(
            &mut result,
            &self.control,
            &self.lease,
            self.generation,
            deadline.min(self.snapshot_deadline),
        )
        .await;
        wait.complete();
        result.map(Some)
    }
    /// Immediately suppresses further pages; exact remote cleanup is separate.
    pub fn cancel(&self) -> NativeBrowseStatus {
        self.control.cancel();
        self.status()
    }
    /// Wait for the actor to drain the original RPC and exact source cleanup.
    /// A dropped wait leaves the original return slot intact.
    pub async fn take_client(&mut self) -> Result<NativeBrowseClient, NativeBrowseError> {
        let status = self.status();
        if !status.actor_finished && !status.delivery_stopped && !status.source_closed {
            return Err(NativeBrowseError::State(
                "client return requires a completed or cancelled browse",
            ));
        }
        let receiver = self
            .client_return
            .as_mut()
            .ok_or(NativeBrowseError::State("directory client already taken"))?;
        let client = receiver.await.map_err(|_| {
            self.monitor
                .status()
                .error
                .unwrap_or(NativeBrowseError::State(
                    "directory actor ended without returning the client",
                ))
        })?;
        self.client_return.take();
        Ok(client)
    }
    pub async fn release_client(&mut self) -> Result<NativeBrowseStatus, NativeBrowseError> {
        self.take_client().await?.retire()?;
        Ok(self.status())
    }
}
impl Drop for NativeDirectoryBrowse {
    fn drop(&mut self) {
        self.control.cancel();
    }
}

/// Exact idle claimant returned by directory cleanup. Its authority and sequence
/// stay bound to the original connection. Drop retires FileRead safely.
pub struct NativeBrowseClient {
    client: Option<FileReadClient>,
    lease: LeaseControl,
    generation: u64,
    idle: bool,
    monitor: NativeBrowseMonitor,
}
impl NativeBrowseClient {
    fn take(&mut self) -> Result<FileReadClient, NativeBrowseError> {
        if !self.idle {
            return Err(self.cleanup_error());
        }
        self.client.take().ok_or(NativeBrowseError::State(
            "directory client already consumed",
        ))
    }
    pub fn begin(
        mut self,
        request: NativeBrowseRequest,
    ) -> Result<NativeDirectoryBrowse, NativeBrowseError> {
        self.lease
            .check_channel_binding(Channel::FileRead, self.generation)?;
        Ok(NativeDirectoryBrowse::start(
            self.take()?,
            self.lease.clone(),
            self.generation,
            request,
        ))
    }
    pub fn start_download(
        mut self,
        request: crate::files::NativeDownloadRequest,
        destination: impl FileDestinationFactory,
    ) -> Result<crate::files::NativeFileDownload, NativeBrowseError> {
        self.lease
            .check_channel_binding(Channel::FileRead, self.generation)?;
        Ok(crate::files::NativeFileDownload::start(
            self.take()?,
            request,
            destination,
        ))
    }
    /// Advanced ownership transfer. Ordinary raw client Drop stops the session.
    pub fn into_client(mut self) -> Result<FileReadClient, NativeBrowseError> {
        self.take()
    }
    pub fn retire(mut self) -> Result<(), NativeBrowseError> {
        self.retire_owned()
    }
    fn cleanup_error(&self) -> NativeBrowseError {
        let status = self.monitor.status();
        status
            .source_cancel_error
            .or(status.source_error)
            .unwrap_or(NativeBrowseError::State(
                "source cleanup was not acknowledged",
            ))
    }
    fn retire_owned(&mut self) -> Result<(), NativeBrowseError> {
        let Some(client) = self.client.take() else {
            return Ok(());
        };
        let result = if self.idle {
            client.retire().map_err(NativeBrowseError::from)
        } else {
            // Never call protocol-failure retirement on an unconsumed network
            // RPC. Its implicit Drop preserves an existing transport stop.
            drop(client);
            Err(self.cleanup_error())
        };
        self.monitor
            .0
            .send_modify(|state| state.status.client_retirement = Some(result));
        result
    }
}
impl Drop for NativeBrowseClient {
    fn drop(&mut self) {
        let _ = self.retire_owned();
    }
}

fn check_live(
    control: &NativeBrowseControl,
    lease: &LeaseControl,
    generation: u64,
    deadline: Instant,
) -> Result<(), NativeBrowseError> {
    if let Some(error) = control.error() {
        return Err(error);
    }
    if let Err(error) = lease.check_channel_binding(Channel::FileRead, generation) {
        let error = NativeBrowseError::from(error);
        control.stop(error);
        return Err(error);
    }
    if Instant::now() >= deadline {
        control.stop(NativeBrowseError::Expired);
        return Err(NativeBrowseError::Expired);
    }
    if let Some(error) = control.error() {
        return Err(error);
    }
    Ok(())
}
async fn wait_page(
    receiver: &mut oneshot::Receiver<PageResult>,
    control: &NativeBrowseControl,
    lease: &LeaseControl,
    generation: u64,
    deadline: Instant,
) -> Result<NativeDirectoryPage, NativeBrowseError> {
    let mut updates = control.0.0.subscribe();
    let mut stopped = lease.subscribe_stopped();
    let reply = loop {
        check_live(control, lease, generation, deadline)?;
        updates.borrow_and_update();
        tokio::select! { biased;
            result = updates.changed() => {
                if result.is_err() { return Err(NativeBrowseError::State("directory monitor closed")); }
            }
            _ = stopped.changed() => {}
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
            reply = &mut *receiver => break reply.map_err(|_| {
                control.0.status().error.unwrap_or(NativeBrowseError::State("directory reply unavailable"))
            })??,
        }
    };
    check_live(
        control,
        lease,
        generation,
        reply.operation_deadline.min(reply.snapshot_deadline),
    )?;
    let page = reply.page;
    check_live(control, lease, generation, deadline)?;
    control.0.0.send_modify(|state| {
        state.status.pages_delivered = state.status.pages_delivered.saturating_add(1);
    });
    Ok(page)
}

/// Observe cancellation/expiry without dropping the exact lower-layer future.
async fn drain<T>(
    future: impl std::future::Future<Output = Result<T, FileReadError>>,
    control: &NativeBrowseControl,
    lease: &LeaseControl,
    generation: u64,
    deadline: Instant,
) -> Result<T, FileReadError> {
    let mut pending = std::pin::pin!(future);
    let mut stopped = lease.subscribe_stopped();
    let mut checked_stop = false;
    let mut expired = false;
    loop {
        tokio::select! { biased;
            _ = stopped.changed(), if !checked_stop => {
                checked_stop = true;
                if let Err(error) = lease.check_channel_binding(Channel::FileRead, generation) {
                    control.stop(error.into());
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)), if !expired => {
                expired = true;
                control.stop(NativeBrowseError::Expired);
            }
            result = &mut pending => return result,
        }
    }
}
struct Actor {
    client: FileReadClient,
    lease: LeaseControl,
    generation: u64,
    request: NativeBrowseRequest,
    source: Option<DirectoryBrowse>,
    client_idle: bool,
    monitor: NativeBrowseMonitor,
    control: NativeBrowseControl,
    snapshot_deadline: Instant,
}
struct Completion(NativeBrowseMonitor);
impl Drop for Completion {
    fn drop(&mut self) {
        self.0.0.send_modify(|state| {
            if !state.status.actor_finished {
                state.status.actor_finished = true;
                state.status.phase = NativeBrowsePhase::Failed;
                state.status.error.get_or_insert(NativeBrowseError::State(
                    "directory actor ended unexpectedly",
                ));
                state.status.delivery_stopped = true;
                state.stop.get_or_insert(NativeBrowseError::State(
                    "directory actor ended unexpectedly",
                ));
            }
        });
    }
}
impl Actor {
    fn pending(&self, phase: NativeBrowsePhase) {
        self.monitor.0.send_modify(|state| {
            state.status.source_request_pending = true;
            if state.stop.is_none() {
                state.status.phase = phase;
            }
        });
    }
    fn source_failure(&mut self, error: FileReadError) -> NativeBrowseError {
        self.client_idle = matches!(error, FileReadError::Source(_));
        let error = NativeBrowseError::from(error);
        self.monitor.0.send_modify(|state| {
            state.status.source_error = Some(error);
            state.status.source_request_pending = false;
            state.status.source_closed = self.client_idle;
        });
        self.control.stop(error);
        error
    }
    fn page(&mut self, page: DirectoryBrowsePage, deadline: Instant) -> PageResult {
        self.client_idle = page.next_cursor.is_empty();
        self.monitor.0.send_modify(|state| {
            state.status.source_request_pending = false;
            state.status.source_closed = self.client_idle;
            state.status.pages_received += 1;
            state.status.entries_received = page.offset + page.entries.len() as u32;
            state.status.total_entries = Some(page.total_entries);
            if state.stop.is_none() {
                state.status.phase = if self.client_idle {
                    NativeBrowsePhase::Completed
                } else {
                    NativeBrowsePhase::Ready
                };
            }
        });
        check_live(
            &self.control,
            &self.lease,
            self.generation,
            deadline.min(self.snapshot_deadline),
        )?;
        let page = NativeDirectoryPage::from(page);
        check_live(
            &self.control,
            &self.lease,
            self.generation,
            deadline.min(self.snapshot_deadline),
        )?;
        Ok(PageReply {
            page,
            operation_deadline: deadline,
            snapshot_deadline: self.snapshot_deadline,
        })
    }
    async fn cancel_source(&mut self) {
        let Some(source) = self.source.as_mut() else {
            return;
        };
        if self.client_idle || source.finished() {
            return;
        }
        self.monitor.0.send_modify(|state| {
            state.status.source_cancel_requested = true;
            state.status.source_request_pending = true;
        });
        let result = drain(
            self.client.cancel_browse(source),
            &self.control,
            &self.lease,
            self.generation,
            Instant::now() + self.request.operation_budget,
        )
        .await;
        self.client_idle = result.is_ok() || matches!(result, Err(FileReadError::Source(_)));
        let result = result.map_err(NativeBrowseError::from);
        self.monitor.0.send_modify(|state| {
            state.status.source_request_pending = false;
            state.status.source_closed = self.client_idle;
            match result {
                Ok(()) => state.status.source_cancel_acknowledged = true,
                Err(error) => state.status.source_cancel_error = Some(error),
            }
        });
    }
    async fn run(
        mut self,
        id: String,
        first_deadline: Instant,
        first_reply: oneshot::Sender<PageResult>,
        mut inbox: mpsc::Receiver<Command>,
        return_client: oneshot::Sender<NativeBrowseClient>,
    ) {
        let _completion = Completion(self.monitor.clone());
        let result = if let Err(error) = check_live(
            &self.control,
            &self.lease,
            self.generation,
            first_deadline.min(self.snapshot_deadline),
        ) {
            self.monitor
                .0
                .send_modify(|state| state.status.source_closed = true);
            Err(error)
        } else {
            self.pending(NativeBrowsePhase::Beginning);
            let result = drain(
                self.client.begin_browse(
                    &id,
                    &self.request.root_id,
                    self.request.directory(),
                    self.request.maximum,
                ),
                &self.control,
                &self.lease,
                self.generation,
                first_deadline.min(self.snapshot_deadline),
            )
            .await;
            match result {
                Ok(source) => {
                    let page = source.page().clone();
                    self.source = Some(source);
                    self.page(page, first_deadline)
                }
                Err(error) => Err(self.source_failure(error)),
            }
        };
        if first_reply.send(result).is_err() {
            self.control.cancel();
        }
        let mut updates = self.monitor.0.subscribe();
        let mut stopped = self.lease.subscribe_stopped();
        while !self.client_idle && self.control.error().is_none() {
            if let Err(error) = check_live(
                &self.control,
                &self.lease,
                self.generation,
                self.snapshot_deadline,
            ) {
                self.control.stop(error);
                break;
            }
            updates.borrow_and_update();
            let command = tokio::select! { biased;
                _ = updates.changed() => continue,
                _ = stopped.changed() => {
                    if let Err(error) = self.lease.check_channel_binding(Channel::FileRead, self.generation) {
                        self.control.stop(error.into());
                    }
                    continue;
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(self.snapshot_deadline)) => {
                    self.control.stop(NativeBrowseError::Expired);
                    continue;
                }
                command = inbox.recv() => match command {
                    Some(command) => command,
                    None => { self.control.cancel(); break; }
                },
            };
            let Command::Next {
                maximum,
                deadline,
                reply,
            } = command;
            let result = if reply.is_closed() {
                self.control.cancel();
                Err(NativeBrowseError::Cancelled)
            } else if let Err(error) = check_live(
                &self.control,
                &self.lease,
                self.generation,
                deadline.min(self.snapshot_deadline),
            ) {
                Err(error)
            } else if let Some(source) = self.source.as_mut() {
                self.monitor.0.send_modify(|state| {
                    state.status.source_request_pending = true;
                    if state.stop.is_none() {
                        state.status.phase = NativeBrowsePhase::Reading;
                    }
                });
                let result = drain(
                    self.client.next_browse(source, maximum),
                    &self.control,
                    &self.lease,
                    self.generation,
                    deadline.min(self.snapshot_deadline),
                )
                .await;
                match result {
                    Ok(Some(page)) => self.page(page, deadline),
                    Ok(None) => {
                        self.control.stop(NativeBrowseError::State(
                            "directory source ended without its final page",
                        ));
                        Err(NativeBrowseError::State(
                            "directory source ended without its final page",
                        ))
                    }
                    Err(error) => Err(self.source_failure(error)),
                }
            } else {
                self.control
                    .stop(NativeBrowseError::State("directory source unavailable"));
                Err(NativeBrowseError::State("directory source unavailable"))
            };
            if reply.send(result).is_err() {
                self.control.cancel();
            }
        }
        self.cancel_source().await;
        self.monitor.0.send_modify(|state| {
            state.status.actor_finished = true;
            if let Some(error) = state.stop {
                state.status.phase = if error == NativeBrowseError::Cancelled {
                    NativeBrowsePhase::Cancelled
                } else {
                    NativeBrowsePhase::Failed
                };
            }
        });
        let _ = return_client.send(NativeBrowseClient {
            client: Some(self.client),
            lease: self.lease,
            generation: self.generation,
            idle: self.client_idle,
            monitor: self.monitor,
        });
    }
}
