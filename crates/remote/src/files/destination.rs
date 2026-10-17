//! A single owned destination worker. Revocation stops new disk calls; an OS
//! call already issued may finish later, and its actual effects stay observable.
use super::*;
use nestlink_session::SessionBinding;
use std::sync::{Mutex, OnceLock, atomic::AtomicUsize};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileDestinationStatus {
    pub confirmed_bytes: u64,
    pub published: bool,
    pub file_closed: bool,
    pub temporary_removed: bool,
    pub directory_synced: bool,
    pub poisoned: bool,
}
/// Methods execute only on the owning std thread, outside authorization locks.
/// `status` reports actual effects even when a method returns an error.
/// Propagate authorization callback errors unchanged. OS errors with the same
/// ErrorKind are fatal and must not be mistaken for a resumable pause.
pub trait FileDestination: Send + 'static {
    fn status(&self) -> FileDestinationStatus;
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()>;
    fn write(
        &mut self,
        source: &FileDownloadSnapshot,
        chunk: &FileReadChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()>;
    fn resume(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()>;
    fn finish(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()>;
    /// Local owner cleanup remains valid after business or local consent stops.
    fn cleanup(&mut self) -> io::Result<()>;
}
pub trait FileDestinationFactory: Send + 'static {
    /// Pure local fact, available before any directory or file is opened.
    fn consent(&self) -> Arc<dyn FileReadConsent>;
    /// Construct state without opening files. `prepare` owns all disk effects,
    /// including partial initialization and its eventual cleanup.
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FileDownloadPhase {
    #[default]
    Starting,
    Active,
    Paused,
    Completed,
    Stopped,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileDownloadWorkerStatus {
    pub phase: FileDownloadPhase,
    pub destination: FileDestinationStatus,
    /// True only after the thread has destroyed the provider and its handles.
    pub finished: bool,
    pub cleanup_timed_out: bool,
    pub error: Option<io::ErrorKind>,
    pub cleanup_error: Option<io::ErrorKind>,
}
pub const FILE_DOWNLOAD_WORKER_LIMIT: usize = 32;
const JOIN_POLL: Duration = Duration::from_millis(1);
static WORKER_SLOTS: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
static RETAINED_WORKERS: Mutex<Vec<Arc<DownloadShared>>> = Mutex::new(Vec::new());

struct WorkerSlot(Arc<AtomicUsize>);
impl WorkerSlot {
    fn reserve() -> io::Result<Self> {
        reap_retained_workers();
        Self::reserve_from(
            WORKER_SLOTS
                .get_or_init(|| Arc::new(AtomicUsize::new(0)))
                .clone(),
        )
    }
    fn reserve_from(slots: Arc<AtomicUsize>) -> io::Result<Self> {
        slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(1)
                    .filter(|next| *next <= FILE_DOWNLOAD_WORKER_LIMIT)
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "download actual worker ownership budget exhausted",
                )
            })?;
        Ok(Self(slots))
    }
}
impl Drop for WorkerSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct OwnedWorker {
    handle: thread::JoinHandle<()>,
    _slot: WorkerSlot,
}
enum WorkerState {
    NotStarted,
    Running(OwnedWorker),
    Joining,
    Joined,
}

/// One shared owner keeps the original OS thread handle through timeout and
/// Drop. A monitor can publish `finished` only after this exact handle joins.
struct DownloadShared {
    status: watch::Sender<FileDownloadWorkerStatus>,
    worker: Mutex<WorkerState>,
    cleanup_until: Mutex<Option<Instant>>,
}
impl DownloadShared {
    fn new() -> Self {
        let (status, _) = watch::channel(FileDownloadWorkerStatus::default());
        Self {
            status,
            worker: Mutex::new(WorkerState::NotStarted),
            cleanup_until: Mutex::new(None),
        }
    }
    fn install_worker(&self, handle: thread::JoinHandle<()>, slot: WorkerSlot) {
        *self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            WorkerState::Running(OwnedWorker {
                handle,
                _slot: slot,
            });
    }
    fn begin_cleanup(&self) -> Instant {
        let mut deadline = self
            .cleanup_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_millis(FILE_WORKER_CLEANUP_MS))
    }
    fn mark_timed_out(&self) {
        self.status.send_if_modified(|status| {
            if status.cleanup_timed_out {
                false
            } else {
                status.cleanup_timed_out = true;
                true
            }
        });
    }
    fn worker_joined(&self) -> bool {
        let worker = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        matches!(&*worker, WorkerState::Joined)
    }
    fn try_join(&self) {
        let worker = {
            let mut current = self
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !matches!(&*current, WorkerState::Running(worker) if worker.handle.is_finished()) {
                return;
            }
            match std::mem::replace(&mut *current, WorkerState::Joining) {
                WorkerState::Running(worker) => worker,
                previous => {
                    *current = previous;
                    return;
                }
            }
        };
        let OwnedWorker { handle, _slot } = worker;
        let join_failed = handle.join().is_err();
        let joined_at = Instant::now();
        let timed_out = self
            .cleanup_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some_and(|deadline| joined_at > deadline);
        *self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = WorkerState::Joined;
        drop(_slot);
        self.status.send_modify(|status| {
            if timed_out {
                status.cleanup_timed_out = true;
            }
            if join_failed {
                status.error.get_or_insert(io::ErrorKind::Other);
                status.cleanup_error.get_or_insert(io::ErrorKind::Other);
                if status.phase != FileDownloadPhase::Completed {
                    status.phase = FileDownloadPhase::Stopped;
                }
            }
            status.finished = true;
        });
        RETAINED_WORKERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|owner| !std::ptr::eq(Arc::as_ptr(owner), self as *const Self));
    }
    fn snapshot(&self) -> FileDownloadWorkerStatus {
        self.try_join();
        let timed_out = {
            let deadline = self
                .cleanup_until
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            !self.worker_joined() && deadline.is_some_and(|until| Instant::now() >= until)
        };
        if timed_out {
            self.mark_timed_out();
        }
        *self.status.borrow()
    }
}

fn reap_retained_workers() {
    let owners = RETAINED_WORKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    for owner in &owners {
        owner.try_join();
    }
    let joined = owners
        .iter()
        .filter(|owner| owner.worker_joined())
        .map(Arc::as_ptr)
        .collect::<Vec<_>>();
    RETAINED_WORKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|owner| !joined.contains(&Arc::as_ptr(owner)));
}

/// Keep the same owner after a bounded shutdown timeout. Every retained owner
/// still holds one of the pre-spawn slots, so this table is inherently bounded.
fn retain_worker(shared: Arc<DownloadShared>) {
    reap_retained_workers();
    shared.try_join();
    let worker = shared
        .worker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if matches!(&*worker, WorkerState::Joined) {
        return;
    }
    let mut retained = RETAINED_WORKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !retained.iter().any(|owner| Arc::ptr_eq(owner, &shared)) {
        retained.push(shared.clone());
    }
}

#[derive(Clone)]
pub struct FileDownloadMonitor(Arc<DownloadShared>);
impl FileDownloadMonitor {
    pub fn status(&self) -> FileDownloadWorkerStatus {
        reap_retained_workers();
        self.0.snapshot()
    }
    pub fn subscribe(&self) -> FileDownloadSubscription {
        reap_retained_workers();
        let _ = self.0.snapshot();
        FileDownloadSubscription {
            monitor: self.clone(),
            updates: self.0.status.subscribe(),
        }
    }
}

/// An owned subscription drives the same original thread's nonblocking join.
/// A raw watch receiver cannot observe OS thread exit after the last provider
/// update. Polling stays inside the caller's future; cancelling that future
/// creates no detached observer and leaves the original owner intact.
#[derive(Clone)]
pub struct FileDownloadSubscription {
    monitor: FileDownloadMonitor,
    updates: watch::Receiver<FileDownloadWorkerStatus>,
}
impl FileDownloadSubscription {
    pub fn borrow(&self) -> watch::Ref<'_, FileDownloadWorkerStatus> {
        self.updates.borrow()
    }

    pub fn borrow_and_update(&mut self) -> watch::Ref<'_, FileDownloadWorkerStatus> {
        let _ = self.monitor.status();
        self.updates.borrow_and_update()
    }

    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        loop {
            let _ = self.monitor.status();
            tokio::select! {
                result = self.updates.changed() => return result,
                _ = tokio::time::sleep(Duration::from_millis(50)) => {},
            }
        }
    }
}
#[derive(Clone)]
pub(super) struct Context {
    pub lease: LeaseControl,
    pub generation: u64,
    pub identity: SessionBinding,
    pub source: (String, String),
    pub snapshot: FileDownloadSnapshot,
}
impl Context {
    fn check(&self, source: &FileDownloadSnapshot, finish: bool) -> io::Result<()> {
        self.lease
            .check_channel_binding(Channel::FileRead, self.generation)
            .map_err(|_| denied("download session stopped"))?;
        if !self.snapshot.binding().matches(source)
            || (finish && !source.source_verified())
            || (!finish && source.finished())
        {
            return Err(denied(
                "download view is stale, closed or from another transfer",
            ));
        }
        Ok(())
    }
    fn accepts(&self, successor: &Self) -> io::Result<()> {
        if self.identity != successor.identity
            || self.source != successor.source
            || self.snapshot.manifest().size != successor.snapshot.manifest().size
            || self.snapshot.manifest().sha256 != successor.snapshot.manifest().sha256
            || successor.generation < self.generation
            || (successor.generation == self.generation
                && !self
                    .snapshot
                    .binding()
                    .same_client(&successor.snapshot.binding()))
        {
            return Err(denied(
                "resumed download changes its verified scope or connection owner",
            ));
        }
        successor.check(&successor.snapshot, false)
    }
    fn may_pause(&self) -> bool {
        self.lease.file_pause_allowed()
    }
}
fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
fn interrupted() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "download worker is paused or cancelled",
    )
}
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct BoundaryFailure(io::Error);
fn boundary_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), BoundaryFailure(error))
}
struct OperationControl {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}
impl OperationControl {
    fn new(budget: Duration) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + budget,
        }
    }
    fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "download disk operation timed out",
            ));
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Err(interrupted());
        }
        Ok(())
    }
}
enum Operation {
    Write(FileDownloadSnapshot, FileReadChunk),
    Finish(FileDownloadSnapshot),
    Pause,
    Resume(Box<Context>),
}
struct Reply {
    context: Context,
    result: io::Result<FileDestinationStatus>,
}
struct Job {
    operation: Operation,
    control: OperationControl,
    reply: oneshot::Sender<Reply>,
}
/// Dropping an async wait invalidates that exact operation. A later operation
/// cannot consume its response or unpause it. Initialization instead shuts down.
struct WaitGuard {
    operation: Arc<AtomicBool>,
    interrupt: Arc<AtomicBool>,
    armed: bool,
}
impl Drop for WaitGuard {
    fn drop(&mut self) {
        if self.armed {
            self.operation.store(true, Ordering::Release);
            self.interrupt.store(true, Ordering::Release);
        }
    }
}
pub struct FileDownloadWorker {
    context: Context,
    consent: Arc<dyn FileReadConsent>,
    jobs: Option<mpsc::SyncSender<Job>>,
    ready: Option<(oneshot::Receiver<Reply>, OperationControl)>,
    in_flight: bool,
    operation_budget: Duration,
    cancelled: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    monitor: FileDownloadMonitor,
}
impl FileDownloadWorker {
    /// No filesystem call runs here. Retain the monitor before awaiting ready.
    pub fn start(
        client: &FileReadClient,
        download: &FileDownload,
        factory: impl FileDestinationFactory,
    ) -> io::Result<Self> {
        Self::with_operation_budget(
            client,
            download,
            factory,
            Duration::from_millis(FILE_OPERATION_MS),
        )
    }
    /// A local application may shorten the original operation deadline, never
    /// extend the protocol's maximum or start a new budget when consuming an ACK.
    pub fn with_operation_budget(
        client: &FileReadClient,
        download: &FileDownload,
        factory: impl FileDestinationFactory,
        operation_budget: Duration,
    ) -> io::Result<Self> {
        if operation_budget.is_zero() || operation_budget > Duration::from_millis(FILE_OPERATION_MS)
        {
            return Err(rejected(
                "download operation budget exceeds the protocol maximum",
            ));
        }
        let context = client
            .worker_context(download)
            .map_err(|_| denied("invalid download client"))?;
        let consent = factory.consent();
        consent.check()?;
        let (jobs, work) = mpsc::sync_channel::<Job>(1);
        let (reply, ready) = oneshot::channel();
        let control = OperationControl::new(operation_budget);
        let worker_control = OperationControl {
            cancelled: control.cancelled.clone(),
            deadline: control.deadline,
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let slot = WorkerSlot::reserve()?;
        let shared = Arc::new(DownloadShared::new());
        let monitor = FileDownloadMonitor(shared.clone());
        let worker_context = context.clone();
        let worker_consent = consent.clone();
        let worker_cancelled = cancelled.clone();
        let worker_paused = paused.clone();
        let worker_monitor = monitor.clone();
        let thread = thread::Builder::new()
            .name("nestlink-file-download".into())
            .spawn(move || {
                run(
                    Box::new(factory),
                    worker_context,
                    worker_consent,
                    worker_cancelled,
                    worker_paused,
                    worker_monitor,
                    work,
                    reply,
                    worker_control,
                );
            })?;
        monitor.0.install_worker(thread, slot);
        Ok(Self {
            context,
            consent,
            jobs: Some(jobs),
            ready: Some((ready, control)),
            in_flight: false,
            operation_budget,
            cancelled,
            paused,
            monitor,
        })
    }
    pub fn monitor(&self) -> FileDownloadMonitor {
        self.monitor.clone()
    }
    pub async fn ready(&mut self) -> io::Result<FileDestinationStatus> {
        let (response, control) = self
            .ready
            .take()
            .ok_or_else(|| rejected("download initialization already awaited"))?;
        self.in_flight = true;
        let result = self
            .wait(
                response,
                control,
                self.context.clone(),
                Some((self.context.snapshot.clone(), false)),
                true,
            )
            .await;
        if result.is_ok() {
            self.in_flight = false;
        }
        result
    }
    pub async fn write(
        &mut self,
        download: &FileDownload,
        chunk: FileReadChunk,
    ) -> io::Result<FileDestinationStatus> {
        if chunk.data.is_empty() || chunk.data.len() as u64 > FILE_PAYLOAD_BYTES {
            return Err(rejected("download chunk exceeds the bounded disk slot"));
        }
        let source = download.snapshot();
        self.context.check(&source, false)?;
        self.dispatch(
            Operation::Write(source.clone(), chunk),
            Some((source, false)),
        )
        .await
    }
    pub async fn finish(&mut self, download: &FileDownload) -> io::Result<FileDestinationStatus> {
        let source = download.snapshot();
        self.context.check(&source, true)?;
        self.dispatch(Operation::Finish(source.clone()), Some((source, true)))
            .await
    }
    /// Acknowledged only after every earlier disk call returned. Keeping partial
    /// bytes is local consent, and does not keep the old session authorized.
    pub async fn pause(&mut self) -> io::Result<FileDestinationStatus> {
        self.paused.store(true, Ordering::Release);
        self.dispatch(Operation::Pause, None).await
    }
    pub async fn resume(
        &mut self,
        client: &FileReadClient,
        download: &FileDownload,
    ) -> io::Result<FileDestinationStatus> {
        if self.in_flight || self.monitor.status().phase != FileDownloadPhase::Paused {
            return Err(rejected("resume requires an acknowledged idle pause"));
        }
        let context = client
            .worker_context(download)
            .map_err(|_| denied("invalid resumed download client"))?;
        self.context.accepts(&context)?;
        self.dispatch(Operation::Resume(Box::new(context)), None)
            .await
    }
    async fn dispatch(
        &mut self,
        operation: Operation,
        view: Option<(FileDownloadSnapshot, bool)>,
    ) -> io::Result<FileDestinationStatus> {
        let barrier = matches!(operation, Operation::Pause);
        if self.ready.is_some()
            || (self.in_flight && !barrier)
            || self.monitor.status().finished
            || self.cancelled.load(Ordering::Acquire)
        {
            return Err(rejected(
                "download worker is unavailable or has an unacknowledged operation",
            ));
        }
        if !barrier
            && !matches!(operation, Operation::Resume(_))
            && (self.paused.load(Ordering::Acquire)
                || self.monitor.status().phase != FileDownloadPhase::Active)
        {
            return Err(interrupted());
        }
        self.consent.check()?;
        let successor = match &operation {
            Operation::Resume(context) => Some(*context.clone()),
            _ => None,
        };
        let wait_context = successor.as_ref().unwrap_or(&self.context).clone();
        let view = successor
            .as_ref()
            .map(|context| (context.snapshot.clone(), false))
            .or(view);
        let (reply, response) = oneshot::channel();
        let control = OperationControl::new(self.operation_budget);
        let wait_control = OperationControl {
            cancelled: control.cancelled.clone(),
            deadline: control.deadline,
        };
        self.jobs
            .as_ref()
            .ok_or_else(interrupted)?
            .try_send(Job {
                operation,
                control,
                reply,
            })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "download disk slot unavailable")
            })?;
        self.in_flight = true;
        let result = self
            .wait(response, wait_control, wait_context, view, false)
            .await;
        // A failed/cancelled wait stays sticky until a pause barrier is received.
        if result.is_ok() {
            self.in_flight = false;
            if successor.is_some() {
                // Only consuming the exact successful response releases the
                // pause. A cancelled async resume can never release it later.
                self.paused.store(false, Ordering::Release);
                self.monitor.0.status.send_modify(|state| {
                    if !state.finished && state.phase == FileDownloadPhase::Paused {
                        state.phase = FileDownloadPhase::Active;
                    }
                });
            }
        }
        result
    }
    async fn wait(
        &mut self,
        mut response: oneshot::Receiver<Reply>,
        control: OperationControl,
        wait_context: Context,
        view: Option<(FileDownloadSnapshot, bool)>,
        initializing: bool,
    ) -> io::Result<FileDestinationStatus> {
        let mut guard = WaitGuard {
            operation: control.cancelled.clone(),
            interrupt: if initializing {
                self.cancelled.clone()
            } else {
                self.paused.clone()
            },
            armed: true,
        };
        let mut stopped = wait_context.lease.subscribe_stopped();
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        loop {
            control.check()?;
            self.consent.check()?;
            if self.cancelled.load(Ordering::Acquire) {
                return Err(interrupted());
            }
            if let Some((source, finish)) = &view {
                wait_context.check(source, *finish)?;
            }
            tokio::select! { biased;
                result = &mut response => {
                    let reply = result.map_err(|_| io::Error::other("download worker ended without the exact response"))?;
                    control.check()?;
                    self.context = reply.context;
                    self.consent.check()?;
                    if let Some((source, finish)) = &view { wait_context.check(source, *finish)?; }
                    guard.armed = false;
                    return reply.result;
                }
                _ = stopped.changed(), if view.is_some() => {}
                _ = tick.tick() => {}
            }
        }
    }
    /// File cancellation does not stop viewing/input on the still-live lease.
    pub async fn shutdown(&mut self) -> io::Result<FileShutdown> {
        self.cancelled.store(true, Ordering::Release);
        self.jobs.take();
        self.ready.take();
        let deadline = self.monitor.0.begin_cleanup();
        loop {
            if self.monitor.status().finished {
                return Ok(FileShutdown::Finished);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.monitor.0.mark_timed_out();
                return Ok(FileShutdown::TimedOut);
            }
            tokio::time::sleep(JOIN_POLL.min(remaining)).await;
        }
    }
}
impl Drop for FileDownloadWorker {
    fn drop(&mut self) {
        self.monitor.0.begin_cleanup();
        self.cancelled.store(true, Ordering::Release);
        self.jobs.take();
        retain_worker(self.monitor.0.clone());
    }
}

#[allow(clippy::too_many_arguments)]
fn run(
    factory: Box<dyn FileDestinationFactory>,
    mut context: Context,
    consent: Arc<dyn FileReadConsent>,
    cancelled: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    monitor: FileDownloadMonitor,
    work: mpsc::Receiver<Job>,
    initial_reply: oneshot::Sender<Reply>,
    initial_control: OperationControl,
) {
    let mut destination: Option<Box<dyn FileDestination>> = None;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut initial_check = || {
            initial_control.check()?;
            consent.check()?;
            if cancelled.load(Ordering::Acquire) {
                return Err(interrupted());
            }
            context.check(&context.snapshot, false)
        };
        let initial = (|| {
            initial_check()?;
            destination = Some(factory.build(&context.snapshot)?);
            let provider = destination
                .as_mut()
                .ok_or_else(|| io::Error::other("missing download provider"))?;
            provider.prepare(&mut initial_check)?;
            initial_check()?;
            Ok(provider.status())
        })();
        publish(
            &monitor,
            destination.as_deref(),
            if initial.is_ok() {
                FileDownloadPhase::Active
            } else {
                FileDownloadPhase::Stopped
            },
            initial.as_ref().err(),
        );
        let failed = initial.is_err();
        let _ = initial_reply.send(Reply {
            context: context.clone(),
            result: initial,
        });
        if failed {
            return;
        }
        loop {
            if cancelled.load(Ordering::Acquire) {
                break;
            }
            if let Err(error) = consent.check() {
                publish(
                    &monitor,
                    destination.as_deref(),
                    FileDownloadPhase::Stopped,
                    Some(&error),
                );
                break;
            }
            if context
                .lease
                .check_channel_binding(Channel::FileRead, context.generation)
                .is_err()
            {
                if context.may_pause() {
                    paused.store(true, Ordering::Release);
                } else {
                    publish(
                        &monitor,
                        destination.as_deref(),
                        FileDownloadPhase::Stopped,
                        Some(&denied("download session stopped")),
                    );
                    break;
                }
            }
            if context.snapshot.cancelled() {
                paused.store(true, Ordering::Release);
            }
            if paused.load(Ordering::Acquire) && monitor.status().phase != FileDownloadPhase::Paused
            {
                publish(
                    &monitor,
                    destination.as_deref(),
                    FileDownloadPhase::Paused,
                    None,
                );
            }
            let job = match work.recv_timeout(Duration::from_millis(50)) {
                Ok(job) => job,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let Some(provider) = destination.as_mut() else {
                monitor.0.status.send_modify(|state| {
                    state.error.get_or_insert(io::ErrorKind::Other);
                });
                break;
            };
            let mut completed = false;
            let result = match &job.operation {
                Operation::Pause => {
                    paused.store(true, Ordering::Release);
                    Ok(())
                }
                Operation::Resume(successor) => (|| {
                    if !paused.load(Ordering::Acquire) {
                        return Err(rejected("download was not paused"));
                    }
                    context.accepts(successor)?;
                    let mut check = || {
                        (|| {
                            job.control.check()?;
                            consent.check()?;
                            if cancelled.load(Ordering::Acquire) {
                                return Err(interrupted());
                            }
                            successor.check(&successor.snapshot, false)
                        })()
                        .map_err(boundary_error)
                    };
                    check()?;
                    provider.resume(&successor.snapshot, &mut check)?;
                    check()?;
                    context = *successor.clone();
                    Ok(())
                })(),
                Operation::Write(source, _) | Operation::Finish(source) => {
                    let finish = matches!(job.operation, Operation::Finish(_));
                    let mut check = || {
                        (|| {
                            job.control.check()?;
                            consent.check()?;
                            if cancelled.load(Ordering::Acquire) || paused.load(Ordering::Acquire) {
                                return Err(interrupted());
                            }
                            context.check(source, finish)
                        })()
                        .map_err(boundary_error)
                    };
                    (|| {
                        check()?;
                        match &job.operation {
                            Operation::Write(_, chunk) => {
                                provider.write(source, chunk, &mut check)?
                            }
                            Operation::Finish(_) => provider.finish(source, &mut check)?,
                            _ => unreachable!(),
                        }
                        check()?;
                        completed = finish;
                        Ok(())
                    })()
                }
            };
            let recoverable = result.is_err()
                && result.as_ref().err().is_some_and(|error| {
                    matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::PermissionDenied
                    ) && error
                        .get_ref()
                        .is_some_and(|inner| inner.is::<BoundaryFailure>())
                })
                && !provider.status().poisoned
                && !provider.status().published
                && consent.check().is_ok()
                && !cancelled.load(Ordering::Acquire)
                && (paused.load(Ordering::Acquire)
                    || job.control.cancelled.load(Ordering::Acquire)
                    || context.snapshot.cancelled()
                    || context.may_pause());
            if recoverable {
                paused.store(true, Ordering::Release);
            }
            let terminal = completed || (result.is_err() && !recoverable);
            let phase = if completed {
                FileDownloadPhase::Completed
            } else if terminal {
                FileDownloadPhase::Stopped
            } else if paused.load(Ordering::Acquire) {
                FileDownloadPhase::Paused
            } else {
                FileDownloadPhase::Active
            };
            publish(
                &monitor,
                Some(provider.as_ref()),
                phase,
                result.as_ref().err(),
            );
            let status = provider.status();
            let _ = job.reply.send(Reply {
                context: context.clone(),
                result: result.map(|()| status),
            });
            if terminal {
                break;
            }
        }
    }));
    if outcome.is_err() {
        monitor.0.status.send_modify(|state| {
            state.error.get_or_insert(io::ErrorKind::Other);
        });
    }
    if monitor.status().phase != FileDownloadPhase::Completed {
        if let Some(provider) = destination.as_mut() {
            let cleanup =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| provider.cleanup()))
                    .unwrap_or_else(|_| Err(io::Error::other("download cleanup panicked")));
            monitor.0.status.send_modify(|state| {
                state.cleanup_error = cleanup.err().map(|error| error.kind());
            });
        }
        publish(
            &monitor,
            destination.as_deref(),
            FileDownloadPhase::Stopped,
            None,
        );
    }
    // Status is frozen from the provider before destruction. The monitor
    // publishes `finished` only after joining this exact OS thread, so captured
    // consent, context and channel resources are also known to be gone.
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(destination))).is_err() {
        monitor.0.status.send_modify(|state| {
            state.cleanup_error.get_or_insert(io::ErrorKind::Other);
            if state.phase != FileDownloadPhase::Completed {
                state.error.get_or_insert(io::ErrorKind::Other);
            }
        });
    }
}
fn publish(
    monitor: &FileDownloadMonitor,
    provider: Option<&dyn FileDestination>,
    phase: FileDownloadPhase,
    error: Option<&io::Error>,
) {
    let provider_status = provider.map(|provider| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| provider.status()))
    });
    monitor.0.status.send_modify(|state| {
        state.phase = phase;
        match provider_status {
            Some(Ok(status)) => state.destination = status,
            Some(Err(_)) => {
                // Keep the last truthful provider snapshot if its status accessor
                // is broken; status reporting must not prevent final destruction.
                state.error.get_or_insert(io::ErrorKind::Other);
            }
            None => {}
        }
        if let Some(error) = error {
            state.error.get_or_insert(error.kind());
        }
    });
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::sync::Condvar;

    #[derive(Default)]
    struct Gate {
        state: Mutex<(bool, bool)>, // entered, released
        changed: Condvar,
    }
    impl Gate {
        fn block(&self) -> io::Result<()> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("download lifecycle test gate poisoned"))?;
            state.0 = true;
            self.changed.notify_all();
            while !state.1 {
                state = self
                    .changed
                    .wait(state)
                    .map_err(|_| io::Error::other("download lifecycle test gate poisoned"))?;
            }
            Ok(())
        }
        fn wait_entered(&self) -> io::Result<()> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("download lifecycle test gate poisoned"))?;
            while !state.0 {
                state = self
                    .changed
                    .wait(state)
                    .map_err(|_| io::Error::other("download lifecycle test gate poisoned"))?;
            }
            Ok(())
        }
        fn release(&self) -> io::Result<()> {
            self.state
                .lock()
                .map_err(|_| io::Error::other("download lifecycle test gate poisoned"))?
                .1 = true;
            self.changed.notify_all();
            Ok(())
        }
        fn release_unpoisoned(&self) {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .1 = true;
            self.changed.notify_all();
        }
    }
    struct ReleaseOnDrop(Arc<Gate>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release_unpoisoned();
        }
    }

    #[tokio::test]
    async fn subscription_alone_observes_natural_thread_exit_and_preserves_prior_updates()
    -> io::Result<()> {
        let budget = Arc::new(AtomicUsize::new(0));
        let shared = Arc::new(DownloadShared::new());
        let monitor = FileDownloadMonitor(shared.clone());
        let gate = Arc::new(Gate::default());
        let _release = ReleaseOnDrop(gate.clone());
        let worker_gate = gate.clone();
        let slot = WorkerSlot::reserve_from(budget.clone())?;
        let thread = thread::spawn(move || {
            let _ = worker_gate.block();
        });
        gate.wait_entered()?;
        shared.install_worker(thread, slot);
        let mut subscription = monitor.subscribe();
        let _ = subscription.borrow_and_update();
        shared
            .status
            .send_modify(|status| status.phase = FileDownloadPhase::Paused);
        tokio::time::timeout(Duration::from_secs(2), subscription.changed())
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        assert_eq!(
            subscription.borrow_and_update().phase,
            FileDownloadPhase::Paused
        );
        assert!(!subscription.borrow().finished);
        drop(monitor);
        drop(shared);

        assert!(
            tokio::time::timeout(Duration::from_millis(20), subscription.changed())
                .await
                .is_err()
        );
        assert_eq!(budget.load(Ordering::Acquire), 1);
        gate.release()?;
        tokio::time::timeout(Duration::from_secs(2), subscription.changed())
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        assert!(subscription.borrow_and_update().finished);
        assert_eq!(budget.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[test]
    fn retained_worker_keeps_one_of_32_slots_until_the_original_thread_joins() -> io::Result<()> {
        let budget = Arc::new(AtomicUsize::new(0));
        let slot = WorkerSlot::reserve_from(budget.clone())?;
        let shared = Arc::new(DownloadShared::new());
        let monitor = FileDownloadMonitor(shared.clone());
        let gate = Arc::new(Gate::default());
        let release = ReleaseOnDrop(gate.clone());
        let worker_failed = Arc::new(AtomicBool::new(false));
        let worker_gate = gate.clone();
        let worker_failed_thread = worker_failed.clone();
        let handle = thread::spawn(move || {
            worker_failed_thread.store(worker_gate.block().is_err(), Ordering::Release);
        });
        gate.wait_entered()?;
        shared.install_worker(handle, slot);
        shared.begin_cleanup();
        retain_worker(shared.clone());

        let mut remaining = Vec::new();
        for _ in 1..FILE_DOWNLOAD_WORKER_LIMIT {
            remaining.push(WorkerSlot::reserve_from(budget.clone())?);
        }
        assert_eq!(remaining.len(), FILE_DOWNLOAD_WORKER_LIMIT - 1);
        assert_eq!(budget.load(Ordering::Acquire), FILE_DOWNLOAD_WORKER_LIMIT);
        assert!(!monitor.status().finished);
        assert!(!worker_failed.load(Ordering::Acquire));
        assert!(WorkerSlot::reserve_from(budget.clone()).is_err());

        gate.release()?;
        drop(release);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut status = monitor.status();
        while !status.finished && Instant::now() < deadline {
            thread::yield_now();
            status = monitor.status();
        }
        assert!(
            status.finished,
            "the retained original handle must be joined"
        );
        assert!(!worker_failed.load(Ordering::Acquire));
        assert_eq!(
            budget.load(Ordering::Acquire),
            FILE_DOWNLOAD_WORKER_LIMIT - 1
        );
        let replacement = WorkerSlot::reserve_from(budget.clone())?;
        drop(replacement);
        drop(remaining);
        Ok(())
    }
}
