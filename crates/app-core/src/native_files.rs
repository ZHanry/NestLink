//! Per-session native file owners.
//!
//! This module deliberately stays below the IPC and UI surfaces. A route is
//! tied to the complete proved session identity and the product generation
//! that created it. It claims each permitted file channel once, and it never
//! accepts an operating-system path from a peer. Callers provide only the
//! existing portable SDK requests and locally selected platform factories.

use super::{CoreHandle, Shared};
use crate::NativeSessionBinding;
use nestlink_auth::random_id;
use nestlink_protocol::{DIRECTORY_SNAPSHOT_MS, FILE_SIZE_BYTES, FILE_WORKER_CLEANUP_MS, FileRoot};
use nestlink_remote::{
    ChannelRuntime, LeaseControl, RemoteError,
    files::{
        ClaimedFileRead, DirectoryBrowse, FileDestination, FileDestinationFactory,
        FileDownloadView, FileReadClient, FileReadConsent, FileReadDevice, FileReadServer,
        FileReadSource, FileShutdown, FileWorkerMonitor, FileWorkerStatus,
    },
    upload::{
        ClaimedFileWrite, FileUploadSourceFactory, FileWriteClient, FileWriteDevice,
        FileWriteMonitor, FileWriteServer,
    },
};
use nestlink_sdk::{
    browse::{NativeBrowseError, NativeBrowseRequest, NativeDirectoryPage},
    download_queue::{NativeDownloadQueueLimits, NativeDownloadQueueStatus},
    files::{
        NativeDownloadControl, NativeDownloadError, NativeDownloadMonitor, NativeDownloadRequest,
        NativeDownloadStatus, NativeFileDownload,
    },
    upload::{NativeFileUpload, NativeUploadError, NativeUploadRequest, NativeUploadStatus},
};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};

pub const NATIVE_FILE_READ_QUEUE_CAPACITY: usize = 8;
pub const NATIVE_FILE_WRITE_QUEUE_CAPACITY: usize = 8;
/// Completed task views remain queryable until this many newer tasks need
/// their slots. Active and queued tasks are never evicted.
pub const NATIVE_FILE_TASK_HISTORY_LIMIT: usize = 128;

/// Bounded errors safe to surface in product status. Paths and OS error text
/// are intentionally omitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeFilesError {
    #[error("native file operation belongs to a replaced session or product generation")]
    StaleBinding,
    #[error("the proved session does not grant this file direction")]
    Unauthorized,
    #[error("native file channel is stopped")]
    Stopped,
    #[error("native file owner is closing")]
    Closing,
    #[error("native file queue is full")]
    QueueFull,
    #[error("native file queue is unavailable")]
    OwnerUnavailable,
    #[error("another directory snapshot is active")]
    BrowseBusy,
    #[error("directory snapshot identity is no longer active")]
    BrowseExpired,
    #[error("the session endpoint does not own this file operation")]
    WrongEndpoint,
    #[error("native file task cannot perform that control action")]
    InvalidControl,
    #[error("file channel cleanup was not acknowledged; a new session is required")]
    ReestablishSession,
    #[error("directory operation failed: {0}")]
    Browse(NativeBrowseError),
    #[error("download operation failed: {0}")]
    Download(NativeDownloadError),
    #[error("upload operation failed: {0}")]
    Upload(NativeUploadError),
    #[error("local file service could not start: {0:?}")]
    LocalService(io::ErrorKind),
}

/// File capabilities proved for the current native session route.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeFileAccess {
    pub is_host: bool,
    pub read: bool,
    pub write: bool,
}

impl From<NativeBrowseError> for NativeFilesError {
    fn from(error: NativeBrowseError) -> Self {
        Self::Browse(error)
    }
}
impl From<NativeDownloadError> for NativeFilesError {
    fn from(error: NativeDownloadError) -> Self {
        Self::Download(error)
    }
}
impl From<NativeUploadError> for NativeFilesError {
    fn from(error: NativeUploadError) -> Self {
        Self::Upload(error)
    }
}

struct NativeFileBudgetLedger {
    tasks: usize,
    reserved_bytes: u64,
}

pub(super) struct NativeFileBudget {
    limits: NativeDownloadQueueLimits,
    ledger: Mutex<NativeFileBudgetLedger>,
    active: Arc<Semaphore>,
}

impl NativeFileBudget {
    pub(super) fn new(limits: NativeDownloadQueueLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            ledger: Mutex::new(NativeFileBudgetLedger {
                tasks: 0,
                reserved_bytes: 0,
            }),
            active: Arc::new(Semaphore::new(limits.active)),
        })
    }

    fn reserve_task(self: &Arc<Self>) -> Result<NativeFileBudgetReservation, NativeFilesError> {
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if ledger.tasks >= self.limits.tasks {
            return Err(NativeFilesError::QueueFull);
        }
        ledger.tasks += 1;
        Ok(NativeFileBudgetReservation {
            inner: Arc::new(NativeFileBudgetReservationInner {
                budget: self.clone(),
                state: Mutex::new(NativeFileBudgetReservationState::default()),
            }),
        })
    }

    fn status(&self, closed: bool) -> NativeDownloadQueueStatus {
        let ledger = self
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let active = self
            .limits
            .active
            .saturating_sub(self.active.available_permits());
        NativeDownloadQueueStatus {
            closed,
            tasks: ledger.tasks,
            active,
            queued: ledger.tasks.saturating_sub(active),
            reserved_bytes: ledger.reserved_bytes,
        }
    }
}

#[derive(Clone)]
struct NativeFileBudgetReservation {
    inner: Arc<NativeFileBudgetReservationInner>,
}

#[derive(Default)]
struct NativeFileBudgetReservationState {
    active: Option<OwnedSemaphorePermit>,
    bytes: Option<u64>,
}

struct NativeFileBudgetReservationInner {
    budget: Arc<NativeFileBudget>,
    state: Mutex<NativeFileBudgetReservationState>,
}

impl Drop for NativeFileBudgetReservationInner {
    fn drop(&mut self) {
        let active = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .take();
        drop(active);
        let mut ledger = self
            .budget
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ledger.tasks = ledger.tasks.saturating_sub(1);
    }
}

impl NativeFileBudgetReservation {
    async fn acquire_active(&self) -> Result<(), NativeFilesError> {
        let permit = self
            .inner
            .budget
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| NativeFilesError::OwnerUnavailable)?;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active.is_none() {
            state.active = Some(permit);
        }
        Ok(())
    }

    fn reserve_manifest(&self, size: u64) -> io::Result<()> {
        if size > FILE_SIZE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "download manifest exceeds the per-file limit",
            ));
        }
        let mut ledger = self
            .inner
            .budget
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.bytes.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "download manifest reservation already exists",
            ));
        }
        if size
            > self
                .inner
                .budget
                .limits
                .reserved_bytes
                .saturating_sub(ledger.reserved_bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "aggregate download temporary-byte budget is full",
            ));
        }
        ledger.reserved_bytes += size;
        state.bytes = Some(size);
        Ok(())
    }

    fn complete(&self, status: &NativeDownloadStatus) {
        let safe_to_release = status.destination.is_some_and(|destination| {
            destination.finished
                && destination.destination.file_closed
                && (destination.destination.temporary_removed || destination.destination.published)
        });
        if safe_to_release {
            self.release_bytes();
        }
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .take();
    }

    fn release_bytes(&self) {
        let mut ledger = self
            .inner
            .budget
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(bytes) = state.bytes.take() {
            ledger.reserved_bytes = ledger.reserved_bytes.saturating_sub(bytes);
        }
    }
}

fn remote_error(error: RemoteError) -> NativeFilesError {
    match error {
        RemoteError::Stopped => NativeFilesError::Stopped,
        RemoteError::Io(error) | RemoteError::Cleanup(error) => {
            if matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput
            ) {
                NativeFilesError::Unauthorized
            } else {
                NativeFilesError::LocalService(error.kind())
            }
        }
        RemoteError::Authorization(_) => NativeFilesError::Unauthorized,
    }
}

#[derive(Clone)]
struct BindingGuard {
    binding: NativeSessionBinding,
    core_generation: u64,
    current_core_generation: Arc<AtomicU64>,
}
impl BindingGuard {
    fn check_identity(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<(), NativeFilesError> {
        if binding != &self.binding
            || core_generation != self.core_generation
            || self.current_core_generation.load(Ordering::Acquire) != self.core_generation
        {
            return Err(NativeFilesError::StaleBinding);
        }
        Ok(())
    }
    fn check_channel(
        &self,
        lease: &LeaseControl,
        channel: Channel,
    ) -> Result<(), NativeFilesError> {
        self.check_identity(&self.binding, self.core_generation)?;
        lease
            .check_channel_binding(channel, self.binding.connection_generation)
            .map_err(remote_error)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeFileQueueStatus {
    /// Number of waiting entries accepted by this owner. The active entry is
    /// reported separately and does not consume a waiting slot.
    pub capacity: usize,
    pub pending: usize,
    pub active: bool,
    pub accepted: u64,
    pub completed: u64,
    pub failed: u64,
    pub closed: bool,
    pub requires_session_recreation: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeFilesQueueStatus {
    pub read: Option<NativeFileQueueStatus>,
    pub write: Option<NativeFileQueueStatus>,
}

#[derive(Default)]
struct QueueCounts {
    pending: usize,
    active: bool,
    accepted: u64,
    completed: u64,
    failed: u64,
    closed: bool,
    requires_session_recreation: bool,
}
struct QueueBook {
    capacity: usize,
    counts: Mutex<QueueCounts>,
    view: watch::Sender<NativeFileQueueStatus>,
}
impl QueueBook {
    fn new(capacity: usize) -> Arc<Self> {
        let (view, _) = watch::channel(NativeFileQueueStatus {
            capacity,
            ..NativeFileQueueStatus::default()
        });
        Arc::new(Self {
            capacity,
            counts: Mutex::new(QueueCounts::default()),
            view,
        })
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, QueueCounts> {
        self.counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn publish(&self, counts: &QueueCounts) {
        self.view.send_replace(NativeFileQueueStatus {
            capacity: self.capacity,
            pending: counts.pending,
            active: counts.active,
            accepted: counts.accepted,
            completed: counts.completed,
            failed: counts.failed,
            closed: counts.closed,
            requires_session_recreation: counts.requires_session_recreation,
        });
    }
    fn started(&self) {
        let mut counts = self.lock();
        counts.pending = counts.pending.saturating_sub(1);
        counts.active = true;
        self.publish(&counts);
    }
    fn finished(&self, failed: bool, requires_recreation: bool) {
        let mut counts = self.lock();
        counts.active = false;
        counts.completed = counts.completed.saturating_add(1);
        if failed {
            counts.failed = counts.failed.saturating_add(1);
        }
        counts.requires_session_recreation |= requires_recreation;
        self.publish(&counts);
    }
    fn closed(&self) {
        let mut counts = self.lock();
        counts.closed = true;
        counts.pending = 0;
        counts.active = false;
        self.publish(&counts);
    }
    fn require_session_recreation(&self) {
        let mut counts = self.lock();
        counts.requires_session_recreation = true;
        self.publish(&counts);
    }
    fn status(&self) -> NativeFileQueueStatus {
        *self.view.borrow()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NativeFileTaskKind {
    #[default]
    Download,
    Upload,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NativeFileTaskPhase {
    #[default]
    Queued,
    Active,
    Paused,
    Settling,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeFileTaskAction {
    Pause,
    Resume,
    Cancel,
}
#[derive(Clone, Debug, Default)]
pub struct NativeFileTaskStatus {
    pub task_id: String,
    pub kind: NativeFileTaskKind,
    pub phase: NativeFileTaskPhase,
    pub confirmed_bytes: u64,
    pub total_bytes: Option<u64>,
    pub download: Option<NativeDownloadStatus>,
    pub upload: Option<NativeUploadStatus>,
    pub error: Option<NativeFilesError>,
    /// True only after the operation actor and all returned channel ownership
    /// have reached a stable result.
    pub finished: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Directive {
    #[default]
    Run,
    Pause,
    Cancel,
}

#[derive(Clone)]
pub struct NativeFileTaskMonitor(watch::Sender<NativeFileTaskStatus>);
impl NativeFileTaskMonitor {
    pub fn status(&self) -> NativeFileTaskStatus {
        self.0.borrow().clone()
    }
    pub fn subscribe(&self) -> watch::Receiver<NativeFileTaskStatus> {
        self.0.subscribe()
    }
    pub async fn wait_finished(&self) -> NativeFileTaskStatus {
        let mut state = self.subscribe();
        loop {
            let current = state.borrow_and_update().clone();
            if current.finished || state.changed().await.is_err() {
                return current;
            }
        }
    }
}

#[derive(Clone)]
pub struct NativeFileTaskControl {
    binding: BindingGuard,
    lease: LeaseControl,
    kind: NativeFileTaskKind,
    directive: watch::Sender<Directive>,
    monitor: NativeFileTaskMonitor,
}
impl NativeFileTaskControl {
    fn check(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<(), NativeFilesError> {
        self.binding.check_channel(
            &self.lease,
            match self.kind {
                NativeFileTaskKind::Download => Channel::FileRead,
                NativeFileTaskKind::Upload => Channel::FileWrite,
            },
        )?;
        self.binding.check_identity(binding, core_generation)
    }
    pub fn pause(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<(), NativeFilesError> {
        self.check(binding, core_generation)?;
        if self.kind != NativeFileTaskKind::Download
            || self.monitor.status().phase != NativeFileTaskPhase::Active
        {
            return Err(NativeFilesError::InvalidControl);
        }
        self.directive.send_replace(Directive::Pause);
        Ok(())
    }
    pub fn resume(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<(), NativeFilesError> {
        self.check(binding, core_generation)?;
        if self.kind != NativeFileTaskKind::Download
            || self.monitor.status().phase != NativeFileTaskPhase::Paused
        {
            return Err(NativeFilesError::InvalidControl);
        }
        self.directive.send_replace(Directive::Run);
        Ok(())
    }
    pub fn cancel(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<(), NativeFilesError> {
        self.check(binding, core_generation)?;
        if self.monitor.status().finished {
            return Ok(());
        }
        self.directive.send_replace(Directive::Cancel);
        Ok(())
    }
}

pub struct NativeFileTask {
    task_id: String,
    control: NativeFileTaskControl,
    monitor: NativeFileTaskMonitor,
}
impl NativeFileTask {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    pub fn control(&self) -> NativeFileTaskControl {
        self.control.clone()
    }
    pub fn monitor(&self) -> NativeFileTaskMonitor {
        self.monitor.clone()
    }
    pub fn status(&self) -> NativeFileTaskStatus {
        self.monitor.status()
    }
    pub async fn wait_finished(&self) -> NativeFileTaskStatus {
        self.monitor.wait_finished().await
    }
}

#[derive(Default)]
struct NativeFileTaskBook {
    controls: HashMap<String, NativeFileTaskControl>,
    insertion_order: VecDeque<String>,
}
impl NativeFileTaskBook {
    fn insert(
        &mut self,
        task_id: String,
        control: NativeFileTaskControl,
    ) -> Result<(), NativeFilesError> {
        while self.controls.len() >= NATIVE_FILE_TASK_HISTORY_LIMIT {
            let Some(position) = self.insertion_order.iter().position(|id| {
                self.controls
                    .get(id)
                    .is_some_and(|task| task.monitor.status().finished)
            }) else {
                return Err(NativeFilesError::QueueFull);
            };
            if let Some(expired) = self.insertion_order.remove(position) {
                self.controls.remove(&expired);
            }
        }
        if self.controls.contains_key(&task_id) {
            return Err(NativeFilesError::OwnerUnavailable);
        }
        self.insertion_order.push_back(task_id.clone());
        self.controls.insert(task_id, control);
        Ok(())
    }

    fn remove(&mut self, task_id: &str) {
        self.controls.remove(task_id);
        self.insertion_order.retain(|id| id != task_id);
    }
}

#[derive(Clone, Debug)]
pub struct NativeBrowsePage {
    pub session: NativeSessionBinding,
    pub browse_id: String,
    pub page: NativeDirectoryPage,
}

struct BoxedDestinationFactory {
    factory: Box<dyn FileDestinationFactory>,
    reservation: NativeFileBudgetReservation,
}
impl FileDestinationFactory for BoxedDestinationFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.factory.consent()
    }
    fn build(
        self: Box<Self>,
        source: &nestlink_remote::files::FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        let Self {
            factory,
            reservation,
        } = *self;
        reservation.reserve_manifest(source.manifest().size)?;
        let destination = factory.build(source)?;
        Ok(Box::new(BoxedDestination {
            destination,
            _reservation: reservation,
        }))
    }
}

struct BoxedDestination {
    destination: Box<dyn FileDestination>,
    // Keep task and active ownership until the SDK's destination thread drops
    // the actual provider, including a cleanup call that outlives its deadline.
    _reservation: NativeFileBudgetReservation,
}
impl FileDestination for BoxedDestination {
    fn status(&self) -> nestlink_remote::files::FileDestinationStatus {
        self.destination.status()
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.destination.prepare(authorized)
    }
    fn write(
        &mut self,
        source: &nestlink_remote::files::FileDownloadSnapshot,
        chunk: &nestlink_protocol::FileReadChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.write(source, chunk, authorized)
    }
    fn resume(
        &mut self,
        source: &nestlink_remote::files::FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.resume(source, authorized)
    }
    fn finish(
        &mut self,
        source: &nestlink_remote::files::FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.finish(source, authorized)
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.destination.cleanup()
    }
}

struct BoxedUploadSourceFactory(Box<dyn FileUploadSourceFactory>);
impl FileUploadSourceFactory for BoxedUploadSourceFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.0.consent()
    }
    fn open(
        self: Box<Self>,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileReadSource>> {
        let Self(factory) = *self;
        factory.open(authorized)
    }
}

enum ReadCommand {
    ListRoots {
        binding: NativeSessionBinding,
        core_generation: u64,
        reply: oneshot::Sender<Result<Vec<FileRoot>, NativeFilesError>>,
    },
    BeginBrowse {
        binding: NativeSessionBinding,
        core_generation: u64,
        request: NativeBrowseRequest,
        reply: oneshot::Sender<Result<NativeBrowsePage, NativeFilesError>>,
    },
    NextBrowse {
        binding: NativeSessionBinding,
        core_generation: u64,
        browse_id: String,
        maximum: u32,
        reply: oneshot::Sender<Result<Option<NativeBrowsePage>, NativeFilesError>>,
    },
    CancelBrowse {
        binding: NativeSessionBinding,
        core_generation: u64,
        browse_id: String,
        reply: oneshot::Sender<Result<(), NativeFilesError>>,
    },
    Download {
        binding: NativeSessionBinding,
        core_generation: u64,
        request: Box<NativeDownloadRequest>,
        destination: Box<dyn FileDestinationFactory>,
        directive: watch::Receiver<Directive>,
        monitor: NativeFileTaskMonitor,
        reservation: NativeFileBudgetReservation,
    },
}
enum WriteCommand {
    ListRoots {
        binding: NativeSessionBinding,
        core_generation: u64,
        reply: oneshot::Sender<Result<Vec<FileRoot>, NativeFilesError>>,
    },
    Upload {
        binding: NativeSessionBinding,
        core_generation: u64,
        request: NativeUploadRequest,
        source: Box<dyn FileUploadSourceFactory>,
        directive: watch::Receiver<Directive>,
        monitor: NativeFileTaskMonitor,
    },
}

struct ReadOwner {
    sender: mpsc::Sender<ReadCommand>,
    queue: Arc<QueueBook>,
    stop: watch::Sender<bool>,
    finished: Arc<std::sync::atomic::AtomicBool>,
    actor_failed: AtomicBool,
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl ReadOwner {
    fn send(&self, command: ReadCommand) -> Result<(), NativeFilesError> {
        let mut counts = self.queue.lock();
        if counts.closed {
            return Err(NativeFilesError::Closing);
        }
        if counts.requires_session_recreation {
            return Err(NativeFilesError::ReestablishSession);
        }
        if counts.pending >= self.queue.capacity {
            counts.failed = counts.failed.saturating_add(1);
            self.queue.publish(&counts);
            return Err(NativeFilesError::QueueFull);
        }
        counts.pending += 1;
        counts.accepted = counts.accepted.saturating_add(1);
        match self.sender.try_send(command) {
            Ok(()) => {
                self.queue.publish(&counts);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                counts.pending = counts.pending.saturating_sub(1);
                counts.accepted = counts.accepted.saturating_sub(1);
                counts.failed = counts.failed.saturating_add(1);
                self.queue.publish(&counts);
                Err(NativeFilesError::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                counts.pending = counts.pending.saturating_sub(1);
                counts.accepted = counts.accepted.saturating_sub(1);
                counts.closed = true;
                self.queue.publish(&counts);
                Err(NativeFilesError::OwnerUnavailable)
            }
        }
    }
    async fn join(&self, budget: Duration) -> bool {
        let mut task = self.task.lock().await;
        let Some(join) = task.as_mut() else {
            return true;
        };
        match tokio::time::timeout(budget, &mut *join).await {
            Ok(result) => {
                if result.is_err() {
                    self.actor_failed.store(true, Ordering::Release);
                    self.queue.require_session_recreation();
                    self.queue.closed();
                }
                self.finished.store(true, Ordering::Release);
                task.take();
                true
            }
            Err(_) => false,
        }
    }
    fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
    fn actor_failed(&self) -> bool {
        self.actor_failed.load(Ordering::Acquire)
    }
}

struct WriteOwner {
    sender: mpsc::Sender<WriteCommand>,
    queue: Arc<QueueBook>,
    stop: watch::Sender<bool>,
    finished: Arc<std::sync::atomic::AtomicBool>,
    actor_failed: AtomicBool,
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl WriteOwner {
    fn send(&self, command: WriteCommand) -> Result<(), NativeFilesError> {
        let mut counts = self.queue.lock();
        if counts.closed {
            return Err(NativeFilesError::Closing);
        }
        if counts.requires_session_recreation {
            return Err(NativeFilesError::ReestablishSession);
        }
        if counts.pending >= self.queue.capacity {
            counts.failed = counts.failed.saturating_add(1);
            self.queue.publish(&counts);
            return Err(NativeFilesError::QueueFull);
        }
        counts.pending += 1;
        counts.accepted = counts.accepted.saturating_add(1);
        match self.sender.try_send(command) {
            Ok(()) => {
                self.queue.publish(&counts);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                counts.pending = counts.pending.saturating_sub(1);
                counts.accepted = counts.accepted.saturating_sub(1);
                counts.failed = counts.failed.saturating_add(1);
                self.queue.publish(&counts);
                Err(NativeFilesError::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                counts.pending = counts.pending.saturating_sub(1);
                counts.accepted = counts.accepted.saturating_sub(1);
                counts.closed = true;
                self.queue.publish(&counts);
                Err(NativeFilesError::OwnerUnavailable)
            }
        }
    }
    async fn join(&self, budget: Duration) -> bool {
        let mut task = self.task.lock().await;
        let Some(join) = task.as_mut() else {
            return true;
        };
        match tokio::time::timeout(budget, &mut *join).await {
            Ok(result) => {
                if result.is_err() {
                    self.actor_failed.store(true, Ordering::Release);
                    self.queue.require_session_recreation();
                    self.queue.closed();
                }
                self.finished.store(true, Ordering::Release);
                task.take();
                true
            }
            Err(_) => false,
        }
    }
    fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
    fn actor_failed(&self) -> bool {
        self.actor_failed.load(Ordering::Acquire)
    }
}

enum ReadActorEvent {
    Wake,
    BrowseExpired,
    Command(ReadCommand),
}

fn stop_requested(stop: &mut watch::Receiver<bool>) -> bool {
    *stop.borrow_and_update()
}

async fn cancel_active_browse(
    client: &mut Option<FileReadClient>,
    browse: &mut Option<(String, DirectoryBrowse)>,
) -> bool {
    let Some((_, mut active)) = browse.take() else {
        return false;
    };
    if active.finished() {
        return false;
    }
    let Some(client) = client.as_mut() else {
        return true;
    };
    match client.cancel_browse(&mut active).await {
        Ok(()) => false,
        Err(error) => browse_error_retires_client(NativeBrowseError::from(error)),
    }
}

async fn acquire_download_active(
    reservation: &NativeFileBudgetReservation,
    directive: &mut watch::Receiver<Directive>,
    stop: &mut watch::Receiver<bool>,
) -> bool {
    loop {
        if stop_requested(stop) || *directive.borrow_and_update() == Directive::Cancel {
            return false;
        }
        tokio::select! {
            biased;
            changed = directive.changed() => {
                if changed.is_err() || *directive.borrow() == Directive::Cancel {
                    return false;
                }
            }
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return false;
                }
            }
            result = reservation.acquire_active() => return result.is_ok(),
        }
    }
}

fn start_read_owner(
    client: FileReadClient,
    guard: BindingGuard,
    lease: LeaseControl,
) -> Arc<ReadOwner> {
    let (sender, receiver) = mpsc::channel(NATIVE_FILE_READ_QUEUE_CAPACITY);
    let (stop, stop_rx) = watch::channel(false);
    let queue = QueueBook::new(NATIVE_FILE_READ_QUEUE_CAPACITY);
    let actor_queue = queue.clone();
    let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let actor_finished = finished.clone();
    let task = tokio::spawn(async move {
        read_actor(client, receiver, guard, lease, actor_queue, stop_rx).await;
        actor_finished.store(true, Ordering::Release);
    });
    Arc::new(ReadOwner {
        sender,
        queue,
        stop,
        finished,
        actor_failed: AtomicBool::new(false),
        task: tokio::sync::Mutex::new(Some(task)),
    })
}

fn start_write_owner(
    client: FileWriteClient,
    guard: BindingGuard,
    lease: LeaseControl,
) -> Arc<WriteOwner> {
    let (sender, receiver) = mpsc::channel(NATIVE_FILE_WRITE_QUEUE_CAPACITY);
    let (stop, stop_rx) = watch::channel(false);
    let queue = QueueBook::new(NATIVE_FILE_WRITE_QUEUE_CAPACITY);
    let actor_queue = queue.clone();
    let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let actor_finished = finished.clone();
    let task = tokio::spawn(async move {
        write_actor(client, receiver, guard, lease, actor_queue, stop_rx).await;
        actor_finished.store(true, Ordering::Release);
    });
    Arc::new(WriteOwner {
        sender,
        queue,
        stop,
        finished,
        actor_failed: AtomicBool::new(false),
        task: tokio::sync::Mutex::new(Some(task)),
    })
}

async fn read_actor(
    client: FileReadClient,
    mut receiver: mpsc::Receiver<ReadCommand>,
    guard: BindingGuard,
    lease: LeaseControl,
    queue: Arc<QueueBook>,
    mut stop: watch::Receiver<bool>,
) {
    let mut client = Some(client);
    let mut browse: Option<(String, DirectoryBrowse)> = None;
    let mut browse_deadline: Option<tokio::time::Instant> = None;
    loop {
        // A command can consume the stop notification while it is cancelling
        // its in-flight transfer. Recheck the current value before waiting
        // for another change or command so this owner cannot outlive shutdown.
        if stop_requested(&mut stop) {
            break;
        }
        let event = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { break; }
                ReadActorEvent::Wake
            }
            _ = async {
                if let Some(deadline) = browse_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => ReadActorEvent::BrowseExpired,
            command = receiver.recv() => match command {
                Some(command) => ReadActorEvent::Command(command),
                None => break,
            }
        };
        let command = match event {
            ReadActorEvent::Wake => continue,
            ReadActorEvent::BrowseExpired => {
                browse_deadline = None;
                if cancel_active_browse(&mut client, &mut browse).await {
                    queue.require_session_recreation();
                    queue.closed();
                    break;
                }
                continue;
            }
            ReadActorEvent::Command(command) => command,
        };
        queue.started();
        let mut recreate = false;
        let mut failed = false;
        match command {
            ReadCommand::ListRoots {
                binding,
                core_generation,
                reply,
            } => {
                let result = async {
                    guard.check_identity(&binding, core_generation)?;
                    guard.check_channel(&lease, Channel::FileRead)?;
                    let client = client
                        .as_mut()
                        .ok_or(NativeFilesError::ReestablishSession)?;
                    client
                        .list_roots(&random_id())
                        .await
                        .map_err(|error| NativeFilesError::Download(error.into()))
                }
                .await;
                failed = result.is_err();
                recreate = matches!(&result, Err(NativeFilesError::Download(error)) if download_error_retires_client(*error));
                let _ = reply.send(result);
            }
            ReadCommand::BeginBrowse {
                binding,
                core_generation,
                request,
                reply,
            } => {
                let result = async {
                    guard.check_identity(&binding, core_generation)?;
                    guard.check_channel(&lease, Channel::FileRead)?;
                    if let Some((_, mut previous)) = browse.take() {
                        browse_deadline = None;
                        if !previous.finished() {
                            client
                                .as_mut()
                                .ok_or(NativeFilesError::ReestablishSession)?
                                .cancel_browse(&mut previous)
                                .await
                                .map_err(|error| NativeFilesError::Browse(error.into()))?;
                        }
                    }
                    let browse_id = random_id();
                    let deadline =
                        tokio::time::Instant::now() + Duration::from_millis(DIRECTORY_SNAPSHOT_MS);
                    let active = client
                        .as_mut()
                        .ok_or(NativeFilesError::ReestablishSession)?
                        .begin_browse(
                            &browse_id,
                            request.root_id(),
                            request.directory(),
                            request.maximum(),
                        )
                        .await
                        .map_err(|error| NativeFilesError::Browse(error.into()))?;
                    let page = active.page().clone();
                    if !active.finished() {
                        browse = Some((browse_id.clone(), active));
                        // A remote snapshot has one fixed maximum lifetime. The
                        // route retires its cursor even if its IPC owner exits.
                        browse_deadline = Some(deadline);
                    } else {
                        browse_deadline = None;
                    }
                    Ok(NativeBrowsePage {
                        session: binding,
                        browse_id,
                        page: NativeDirectoryPage::from(page),
                    })
                }
                .await;
                if let Err(NativeFilesError::Browse(error)) = &result {
                    recreate = browse_error_retires_client(*error);
                }
                failed = result.is_err();
                if let Err(undelivered) = reply.send(result) {
                    failed = true;
                    if let Ok(page) = undelivered
                        && browse
                            .as_ref()
                            .is_some_and(|(active_id, _)| active_id == &page.browse_id)
                    {
                        browse_deadline = None;
                        recreate |= cancel_active_browse(&mut client, &mut browse).await;
                    }
                }
            }
            ReadCommand::NextBrowse {
                binding,
                core_generation,
                browse_id,
                maximum,
                reply,
            } => {
                let result = async {
                    guard.check_identity(&binding, core_generation)?;
                    guard.check_channel(&lease, Channel::FileRead)?;
                    let Some((active_id, active)) = browse.as_mut() else {
                        return Err(NativeFilesError::BrowseExpired);
                    };
                    if active_id != &browse_id {
                        return Err(NativeFilesError::BrowseExpired);
                    }
                    let next = client
                        .as_mut()
                        .ok_or(NativeFilesError::ReestablishSession)?
                        .next_browse(active, maximum)
                        .await
                        .map_err(|error| NativeFilesError::Browse(error.into()))?;
                    match next {
                        Some(page) => {
                            let result = NativeBrowsePage {
                                session: binding,
                                browse_id,
                                page: NativeDirectoryPage::from(page),
                            };
                            if active.finished() {
                                browse = None;
                                browse_deadline = None;
                            }
                            Ok(Some(result))
                        }
                        None => {
                            browse = None;
                            browse_deadline = None;
                            Ok(None)
                        }
                    }
                }
                .await;
                if let Err(NativeFilesError::Browse(error)) = &result {
                    recreate = browse_error_retires_client(*error);
                    browse = None;
                    browse_deadline = None;
                }
                failed = result.is_err();
                if reply.send(result).is_err() {
                    failed = true;
                    browse_deadline = None;
                    recreate |= cancel_active_browse(&mut client, &mut browse).await;
                }
            }
            ReadCommand::CancelBrowse {
                binding,
                core_generation,
                browse_id,
                reply,
            } => {
                let result = async {
                    guard.check_identity(&binding, core_generation)?;
                    guard.check_channel(&lease, Channel::FileRead)?;
                    let Some((active_id, mut active)) = browse.take() else {
                        return Err(NativeFilesError::BrowseExpired);
                    };
                    if active_id != browse_id {
                        browse = Some((active_id, active));
                        return Err(NativeFilesError::BrowseExpired);
                    }
                    if !active.finished() {
                        client
                            .as_mut()
                            .ok_or(NativeFilesError::ReestablishSession)?
                            .cancel_browse(&mut active)
                            .await
                            .map_err(|error| NativeFilesError::Browse(error.into()))?;
                    }
                    browse_deadline = None;
                    Ok(())
                }
                .await;
                if let Err(NativeFilesError::Browse(error)) = &result {
                    recreate = browse_error_retires_client(*error);
                    browse = None;
                    browse_deadline = None;
                }
                if result.is_ok() {
                    browse_deadline = None;
                }
                failed = result.is_err();
                let _ = reply.send(result);
            }
            ReadCommand::Download {
                binding,
                core_generation,
                request,
                destination,
                mut directive,
                monitor,
                reservation,
            } => {
                let mut browse_cancel_failed = false;
                if let Some((_, mut active)) = browse.take()
                    && !active.finished()
                {
                    browse_deadline = None;
                    browse_cancel_failed = match client.as_mut() {
                        Some(client) => client.cancel_browse(&mut active).await.is_err(),
                        None => true,
                    };
                }
                if browse_cancel_failed {
                    recreate = true;
                    failed = true;
                    finish_task(
                        &monitor,
                        NativeFileTaskPhase::Failed,
                        Some(NativeFilesError::ReestablishSession),
                        None,
                        None,
                    );
                } else if let Err(error) = guard
                    .check_identity(&binding, core_generation)
                    .and_then(|()| guard.check_channel(&lease, Channel::FileRead))
                {
                    failed = true;
                    finish_task(
                        &monitor,
                        NativeFileTaskPhase::Failed,
                        Some(error),
                        None,
                        None,
                    );
                } else if directive.borrow().eq(&Directive::Cancel) {
                    finish_task(&monitor, NativeFileTaskPhase::Cancelled, None, None, None);
                } else if client.is_none() {
                    failed = true;
                    recreate = true;
                    finish_task(
                        &monitor,
                        NativeFileTaskPhase::Failed,
                        Some(NativeFilesError::ReestablishSession),
                        None,
                        None,
                    );
                } else if !acquire_download_active(&reservation, &mut directive, &mut stop).await {
                    finish_task(&monitor, NativeFileTaskPhase::Cancelled, None, None, None);
                } else {
                    monitor
                        .0
                        .send_modify(|status| status.phase = NativeFileTaskPhase::Active);
                    let Some(active_client) = client.take() else {
                        failed = true;
                        recreate = true;
                        finish_task(
                            &monitor,
                            NativeFileTaskPhase::Failed,
                            Some(NativeFilesError::ReestablishSession),
                            None,
                            None,
                        );
                        queue.finished(failed, recreate);
                        queue.closed();
                        break;
                    };
                    let result = run_download(
                        active_client,
                        *request,
                        BoxedDestinationFactory {
                            factory: destination,
                            reservation: reservation.clone(),
                        },
                        directive,
                        reservation,
                        NativeFileTaskContext {
                            task_monitor: monitor.clone(),
                            guard: guard.clone(),
                            lease: lease.clone(),
                            stop: stop.clone(),
                        },
                    )
                    .await;
                    client = result.client;
                    failed = result.failed;
                    recreate = result.recreate;
                    if let Some(error) = result.error {
                        finish_task(
                            &monitor,
                            NativeFileTaskPhase::Failed,
                            Some(error),
                            result.download,
                            None,
                        );
                    } else if result.cancelled {
                        finish_task(
                            &monitor,
                            NativeFileTaskPhase::Cancelled,
                            None,
                            result.download,
                            None,
                        );
                    } else {
                        finish_task(
                            &monitor,
                            NativeFileTaskPhase::Completed,
                            None,
                            result.download,
                            None,
                        );
                    }
                }
            }
        }
        queue.finished(failed, recreate);
        if recreate || guard.check_channel(&lease, Channel::FileRead).is_err() {
            queue.closed();
            break;
        }
    }
    while let Ok(command) = receiver.try_recv() {
        abandon_read_command(command);
    }
    queue.closed();
    // The active browse is intentionally not replaced by a new claimant. On
    // session shutdown the lease/remote owner performs source cleanup.
    drop(browse);
    drop(client);
}

async fn write_actor(
    client: FileWriteClient,
    mut receiver: mpsc::Receiver<WriteCommand>,
    guard: BindingGuard,
    lease: LeaseControl,
    queue: Arc<QueueBook>,
    mut stop: watch::Receiver<bool>,
) {
    let mut client = Some(client);
    loop {
        // Keep the cancellation boundary symmetric with the read actor. An
        // upload may have observed the same stop value before returning here.
        if stop_requested(&mut stop) {
            break;
        }
        let command = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { break; }
                continue;
            }
            command = receiver.recv() => match command {
                Some(command) => command,
                None => break,
            }
        };
        queue.started();
        let mut recreate = false;
        let mut failed = false;
        match command {
            WriteCommand::ListRoots {
                binding,
                core_generation,
                reply,
            } => {
                let result = async {
                    guard.check_identity(&binding, core_generation)?;
                    guard.check_channel(&lease, Channel::FileWrite)?;
                    let client = client
                        .as_mut()
                        .ok_or(NativeFilesError::ReestablishSession)?;
                    client
                        .list_roots(&random_id())
                        .await
                        .map_err(|error| NativeFilesError::Upload(error.into()))
                }
                .await;
                if matches!(&result, Err(NativeFilesError::Upload(error)) if upload_error_retires_client(*error))
                {
                    recreate = true;
                }
                failed = result.is_err();
                let _ = reply.send(result);
            }
            WriteCommand::Upload {
                binding,
                core_generation,
                request,
                source,
                directive,
                monitor,
            } => {
                if let Err(error) = guard
                    .check_identity(&binding, core_generation)
                    .and_then(|()| guard.check_channel(&lease, Channel::FileWrite))
                {
                    failed = true;
                    finish_task(
                        &monitor,
                        NativeFileTaskPhase::Failed,
                        Some(error),
                        None,
                        None,
                    );
                } else if directive.borrow().eq(&Directive::Cancel) {
                    finish_task(&monitor, NativeFileTaskPhase::Cancelled, None, None, None);
                } else if client.is_none() {
                    failed = true;
                    recreate = true;
                    finish_task(
                        &monitor,
                        NativeFileTaskPhase::Failed,
                        Some(NativeFilesError::ReestablishSession),
                        None,
                        None,
                    );
                } else {
                    monitor
                        .0
                        .send_modify(|status| status.phase = NativeFileTaskPhase::Active);
                    let Some(active_client) = client.take() else {
                        failed = true;
                        recreate = true;
                        finish_task(
                            &monitor,
                            NativeFileTaskPhase::Failed,
                            Some(NativeFilesError::ReestablishSession),
                            None,
                            None,
                        );
                        queue.finished(failed, recreate);
                        queue.closed();
                        break;
                    };
                    let result = run_upload(
                        active_client,
                        request,
                        BoxedUploadSourceFactory(source),
                        directive,
                        NativeFileTaskContext {
                            task_monitor: monitor.clone(),
                            guard: guard.clone(),
                            lease: lease.clone(),
                            stop: stop.clone(),
                        },
                    )
                    .await;
                    client = result.client;
                    failed = result.failed;
                    recreate = result.recreate;
                    if let Some(error) = result.error {
                        finish_task(
                            &monitor,
                            NativeFileTaskPhase::Failed,
                            Some(error),
                            None,
                            result.upload,
                        );
                    } else if result.cancelled {
                        finish_task(
                            &monitor,
                            NativeFileTaskPhase::Cancelled,
                            None,
                            None,
                            result.upload,
                        );
                    } else {
                        finish_task(
                            &monitor,
                            NativeFileTaskPhase::Completed,
                            None,
                            None,
                            result.upload,
                        );
                    }
                }
            }
        }
        queue.finished(failed, recreate);
        if recreate || guard.check_channel(&lease, Channel::FileWrite).is_err() {
            queue.closed();
            break;
        }
    }
    while let Ok(command) = receiver.try_recv() {
        abandon_write_command(command);
    }
    queue.closed();
    drop(client);
}

fn abandon_write_command(command: WriteCommand) {
    match command {
        WriteCommand::ListRoots { reply, .. } => {
            let _ = reply.send(Err(NativeFilesError::Closing));
        }
        WriteCommand::Upload { monitor, .. } => {
            finish_task(&monitor, NativeFileTaskPhase::Cancelled, None, None, None)
        }
    }
}

struct UploadRun {
    client: Option<FileWriteClient>,
    upload: Option<NativeUploadStatus>,
    error: Option<NativeFilesError>,
    failed: bool,
    cancelled: bool,
    recreate: bool,
}

struct NativeFileTaskContext {
    task_monitor: NativeFileTaskMonitor,
    guard: BindingGuard,
    lease: LeaseControl,
    stop: watch::Receiver<bool>,
}

async fn run_upload(
    client: FileWriteClient,
    request: NativeUploadRequest,
    source: BoxedUploadSourceFactory,
    mut directive: watch::Receiver<Directive>,
    context: NativeFileTaskContext,
) -> UploadRun {
    let NativeFileTaskContext {
        task_monitor,
        guard,
        lease,
        mut stop,
    } = context;
    let upload = NativeFileUpload::start(client, request, source);
    let native_monitor = upload.monitor();
    let control = upload.control();
    let mut progress = native_monitor.subscribe();
    let mut cancelled = false;
    let mut error = None;
    let mut failed = false;
    let mut recreate = false;
    let completion = async {
        let upload = upload;
        let finish = upload.finish();
        tokio::pin!(finish);
        loop {
            if let Err(identity_error) = guard
                .check_identity(&guard.binding, guard.core_generation)
                .and_then(|()| guard.check_channel(&lease, Channel::FileWrite))
            {
                error = Some(identity_error);
                failed = true;
                cancelled = true;
                control.cancel();
            }
            if stop.has_changed().is_err() || *stop.borrow() {
                cancelled = true;
                control.cancel();
            }
            match *directive.borrow() {
                Directive::Cancel => {
                    cancelled = true;
                    control.cancel();
                }
                Directive::Pause | Directive::Run => {}
            }
            tokio::select! {
                biased;
                result = &mut finish => break result,
                changed = directive.changed() => {
                    if changed.is_err() {
                        cancelled = true;
                        control.cancel();
                    }
                }
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        cancelled = true;
                        control.cancel();
                    }
                }
                changed = progress.changed() => {
                    if changed.is_err() {
                        break Err(nestlink_sdk::upload::NativeUploadError::State("upload monitor closed"));
                    }
                    publish_upload(&task_monitor, native_monitor.status());
                }
            }
        }
    }
    .await;
    let outcome = match completion {
        Ok(outcome) => outcome,
        Err(upload_error) => {
            error.get_or_insert(NativeFilesError::Upload(upload_error));
            failed = true;
            recreate = true;
            let state = native_monitor.status();
            return UploadRun {
                client: None,
                upload: Some(state),
                error,
                failed,
                cancelled,
                recreate,
            };
        }
    };
    let native = outcome.monitor.status();
    publish_upload(&task_monitor, native.clone());
    if let Err(upload_error) = outcome.result {
        if upload_error == nestlink_sdk::upload::NativeUploadError::Cancelled || cancelled {
            cancelled = true;
        } else {
            error.get_or_insert(NativeFilesError::Upload(upload_error));
            failed = true;
            recreate |= upload_error_retires_client(upload_error);
        }
    }
    let client = outcome
        .client
        .and_then(|client| match client.into_client() {
            Ok(client) => Some(client),
            Err(upload_error) => {
                error.get_or_insert(NativeFilesError::Upload(upload_error));
                failed = true;
                recreate = true;
                None
            }
        });
    if client.is_none() {
        recreate = true;
        if error.is_none() && !cancelled {
            error = Some(NativeFilesError::ReestablishSession);
            failed = true;
        }
    }
    UploadRun {
        client,
        upload: Some(native),
        error,
        failed,
        cancelled,
        recreate,
    }
}

fn upload_error_retires_client(error: NativeUploadError) -> bool {
    matches!(
        error,
        NativeUploadError::Transport(_)
            | NativeUploadError::Cleanup(_)
            | NativeUploadError::Authorization { .. }
            | NativeUploadError::Stopped
    )
}

fn download_error_retires_client(error: NativeDownloadError) -> bool {
    matches!(
        error,
        NativeDownloadError::Transport(_)
            | NativeDownloadError::Cleanup(_)
            | NativeDownloadError::Authorization { .. }
            | NativeDownloadError::Stopped
    )
}

fn browse_error_retires_client(error: NativeBrowseError) -> bool {
    matches!(
        error,
        NativeBrowseError::Transport(_)
            | NativeBrowseError::Cleanup(_)
            | NativeBrowseError::Authorization { .. }
            | NativeBrowseError::Stopped
    )
}

fn abandon_read_command(command: ReadCommand) {
    match command {
        ReadCommand::ListRoots { reply, .. } => {
            let _ = reply.send(Err(NativeFilesError::Closing));
        }
        ReadCommand::BeginBrowse { reply, .. } => {
            let _ = reply.send(Err(NativeFilesError::Closing));
        }
        ReadCommand::NextBrowse { reply, .. } => {
            let _ = reply.send(Err(NativeFilesError::Closing));
        }
        ReadCommand::CancelBrowse { reply, .. } => {
            let _ = reply.send(Err(NativeFilesError::Closing));
        }
        ReadCommand::Download { monitor, .. } => {
            finish_task(&monitor, NativeFileTaskPhase::Cancelled, None, None, None)
        }
    }
}

struct DownloadRun {
    client: Option<FileReadClient>,
    download: Option<NativeDownloadStatus>,
    error: Option<NativeFilesError>,
    failed: bool,
    cancelled: bool,
    recreate: bool,
}

async fn await_download_request<F, T>(
    future: F,
    directive: &mut watch::Receiver<Directive>,
    stop: &mut watch::Receiver<bool>,
    control: &NativeDownloadControl,
    task_monitor: &NativeFileTaskMonitor,
    native_monitor: &NativeDownloadMonitor,
) -> (T, bool)
where
    F: Future<Output = T>,
{
    let mut future = Box::pin(future);
    let mut updates = native_monitor.subscribe();
    let mut monitor_open = true;
    let mut cancelled = false;
    publish_download(task_monitor, native_monitor.status());
    loop {
        if !cancelled
            && (directive.has_changed().is_err()
                || *directive.borrow() == Directive::Cancel
                || stop.has_changed().is_err()
                || *stop.borrow())
        {
            control.cancel();
            cancelled = true;
        }
        tokio::select! {
            biased;
            result = &mut future => {
                if !cancelled
                    && (directive.has_changed().is_err()
                        || *directive.borrow() == Directive::Cancel
                        || stop.has_changed().is_err()
                        || *stop.borrow())
                {
                    control.cancel();
                    cancelled = true;
                }
                return (result, cancelled);
            }
            changed = directive.changed(), if !cancelled => {
                if changed.is_err() || *directive.borrow() == Directive::Cancel {
                    control.cancel();
                    cancelled = true;
                }
            }
            changed = stop.changed(), if !cancelled => {
                if changed.is_err() || *stop.borrow() {
                    control.cancel();
                    cancelled = true;
                }
            }
            changed = updates.changed(), if monitor_open => {
                if changed.is_err() {
                    monitor_open = false;
                } else {
                    publish_download(task_monitor, updates.borrow_and_update().clone());
                }
            }
        }
    }
}

async fn publish_download_until_finished(
    task_monitor: &NativeFileTaskMonitor,
    native_monitor: &NativeDownloadMonitor,
) -> NativeDownloadStatus {
    let mut updates = native_monitor.subscribe();
    loop {
        let current = updates.borrow_and_update().clone();
        publish_download(task_monitor, current.clone());
        if current.actor_finished && current.destination.is_none_or(|worker| worker.finished) {
            return current;
        }
        if updates.changed().await.is_err() {
            let current = native_monitor.status();
            publish_download(task_monitor, current.clone());
            return current;
        }
    }
}

async fn run_download(
    client: FileReadClient,
    request: NativeDownloadRequest,
    destination: BoxedDestinationFactory,
    mut directive: watch::Receiver<Directive>,
    reservation: NativeFileBudgetReservation,
    context: NativeFileTaskContext,
) -> DownloadRun {
    let NativeFileTaskContext {
        task_monitor: monitor,
        guard,
        lease,
        mut stop,
    } = context;
    let mut download = NativeFileDownload::start(client, request, destination);
    let native_monitor = download.monitor();
    let control = download.control();
    let mut error = None;
    let mut failed = false;
    let (ready, interrupted) = await_download_request(
        download.ready(),
        &mut directive,
        &mut stop,
        &control,
        &monitor,
        &native_monitor,
    )
    .await;
    let mut cancelled = interrupted;
    if let Err(error_value) = ready {
        if error_value == NativeDownloadError::Cancelled {
            cancelled = true;
        } else {
            error = Some(NativeFilesError::Download(error_value));
            failed = true;
        }
    }
    loop {
        let actual = download.status();
        publish_download(&monitor, actual.clone());
        if error.is_some() || cancelled {
            break;
        }
        let identity = guard
            .check_identity(&guard.binding, guard.core_generation)
            .and_then(|()| guard.check_channel(&lease, Channel::FileRead));
        if let Err(identity_error) = identity {
            error = Some(identity_error);
            failed = true;
            break;
        }
        if stop.has_changed().is_err() || *stop.borrow() {
            download.control().cancel();
            cancelled = true;
            break;
        }
        let requested = if directive.has_changed().is_err() {
            Directive::Cancel
        } else {
            *directive.borrow()
        };
        match requested {
            Directive::Cancel => {
                download.control().cancel();
                cancelled = true;
                break;
            }
            Directive::Pause
                if actual.phase != nestlink_sdk::files::NativeDownloadPhase::Paused =>
            {
                let (pause, interrupted) = await_download_request(
                    download.pause(),
                    &mut directive,
                    &mut stop,
                    &control,
                    &monitor,
                    &native_monitor,
                )
                .await;
                cancelled |= interrupted;
                match pause {
                    Ok(_) if interrupted => {
                        cancelled = true;
                        break;
                    }
                    Ok(status) => {
                        monitor.0.send_modify(|task| {
                            task.phase = NativeFileTaskPhase::Paused;
                            task.download = Some(status);
                        });
                    }
                    Err(NativeDownloadError::Cancelled) => {
                        cancelled = true;
                        break;
                    }
                    Err(pause_error) => {
                        error = Some(NativeFilesError::Download(pause_error));
                        failed = true;
                        break;
                    }
                }
                continue;
            }
            Directive::Pause => {
                monitor
                    .0
                    .send_modify(|task| task.phase = NativeFileTaskPhase::Paused);
                tokio::select! {
                    changed = directive.changed() => {
                        if changed.is_err() { cancelled = true; }
                    }
                    changed = stop.changed() => {
                        if changed.is_err() || *stop.borrow() { cancelled = true; }
                    }
                }
                continue;
            }
            Directive::Run if actual.phase == nestlink_sdk::files::NativeDownloadPhase::Paused => {
                let (resume, interrupted) = await_download_request(
                    download.resume(None),
                    &mut directive,
                    &mut stop,
                    &control,
                    &monitor,
                    &native_monitor,
                )
                .await;
                cancelled |= interrupted;
                match resume {
                    Ok(_) if interrupted => {
                        cancelled = true;
                        break;
                    }
                    Ok(_) => monitor
                        .0
                        .send_modify(|task| task.phase = NativeFileTaskPhase::Active),
                    Err(NativeDownloadError::Cancelled) => {
                        cancelled = true;
                        break;
                    }
                    Err(resume_error) => {
                        error = Some(NativeFilesError::Download(resume_error));
                        failed = true;
                        break;
                    }
                }
                continue;
            }
            Directive::Run => {}
        }
        if actual.source_verified {
            monitor
                .0
                .send_modify(|task| task.phase = NativeFileTaskPhase::Settling);
            let (finish, interrupted) = await_download_request(
                download.finish(),
                &mut directive,
                &mut stop,
                &control,
                &monitor,
                &native_monitor,
            )
            .await;
            match finish {
                Ok(_) => {
                    // A successful Finish is the publication fact. A cancel
                    // racing after it must not rewrite that result.
                }
                Err(NativeDownloadError::Cancelled) => {
                    cancelled = true;
                }
                Err(finish_error) => {
                    cancelled |= interrupted;
                    error = Some(NativeFilesError::Download(finish_error));
                    failed = true;
                }
            }
            break;
        }
        let pull = download.pull();
        tokio::pin!(pull);
        tokio::select! {
            biased;
            changed = directive.changed() => {
                if changed.is_err() { cancelled = true; }
            }
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { cancelled = true; }
            }
            result = &mut pull => {
                if let Err(pull_error) = result {
                    error = Some(NativeFilesError::Download(pull_error));
                    failed = true;
                }
            }
        }
        if cancelled || failed {
            break;
        }
    }
    if error.is_some() || cancelled {
        control.cancel();
        let _ = download.cancel().await;
    }
    let returned = download.take_client().await;
    // `NativeFileDownload::cancel()` is deliberately bounded. A blocked local
    // filesystem call can therefore outlive its actor and returned client; do
    // not mark this Core task finished until the SDK monitor confirms that the
    // owned destination thread actually destroyed its provider and handles.
    let final_status = publish_download_until_finished(&monitor, &native_monitor).await;
    reservation.complete(&final_status);
    match returned {
        Ok(client) => match client.into_client() {
            Ok(client) => DownloadRun {
                client: Some(client),
                download: Some(final_status),
                error,
                failed,
                cancelled,
                recreate: false,
            },
            Err(client_error) => DownloadRun {
                client: None,
                download: Some(final_status),
                error: Some(NativeFilesError::Download(client_error)),
                failed: true,
                cancelled: false,
                recreate: true,
            },
        },
        Err(client_error) => DownloadRun {
            client: None,
            download: Some(final_status),
            error: Some(NativeFilesError::Download(client_error)),
            failed: true,
            cancelled: false,
            recreate: true,
        },
    }
}

fn publish_download(monitor: &NativeFileTaskMonitor, native: NativeDownloadStatus) {
    monitor.0.send_modify(|status| {
        status.confirmed_bytes = native
            .destination
            .map_or(0, |destination| destination.destination.confirmed_bytes);
        status.total_bytes = native.manifest.as_ref().map(|manifest| manifest.size);
        if native.phase == nestlink_sdk::files::NativeDownloadPhase::Paused {
            status.phase = NativeFileTaskPhase::Paused;
        } else if matches!(
            native.phase,
            nestlink_sdk::files::NativeDownloadPhase::SourceVerified
                | nestlink_sdk::files::NativeDownloadPhase::Finalizing
        ) {
            status.phase = NativeFileTaskPhase::Settling;
        } else if !matches!(
            native.phase,
            nestlink_sdk::files::NativeDownloadPhase::Completed
                | nestlink_sdk::files::NativeDownloadPhase::Cancelled
                | nestlink_sdk::files::NativeDownloadPhase::Failed
        ) {
            status.phase = NativeFileTaskPhase::Active;
        }
        status.download = Some(native);
    });
}

fn publish_upload(monitor: &NativeFileTaskMonitor, native: NativeUploadStatus) {
    monitor.0.send_modify(|status| {
        status.confirmed_bytes = native.confirmed_bytes;
        status.total_bytes = native.size;
        if native.phase == nestlink_sdk::upload::NativeUploadPhase::Completed {
            status.phase = NativeFileTaskPhase::Settling;
        } else if !matches!(
            native.phase,
            nestlink_sdk::upload::NativeUploadPhase::Cancelled
                | nestlink_sdk::upload::NativeUploadPhase::Failed
        ) {
            status.phase = NativeFileTaskPhase::Active;
        }
        status.upload = Some(native);
    });
}

fn finish_task(
    monitor: &NativeFileTaskMonitor,
    phase: NativeFileTaskPhase,
    error: Option<NativeFilesError>,
    download: Option<NativeDownloadStatus>,
    upload: Option<NativeUploadStatus>,
) {
    monitor.0.send_modify(|status| {
        status.phase = phase;
        status.error = error;
        if let Some(download) = download {
            status.confirmed_bytes = download
                .destination
                .map_or(0, |destination| destination.destination.confirmed_bytes);
            status.total_bytes = download.manifest.as_ref().map(|manifest| manifest.size);
            status.download = Some(download);
        }
        if let Some(upload) = upload {
            status.confirmed_bytes = upload.confirmed_bytes;
            status.total_bytes = upload.size;
            status.upload = Some(upload);
        }
        status.finished = true;
    });
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeFilesShutdown {
    /// At least one actor or platform worker still owns resources. The caller
    /// must retain this route and keep reaping it until this becomes false.
    pub owner_pending: bool,
    pub cleanup_failed: bool,
    pub worker_failed: bool,
}

#[derive(Default)]
struct NativeFilesShutdownGate {
    outcome: AsyncMutex<Option<NativeFilesShutdown>>,
}

impl NativeFilesShutdownGate {
    async fn run(&self, pass: impl Future<Output = NativeFilesShutdown>) -> NativeFilesShutdown {
        let mut outcome = self.outcome.lock().await;
        if let Some(outcome) = *outcome {
            return outcome;
        }
        let result = pass.await;
        if !result.owner_pending {
            *outcome = Some(result);
        }
        result
    }
}

pub(super) struct NativeFilesRoute {
    owner_store: Weak<Shared>,
    binding: NativeSessionBinding,
    core_generation: u64,
    current_core_generation: Arc<AtomicU64>,
    host: bool,
    read_authorized: bool,
    write_authorized: bool,
    lease: LeaseControl,
    read_claim: Mutex<Option<ClaimedFileRead>>,
    write_claim: Mutex<Option<ClaimedFileWrite>>,
    read_server: AsyncMutex<Option<FileReadServer>>,
    write_server: AsyncMutex<Option<FileWriteServer>>,
    read_server_monitor: Mutex<Option<FileWorkerMonitor>>,
    write_server_monitor: Mutex<Option<FileWriteMonitor>>,
    shutdown_gate: NativeFilesShutdownGate,
    download_budget: Arc<NativeFileBudget>,
    tasks: Mutex<NativeFileTaskBook>,
    reader: Option<Arc<ReadOwner>>,
    writer: Option<Arc<WriteOwner>>,
    closing: std::sync::atomic::AtomicBool,
    cleanup_complete: std::sync::atomic::AtomicBool,
    reaper_running: std::sync::atomic::AtomicBool,
}

impl NativeFilesRoute {
    pub(super) fn attach(
        shared: &Arc<Shared>,
        channels: &mut ChannelRuntime,
        key: &super::NativeSessionKey,
        core_generation: u64,
    ) -> Result<Arc<Self>, NativeFilesError> {
        let binding = NativeSessionBinding {
            request_id: key.request_id.clone(),
            connection_generation: key.connection_generation,
        };
        if binding.request_id.is_empty()
            || binding.connection_generation == 0
            || core_generation == 0
        {
            return Err(NativeFilesError::StaleBinding);
        }
        let lease = channels.lease_control();
        let guard = BindingGuard {
            binding: binding.clone(),
            core_generation,
            current_core_generation: shared.generation.clone(),
        };
        let mut read_claim = None;
        let mut write_claim = None;
        let mut reader = None;
        let mut writer = None;
        if key.file_read_authorized {
            let claim = channels
                .claim_file_read(key.connection_generation)
                .map_err(remote_error)?;
            if key.is_host {
                read_claim = Some(claim);
            } else {
                let client = FileReadClient::from_claimed(claim).map_err(remote_error)?;
                reader = Some(start_read_owner(client, guard.clone(), lease.clone()));
            }
        }
        if key.file_write_authorized {
            let claim = channels
                .claim_file_write(key.connection_generation)
                .map_err(remote_error)?;
            if key.is_host {
                write_claim = Some(claim);
            } else {
                let client = FileWriteClient::from_claimed(claim).map_err(remote_error)?;
                writer = Some(start_write_owner(client, guard, lease.clone()));
            }
        }
        Ok(Arc::new(Self {
            owner_store: Arc::downgrade(shared),
            binding,
            core_generation,
            current_core_generation: shared.generation.clone(),
            host: key.is_host,
            read_authorized: key.file_read_authorized,
            write_authorized: key.file_write_authorized,
            lease,
            read_claim: Mutex::new(read_claim),
            write_claim: Mutex::new(write_claim),
            read_server: AsyncMutex::new(None),
            write_server: AsyncMutex::new(None),
            read_server_monitor: Mutex::new(None),
            write_server_monitor: Mutex::new(None),
            shutdown_gate: NativeFilesShutdownGate::default(),
            download_budget: shared.native_file_budget.clone(),
            tasks: Mutex::new(NativeFileTaskBook::default()),
            reader,
            writer,
            closing: std::sync::atomic::AtomicBool::new(false),
            cleanup_complete: std::sync::atomic::AtomicBool::new(false),
            reaper_running: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    fn check(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        channel: Channel,
    ) -> Result<(), NativeFilesError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(NativeFilesError::Closing);
        }
        BindingGuard {
            binding: self.binding.clone(),
            core_generation: self.core_generation,
            current_core_generation: self.current_core_generation.clone(),
        }
        .check_identity(binding, core_generation)?;
        if (channel == Channel::FileRead && !self.read_authorized)
            || (channel == Channel::FileWrite && !self.write_authorized)
        {
            return Err(NativeFilesError::Unauthorized);
        }
        self.lease
            .check_channel_binding(channel, self.binding.connection_generation)
            .map_err(remote_error)
    }

    fn check_endpoint(&self, host: bool) -> Result<(), NativeFilesError> {
        if self.host != host {
            return Err(NativeFilesError::WrongEndpoint);
        }
        Ok(())
    }

    pub(super) fn permits_file_access(&self) -> bool {
        self.read_authorized || self.write_authorized
    }

    fn access(&self) -> NativeFileAccess {
        NativeFileAccess {
            is_host: self.host,
            read: self.read_authorized,
            write: self.write_authorized,
        }
    }

    pub(super) fn current_for_core(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> bool {
        !self.closing.load(Ordering::Acquire)
            && binding == &self.binding
            && core_generation == self.core_generation
            && self.current_core_generation.load(Ordering::Acquire) == self.core_generation
    }

    async fn start_file_read_service<D: FileReadDevice>(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        device: D,
    ) -> Result<FileWorkerMonitor, NativeFilesError> {
        self.check_endpoint(true)?;
        self.check(binding, core_generation, Channel::FileRead)?;
        let mut server = self.read_server.lock().await;
        if server.is_some() {
            return Err(NativeFilesError::InvalidControl);
        }
        let claim = self
            .read_claim
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(NativeFilesError::OwnerUnavailable)?;
        let read = FileReadServer::start_claimed(claim, device).map_err(remote_error)?;
        let monitor = read.monitor();
        *self
            .read_server_monitor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(monitor.clone());
        *server = Some(read);
        Ok(monitor)
    }

    async fn start_file_write_service<D: FileWriteDevice>(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        device: D,
    ) -> Result<FileWriteMonitor, NativeFilesError> {
        self.check_endpoint(true)?;
        self.check(binding, core_generation, Channel::FileWrite)?;
        let mut server = self.write_server.lock().await;
        if server.is_some() {
            return Err(NativeFilesError::InvalidControl);
        }
        let claim = self
            .write_claim
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(NativeFilesError::OwnerUnavailable)?;
        let write = FileWriteServer::start_claimed(claim, device).map_err(remote_error)?;
        let monitor = write.monitor();
        *self
            .write_server_monitor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(monitor.clone());
        *server = Some(write);
        Ok(monitor)
    }

    fn read_server_status(&self) -> Option<FileWorkerStatus> {
        self.read_server_monitor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(FileWorkerMonitor::status)
    }

    fn write_server_status(&self) -> Option<nestlink_remote::upload::FileWriteWorkerStatus> {
        self.write_server_monitor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(FileWriteMonitor::status)
    }

    async fn read_roots(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<Vec<FileRoot>, NativeFilesError> {
        self.check_endpoint(false)?;
        self.check(binding, core_generation, Channel::FileRead)?;
        let owner = self
            .reader
            .as_ref()
            .ok_or(NativeFilesError::OwnerUnavailable)?;
        let (reply, result) = oneshot::channel();
        owner.send(ReadCommand::ListRoots {
            binding: binding.clone(),
            core_generation,
            reply,
        })?;
        result
            .await
            .map_err(|_| NativeFilesError::OwnerUnavailable)?
    }

    async fn write_roots(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<Vec<FileRoot>, NativeFilesError> {
        self.check_endpoint(false)?;
        self.check(binding, core_generation, Channel::FileWrite)?;
        let owner = self
            .writer
            .as_ref()
            .ok_or(NativeFilesError::OwnerUnavailable)?;
        let (reply, result) = oneshot::channel();
        owner.send(WriteCommand::ListRoots {
            binding: binding.clone(),
            core_generation,
            reply,
        })?;
        result
            .await
            .map_err(|_| NativeFilesError::OwnerUnavailable)?
    }

    async fn browse_begin(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        request: NativeBrowseRequest,
    ) -> Result<NativeBrowsePage, NativeFilesError> {
        self.check_endpoint(false)?;
        self.check(binding, core_generation, Channel::FileRead)?;
        let owner = self
            .reader
            .as_ref()
            .ok_or(NativeFilesError::OwnerUnavailable)?;
        let (reply, result) = oneshot::channel();
        owner.send(ReadCommand::BeginBrowse {
            binding: binding.clone(),
            core_generation,
            request,
            reply,
        })?;
        result
            .await
            .map_err(|_| NativeFilesError::OwnerUnavailable)?
    }

    async fn browse_next(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        browse_id: &str,
        maximum: u32,
    ) -> Result<Option<NativeBrowsePage>, NativeFilesError> {
        self.check_endpoint(false)?;
        self.check(binding, core_generation, Channel::FileRead)?;
        let owner = self
            .reader
            .as_ref()
            .ok_or(NativeFilesError::OwnerUnavailable)?;
        let (reply, result) = oneshot::channel();
        owner.send(ReadCommand::NextBrowse {
            binding: binding.clone(),
            core_generation,
            browse_id: browse_id.to_owned(),
            maximum,
            reply,
        })?;
        result
            .await
            .map_err(|_| NativeFilesError::OwnerUnavailable)?
    }

    async fn browse_cancel(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        browse_id: &str,
    ) -> Result<(), NativeFilesError> {
        self.check_endpoint(false)?;
        self.check(binding, core_generation, Channel::FileRead)?;
        let owner = self
            .reader
            .as_ref()
            .ok_or(NativeFilesError::OwnerUnavailable)?;
        let (reply, result) = oneshot::channel();
        owner.send(ReadCommand::CancelBrowse {
            binding: binding.clone(),
            core_generation,
            browse_id: browse_id.to_owned(),
            reply,
        })?;
        result
            .await
            .map_err(|_| NativeFilesError::OwnerUnavailable)?
    }

    fn download<D: FileDestinationFactory>(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        request: NativeDownloadRequest,
        destination: D,
    ) -> Result<NativeFileTask, NativeFilesError> {
        self.check_endpoint(false)?;
        self.check(binding, core_generation, Channel::FileRead)?;
        let owner = self
            .reader
            .as_ref()
            .ok_or(NativeFilesError::OwnerUnavailable)?;
        let reservation = self.download_budget.reserve_task()?;
        let (task, directive, monitor) = self.new_task(NativeFileTaskKind::Download);
        self.remember_task(&task)?;
        if let Err(error) = owner.send(ReadCommand::Download {
            binding: binding.clone(),
            core_generation,
            request: Box::new(request),
            destination: Box::new(destination),
            directive,
            monitor,
            reservation,
        }) {
            self.forget_task(task.task_id());
            return Err(error);
        }
        Ok(task)
    }

    fn upload<S: FileUploadSourceFactory>(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        request: NativeUploadRequest,
        source: S,
    ) -> Result<NativeFileTask, NativeFilesError> {
        self.check_endpoint(false)?;
        self.check(binding, core_generation, Channel::FileWrite)?;
        let owner = self
            .writer
            .as_ref()
            .ok_or(NativeFilesError::OwnerUnavailable)?;
        let (task, directive, monitor) = self.new_task(NativeFileTaskKind::Upload);
        self.remember_task(&task)?;
        if let Err(error) = owner.send(WriteCommand::Upload {
            binding: binding.clone(),
            core_generation,
            request,
            source: Box::new(source),
            directive,
            monitor,
        }) {
            self.forget_task(task.task_id());
            return Err(error);
        }
        Ok(task)
    }

    fn new_task(
        &self,
        kind: NativeFileTaskKind,
    ) -> (
        NativeFileTask,
        watch::Receiver<Directive>,
        NativeFileTaskMonitor,
    ) {
        let task_id = random_id();
        let (status, _) = watch::channel(NativeFileTaskStatus {
            task_id: task_id.clone(),
            kind,
            ..NativeFileTaskStatus::default()
        });
        let monitor = NativeFileTaskMonitor(status);
        let (directive, signals) = watch::channel(Directive::Run);
        let task = NativeFileTask {
            task_id: task_id.clone(),
            control: NativeFileTaskControl {
                binding: BindingGuard {
                    binding: self.binding.clone(),
                    core_generation: self.core_generation,
                    current_core_generation: self.current_core_generation.clone(),
                },
                lease: self.lease.clone(),
                kind,
                directive,
                monitor: monitor.clone(),
            },
            monitor: monitor.clone(),
        };
        (task, signals, monitor)
    }

    fn remember_task(&self, task: &NativeFileTask) -> Result<(), NativeFilesError> {
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(task.task_id.clone(), task.control.clone())
    }

    fn forget_task(&self, task_id: &str) {
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(task_id);
    }

    fn find_task(&self, task_id: &str) -> Result<NativeFileTaskControl, NativeFilesError> {
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .controls
            .get(task_id)
            .cloned()
            .ok_or(NativeFilesError::InvalidControl)
    }

    fn task_status(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        task_id: &str,
    ) -> Result<NativeFileTaskStatus, NativeFilesError> {
        self.check_endpoint(false)?;
        let task = self.find_task(task_id)?;
        let channel = match task.kind {
            NativeFileTaskKind::Download => Channel::FileRead,
            NativeFileTaskKind::Upload => Channel::FileWrite,
        };
        self.check(binding, core_generation, channel)?;
        Ok(task.monitor.status())
    }

    fn task_control(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        task_id: &str,
        action: NativeFileTaskAction,
    ) -> Result<(), NativeFilesError> {
        self.check_endpoint(false)?;
        let task = self.find_task(task_id)?;
        let channel = match task.kind {
            NativeFileTaskKind::Download => Channel::FileRead,
            NativeFileTaskKind::Upload => Channel::FileWrite,
        };
        self.check(binding, core_generation, channel)?;
        match action {
            NativeFileTaskAction::Pause => task.pause(binding, core_generation),
            NativeFileTaskAction::Resume => task.resume(binding, core_generation),
            NativeFileTaskAction::Cancel => task.cancel(binding, core_generation),
        }
    }

    fn queue_status(&self) -> NativeFilesQueueStatus {
        NativeFilesQueueStatus {
            read: self.reader.as_ref().map(|owner| owner.queue.status()),
            write: self.writer.as_ref().map(|owner| owner.queue.status()),
        }
    }

    fn request_stop(&self) {
        self.closing.store(true, Ordering::Release);
        if let Some(reader) = &self.reader {
            reader.stop.send_replace(true);
        }
        if let Some(writer) = &self.writer {
            writer.stop.send_replace(true);
        }
        self.read_claim
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        self.write_claim
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    pub(super) fn is_cleanup_complete(&self) -> bool {
        self.cleanup_complete.load(Ordering::Acquire)
    }

    pub(super) fn schedule_reap(self: &Arc<Self>) {
        self.request_stop();
        if self
            .reaper_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let route = self.clone();
        tokio::spawn(async move {
            let result = route.shutdown(StopReason::ExplicitExit).await;
            route.reaper_running.store(false, Ordering::Release);
            if result.owner_pending {
                tokio::time::sleep(Duration::from_millis(50)).await;
                route.schedule_reap();
            } else if let Some(shared) = route.owner_store.upgrade() {
                shared.remove_completed_native_files_owners();
            }
        });
    }

    pub(super) async fn shutdown(self: &Arc<Self>, reason: StopReason) -> NativeFilesShutdown {
        self.request_stop();
        // The actor's periodic owner reaper and the native-session task can
        // both reach this route after it is detached. Serialize the complete
        // pass so a late timed-out pass cannot overwrite completion recorded
        // by a concurrent pass that already joined the workers.
        self.shutdown_gate
            .run(async {
                let mut cleanup_failed = self.lease.stop(reason).is_err();
                let mut worker_failed = false;
                let mut pending = false;
                if let Some(reader) = &self.reader {
                    pending |= !reader
                        .join(Duration::from_millis(FILE_WORKER_CLEANUP_MS))
                        .await;
                    worker_failed |= reader.actor_failed();
                }
                if let Some(writer) = &self.writer {
                    pending |= !writer
                        .join(Duration::from_millis(FILE_WORKER_CLEANUP_MS))
                        .await;
                    worker_failed |= writer.actor_failed();
                }
                {
                    let mut server = self.read_server.lock().await;
                    if let Some(current) = server.as_mut() {
                        match current.shutdown(reason).await {
                            Ok(FileShutdown::Finished) => {
                                server.take();
                            }
                            Ok(FileShutdown::TimedOut) => {
                                cleanup_failed = true;
                                pending = true;
                            }
                            Err(_) => {
                                cleanup_failed = true;
                                pending = true;
                            }
                        }
                    }
                }
                {
                    let mut server = self.write_server.lock().await;
                    if let Some(current) = server.as_mut() {
                        match current.shutdown(reason).await {
                            Ok(FileShutdown::Finished) => {
                                server.take();
                            }
                            Ok(FileShutdown::TimedOut) => {
                                cleanup_failed = true;
                                pending = true;
                            }
                            Err(_) => {
                                cleanup_failed = true;
                                pending = true;
                            }
                        }
                    }
                }
                if self
                    .reader
                    .as_ref()
                    .is_some_and(|reader| !reader.finished())
                    || self
                        .writer
                        .as_ref()
                        .is_some_and(|writer| !writer.finished())
                {
                    pending = true;
                }
                if let Some(status) = self.read_server_status() {
                    pending |= !status.finished;
                    cleanup_failed |= status.cleanup_timed_out;
                    worker_failed |= status.error.is_some();
                }
                if let Some(status) = self.write_server_status() {
                    pending |= !status.finished;
                    cleanup_failed |= status.cleanup_timed_out || status.cleanup_error.is_some();
                    worker_failed |= status.error.is_some();
                }
                self.cleanup_complete.store(!pending, Ordering::Release);
                let outcome = NativeFilesShutdown {
                    owner_pending: pending,
                    cleanup_failed,
                    worker_failed,
                };
                if !pending && let Some(shared) = self.owner_store.upgrade() {
                    shared.remove_completed_native_files_owners();
                }
                outcome
            })
            .await
    }
}

impl Shared {
    pub(super) fn set_native_files_route(&self, route: Option<Arc<NativeFilesRoute>>) {
        let mut current = self
            .native_files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(previous) = std::mem::replace(&mut *current, route) {
            previous.request_stop();
            self.store_native_files_owner(previous, false);
        }
    }

    pub(super) fn retain_native_files_owner(&self, route: Arc<NativeFilesRoute>) {
        self.store_native_files_owner(route, true);
    }

    fn store_native_files_owner(&self, route: Arc<NativeFilesRoute>, schedule: bool) {
        route.request_stop();
        let mut owners = self
            .native_files_owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Shutdown publishes completion before acquiring this same lock to
        // remove completed routes. Recheck under the lock so a route that
        // finished just before it was detached cannot be inserted after its
        // final removal and strand AppCore shutdown waiting on a dead owner.
        if route.is_cleanup_complete() {
            return;
        }
        if !owners.iter().any(|owner| Arc::ptr_eq(owner, &route)) {
            owners.push(route.clone());
        }
        drop(owners);
        if schedule {
            route.schedule_reap();
        }
    }

    pub(super) fn reap_native_files_owners(&self) {
        let mut owners = self
            .native_files_owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        owners.retain(|owner| {
            if owner.is_cleanup_complete() {
                false
            } else {
                owner.schedule_reap();
                true
            }
        });
    }

    fn remove_completed_native_files_owners(&self) {
        self.native_files_owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|owner| !owner.is_cleanup_complete());
    }

    pub(super) fn native_files_cleanup_pending(&self) -> bool {
        !self
            .native_files_owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    fn native_files_route(&self) -> Option<Arc<NativeFilesRoute>> {
        self.native_files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl CoreHandle {
    /// Snapshot of the shared native-download budget for this Core. Temporary
    /// bytes can remain reserved after an uncertain cleanup until the Core is
    /// dropped; callers should use this for admission and diagnostics.
    pub fn native_download_budget_status(&self) -> NativeDownloadQueueStatus {
        self.shared
            .native_file_budget
            .status(self.shared.closing.load(Ordering::Acquire))
    }

    fn file_route(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<Arc<NativeFilesRoute>, NativeFilesError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(NativeFilesError::Closing);
        }
        if self.shared.generation.load(Ordering::Acquire) != core_generation {
            return Err(NativeFilesError::StaleBinding);
        }
        let snapshot = self.snapshot();
        if !snapshot
            .native_session
            .data
            .as_ref()
            .is_some_and(|session| {
                session.status == crate::NativeSessionStatus::Connected
                    && session.request_id == binding.request_id
                    && session.connection_generation == binding.connection_generation
            })
        {
            return Err(NativeFilesError::StaleBinding);
        }
        let route = self
            .shared
            .native_files_route()
            .ok_or(NativeFilesError::Unauthorized)?;
        if !route.current_for_core(binding, core_generation) {
            return Err(NativeFilesError::StaleBinding);
        }
        Ok(route)
    }

    /// Current binding for a session that has at least one approved file
    /// direction. It contains no permission or operating-system path data.
    pub fn native_file_session_binding(&self) -> Option<NativeSessionBinding> {
        let snapshot = self.snapshot();
        let session = snapshot.native_session.data.as_ref()?;
        if session.status != crate::NativeSessionStatus::Connected {
            return None;
        }
        let binding = NativeSessionBinding {
            request_id: session.request_id.clone(),
            connection_generation: session.connection_generation,
        };
        let route = self.shared.native_files_route()?;
        route.permits_file_access().then(|| {
            route
                .current_for_core(&binding, snapshot.generation)
                .then_some(binding)
        })?
    }

    /// Return the file directions granted by this session's proved route.
    pub fn native_file_access(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<NativeFileAccess, NativeFilesError> {
        Ok(self.file_route(binding, core_generation)?.access())
    }

    pub async fn native_file_read_roots(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<Vec<FileRoot>, NativeFilesError> {
        let route = self.file_route(binding, core_generation)?;
        route.read_roots(binding, core_generation).await
    }

    pub async fn native_file_write_roots(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<Vec<FileRoot>, NativeFilesError> {
        let route = self.file_route(binding, core_generation)?;
        route.write_roots(binding, core_generation).await
    }

    pub async fn native_browse_begin(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        request: NativeBrowseRequest,
    ) -> Result<NativeBrowsePage, NativeFilesError> {
        let route = self.file_route(binding, core_generation)?;
        route.browse_begin(binding, core_generation, request).await
    }

    pub async fn native_browse_next(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        browse_id: &str,
        maximum: u32,
    ) -> Result<Option<NativeBrowsePage>, NativeFilesError> {
        let route = self.file_route(binding, core_generation)?;
        route
            .browse_next(binding, core_generation, browse_id, maximum)
            .await
    }

    pub async fn native_browse_cancel(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        browse_id: &str,
    ) -> Result<(), NativeFilesError> {
        let route = self.file_route(binding, core_generation)?;
        route
            .browse_cancel(binding, core_generation, browse_id)
            .await
    }

    pub fn native_download<D: FileDestinationFactory>(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        request: NativeDownloadRequest,
        destination: D,
    ) -> Result<NativeFileTask, NativeFilesError> {
        self.file_route(binding, core_generation)?.download(
            binding,
            core_generation,
            request,
            destination,
        )
    }

    /// Restart recovery enters the normal current-route queue. No stored task
    /// recreates a lease, client, generation, endpoint proof or local consent.
    pub fn native_download_recover<D: FileDestinationFactory>(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        recovery: nestlink_protocol::file_recovery::DownloadRecoveryResume,
        destination: D,
    ) -> Result<NativeFileTask, NativeFilesError> {
        let request = NativeDownloadRequest::recover(recovery)
            .map_err(|_| NativeFilesError::InvalidControl)?;
        self.native_download(binding, core_generation, request, destination)
    }

    pub fn native_upload<S: FileUploadSourceFactory>(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        request: NativeUploadRequest,
        source: S,
    ) -> Result<NativeFileTask, NativeFilesError> {
        self.file_route(binding, core_generation)?
            .upload(binding, core_generation, request, source)
    }

    pub fn native_files_queue_status(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
    ) -> Result<NativeFilesQueueStatus, NativeFilesError> {
        let route = self.file_route(binding, core_generation)?;
        Ok(route.queue_status())
    }

    pub async fn native_host_start_file_read<D: FileReadDevice>(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        device: D,
    ) -> Result<FileWorkerMonitor, NativeFilesError> {
        // The claimed channel and device are transferred to one route-owned
        // actor. A dynamic device can share its local consent registry with
        // the caller, so root selection and revocation do not reclaim the
        // channel or restart the service.
        let route = self.file_route(binding, core_generation)?;
        route
            .start_file_read_service(binding, core_generation, device)
            .await
    }

    pub async fn native_host_start_file_write<D: FileWriteDevice>(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        device: D,
    ) -> Result<FileWriteMonitor, NativeFilesError> {
        // Like FileRead, this service is started once per proved session; a
        // device may consult a shared local registry for later root changes.
        let route = self.file_route(binding, core_generation)?;
        route
            .start_file_write_service(binding, core_generation, device)
            .await
    }

    /// Return a status snapshot for a task retained by the current session
    /// route. Task IDs are random, session-scoped opaque identifiers.
    pub fn native_file_task_status(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        task_id: &str,
    ) -> Result<NativeFileTaskStatus, NativeFilesError> {
        self.file_route(binding, core_generation)?
            .task_status(binding, core_generation, task_id)
    }

    /// Control a task retained by the current route. The caller must keep the
    /// same proved binding and product generation used to create the task.
    pub fn native_file_task_control(
        &self,
        binding: &NativeSessionBinding,
        core_generation: u64,
        task_id: &str,
        action: NativeFileTaskAction,
    ) -> Result<(), NativeFilesError> {
        self.file_route(binding, core_generation)?.task_control(
            binding,
            core_generation,
            task_id,
            action,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{NativeFilesShutdownGate, QueueBook, ReadOwner, WriteOwner, stop_requested};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot, watch};

    fn cancelled_actor(
        stop: watch::Receiver<bool>,
        finished: Arc<AtomicBool>,
    ) -> (
        tokio::task::JoinHandle<()>,
        oneshot::Receiver<()>,
        oneshot::Sender<()>,
    ) {
        let (cancel_seen, cancel_seen_rx) = oneshot::channel();
        let (resume, resume_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut stop = stop;
            // Model an in-flight command consuming the cancellation update.
            let _ = stop.changed().await;
            let _ = cancel_seen.send(());
            let _ = resume_rx.await;
            while !stop_requested(&mut stop) {
                if stop.changed().await.is_err() {
                    break;
                }
            }
            finished.store(true, Ordering::Release);
        });
        (task, cancel_seen_rx, resume)
    }

    #[tokio::test]
    async fn reader_and_writer_join_keep_timed_out_owners_until_stop_is_observed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (read_stop, read_stop_rx) = watch::channel(false);
        let read_finished = Arc::new(AtomicBool::new(false));
        let (read_task, read_cancel_seen, read_resume) =
            cancelled_actor(read_stop_rx, read_finished.clone());
        let (read_sender, _read_receiver) = mpsc::channel(1);
        let reader = ReadOwner {
            sender: read_sender,
            queue: QueueBook::new(1),
            stop: read_stop.clone(),
            finished: read_finished.clone(),
            actor_failed: AtomicBool::new(false),
            task: tokio::sync::Mutex::new(Some(read_task)),
        };
        read_stop.send_replace(true);
        read_cancel_seen.await?;
        assert!(!reader.join(Duration::from_millis(1)).await);
        assert!(!read_finished.load(Ordering::Acquire));
        read_resume
            .send(())
            .map_err(|_| "reader stopped before resume")?;
        assert!(reader.join(Duration::from_secs(1)).await);
        assert!(read_finished.load(Ordering::Acquire));
        assert!(!reader.actor_failed());

        let (write_stop, write_stop_rx) = watch::channel(false);
        let write_finished = Arc::new(AtomicBool::new(false));
        let (write_task, write_cancel_seen, write_resume) =
            cancelled_actor(write_stop_rx, write_finished.clone());
        let (write_sender, _write_receiver) = mpsc::channel(1);
        let writer = WriteOwner {
            sender: write_sender,
            queue: QueueBook::new(1),
            stop: write_stop.clone(),
            finished: write_finished.clone(),
            actor_failed: AtomicBool::new(false),
            task: tokio::sync::Mutex::new(Some(write_task)),
        };
        write_stop.send_replace(true);
        write_cancel_seen.await?;
        assert!(!writer.join(Duration::from_millis(1)).await);
        assert!(!write_finished.load(Ordering::Acquire));
        write_resume
            .send(())
            .map_err(|_| "writer stopped before resume")?;
        assert!(writer.join(Duration::from_secs(1)).await);
        assert!(write_finished.load(Ordering::Acquire));
        assert!(!writer.actor_failed());
        Ok(())
    }

    struct ActivePass {
        active: Arc<AtomicUsize>,
    }

    impl ActivePass {
        fn enter(active: Arc<AtomicUsize>, overlap: Arc<AtomicBool>) -> Self {
            if active.fetch_add(1, Ordering::SeqCst) != 0 {
                overlap.store(true, Ordering::SeqCst);
            }
            Self { active }
        }
    }

    impl Drop for ActivePass {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_files_reaper_and_session_shutdown_share_one_retryable_pass()
    -> Result<(), Box<dyn std::error::Error>> {
        let gate = Arc::new(NativeFilesShutdownGate::default());
        let active = Arc::new(AtomicUsize::new(0));
        let overlap = Arc::new(AtomicBool::new(false));
        let passes = Arc::new(AtomicUsize::new(0));
        let (reaper_started, reaper_started_rx) = oneshot::channel();
        let (release_reaper, release_reaper_rx) = oneshot::channel();

        let reaper_gate = gate.clone();
        let reaper_active = active.clone();
        let reaper_overlap = overlap.clone();
        let reaper_passes = passes.clone();
        let reaper = tokio::spawn(async move {
            reaper_gate
                .run(async move {
                    let _active = ActivePass::enter(reaper_active, reaper_overlap);
                    reaper_passes.fetch_add(1, Ordering::SeqCst);
                    let _ = reaper_started.send(());
                    let _ = release_reaper_rx.await;
                    super::NativeFilesShutdown {
                        owner_pending: true,
                        ..Default::default()
                    }
                })
                .await
        });
        reaper_started_rx.await?;

        let session_gate = gate.clone();
        let session_active = active.clone();
        let session_overlap = overlap.clone();
        let session_passes = passes.clone();
        let (session_requested, session_requested_rx) = oneshot::channel();
        let session = tokio::spawn(async move {
            let _ = session_requested.send(());
            session_gate
                .run(async move {
                    let _active = ActivePass::enter(session_active, session_overlap);
                    session_passes.fetch_add(1, Ordering::SeqCst);
                    super::NativeFilesShutdown::default()
                })
                .await
        });
        session_requested_rx.await?;
        release_reaper
            .send(())
            .map_err(|_| "reaper pass was not waiting for release")?;

        let reaper_outcome = reaper.await?;
        let session_outcome = session.await?;
        assert!(reaper_outcome.owner_pending);
        assert!(!session_outcome.owner_pending);
        assert!(!overlap.load(Ordering::SeqCst));
        assert_eq!(passes.load(Ordering::SeqCst), 2);

        // A completed worker join is terminal and must not be rerun by a late
        // owner-reaper wakeup. Pending results above remain retryable.
        let cached = gate
            .run(async {
                passes.fetch_add(1, Ordering::SeqCst);
                super::NativeFilesShutdown::default()
            })
            .await;
        assert_eq!(cached, session_outcome);
        assert_eq!(passes.load(Ordering::SeqCst), 2);
        Ok(())
    }
}
