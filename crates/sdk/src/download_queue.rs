//! Bounded native download ownership and temporary-byte reservations. Share one
//! queue across an application's sessions to enforce its aggregate budget. A task
//! keeps its reservation until source cleanup and the actual destination thread
//! have finished, including cleanup that outlives a bounded shutdown timeout.
use crate::files::{
    NativeDownloadError, NativeDownloadMonitor, NativeDownloadPhase, NativeDownloadRequest,
    NativeDownloadStatus, NativeFileDownload,
};
use nestlink_protocol::FILE_SIZE_BYTES;
use nestlink_remote::files::{
    FileDestination, FileDestinationFactory, FileDownloadSnapshot, FileDownloadView,
    FileReadClient, FileReadConsent,
};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::sync::{Notify, watch};

pub const NATIVE_DOWNLOAD_ACTIVE_MAX: usize = 16;
pub const NATIVE_DOWNLOAD_TASKS_MAX: usize = 128;
pub const NATIVE_DOWNLOAD_RESERVED_MAX: u64 = FILE_SIZE_BYTES * NATIVE_DOWNLOAD_ACTIVE_MAX as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeDownloadQueueLimits {
    pub active: usize,
    /// Active and queued owners together; cancelled cleanup still counts.
    pub tasks: usize,
    /// Concurrent temporary-byte reservations, not a persistent storage quota.
    pub reserved_bytes: u64,
}
impl Default for NativeDownloadQueueLimits {
    fn default() -> Self {
        Self {
            active: 2,
            tasks: 32,
            reserved_bytes: FILE_SIZE_BYTES,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeDownloadQueueError {
    #[error("download queue limits exceed the local hard limits")]
    InvalidLimits,
    #[error("download task exceeds its file or aggregate reservation limit")]
    ReservationLimit,
    #[error("download queue is full")]
    Full,
    #[error("download queue is closed")]
    Closed,
    #[error("download queue requires an active Tokio runtime")]
    NoRuntime,
    #[error("download task was cancelled")]
    Cancelled,
    #[error("verified source manifest exceeds the approved task budget")]
    ManifestBudget,
    #[error("download failed: {0}")]
    Download(NativeDownloadError),
    #[error("download task owner ended unexpectedly")]
    OwnerEnded,
}
/// A rejected submission has already retired its idle FileRead claim. The
/// retirement result is separate from the admission error and remains visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{cause}")]
pub struct NativeDownloadSubmissionError {
    pub cause: NativeDownloadQueueError,
    pub client_retirement: Result<(), NativeDownloadError>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NativeDownloadTaskPhase {
    #[default]
    Queued,
    Active,
    Settling,
    Completed,
    Cancelled,
    Failed,
}
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NativeDownloadTaskStatus {
    pub phase: NativeDownloadTaskPhase,
    pub maximum_bytes: u64,
    pub reserved_bytes: u64,
    pub native: Option<NativeDownloadStatus>,
    pub client_retirement: Option<Result<(), NativeDownloadError>>,
    pub error: Option<NativeDownloadQueueError>,
    /// True only after all owned source/destination cleanup and budget release.
    pub finished: bool,
}
#[derive(Clone)]
pub struct NativeDownloadTaskMonitor(watch::Sender<NativeDownloadTaskStatus>);
impl NativeDownloadTaskMonitor {
    pub fn status(&self) -> NativeDownloadTaskStatus {
        self.0.borrow().clone()
    }
    pub fn subscribe(&self) -> watch::Receiver<NativeDownloadTaskStatus> {
        self.0.subscribe()
    }
    /// Dropping this wait neither releases resources nor stops the owned task.
    pub async fn wait_finished(&self) -> NativeDownloadTaskStatus {
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
pub struct NativeDownloadTaskControl(watch::Sender<bool>);
impl NativeDownloadTaskControl {
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }
    fn cancelled(&self) -> bool {
        *self.0.borrow()
    }
}
/// The handle owns user intent; dropping it requests cancellation. Retain a
/// cloned monitor to observe actual late cleanup independently of the handle.
pub struct NativeDownloadTask {
    control: NativeDownloadTaskControl,
    monitor: NativeDownloadTaskMonitor,
}
impl NativeDownloadTask {
    pub fn control(&self) -> NativeDownloadTaskControl {
        self.control.clone()
    }
    pub fn monitor(&self) -> NativeDownloadTaskMonitor {
        self.monitor.clone()
    }
    pub fn status(&self) -> NativeDownloadTaskStatus {
        self.monitor.status()
    }
    pub fn cancel(&self) {
        self.control.cancel();
    }
    pub async fn wait_finished(&self) -> NativeDownloadTaskStatus {
        self.monitor.wait_finished().await
    }
}
impl Drop for NativeDownloadTask {
    fn drop(&mut self) {
        self.cancel();
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeDownloadQueueStatus {
    pub closed: bool,
    pub tasks: usize,
    pub active: usize,
    pub queued: usize,
    pub reserved_bytes: u64,
}
#[derive(Clone)]
pub struct NativeDownloadQueueMonitor(Arc<Budget>);
impl NativeDownloadQueueMonitor {
    pub fn status(&self) -> NativeDownloadQueueStatus {
        *self.0.events.borrow()
    }
    pub fn subscribe(&self) -> watch::Receiver<NativeDownloadQueueStatus> {
        self.0.events.subscribe()
    }
    pub async fn wait_idle(&self) -> NativeDownloadQueueStatus {
        let mut state = self.subscribe();
        loop {
            let current = *state.borrow_and_update();
            if current.tasks == 0 || state.changed().await.is_err() {
                return current;
            }
        }
    }
}
struct QueueOwner(Arc<Budget>);
impl Drop for QueueOwner {
    fn drop(&mut self) {
        self.0.close();
    }
}
/// Clones share one queue owner. Closing, or dropping the last queue clone,
/// cancels every pending and active task without granting session-stop authority.
#[derive(Clone)]
pub struct NativeDownloadQueue(Arc<QueueOwner>);
impl NativeDownloadQueue {
    pub fn new(limits: NativeDownloadQueueLimits) -> Result<Self, NativeDownloadQueueError> {
        if limits.active == 0
            || limits.active > NATIVE_DOWNLOAD_ACTIVE_MAX
            || limits.tasks < limits.active
            || limits.tasks > NATIVE_DOWNLOAD_TASKS_MAX
            || limits.reserved_bytes == 0
            || limits.reserved_bytes > NATIVE_DOWNLOAD_RESERVED_MAX
        {
            return Err(NativeDownloadQueueError::InvalidLimits);
        }
        let (events, _) = watch::channel(NativeDownloadQueueStatus::default());
        Ok(Self(Arc::new(QueueOwner(Arc::new(Budget {
            limits,
            state: Mutex::new(Ledger::default()),
            events,
            changed: Notify::new(),
        })))))
    }
    pub fn monitor(&self) -> NativeDownloadQueueMonitor {
        NativeDownloadQueueMonitor(self.0.0.clone())
    }
    pub fn status(&self) -> NativeDownloadQueueStatus {
        self.monitor().status()
    }
    pub fn close(&self) {
        self.0.0.close();
    }
    /// Admission is synchronous and bounded. Queued tasks do no source RPC or
    /// disk work. Before Open, the active owner reserves the entire approved
    /// maximum; the verified manifest may only shrink that reservation.
    /// The caller transfers an idle FileRead client with no open transfers.
    /// Every rejected or finished task retires that claim; independent local
    /// save consent must remain alive while its task is active. Source/disk
    /// failures cancel this queue task rather than retaining a resumable partial.
    pub fn submit(
        &self,
        client: FileReadClient,
        request: NativeDownloadRequest,
        maximum_bytes: u64,
        destination: impl FileDestinationFactory,
    ) -> Result<NativeDownloadTask, NativeDownloadSubmissionError> {
        if maximum_bytes > FILE_SIZE_BYTES || maximum_bytes > self.0.0.limits.reserved_bytes {
            return Err(reject_submission(
                client,
                NativeDownloadQueueError::ReservationLimit,
            ));
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return Err(reject_submission(
                client,
                NativeDownloadQueueError::NoRuntime,
            ));
        };
        let (signal, _) = watch::channel(false);
        let control = NativeDownloadTaskControl(signal);
        let (progress, _) = watch::channel(NativeDownloadTaskStatus {
            maximum_bytes,
            ..NativeDownloadTaskStatus::default()
        });
        let monitor = NativeDownloadTaskMonitor(progress);
        let id = match self
            .0
            .0
            .admit(maximum_bytes, control.clone(), monitor.clone())
        {
            Ok(id) => id,
            Err(error) => return Err(reject_submission(client, error)),
        };
        let reservation = Reservation {
            id,
            budget: self.0.0.clone(),
            task: monitor.clone(),
            client: Some(client),
            native: None,
            armed: true,
        };
        runtime.spawn(run(
            reservation,
            control.clone(),
            request,
            maximum_bytes,
            destination,
        ));
        Ok(NativeDownloadTask { control, monitor })
    }
}
fn reject_submission(
    client: FileReadClient,
    cause: NativeDownloadQueueError,
) -> NativeDownloadSubmissionError {
    NativeDownloadSubmissionError {
        cause,
        client_retirement: client.retire().map_err(NativeDownloadError::from),
    }
}
struct Entry {
    maximum: u64,
    reserved: Option<u64>,
    control: NativeDownloadTaskControl,
    monitor: NativeDownloadTaskMonitor,
}
#[derive(Default)]
struct Ledger {
    next: u64,
    closed: bool,
    active: usize,
    bytes: u64,
    order: VecDeque<u64>,
    entries: BTreeMap<u64, Entry>,
}
struct Budget {
    limits: NativeDownloadQueueLimits,
    state: Mutex<Ledger>,
    events: watch::Sender<NativeDownloadQueueStatus>,
    changed: Notify,
}
impl Budget {
    fn lock(&self) -> MutexGuard<'_, Ledger> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
    fn publish(&self, state: &Ledger) {
        self.events.send_replace(NativeDownloadQueueStatus {
            closed: state.closed,
            tasks: state.entries.len(),
            active: state.active,
            queued: state.order.len(),
            reserved_bytes: state.bytes,
        });
    }
    fn admit(
        &self,
        maximum: u64,
        control: NativeDownloadTaskControl,
        monitor: NativeDownloadTaskMonitor,
    ) -> Result<u64, NativeDownloadQueueError> {
        let mut state = self.lock();
        if state.closed {
            return Err(NativeDownloadQueueError::Closed);
        }
        if state.entries.len() >= self.limits.tasks {
            return Err(NativeDownloadQueueError::Full);
        }
        let id = state
            .next
            .checked_add(1)
            .ok_or(NativeDownloadQueueError::Closed)?;
        state.next = id;
        state.entries.insert(
            id,
            Entry {
                maximum,
                reserved: None,
                control,
                monitor,
            },
        );
        state.order.push_back(id);
        self.publish(&state);
        Ok(id)
    }
    fn acquire(&self, id: u64) -> Result<bool, NativeDownloadQueueError> {
        let mut state = self.lock();
        let entry = state
            .entries
            .get(&id)
            .ok_or(NativeDownloadQueueError::Closed)?;
        if state.closed || entry.control.cancelled() {
            return Err(NativeDownloadQueueError::Cancelled);
        }
        let bytes = state.bytes.checked_add(entry.maximum);
        if state.order.front() != Some(&id)
            || state.active >= self.limits.active
            || bytes.is_none_or(|bytes| bytes > self.limits.reserved_bytes)
        {
            return Ok(false);
        }
        let maximum = entry.maximum;
        state.order.pop_front();
        state.active += 1;
        state.bytes = bytes.ok_or(NativeDownloadQueueError::ReservationLimit)?;
        if let Some(entry) = state.entries.get_mut(&id) {
            entry.reserved = Some(maximum);
            entry.monitor.0.send_modify(|status| {
                status.phase = NativeDownloadTaskPhase::Active;
                status.reserved_bytes = maximum;
            });
        }
        self.publish(&state);
        drop(state);
        self.changed.notify_waiters();
        Ok(true)
    }
    fn shrink(&self, id: u64, size: u64) -> io::Result<()> {
        let mut state = self.lock();
        let old = state
            .entries
            .get(&id)
            .and_then(|entry| entry.reserved)
            .ok_or_else(|| io::Error::other("missing download reservation"))?;
        let reduction = old.checked_sub(size).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "manifest exceeds reservation")
        })?;
        state.bytes = state
            .bytes
            .checked_sub(reduction)
            .ok_or_else(|| io::Error::other("download accounting underflow"))?;
        if let Some(entry) = state.entries.get_mut(&id) {
            entry.reserved = Some(size);
            entry
                .monitor
                .0
                .send_modify(|status| status.reserved_bytes = size);
        }
        self.publish(&state);
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }
    fn release(&self, id: u64) -> bool {
        let mut state = self.lock();
        let Some(entry) = state.entries.get(&id) else {
            return false;
        };
        if let Some(reserved) = entry.reserved {
            let (Some(bytes), Some(active)) = (
                state.bytes.checked_sub(reserved),
                state.active.checked_sub(1),
            ) else {
                // Conservative failure: never report a release we cannot prove.
                return false;
            };
            state.bytes = bytes;
            state.active = active;
        }
        state.entries.remove(&id);
        state.order.retain(|queued| *queued != id);
        self.publish(&state);
        drop(state);
        self.changed.notify_waiters();
        true
    }
    fn close(&self) {
        let controls = {
            let mut state = self.lock();
            state.closed = true;
            self.publish(&state);
            state
                .entries
                .values()
                .map(|entry| entry.control.clone())
                .collect::<Vec<_>>()
        };
        for control in controls {
            control.cancel();
        }
        self.changed.notify_waiters();
    }
}
struct Reservation {
    id: u64,
    budget: Arc<Budget>,
    task: NativeDownloadTaskMonitor,
    client: Option<FileReadClient>,
    native: Option<NativeFileDownload>,
    armed: bool,
}
impl Reservation {
    fn retire_idle(&mut self) {
        if let Some(client) = self.client.take() {
            let result = client.retire().map_err(NativeDownloadError::from);
            self.task.0.send_modify(|status| {
                status.client_retirement = Some(result);
                if let Err(error) = result {
                    status
                        .error
                        .get_or_insert(NativeDownloadQueueError::Download(error));
                }
            });
        }
    }
    fn finish(&mut self) {
        self.retire_idle();
        if self.budget.release(self.id) {
            self.armed = false;
            self.task.0.send_modify(|status| {
                status.reserved_bytes = 0;
                status.finished = true;
                status.phase = match status.error {
                    None => NativeDownloadTaskPhase::Completed,
                    Some(NativeDownloadQueueError::Cancelled) => NativeDownloadTaskPhase::Cancelled,
                    Some(_) => NativeDownloadTaskPhase::Failed,
                };
            });
        }
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.retire_idle();
        self.task.0.send_modify(|status| {
            status
                .error
                .get_or_insert(NativeDownloadQueueError::OwnerEnded);
            status.phase = NativeDownloadTaskPhase::Settling;
        });
        let Some(mut download) = self.native.take() else {
            self.finish();
            return;
        };
        download.control().cancel();
        // A runtime disappearing does not prove disk/source completion. Keep
        // the ledger conservative if an actual-completion watcher cannot run.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let budget = self.budget.clone();
            let task = self.task.clone();
            let id = self.id;
            runtime.spawn(async move {
                let actual = download.monitor().wait_finished().await;
                if !actual.actor_finished || actual.destination.is_some_and(|disk| !disk.finished) {
                    return;
                }
                // actor_finished is published before return_client. Retain the
                // receiver and consume its exact guard even during unwind/abort.
                let retirement = download.release_client().await.map(|_| ());
                let actual = download.status();
                if budget.release(id) {
                    task.0.send_modify(|status| {
                        status.client_retirement = Some(retirement);
                        status.native = Some(actual);
                        status.reserved_bytes = 0;
                        status.finished = true;
                        status.phase = NativeDownloadTaskPhase::Failed;
                    });
                }
            });
        }
    }
}
struct ReservedFactory {
    inner: Box<dyn FileDestinationFactory>,
    budget: Arc<Budget>,
    task: NativeDownloadTaskMonitor,
    id: u64,
    maximum: u64,
}
impl FileDestinationFactory for ReservedFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.inner.consent()
    }
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        if source.manifest().size > self.maximum {
            self.task.0.send_modify(|status| {
                status
                    .error
                    .get_or_insert(NativeDownloadQueueError::ManifestBudget);
            });
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source exceeds task budget",
            ));
        }
        self.budget.shrink(self.id, source.manifest().size)?;
        self.inner.build(source)
    }
}
fn observe_native(source: NativeDownloadMonitor, task: NativeDownloadTaskMonitor) {
    tokio::spawn(async move {
        let mut state = source.subscribe();
        loop {
            let actual = state.borrow_and_update().clone();
            let finished = actual.actor_finished
                && actual.destination.as_ref().is_none_or(|disk| disk.finished);
            task.0.send_modify(|status| {
                if !status.finished {
                    status.native = Some(actual);
                }
            });
            if finished || state.changed().await.is_err() {
                break;
            }
        }
    });
}
async fn run(
    mut reservation: Reservation,
    control: NativeDownloadTaskControl,
    request: NativeDownloadRequest,
    maximum: u64,
    destination: impl FileDestinationFactory,
) {
    let mut signal = control.0.subscribe();
    let budget = reservation.budget.clone();
    loop {
        // Register before checking the ledger; releases cannot be lost between
        // the check and the wait. At most the configured task cap waits here.
        let changed = budget.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        match reservation.budget.acquire(reservation.id) {
            Ok(true) => break,
            Ok(false) => {}
            Err(error) => {
                reservation
                    .task
                    .0
                    .send_modify(|status| status.error = Some(error));
                reservation.finish();
                return;
            }
        }
        tokio::select! { biased;
            _ = signal.changed() => {},
            _ = &mut changed => {},
        }
    }
    if control.cancelled() {
        reservation
            .task
            .0
            .send_modify(|status| status.error = Some(NativeDownloadQueueError::Cancelled));
        reservation.finish();
        return;
    }
    let Some(client) = reservation.client.take() else {
        return;
    };
    let factory = ReservedFactory {
        inner: Box::new(destination),
        budget: reservation.budget.clone(),
        task: reservation.task.clone(),
        id: reservation.id,
        maximum,
    };
    let download = NativeFileDownload::start(client, request, factory);
    let monitor = download.monitor();
    reservation.native = Some(download);
    observe_native(monitor.clone(), reservation.task.clone());
    let Some(download) = reservation.native.as_mut() else {
        return;
    };
    let result = tokio::select! { biased;
        _ = async {
            loop {
                if *signal.borrow_and_update() { break; }
                if signal.changed().await.is_err() { break; }
            }
        } => Err(NativeDownloadError::Cancelled),
        result = download.download_to_end() => result,
    }
    .map(|_| ());
    reservation.task.0.send_modify(|status| {
        status.phase = NativeDownloadTaskPhase::Settling;
        if let Err(error) = result {
            let error = if error == NativeDownloadError::Cancelled {
                NativeDownloadQueueError::Cancelled
            } else {
                NativeDownloadQueueError::Download(error)
            };
            status.error.get_or_insert(error);
        }
    });
    if result.is_err() {
        download.cancel().await;
    }
    let actual = monitor.wait_finished().await;
    if !actual.actor_finished
        || actual
            .destination
            .as_ref()
            .is_some_and(|disk| !disk.finished)
    {
        return;
    }
    let retired = download.release_client().await.map(|_| ());
    reservation.task.0.send_modify(|status| {
        status.native = Some(download.status());
        status.client_retirement = Some(retired);
        if let Err(error) = retired {
            status
                .error
                .get_or_insert(NativeDownloadQueueError::Download(error));
        }
        if status.error.is_none() && actual.phase != NativeDownloadPhase::Completed {
            status.error = Some(NativeDownloadQueueError::OwnerEnded);
        }
    });
    reservation.finish();
}

#[cfg(test)]
#[path = "../tests/download_queue/owner.rs"]
mod tests;
