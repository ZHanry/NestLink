//! FileWrite is an independently approved, proved channel. A single owned disk
//! thread performs all destination effects; cancellation does not invent cleanup.
use crate::{
    ChannelReceiver, ChannelRuntime, ChannelSender, DeliveryGuard, LeaseControl, RemoteError,
};
use nestlink_identity::digest;
use nestlink_protocol::{
    FILE_OPERATION_MS, FILE_PAYLOAD_BYTES, FILE_WORKER_CLEANUP_MS, FILE_WRITE_ACTIVE,
    FILE_WRITE_TRANSFERS, FileRoot, FileRoots, FileRootsRequest, FileWriteAck, FileWriteCancelled,
    FileWriteChunk, FileWriteCommit, FileWriteErrorCode, FileWriteFailure, FileWriteOpen,
    FileWriteReady, FileWriteReceipt, FileWriteState, NativeFileWrite, SCHEMA_VERSION,
    native_file_write::Action,
};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};
mod client;
mod source;
pub use crate::files::FileShutdown;
pub use client::{FileUpload, FileUploadProgress, FileWriteClient, FileWriteError};
pub use source::{FileUploadSourceFactory, FileUploadSourceMonitor, FileUploadSourceStatus};

/// This approval is independent of FileRead and the business FileWrite permit.
/// Checking it must only read local facts, never acquire a lease or perform I/O.
pub trait FileWriteConsent: Send + Sync {
    fn check(&self) -> io::Result<()>;
}
impl FileWriteConsent for AtomicBool {
    fn check(&self) -> io::Result<()> {
        if self.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(denied("local file write consent revoked"))
        }
    }
}
/// Trusted adapter. Every method executes on the disk owner thread. Preserve
/// callback errors and record actual effects before any post-operation check.
/// It owns every file handle it opens; dropping it must close those handles.
pub trait FileWriteDestination: Send + 'static {
    fn consent(&self) -> Arc<dyn FileWriteConsent>;
    fn status(&self) -> FileWriteState;
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()>;
    fn write(
        &mut self,
        chunk: &FileWriteChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()>;
    /// Re-read the actual complete object, sync it, and atomically publish
    /// without replacing any existing entry. An earlier hash is insufficient.
    fn finish(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()>;
    /// Owner cleanup is valid even after either authorization is withdrawn.
    /// It must never delete the final published target.
    fn cleanup(&mut self) -> io::Result<()>;
}
pub trait FileWriteDevice: Send + 'static {
    fn retire_revoked(&mut self) {}
    /// Return name-only write roots under the current local destination
    /// approvals. The transport checks the guard again at actual delivery.
    fn list_roots(&mut self) -> io::Result<FileWriteRootListing> {
        Err(denied("file write root discovery was not locally approved"))
    }
    /// Return owned state before any temporary-file I/O, so failed prepare
    /// always leaves an owned destination with observable cleanup facts.
    fn build(
        &mut self,
        open: &FileWriteOpen,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileWriteDestination>>;
}

#[derive(Clone)]
pub struct FileWriteRootListing {
    pub roots: Vec<FileRoot>,
    pub consent: Arc<dyn FileWriteConsent>,
}

/// The one-shot, non-clonable FileWrite claim captured at session creation.
pub struct ClaimedFileWrite {
    pub(super) receiver: ChannelReceiver,
    pub(super) sender: ChannelSender,
    pub(super) lease: LeaseControl,
    pub(super) generation: u64,
}
impl ClaimedFileWrite {
    pub fn claim(runtime: &mut ChannelRuntime, generation: u64) -> Result<Self, RemoteError> {
        let lease = runtime.lease_control();
        lease.check_channel_binding(Channel::FileWrite, generation)?;
        let receiver = runtime.claim_channel(Channel::FileWrite)?;
        let sender = runtime.sender();
        Ok(Self {
            receiver,
            sender,
            lease,
            generation,
        })
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn lease_control(&self) -> LeaseControl {
        self.lease.clone()
    }
}
impl ChannelRuntime {
    pub fn claim_file_write(&mut self, generation: u64) -> Result<ClaimedFileWrite, RemoteError> {
        ClaimedFileWrite::claim(self, generation)
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileWriteWorkerStatus {
    pub finished: bool,
    pub cleanup_timed_out: bool,
    pub error: Option<io::ErrorKind>,
    pub cleanup_error: Option<io::ErrorKind>,
    /// Bounded by FILE_WRITE_TRANSFERS. Historical facts survive cancellation.
    pub transfers: BTreeMap<String, FileWriteState>,
}
#[derive(Clone)]
pub struct FileWriteMonitor(watch::Sender<FileWriteWorkerStatus>);
impl FileWriteMonitor {
    pub fn status(&self) -> FileWriteWorkerStatus {
        self.0.borrow().clone()
    }
    pub fn subscribe(&self) -> watch::Receiver<FileWriteWorkerStatus> {
        self.0.subscribe()
    }
}
pub struct FileWriteServer {
    lease: LeaseControl,
    cancelled: Arc<AtomicBool>,
    task: Option<tokio::task::JoinHandle<Result<(), RemoteError>>>,
    thread: Option<thread::JoinHandle<()>>,
    monitor: FileWriteMonitor,
}
struct Work {
    request: NativeFileWrite,
    submitted: Instant,
    reply: oneshot::Sender<io::Result<WriteReply>>,
}
#[derive(Clone)]
struct WriteReply {
    message: NativeFileWrite,
    disclosure: Option<Arc<dyn FileWriteConsent>>,
}
struct WriteDisclosure(Arc<dyn FileWriteConsent>);
impl DeliveryGuard for WriteDisclosure {
    fn check(&self) -> io::Result<()> {
        self.0.check()
    }
}
struct WriteTransfer {
    destination: Box<dyn FileWriteDestination>,
    open: FileWriteOpen,
    offset: u64,
    hash: sha2::Sha256,
    progress: Instant,
}
struct Writer<D> {
    device: D,
    transfers: BTreeMap<String, Option<WriteTransfer>>,
    pending_cleanup: BTreeMap<String, Box<dyn FileWriteDestination>>,
    consents: BTreeMap<String, Arc<dyn FileWriteConsent>>,
    retired: BTreeMap<String, FileWriteErrorCode>,
    previous: Option<(NativeFileWrite, WriteReply)>,
    sequence: u64,
    monitor: FileWriteMonitor,
    operation_budget: Duration,
}
fn rejected(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}
fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
fn deadline_check(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original file write operation expired",
        ))
    } else {
        Ok(())
    }
}
fn error_code(error: &io::Error) -> FileWriteErrorCode {
    match error.kind() {
        io::ErrorKind::PermissionDenied => FileWriteErrorCode::FileWriteDenied,
        io::ErrorKind::AlreadyExists => FileWriteErrorCode::FileWriteExists,
        io::ErrorKind::FileTooLarge | io::ErrorKind::StorageFull => {
            FileWriteErrorCode::FileWriteCapacity
        }
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
            FileWriteErrorCode::FileWriteChecksumMismatch
        }
        io::ErrorKind::TimedOut => FileWriteErrorCode::FileWriteExpired,
        _ => FileWriteErrorCode::FileWriteIoFailed,
    }
}
fn failure(code: FileWriteErrorCode, state: Option<FileWriteState>) -> Action {
    Action::Failure(FileWriteFailure {
        code: code as i32,
        state,
    })
}
impl<D> Writer<D> {
    fn error(&self, error: &io::Error) {
        self.monitor.0.send_modify(|s| {
            s.error.get_or_insert(error.kind());
        });
    }
    fn record(&self, id: &str, destination: &dyn FileWriteDestination) {
        self.monitor.0.send_modify(|s| {
            s.transfers.insert(id.into(), destination.status());
        });
    }
    fn cleanup(
        &mut self,
        id: &str,
        mut destination: Box<dyn FileWriteDestination>,
    ) -> FileWriteState {
        if let Err(error) = destination.cleanup() {
            self.monitor.0.send_modify(|s| {
                s.cleanup_error.get_or_insert(error.kind());
            });
        }
        let state = destination.status();
        self.record(id, destination.as_ref());
        if !state.file_closed || !state.temporary_removed {
            self.pending_cleanup.insert(id.into(), destination);
        }
        state
    }
    fn close_transfer(&mut self, id: &str, code: FileWriteErrorCode) -> Option<FileWriteState> {
        self.retired.insert(id.into(), code);
        let transfer = self.transfers.get_mut(id).and_then(Option::take);
        transfer
            .map(|transfer| self.cleanup(id, transfer.destination))
            .or_else(|| {
                self.pending_cleanup
                    .remove(id)
                    .map(|destination| self.cleanup(id, destination))
            })
            .or_else(|| self.monitor.status().transfers.get(id).copied())
    }
}
impl<D: FileWriteDevice> Writer<D> {
    fn retire(&mut self) {
        self.device.retire_revoked();
        let now = Instant::now();
        let retired: Vec<_> = self
            .transfers
            .iter()
            .filter_map(|(id, value)| {
                let transfer = value.as_ref()?;
                if let Err(error) = transfer.destination.consent().check() {
                    Some((id.clone(), error_code(&error)))
                } else if now >= transfer.progress + self.operation_budget {
                    Some((id.clone(), FileWriteErrorCode::FileWriteExpired))
                } else {
                    None
                }
            })
            .collect();
        for (id, code) in retired {
            self.close_transfer(&id, code);
        }
    }
    fn reserve(&mut self, id: &str) -> io::Result<bool> {
        if self.transfers.contains_key(id) {
            return Err(rejected("upload UUID is already used"));
        }
        if self.transfers.len() as u64 >= FILE_WRITE_TRANSFERS {
            return Ok(false);
        }
        let active = (self.transfers.values().filter(|t| t.is_some()).count()
            + self.pending_cleanup.len()) as u64;
        self.transfers.insert(id.into(), None);
        Ok(active < FILE_WRITE_ACTIVE)
    }
    fn handle(
        &mut self,
        request: NativeFileWrite,
        started: Instant,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<WriteReply> {
        use sha2::Digest;
        check()?;
        self.retire();
        if request.sequence == self.sequence {
            let mut reply = self
                .previous
                .as_ref()
                .filter(|(old, _)| old == &request)
                .map(|(_, reply)| reply.clone())
                .ok_or_else(|| rejected("upload retry changed its fields"))?;
            if !matches!(
                reply.message.action,
                Some(Action::Cancelled(_) | Action::Failure(_))
            ) && let Some(code) = self.retired.get(&request.transfer_id).copied()
            {
                reply.message.action = Some(failure(
                    code,
                    self.monitor
                        .status()
                        .transfers
                        .get(&request.transfer_id)
                        .cloned(),
                ));
            } else if !matches!(
                reply.message.action,
                Some(Action::Cancelled(_) | Action::Failure(_))
            ) && let Some(consent) = self.consents.get(&request.transfer_id)
                && let Err(error) = consent.check()
            {
                let code = error_code(&error);
                let state = self.close_transfer(&request.transfer_id, code);
                reply.message.action = Some(failure(code, state));
            }
            if let Some(consent) = &reply.disclosure
                && consent.check().is_err()
            {
                reply.disclosure = None;
                reply.message.action = Some(failure(FileWriteErrorCode::FileWriteDenied, None));
            }
            check()?;
            return Ok(reply);
        }
        if request.sequence
            != self
                .sequence
                .checked_add(1)
                .ok_or_else(|| rejected("upload sequence exhausted"))?
        {
            return Err(rejected("upload sequence skipped or repeated"));
        }
        let id = &request.transfer_id;
        let mut disclosure = None;
        let action = match request
            .action
            .as_ref()
            .ok_or_else(|| rejected("upload action missing"))?
        {
            Action::Open(open) => {
                if !self.reserve(id)? {
                    failure(FileWriteErrorCode::FileWriteCapacity, None)
                } else {
                    let result = self.device.build(open, check);
                    match result {
                        Err(error) => {
                            self.error(&error);
                            failure(error_code(&error), None)
                        }
                        Ok(mut destination) => {
                            let consent = destination.consent();
                            self.consents.insert(id.into(), consent.clone());
                            let result = consent
                                .check()
                                .and_then(|()| destination.prepare(check))
                                .and_then(|()| check())
                                .and_then(|()| consent.check());
                            self.record(id, destination.as_ref());
                            match result {
                                Ok(()) => {
                                    if destination.status().confirmed_bytes != 0
                                        || destination.status().published
                                    {
                                        self.cleanup(id, destination);
                                        return Err(rejected(
                                            "upload destination did not start empty",
                                        ));
                                    }
                                    self.transfers.insert(
                                        id.into(),
                                        Some(WriteTransfer {
                                            destination,
                                            open: open.clone(),
                                            offset: 0,
                                            hash: sha2::Sha256::new(),
                                            progress: started,
                                        }),
                                    );
                                    Action::Ready(FileWriteReady {
                                        size: open.size,
                                        sha256: open.sha256.clone(),
                                        offset: 0,
                                    })
                                }
                                Err(error) => {
                                    self.error(&error);
                                    let code = error_code(&error);
                                    self.retired.insert(id.into(), code);
                                    let state = self.cleanup(id, destination);
                                    failure(code, Some(state))
                                }
                            }
                        }
                    }
                }
            }
            Action::Chunk(chunk) => {
                if let Some(code) = self.retired.get(id).copied() {
                    failure(code, self.monitor.status().transfers.get(id).cloned())
                } else {
                    let mut transfer = self
                        .transfers
                        .get_mut(id)
                        .ok_or_else(|| rejected("unknown upload"))?
                        .take()
                        .ok_or_else(|| rejected("upload is already closed"))?;
                    if chunk.offset != transfer.offset
                        || chunk
                            .offset
                            .checked_add(chunk.data.len() as u64)
                            .is_none_or(|end| end > transfer.open.size)
                    {
                        self.cleanup(id, transfer.destination);
                        return Err(rejected("upload chunk offset or extent differs"));
                    }
                    let result = if digest(&chunk.data).as_slice() != chunk.sha256 {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "upload chunk checksum differs",
                        ))
                    } else {
                        transfer
                            .destination
                            .consent()
                            .check()
                            .and_then(|()| transfer.destination.write(chunk, check))
                            .and_then(|()| check())
                            .and_then(|()| transfer.destination.consent().check())
                    };
                    self.record(id, transfer.destination.as_ref());
                    match result {
                        Ok(()) => {
                            transfer.offset += chunk.data.len() as u64;
                            transfer.hash.update(&chunk.data);
                            transfer.progress = started;
                            if transfer.destination.status().confirmed_bytes != transfer.offset {
                                self.cleanup(id, transfer.destination);
                                return Err(rejected(
                                    "upload adapter did not confirm the exact disk offset",
                                ));
                            }
                            let offset = transfer.offset;
                            self.transfers.insert(id.into(), Some(transfer));
                            Action::Ack(FileWriteAck { offset })
                        }
                        Err(error) => {
                            self.error(&error);
                            let code = error_code(&error);
                            self.retired.insert(id.into(), code);
                            let state = self.cleanup(id, transfer.destination);
                            failure(code, Some(state))
                        }
                    }
                }
            }
            Action::Commit(commit) => {
                if let Some(code) = self.retired.get(id).copied() {
                    failure(code, self.monitor.status().transfers.get(id).cloned())
                } else {
                    let mut transfer = self
                        .transfers
                        .get_mut(id)
                        .ok_or_else(|| rejected("unknown upload commit"))?
                        .take()
                        .ok_or_else(|| rejected("upload is already closed"))?;
                    let result = if commit.size != transfer.open.size
                        || commit.sha256 != transfer.open.sha256
                        || transfer.offset != transfer.open.size
                        || transfer.hash.finalize().as_slice() != transfer.open.sha256
                    {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "upload complete checksum or extent differs",
                        ))
                    } else {
                        transfer
                            .destination
                            .consent()
                            .check()
                            .and_then(|()| transfer.destination.finish(check))
                            .and_then(|()| check())
                    };
                    self.record(id, transfer.destination.as_ref());
                    match result {
                        Ok(()) => {
                            let state = transfer.destination.status();
                            if !state.published
                                || !state.file_closed
                                || !state.temporary_removed
                                || state.poisoned
                            {
                                self.cleanup(id, transfer.destination);
                                return Err(rejected(
                                    "upload adapter did not actually publish and clean storage",
                                ));
                            }
                            Action::Committed(FileWriteReceipt {
                                size: commit.size,
                                sha256: commit.sha256.clone(),
                                state: Some(state),
                            })
                        }
                        Err(error) => {
                            self.error(&error);
                            let code = error_code(&error);
                            self.retired.insert(id.into(), code);
                            let state = self.cleanup(id, transfer.destination);
                            failure(code, Some(state))
                        }
                    }
                }
            }
            Action::Cancel(true) => {
                if !self.transfers.contains_key(id) {
                    return Err(rejected("unknown upload cancellation"));
                }
                let state = self
                    .close_transfer(id, FileWriteErrorCode::FileWriteDenied)
                    .unwrap_or(FileWriteState {
                        file_closed: true,
                        temporary_removed: true,
                        poisoned: true,
                        ..FileWriteState::default()
                    });
                if state.file_closed && state.temporary_removed {
                    Action::Cancelled(FileWriteCancelled { state: Some(state) })
                } else {
                    failure(FileWriteErrorCode::FileWriteIoFailed, Some(state))
                }
            }
            Action::RootsRequest(_) => {
                let listing = self.device.list_roots()?;
                if listing.consent.check().is_err() {
                    failure(FileWriteErrorCode::FileWriteDenied, None)
                } else {
                    disclosure = Some(listing.consent);
                    Action::Roots(FileRoots {
                        roots: listing.roots,
                    })
                }
            }
            _ => return Err(rejected("upload service accepts requests only")),
        };
        check()?;
        let message = NativeFileWrite {
            action: Some(action),
            ..request.clone()
        };
        message
            .validate()
            .map_err(|_| rejected("invalid upload worker reply"))?;
        self.sequence = request.sequence;
        let reply = WriteReply {
            message,
            disclosure,
        };
        self.previous = Some((request, reply.clone()));
        Ok(reply)
    }
}
impl<D> Drop for Writer<D> {
    fn drop(&mut self) {
        // Only the disk owner executes cleanup. A blocked cleanup leaves the
        // monitor unfinished; no async timeout pretends that it reclaimed I/O.
        let active: Vec<_> = self
            .transfers
            .iter_mut()
            .filter_map(|(id, transfer)| transfer.take().map(|t| (id.clone(), t.destination)))
            .collect();
        for (id, destination) in active {
            self.cleanup(&id, destination);
        }
        let pending = std::mem::take(&mut self.pending_cleanup);
        for (id, mut destination) in pending {
            if let Err(error) = destination.cleanup() {
                self.monitor.0.send_modify(|s| {
                    s.cleanup_error.get_or_insert(error.kind());
                });
            }
            let mut state = destination.status();
            drop(destination);
            // Destruction closed owned handles, but cannot prove that cleanup
            // removed a temporary file after a failed OS removal operation.
            state.file_closed = true;
            self.monitor.0.send_modify(|s| {
                s.transfers.insert(id, state);
            });
        }
    }
}
impl FileWriteServer {
    pub fn start(
        runtime: &mut ChannelRuntime,
        generation: u64,
        device: impl FileWriteDevice,
    ) -> Result<Self, RemoteError> {
        Self::start_with_budget(
            runtime,
            generation,
            device,
            Duration::from_millis(FILE_OPERATION_MS),
        )
    }
    /// Applications may shorten operation/idle storage budgets, never extend
    /// the contract maximum. The same submitted deadline governs result consume.
    pub fn start_with_budget(
        runtime: &mut ChannelRuntime,
        generation: u64,
        device: impl FileWriteDevice,
        operation_budget: Duration,
    ) -> Result<Self, RemoteError> {
        Self::start_with_budget_claimed(
            ClaimedFileWrite::claim(runtime, generation)?,
            device,
            operation_budget,
        )
    }
    /// Start from the one-shot transport retained at session establishment.
    pub fn start_claimed(
        claim: ClaimedFileWrite,
        device: impl FileWriteDevice,
    ) -> Result<Self, RemoteError> {
        Self::start_with_budget_claimed(claim, device, Duration::from_millis(FILE_OPERATION_MS))
    }
    /// Start a claimed writer with a lower application operation budget.
    pub fn start_with_budget_claimed(
        claim: ClaimedFileWrite,
        device: impl FileWriteDevice,
        operation_budget: Duration,
    ) -> Result<Self, RemoteError> {
        if operation_budget.is_zero() || operation_budget > Duration::from_millis(FILE_OPERATION_MS)
        {
            return Err(rejected("invalid local upload operation budget").into());
        }
        let ClaimedFileWrite {
            receiver,
            sender,
            lease,
            generation,
        } = claim;
        lease.check_channel_binding(Channel::FileWrite, generation)?;
        let (jobs, work) = mpsc::sync_channel::<Work>(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let (status, _) = watch::channel(FileWriteWorkerStatus::default());
        let monitor = FileWriteMonitor(status.clone());
        let worker_cancelled = cancelled.clone();
        let worker_lease = lease.clone();
        let worker_monitor = monitor.clone();
        let thread = thread::Builder::new()
            .name("nestlink-file-write".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut writer = Writer {
                        device,
                        transfers: BTreeMap::new(),
                        pending_cleanup: BTreeMap::new(),
                        consents: BTreeMap::new(),
                        retired: BTreeMap::new(),
                        previous: None,
                        sequence: 0,
                        monitor: worker_monitor,
                        operation_budget,
                    };
                    let current = || {
                        if worker_cancelled.load(Ordering::Acquire) {
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "upload worker stopped",
                            ));
                        }
                        worker_lease
                            .check_channel_binding(Channel::FileWrite, generation)
                            .map_err(|_| denied("upload session stopped"))
                    };
                    loop {
                        writer.retire();
                        if current().is_err() {
                            return Ok::<_, io::Error>(());
                        }
                        let Work {
                            request,
                            submitted,
                            reply,
                        } = match work.recv_timeout(Duration::from_millis(50)) {
                            Ok(work) => work,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                        };
                        let deadline = submitted + operation_budget;
                        let mut check = || {
                            current()?;
                            if reply.is_closed() {
                                return Err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "upload response abandoned",
                                ));
                            }
                            deadline_check(deadline)
                        };
                        let result = writer.handle(request, submitted, &mut check);
                        let terminal = result.is_err();
                        if reply.send(result).is_err() || terminal {
                            return Ok(());
                        }
                    }
                }))
                .unwrap_or_else(|_| Err(io::Error::other("upload worker panicked")));
                if let Err(error) = outcome {
                    status.send_modify(|s| {
                        s.error.get_or_insert(error.kind());
                    });
                    let _ = worker_lease.stop(StopReason::PlatformChanged);
                }
                // Writer/provider/real destination objects were destroyed first.
                status.send_modify(|s| s.finished = true);
            })?;
        let task_lease = lease.clone();
        let task_cancelled = cancelled.clone();
        let task = tokio::spawn(async move {
            let mut receiver = receiver;
            let outcome = serve(
                &mut receiver,
                sender,
                jobs,
                task_lease.clone(),
                generation,
                operation_budget,
            )
            .await;
            task_cancelled.store(true, Ordering::Release);
            crate::queues::stop_io_result(&task_lease, &outcome);
            outcome
        });
        Ok(Self {
            lease,
            cancelled,
            task: Some(task),
            thread: Some(thread),
            monitor,
        })
    }
    pub fn monitor(&self) -> FileWriteMonitor {
        self.monitor.clone()
    }
    pub async fn shutdown(&mut self, reason: StopReason) -> Result<FileShutdown, RemoteError> {
        self.cancelled.store(true, Ordering::Release);
        self.lease.stop(reason)?;
        let mut progress = self.monitor.subscribe();
        let wait = async {
            while !progress.borrow_and_update().finished {
                progress.changed().await.map_err(|_| RemoteError::Stopped)?;
            }
            if let Some(task) = &mut self.task {
                let _ = task.await;
            }
            self.task.take();
            while self.thread.as_ref().is_some_and(|t| !t.is_finished()) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if let Some(thread) = self.thread.take() {
                thread
                    .join()
                    .map_err(|_| io::Error::other("upload worker panicked"))?;
            }
            Ok::<_, RemoteError>(())
        };
        match tokio::time::timeout(Duration::from_millis(FILE_WORKER_CLEANUP_MS), wait).await {
            Ok(result) => {
                result?;
                Ok(FileShutdown::Finished)
            }
            Err(_) => {
                self.monitor.0.send_modify(|s| s.cleanup_timed_out = true);
                Ok(FileShutdown::TimedOut)
            }
        }
    }
}
impl Drop for FileWriteServer {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.lease.stop_if_running(StopReason::ExplicitExit);
    }
}
async fn serve(
    receiver: &mut ChannelReceiver,
    sender: ChannelSender,
    jobs: mpsc::SyncSender<Work>,
    lease: LeaseControl,
    generation: u64,
    operation_budget: Duration,
) -> Result<(), RemoteError> {
    let mut stopped = lease.subscribe_stopped();
    loop {
        lease.check_channel_binding(Channel::FileWrite, generation)?;
        let frame = receiver.receive().await?;
        let submitted = Instant::now();
        let deadline = submitted + operation_budget;
        deadline_check(deadline)?;
        let request = NativeFileWrite::decode_validated(&frame.payload).map_err(|error| {
            let _ = lease.stop(StopReason::ProtocolViolation);
            RemoteError::from(error)
        })?;
        if request.connection_generation != generation {
            let _ = lease.stop(StopReason::ProtocolViolation);
            return Err(rejected("upload request generation differs").into());
        }
        deadline_check(deadline)?;
        let (reply, response) = oneshot::channel();
        jobs.try_send(Work {
            request,
            submitted,
            reply,
        })
        .map_err(|_| io::Error::other("upload disk owner unavailable"))?;
        let reply = tokio::select! { biased;
            _ = stopped.changed() => return Err(RemoteError::Stopped),
            result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), response) => {
                result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upload operation deadline expired"))?
                    .map_err(|_| io::Error::other("upload worker ended without response"))??
            }
        };
        deadline_check(deadline)?;
        lease.check_channel_binding(Channel::FileWrite, generation)?;
        let bytes = reply.message.encode_validated()?;
        deadline_check(deadline)?;
        let send = async {
            if let Some(consent) = reply.disclosure {
                let mut denied = reply.message.clone();
                denied.action = Some(failure(FileWriteErrorCode::FileWriteDenied, None));
                let denied = denied.encode_validated()?;
                let mut expired = reply.message.clone();
                expired.action = Some(failure(FileWriteErrorCode::FileWriteExpired, None));
                let expired = expired.encode_validated()?;
                sender
                    .send_checked_delivery(
                        Channel::FileWrite,
                        &bytes,
                        Arc::new(WriteDisclosure(consent)),
                        denied,
                        expired,
                    )
                    .await
            } else {
                sender.send(Channel::FileWrite, &bytes).await
            }
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), send)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "upload reply queue deadline expired",
                )
            })??;
        deadline_check(deadline)?;
    }
}
