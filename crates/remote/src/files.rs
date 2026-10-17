//! Bounded, generation-bound file reads. OS I/O runs on one owned worker,
//! outside the lease lock. No file path is an ambient filesystem authority.
use crate::{ChannelReceiver, ChannelRuntime, ChannelSender, LeaseControl, RemoteError};
use nestlink_identity::digest;
use nestlink_protocol::{
    FILE_OPERATION_MS, FILE_PAYLOAD_BYTES, FILE_READ_ACTIVE, FILE_READ_TRANSFERS,
    FILE_WORKER_CLEANUP_MS, FileReadChunk, FileReadEnd, FileReadErrorCode, FileReadFailure,
    FileReadManifest, FileRoot, FileRoots, NativeFileRead, SCHEMA_VERSION,
    native_file_read::Action,
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
mod browse;
mod client;
#[cfg(test)]
#[path = "files/deadline_tests.rs"]
mod deadline_tests;
mod destination;
use browse::BrowseTransfer;
pub use browse::{DirectoryBrowse, DirectoryBrowseSource};
pub use client::{
    FileDownload, FileDownloadBinding, FileDownloadSnapshot, FileDownloadView, FileReadClient,
    FileReadError, FileReadVerifier,
};
pub use destination::{
    FileDestination, FileDestinationFactory, FileDestinationStatus, FileDownloadMonitor,
    FileDownloadPhase, FileDownloadSubscription, FileDownloadWorker, FileDownloadWorkerStatus,
};

/// Local adapters must check `authorized` between bounded reads and again before
/// returning data. Never run disk I/O while holding an authorization lock.
pub trait FileReadConsent: Send + Sync {
    /// Pure local facts; no disk I/O or lease acquisition.
    fn check(&self) -> io::Result<()>;
}
impl FileReadConsent for AtomicBool {
    fn check(&self) -> io::Result<()> {
        if self.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local file consent revoked",
            ))
        }
    }
}
pub trait FileReadSource: Send {
    fn consent(&self) -> Arc<dyn FileReadConsent>;
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest>;
    fn read_chunk(
        &mut self,
        offset: u64,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>>;
    /// Revalidate the whole original object, including content, before success.
    fn verify(
        &mut self,
        original: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()>;
}
/// The application's explicit local root approvals are scoped to this session.
/// Opening or keeping a source never bypasses independent root consent.
pub trait FileReadDevice: Send + 'static {
    fn retire_revoked(&mut self) {}
    /// Return one bounded, name-only list under the local metadata approval.
    /// The guard is rechecked by the transport immediately before delivery.
    fn list_roots(
        &mut self,
        _authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadRootListing> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file root discovery was not locally approved",
        ))
    }
    fn open(&mut self, root: &str, relative_path: &str) -> io::Result<Box<dyn FileReadSource>>;
    fn browse(
        &mut self,
        _root: &str,
        _authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn DirectoryBrowseSource>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory metadata was not locally approved",
        ))
    }
}

#[derive(Clone)]
pub struct FileReadRootListing {
    pub roots: Vec<FileRoot>,
    pub consent: Arc<dyn FileReadConsent>,
}

/// The one-shot, non-clonable FileRead claim captured at session creation.
/// Only `claim` can construct it, and both halves retain one exact proved lease.
pub struct ClaimedFileRead {
    pub(super) receiver: ChannelReceiver,
    pub(super) sender: ChannelSender,
    pub(super) lease: LeaseControl,
    pub(super) generation: u64,
}
impl ClaimedFileRead {
    pub fn claim(runtime: &mut ChannelRuntime, generation: u64) -> Result<Self, RemoteError> {
        let lease = runtime.lease_control();
        lease.check_channel_binding(Channel::FileRead, generation)?;
        let receiver = runtime.claim_channel(Channel::FileRead)?;
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
    pub fn claim_file_read(&mut self, generation: u64) -> Result<ClaimedFileRead, RemoteError> {
        ClaimedFileRead::claim(self, generation)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileWorkerStatus {
    pub finished: bool,
    /// Sticky: a blocked filesystem operation may still own a handle. Its result
    /// cannot reach the stopped session, even if that operation later finishes.
    pub cleanup_timed_out: bool,
    pub error: Option<io::ErrorKind>,
}
#[derive(Clone)]
pub struct FileWorkerMonitor(watch::Sender<FileWorkerStatus>);
impl FileWorkerMonitor {
    pub fn status(&self) -> FileWorkerStatus {
        *self.0.borrow()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileShutdown {
    Finished,
    TimedOut,
}

pub struct FileReadServer {
    lease: LeaseControl,
    cancelled: Arc<AtomicBool>,
    task: Option<tokio::task::JoinHandle<Result<(), RemoteError>>>,
    thread: Option<thread::JoinHandle<()>>,
    monitor: FileWorkerMonitor,
}
struct Work {
    request: NativeFileRead,
    submitted: Instant,
    reply: oneshot::Sender<io::Result<WorkerReply>>,
}
#[derive(Clone)]
struct WorkerReply {
    message: NativeFileRead,
    disclosure: Option<Arc<dyn FileReadConsent>>,
}
struct ReadTransfer {
    source: Box<dyn FileReadSource>,
    manifest: FileReadManifest,
    offset: u64,
}
enum Transfer {
    Read(ReadTransfer),
    Browse(BrowseTransfer),
}
struct Reader<D> {
    device: D,
    // None is a runtime tombstone: a cancelled/failed/finished ID never reopens.
    transfers: BTreeMap<String, Option<Transfer>>,
    consents: BTreeMap<String, Arc<dyn FileReadConsent>>,
    revoked: BTreeSet<String>,
    expired: BTreeSet<String>,
    previous: Option<(NativeFileRead, WorkerReply)>,
    sequence: u64,
}
fn rejected(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}
fn file_deadline(deadline: Instant) -> Result<(), RemoteError> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original file operation budget expired",
        )
        .into())
    } else {
        Ok(())
    }
}
/// Tokio timeouts cannot preempt synchronous decoding or final result consume.
/// Check the same absolute deadline on both sides of that bounded operation.
fn file_operation<T>(
    deadline: Instant,
    operation: impl FnOnce() -> Result<T, RemoteError>,
) -> Result<T, RemoteError> {
    file_deadline(deadline)?;
    let result = operation();
    file_deadline(deadline)?;
    result
}
fn failure(error: io::Error) -> Action {
    let code = match error.kind() {
        io::ErrorKind::NotFound => FileReadErrorCode::FileReadNotFound,
        io::ErrorKind::PermissionDenied => FileReadErrorCode::FileReadDenied,
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof | io::ErrorKind::TimedOut => {
            FileReadErrorCode::FileReadChanged
        }
        io::ErrorKind::FileTooLarge => FileReadErrorCode::FileReadCapacity,
        _ => FileReadErrorCode::FileReadIoFailed,
    };
    Action::Failure(FileReadFailure { code: code as i32 })
}
impl<D: FileReadDevice> Reader<D> {
    fn retire_revoked(&mut self) {
        self.device.retire_revoked();
        for (id, consent) in &self.consents {
            if let Err(error) = consent.check() {
                if let Some(slot) = self.transfers.get_mut(id) {
                    slot.take();
                }
                if error.kind() == io::ErrorKind::TimedOut {
                    self.expired.insert(id.clone());
                } else {
                    self.revoked.insert(id.clone());
                }
            }
        }
    }
    fn reserve(&mut self, id: &str) -> io::Result<bool> {
        if self.transfers.contains_key(id) {
            return Err(rejected("file transfer ID is retired or already open"));
        }
        let active = self
            .transfers
            .values()
            .filter(|value| value.is_some())
            .count();
        if self.transfers.len() as u64 >= FILE_READ_TRANSFERS {
            return Ok(false);
        }
        // Capacity failures also consume their identity; no completed UUID reopens.
        self.transfers.insert(id.into(), None);
        Ok((active as u64) < FILE_READ_ACTIVE)
    }
    fn handle(
        &mut self,
        request: NativeFileRead,
        started: Instant,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<WorkerReply> {
        check()?;
        self.retire_revoked();
        if request.sequence == self.sequence {
            let mut reply = self
                .previous
                .as_ref()
                .filter(|(old, _)| old == &request)
                .map(|(_, reply)| reply.clone())
                .ok_or_else(|| rejected("file retry differs from the original request"))?;
            let error = if self.revoked.contains(&request.transfer_id) {
                Some(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "local root consent revoked",
                ))
            } else if self.expired.contains(&request.transfer_id) {
                Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "directory snapshot expired",
                ))
            } else {
                reply
                    .disclosure
                    .as_ref()
                    .and_then(|guard| guard.check().err())
            };
            if let Some(error) = error {
                if let Some(slot) = self.transfers.get_mut(&request.transfer_id) {
                    slot.take();
                }
                reply.message.action = Some(failure(error));
                reply.disclosure = None;
            }
            return Ok(reply);
        }
        if request.sequence != self.sequence + 1 {
            return Err(rejected(
                "file request sequence is not the strict successor",
            ));
        }
        let mut reply = request.clone();
        let mut disclosure = None;
        let action = match request.action.as_ref() {
            Some(Action::Open(open)) => {
                if !self.reserve(&request.transfer_id)? {
                    Action::Failure(FileReadFailure {
                        code: FileReadErrorCode::FileReadCapacity as i32,
                    })
                } else {
                    let opened = (|| {
                        check()?;
                        let mut source = self.device.open(&open.root_id, &open.path)?;
                        self.consents
                            .insert(request.transfer_id.clone(), source.consent());
                        check()?;
                        let mut manifest = source.describe(check)?;
                        manifest.offset = open.offset;
                        if open.offset > manifest.size
                            || (!open.expected_sha256.is_empty()
                                && manifest.sha256 != open.expected_sha256)
                        {
                            return Ok::<_, io::Error>(Action::Failure(FileReadFailure {
                                code: FileReadErrorCode::FileReadChecksumMismatch as i32,
                            }));
                        }
                        // Validate adapter output before accepting it into state.
                        let mut probe = reply.clone();
                        probe.action = Some(Action::Manifest(manifest.clone()));
                        probe
                            .validate()
                            .map_err(|_| io::Error::other("invalid file adapter manifest"))?;
                        check()?;
                        self.transfers.insert(
                            request.transfer_id.clone(),
                            Some(Transfer::Read(ReadTransfer {
                                source,
                                manifest: manifest.clone(),
                                offset: open.offset,
                            })),
                        );
                        Ok(Action::Manifest(manifest))
                    })();
                    opened.unwrap_or_else(failure)
                }
            }
            Some(Action::Next(next)) => {
                if self.revoked.contains(&request.transfer_id) {
                    reply.action = Some(Action::Failure(FileReadFailure {
                        code: FileReadErrorCode::FileReadDenied as i32,
                    }));
                    self.sequence = request.sequence;
                    let reply = WorkerReply {
                        message: reply,
                        disclosure: None,
                    };
                    self.previous = Some((request, reply.clone()));
                    return Ok(reply);
                }
                let slot = self
                    .transfers
                    .get_mut(&request.transfer_id)
                    .ok_or_else(|| rejected("unknown file transfer"))?;
                let transfer = slot
                    .take()
                    .ok_or_else(|| rejected("file transfer has already ended"))?;
                let Transfer::Read(mut transfer) = transfer else {
                    return Err(rejected("file read request addressed a directory browse"));
                };
                if next.offset != transfer.offset {
                    return Err(rejected(
                        "file read offset is not the acknowledged successor",
                    ));
                }
                let outcome = if transfer.offset == transfer.manifest.size {
                    transfer.source.verify(&transfer.manifest, check).map(|()| {
                        Action::End(FileReadEnd {
                            size: transfer.manifest.size,
                            sha256: transfer.manifest.sha256.clone(),
                        })
                    })
                } else {
                    let maximum =
                        (transfer.manifest.size - transfer.offset).min(FILE_PAYLOAD_BYTES) as usize;
                    transfer
                        .source
                        .read_chunk(transfer.offset, maximum, check)
                        .and_then(|bytes| {
                            if bytes.len() != maximum {
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "source changed during file read",
                                ));
                            }
                            let action = Action::Chunk(FileReadChunk {
                                offset: transfer.offset,
                                sha256: digest(&bytes).to_vec(),
                                data: bytes,
                            });
                            transfer.offset += maximum as u64;
                            *slot = Some(Transfer::Read(transfer));
                            Ok(action)
                        })
                };
                outcome.unwrap_or_else(failure)
            }
            Some(Action::BrowseBegin(begin)) => {
                if !self.reserve(&request.transfer_id)? {
                    Action::Failure(FileReadFailure {
                        code: FileReadErrorCode::FileReadCapacity as i32,
                    })
                } else {
                    match BrowseTransfer::open(&mut self.device, begin, started, check) {
                        Ok((transfer, page, guard)) => {
                            self.consents
                                .insert(request.transfer_id.clone(), transfer.consent());
                            if !page.next_cursor.is_empty() {
                                self.transfers.insert(
                                    request.transfer_id.clone(),
                                    Some(Transfer::Browse(transfer)),
                                );
                            }
                            disclosure = Some(guard);
                            Action::BrowsePage(page)
                        }
                        Err(error) => failure(error),
                    }
                }
            }
            Some(Action::BrowseNext(next)) => {
                if self.revoked.contains(&request.transfer_id) {
                    Action::Failure(FileReadFailure {
                        code: FileReadErrorCode::FileReadDenied as i32,
                    })
                } else if self.expired.contains(&request.transfer_id) {
                    Action::Failure(FileReadFailure {
                        code: FileReadErrorCode::FileReadChanged as i32,
                    })
                } else {
                    let slot = self
                        .transfers
                        .get_mut(&request.transfer_id)
                        .ok_or_else(|| rejected("unknown directory browse"))?;
                    let transfer = slot
                        .take()
                        .ok_or_else(|| rejected("directory browse has already ended"))?;
                    let Transfer::Browse(mut transfer) = transfer else {
                        return Err(rejected("directory request addressed a file download"));
                    };
                    match transfer.next(next, started, check) {
                        Ok((page, guard)) => {
                            if !page.next_cursor.is_empty() {
                                *slot = Some(Transfer::Browse(transfer));
                            }
                            disclosure = Some(guard);
                            Action::BrowsePage(page)
                        }
                        Err(error) => failure(error),
                    }
                }
            }
            Some(Action::RootsRequest(_)) => {
                let listing = self.device.list_roots(check)?;
                check()?;
                listing.consent.check()?;
                let roots = FileRoots {
                    roots: listing.roots,
                };
                roots
                    .validate_file_read()
                    .map_err(|_| io::Error::other("file root listing violates wire bounds"))?;
                disclosure = Some(listing.consent);
                Action::Roots(roots)
            }
            Some(Action::Cancel(true)) => {
                self.transfers
                    .get_mut(&request.transfer_id)
                    .ok_or_else(|| rejected("unknown file transfer cancellation"))?
                    .take();
                Action::Cancelled(true)
            }
            _ => {
                return Err(rejected(
                    "only file requests are accepted by a read service",
                ));
            }
        };
        check()?;
        reply.action = Some(action);
        if let Some(guard) = &disclosure
            && let Err(error) = guard.check()
        {
            self.transfers
                .get_mut(&request.transfer_id)
                .and_then(Option::take);
            reply.action = Some(failure(error));
            disclosure = None;
        }
        reply
            .validate()
            .map_err(|_| io::Error::other("invalid file worker reply"))?;
        self.sequence = request.sequence;
        let reply = WorkerReply {
            message: reply,
            disclosure,
        };
        self.previous = Some((request, reply.clone()));
        Ok(reply)
    }
}
impl FileReadServer {
    pub fn start(
        runtime: &mut ChannelRuntime,
        generation: u64,
        device: impl FileReadDevice,
    ) -> Result<Self, RemoteError> {
        Self::start_claimed(ClaimedFileRead::claim(runtime, generation)?, device)
    }
    /// Start after the proved session has claimed FileRead. This lets the
    /// product retain the one-shot transport until a local chooser supplies a
    /// device, without creating a second channel claim.
    pub fn start_claimed(
        claim: ClaimedFileRead,
        device: impl FileReadDevice,
    ) -> Result<Self, RemoteError> {
        let ClaimedFileRead {
            receiver,
            sender,
            lease,
            generation,
        } = claim;
        lease.check_channel_binding(Channel::FileRead, generation)?;
        let (jobs, work) = mpsc::sync_channel::<Work>(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let (status, _) = watch::channel(FileWorkerStatus::default());
        let monitor = FileWorkerMonitor(status.clone());
        let worker_cancelled = cancelled.clone();
        let worker_lease = lease.clone();
        // The worker owns all open handles and provider state. Its completion is
        // published after those resources have actually been destroyed.
        let thread = thread::Builder::new()
            .name("nestlink-file-read".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut reader = Reader {
                        device,
                        transfers: BTreeMap::new(),
                        consents: BTreeMap::new(),
                        revoked: BTreeSet::new(),
                        expired: BTreeSet::new(),
                        previous: None,
                        sequence: 0,
                    };
                    let mut check = || {
                        if worker_cancelled.load(Ordering::Acquire) {
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "file worker stopped",
                            ));
                        }
                        worker_lease
                            .check_channel_binding(Channel::FileRead, generation)
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "file session stopped",
                                )
                            })
                    };
                    loop {
                        reader.retire_revoked();
                        if check().is_err() {
                            return Ok::<_, io::Error>(());
                        }
                        let work = match work.recv_timeout(Duration::from_millis(50)) {
                            Ok(work) => work,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                        };
                        let result = reader.handle(work.request, work.submitted, &mut check);
                        let terminal = result.is_err();
                        if work.reply.send(result).is_err() || terminal {
                            return Ok(());
                        }
                    }
                }))
                .unwrap_or_else(|_| Err(io::Error::other("file worker panicked")));
                if outcome.is_err() {
                    let _ = worker_lease.stop(StopReason::PlatformChanged);
                }
                status.send_modify(|state| {
                    state.finished = true;
                    state.error = outcome.err().map(|e| e.kind());
                });
            })
            .map_err(RemoteError::from)?;
        let task_lease = lease.clone();
        let task_cancelled = cancelled.clone();
        let task = tokio::spawn(async move {
            let mut receiver = receiver;
            let outcome = serve(&mut receiver, sender, jobs, task_lease.clone(), generation).await;
            task_cancelled.store(true, Ordering::Release);
            if outcome.is_err() {
                crate::queues::stop_io_result(&task_lease, &outcome);
            }
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
    pub fn monitor(&self) -> FileWorkerMonitor {
        self.monitor.clone()
    }
    pub async fn shutdown(&mut self, reason: StopReason) -> Result<FileShutdown, RemoteError> {
        self.cancelled.store(true, Ordering::Release);
        self.lease.stop(reason)?;
        let mut completed = self.monitor.0.subscribe();
        let wait = async {
            loop {
                let finished = completed.borrow_and_update().finished;
                if finished {
                    break;
                }
                completed
                    .changed()
                    .await
                    .map_err(|_| RemoteError::Stopped)?;
            }
            if let Some(task) = &mut self.task {
                let _ = task.await;
            }
            self.task.take();
            while self
                .thread
                .as_ref()
                .is_some_and(|thread| !thread.is_finished())
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            // is_finished was observed first; this join never waits for disk I/O.
            if let Some(thread) = self.thread.take() {
                thread
                    .join()
                    .map_err(|_| io::Error::other("file worker thread panicked"))?;
            }
            Ok::<_, RemoteError>(())
        };
        match tokio::time::timeout(Duration::from_millis(FILE_WORKER_CLEANUP_MS), wait).await {
            Ok(result) => {
                result?;
                Ok(FileShutdown::Finished)
            }
            Err(_) => {
                self.monitor
                    .0
                    .send_modify(|state| state.cleanup_timed_out = true);
                Ok(FileShutdown::TimedOut)
            }
        }
    }
}
impl Drop for FileReadServer {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.lease.stop_if_running(StopReason::ExplicitExit);
        // Read-only disk calls cannot be forcefully reclaimed. Keep the monitor
        // truthful until the worker returns and destroys its original handles.
    }
}
async fn serve(
    receiver: &mut ChannelReceiver,
    sender: ChannelSender,
    jobs: mpsc::SyncSender<Work>,
    lease: LeaseControl,
    generation: u64,
) -> Result<(), RemoteError> {
    let mut stopped = lease.subscribe_stopped();
    loop {
        lease.check_channel_binding(Channel::FileRead, generation)?;
        let frame = receiver.receive().await?;
        let submitted = Instant::now();
        let deadline = submitted + Duration::from_millis(FILE_OPERATION_MS);
        let request = file_operation(deadline, || {
            let request = NativeFileRead::decode_validated(&frame.payload).map_err(|error| {
                let _ = lease.stop(StopReason::ProtocolViolation);
                RemoteError::from(error)
            })?;
            if request.connection_generation != generation {
                let _ = lease.stop(StopReason::ProtocolViolation);
                return Err(
                    rejected("file request belongs to another connection generation").into(),
                );
            }
            Ok(request)
        })?;
        let (reply, response) = oneshot::channel();
        jobs.try_send(Work {
            request,
            submitted,
            reply,
        })
        .map_err(|_| io::Error::other("file worker unavailable"))?;
        let reply = tokio::select! { biased;
            _ = stopped.changed() => return Err(RemoteError::Stopped),
            result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), response) => {
                let result = result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "file operation timed out"))?
                    .map_err(|_| io::Error::other("file worker ended without response"))?;
                file_operation(deadline, || result.map_err(RemoteError::from))?
            },
        };
        lease.check_channel_binding(Channel::FileRead, generation)?;
        let bytes = file_operation(deadline, || Ok(reply.message.encode_validated()?))?;
        let fallback = if reply.disclosure.is_some() {
            Some(file_operation(deadline, || {
                let mut denied = reply.message.clone();
                denied.action = Some(Action::Failure(FileReadFailure {
                    code: FileReadErrorCode::FileReadDenied as i32,
                }));
                let mut expired = reply.message.clone();
                expired.action = Some(Action::Failure(FileReadFailure {
                    code: FileReadErrorCode::FileReadChanged as i32,
                }));
                Ok((denied.encode_validated()?, expired.encode_validated()?))
            })?)
        } else {
            None
        };
        let send = async {
            if let (Some(disclosure), Some((denied, expired))) = (reply.disclosure, fallback) {
                sender
                    .send_checked_file_read(&bytes, disclosure, denied, expired)
                    .await
            } else {
                sender.send(Channel::FileRead, &bytes).await
            }
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), send)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "file reply queue deadline expired")
            })??;
        file_deadline(deadline)?;
    }
}
