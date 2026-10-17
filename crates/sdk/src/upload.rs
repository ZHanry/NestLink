//! Application-owned native uploads. The actor consumes exact FileWrite replies
//! after caller cancellation and returns the original idle writer for safe reuse.
use nestlink_auth::random_id;
use nestlink_protocol::{
    ContractError, ErrorCode, FILE_WORKER_CLEANUP_MS, FileWriteErrorCode, FileWriteReceipt,
    FileWriteState, valid_id,
};
use nestlink_remote::{
    ChannelRuntime, RemoteError,
    files::{FileReadConsent, FileReadSource, FileShutdown},
    upload::{
        FileUploadSourceFactory, FileUploadSourceMonitor, FileUploadSourceStatus, FileWriteClient,
        FileWriteError,
    },
};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{oneshot, watch};

#[derive(Clone, Debug)]
pub struct NativeUploadRequest {
    root: String,
    path: String,
}
impl NativeUploadRequest {
    pub fn new(root_id: &str, relative_path: &str) -> Result<Self, ContractError> {
        if !valid_id(root_id) {
            return Err(ContractError::new(
                ErrorCode::InvalidMessage,
                "invalid upload root",
            ));
        }
        nestlink_protocol::files::validate_relative_path(relative_path)?;
        Ok(Self {
            root: root_id.into(),
            path: relative_path.into(),
        })
    }
    pub fn root_id(&self) -> &str {
        &self.root
    }
    pub fn relative_path(&self) -> &str {
        &self.path
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NativeUploadPhase {
    #[default]
    Opening,
    Transferring,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeUploadError {
    #[error("remote upload destination rejected the operation: {0:?}")]
    Destination(FileWriteErrorCode),
    #[error("local upload source failed: {0:?}")]
    Source(io::ErrorKind),
    #[error("upload transport failed: {0:?}")]
    Transport(io::ErrorKind),
    #[error("upload platform cleanup failed: {0:?}")]
    Cleanup(io::ErrorKind),
    #[error("upload authorization failed ({code:?}): {reason}")]
    Authorization {
        code: ErrorCode,
        reason: &'static str,
    },
    #[error("upload connection stopped")]
    Stopped,
    #[error("upload was cancelled")]
    Cancelled,
    #[error("upload operation unavailable: {0}")]
    State(&'static str),
}
impl From<RemoteError> for NativeUploadError {
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
impl From<FileWriteError> for NativeUploadError {
    fn from(error: FileWriteError) -> Self {
        match error {
            FileWriteError::Remote(error) => error.into(),
            FileWriteError::Source(error) => Self::Source(error.kind()),
            FileWriteError::Destination(failure) => Self::Destination(
                FileWriteErrorCode::try_from(failure.code)
                    .unwrap_or(FileWriteErrorCode::FileWriteIoFailed),
            ),
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct NativeUploadStatus {
    pub transfer_id: String,
    pub phase: NativeUploadPhase,
    pub size: Option<u64>,
    pub confirmed_bytes: u64,
    pub destination: Option<FileWriteState>,
    pub receipt: Option<FileWriteReceipt>,
    pub source: Option<FileUploadSourceStatus>,
    pub error: Option<NativeUploadError>,
    /// Actor has consumed its exact response; disk facts remain separate.
    pub actor_finished: bool,
    /// Requires consumed matching cleanup receipts. A transport loss cannot
    /// establish that the remote OS closed a blocked destination operation.
    pub remote_closed: bool,
    pub finished: bool,
    pub cleanup_timed_out: bool,
    pub client_retirement: Option<Result<(), NativeUploadError>>,
}
#[derive(Clone)]
pub struct NativeUploadMonitor {
    status: watch::Sender<NativeUploadStatus>,
    source: Arc<Mutex<Option<FileUploadSourceMonitor>>>,
}
impl NativeUploadMonitor {
    pub fn status(&self) -> NativeUploadStatus {
        let mut status = self.status.borrow().clone();
        if let Ok(source) = self.source.lock()
            && let Some(source) = source.as_ref()
        {
            let source = source.status();
            status.cleanup_timed_out |= source.cleanup_timed_out;
            status.source = Some(source);
        }
        let source_closed = status
            .source
            .is_none_or(|source| source.finished && source.source_closed);
        let destination_closed = status
            .destination
            .as_ref()
            .is_none_or(|state| state.file_closed && state.temporary_removed);
        status.finished =
            status.actor_finished && status.remote_closed && source_closed && destination_closed;
        status
    }
    pub fn subscribe(&self) -> watch::Receiver<NativeUploadStatus> {
        self.status.subscribe()
    }
    pub fn source_monitor(&self) -> Option<FileUploadSourceMonitor> {
        self.source.lock().ok().and_then(|source| source.clone())
    }
}
#[derive(Clone)]
pub struct NativeUploadControl {
    cancelled: Arc<AtomicBool>,
}
impl NativeUploadControl {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}
pub struct NativeUploadClient {
    client: Option<FileWriteClient>,
    monitor: NativeUploadMonitor,
}
impl NativeUploadClient {
    pub fn start(
        mut self,
        request: NativeUploadRequest,
        source: impl FileUploadSourceFactory,
    ) -> Result<NativeFileUpload, NativeUploadError> {
        let client = self
            .client
            .take()
            .ok_or(NativeUploadError::State("upload writer already consumed"))?;
        Ok(NativeFileUpload::start(client, request, source))
    }
    pub fn into_client(mut self) -> Result<FileWriteClient, NativeUploadError> {
        self.client
            .take()
            .ok_or(NativeUploadError::State("upload writer already consumed"))
    }
    pub fn retire(mut self) -> Result<(), NativeUploadError> {
        self.retire_owned()
    }
    fn retire_owned(&mut self) -> Result<(), NativeUploadError> {
        let Some(client) = self.client.take() else {
            return Ok(());
        };
        let result = client.retire().map_err(NativeUploadError::from);
        self.monitor
            .status
            .send_modify(|status| status.client_retirement = Some(result));
        result
    }
}
impl Drop for NativeUploadClient {
    fn drop(&mut self) {
        let _ = self.retire_owned();
    }
}
pub struct NativeUploadOutcome {
    pub result: Result<FileWriteReceipt, NativeUploadError>,
    /// Returned only after all exact replies and actual cleanup facts were
    /// consumed. It can perform another upload or safely retire only FileWrite.
    pub client: Option<NativeUploadClient>,
    pub monitor: NativeUploadMonitor,
}
pub struct NativeFileUpload {
    control: NativeUploadControl,
    monitor: NativeUploadMonitor,
    outcome: Option<oneshot::Receiver<NativeUploadOutcome>>,
}
struct CancellationConsent {
    local: Arc<dyn FileReadConsent>,
    cancelled: Arc<AtomicBool>,
}
impl FileReadConsent for CancellationConsent {
    fn check(&self) -> io::Result<()> {
        self.local.check()?;
        if self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "application upload cancelled",
            ));
        }
        Ok(())
    }
}
struct CancellableFactory<F> {
    inner: F,
    consent: Arc<CancellationConsent>,
}
impl<F: FileUploadSourceFactory> FileUploadSourceFactory for CancellableFactory<F> {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.consent.clone()
    }
    fn open(
        self: Box<Self>,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileReadSource>> {
        let consent = self.consent;
        consent.check()?;
        Box::new(self.inner).open(&mut || {
            consent.check()?;
            authorized()
        })
    }
}
impl NativeFileUpload {
    pub fn attach(
        runtime: &mut ChannelRuntime,
        generation: u64,
        request: NativeUploadRequest,
        source: impl FileUploadSourceFactory,
    ) -> Result<Self, RemoteError> {
        Ok(Self::start(
            FileWriteClient::attach(runtime, generation)?,
            request,
            source,
        ))
    }
    pub fn start(
        mut client: FileWriteClient,
        request: NativeUploadRequest,
        source: impl FileUploadSourceFactory,
    ) -> Self {
        let id = random_id();
        let (status, _) = watch::channel(NativeUploadStatus {
            transfer_id: id.clone(),
            ..NativeUploadStatus::default()
        });
        let monitor = NativeUploadMonitor {
            status,
            source: Arc::new(Mutex::new(None)),
        };
        let control = NativeUploadControl {
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let wrapped = CancellableFactory {
            consent: Arc::new(CancellationConsent {
                local: source.consent(),
                cancelled: control.cancelled.clone(),
            }),
            inner: source,
        };
        let (send, outcome) = oneshot::channel();
        let task_monitor = monitor.clone();
        let task_control = control.clone();
        tokio::spawn(async move {
            let progress_monitor = task_monitor.clone();
            let result = client
                .upload_source_with_progress(
                    &id,
                    &request.root,
                    &request.path,
                    wrapped,
                    move |progress| {
                        if let Ok(mut source) = progress_monitor.source.lock() {
                            *source = Some(progress.source.clone());
                        }
                        progress_monitor.status.send_modify(|status| {
                            if status.phase != NativeUploadPhase::Cancelling {
                                status.phase = if progress.size.is_some() {
                                    NativeUploadPhase::Transferring
                                } else {
                                    NativeUploadPhase::Opening
                                };
                            }
                            status.size = progress.size;
                            status.confirmed_bytes = progress.confirmed_bytes;
                            status.destination = progress.destination;
                            status.source = Some(progress.source.status());
                        });
                    },
                )
                .await
                .map_err(NativeUploadError::from);
            let result = if result.is_err() && task_control.cancelled.load(Ordering::Acquire) {
                Err(NativeUploadError::Cancelled)
            } else {
                result
            };
            task_monitor.status.send_modify(|status| {
                status.actor_finished = true;
                status.remote_closed = client.is_protocol_idle();
                status.receipt = result.as_ref().ok().cloned();
                status.error = result.as_ref().err().copied();
                status.phase = match &result {
                    Ok(_) => NativeUploadPhase::Completed,
                    Err(NativeUploadError::Cancelled) => NativeUploadPhase::Cancelled,
                    Err(_) => NativeUploadPhase::Failed,
                };
                if let Ok(receipt) = &result {
                    status.destination = receipt.state;
                }
            });
            task_monitor.status.send_replace(task_monitor.status());
            if client.is_protocol_idle()
                && let Some(source) = client.source_monitor()
            {
                // Keep the original writer while an OS source call is blocked.
                // A cancellation timeout cannot authorize a replacement worker.
                let mut progress = source.subscribe();
                loop {
                    let source = *progress.borrow_and_update();
                    if source.finished && source.source_closed {
                        break;
                    }
                    if progress.changed().await.is_err() {
                        break;
                    }
                }
            }
            task_monitor.status.send_replace(task_monitor.status());
            let returned = if client.is_idle() {
                Some(NativeUploadClient {
                    client: Some(client),
                    monitor: task_monitor.clone(),
                })
            } else {
                drop(client);
                None
            };
            let _ = send.send(NativeUploadOutcome {
                result,
                client: returned,
                monitor: task_monitor,
            });
        });
        Self {
            control,
            monitor,
            outcome: Some(outcome),
        }
    }
    pub fn monitor(&self) -> NativeUploadMonitor {
        self.monitor.clone()
    }
    pub fn control(&self) -> NativeUploadControl {
        self.control.clone()
    }
    /// Stop new source reads and queue disclosure immediately. The actor keeps
    /// consuming the exact in-flight Ack before issuing per-file Cancel.
    pub async fn cancel(&mut self) -> FileShutdown {
        self.control.cancel();
        self.monitor.status.send_modify(|status| {
            if !status.actor_finished {
                status.phase = NativeUploadPhase::Cancelling;
            }
        });
        let wait = async {
            while !self.monitor.status().finished {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        match tokio::time::timeout(Duration::from_millis(FILE_WORKER_CLEANUP_MS), wait).await {
            Ok(()) => FileShutdown::Finished,
            Err(_) => {
                self.monitor
                    .status
                    .send_modify(|status| status.cleanup_timed_out = true);
                FileShutdown::TimedOut
            }
        }
    }
    pub async fn finish(mut self) -> Result<NativeUploadOutcome, NativeUploadError> {
        self.outcome
            .take()
            .ok_or(NativeUploadError::State("upload outcome already consumed"))?
            .await
            .map_err(|_| NativeUploadError::State("upload actor ended without outcome"))
    }
}
impl Drop for NativeFileUpload {
    fn drop(&mut self) {
        self.control.cancel();
    }
}
