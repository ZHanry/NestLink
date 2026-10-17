use super::*;
use crate::files::{FileReadConsent, FileReadSource};
use nestlink_protocol::FileReadManifest;

/// Explicit local source selection. Construct without I/O; the owned source
/// thread opens and pins the selected file and owns its complete lifetime.
pub trait FileUploadSourceFactory: Send + 'static {
    fn consent(&self) -> Arc<dyn FileReadConsent>;
    fn open(
        self: Box<Self>,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileReadSource>>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileUploadSourceStatus {
    pub finished: bool,
    pub source_closed: bool,
    pub source_verified: bool,
    pub cleanup_timed_out: bool,
    pub error: Option<io::ErrorKind>,
    pub read_bytes: u64,
}
#[derive(Clone)]
pub struct FileUploadSourceMonitor(watch::Sender<FileUploadSourceStatus>);
impl FileUploadSourceMonitor {
    pub fn status(&self) -> FileUploadSourceStatus {
        *self.0.borrow()
    }
    pub fn subscribe(&self) -> watch::Receiver<FileUploadSourceStatus> {
        self.0.subscribe()
    }
}
enum Operation {
    Describe,
    Read(u64, usize),
    Verify,
}
enum Value {
    Manifest(FileReadManifest),
    Data(Vec<u8>),
    Verified,
}
struct SourceWork {
    operation: Operation,
    submitted: Instant,
    reply: oneshot::Sender<io::Result<Value>>,
}
pub(super) struct SourceWorker {
    jobs: mpsc::SyncSender<SourceWork>,
    cancelled: Arc<AtomicBool>,
    consent: Arc<dyn FileReadConsent>,
    monitor: FileUploadSourceMonitor,
    thread: Option<thread::JoinHandle<()>>,
    in_flight: bool,
    lease: LeaseControl,
    generation: u64,
}
impl SourceWorker {
    pub fn start(
        lease: LeaseControl,
        generation: u64,
        factory: Box<dyn FileUploadSourceFactory>,
    ) -> io::Result<Self> {
        let consent = factory.consent();
        consent.check()?;
        lease
            .check_channel_binding(Channel::FileWrite, generation)
            .map_err(|_| denied("upload source session stopped"))?;
        let (jobs, work) = mpsc::sync_channel::<SourceWork>(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let (status, _) = watch::channel(FileUploadSourceStatus {
            source_closed: true,
            ..FileUploadSourceStatus::default()
        });
        let monitor = FileUploadSourceMonitor(status.clone());
        let worker_cancelled = cancelled.clone();
        let worker_consent = consent.clone();
        let worker_lease = lease.clone();
        let thread = thread::Builder::new()
            .name("nestlink-upload-source".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let current = || {
                        if worker_cancelled.load(Ordering::Acquire) {
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "upload source stopped",
                            ));
                        }
                        worker_consent.check()?;
                        worker_lease
                            .check_channel_binding(Channel::FileWrite, generation)
                            .map_err(|_| denied("upload source session stopped"))
                    };
                    let mut factory = Some(factory);
                    let mut source: Option<Box<dyn FileReadSource>> = None;
                    let mut manifest = None;
                    loop {
                        if worker_cancelled.load(Ordering::Acquire) {
                            return Ok::<_, io::Error>(());
                        }
                        current()?;
                        let SourceWork {
                            operation,
                            submitted,
                            reply,
                        } = match work.recv_timeout(Duration::from_millis(50)) {
                            Ok(work) => work,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => {
                                return Ok::<_, io::Error>(());
                            }
                        };
                        let deadline = submitted + Duration::from_millis(FILE_OPERATION_MS);
                        let mut check = || {
                            current()?;
                            if reply.is_closed() {
                                return Err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "upload source wait abandoned",
                                ));
                            }
                            deadline_check(deadline)
                        };
                        let result = (|| {
                            check()?;
                            match operation {
                                Operation::Describe => {
                                    let factory = factory.take().ok_or_else(|| {
                                        rejected("upload source already described")
                                    })?;
                                    // Opening may block after acquiring a handle. Only
                                    // actual destruction can establish closed=true.
                                    status.send_modify(|s| s.source_closed = false);
                                    source = Some(factory.open(&mut check)?);
                                    check()?;
                                    let described = source
                                        .as_mut()
                                        .ok_or_else(|| rejected("upload source missing"))?
                                        .describe(&mut check)?;
                                    if described.size > nestlink_protocol::FILE_SIZE_BYTES
                                        || described.sha256.len() != 32
                                        || described.offset != 0
                                    {
                                        return Err(rejected(
                                            "invalid local upload source manifest",
                                        ));
                                    }
                                    manifest = Some(described.clone());
                                    Ok(Value::Manifest(described))
                                }
                                Operation::Read(offset, maximum) => {
                                    let described = manifest
                                        .as_ref()
                                        .ok_or_else(|| rejected("upload source not described"))?;
                                    if maximum == 0
                                        || maximum as u64 > FILE_PAYLOAD_BYTES
                                        || offset
                                            .checked_add(maximum as u64)
                                            .is_none_or(|end| end > described.size)
                                    {
                                        return Err(rejected("invalid bounded upload source read"));
                                    }
                                    let data = source
                                        .as_mut()
                                        .ok_or_else(|| rejected("upload source closed"))?
                                        .read_chunk(offset, maximum, &mut check)?;
                                    if data.len() != maximum {
                                        return Err(io::Error::new(
                                            io::ErrorKind::UnexpectedEof,
                                            "local upload read was short",
                                        ));
                                    }
                                    status.send_modify(|s| {
                                        s.read_bytes =
                                            s.read_bytes.saturating_add(data.len() as u64)
                                    });
                                    Ok(Value::Data(data))
                                }
                                Operation::Verify => {
                                    let described = manifest
                                        .as_ref()
                                        .ok_or_else(|| rejected("upload source not described"))?;
                                    source
                                        .as_mut()
                                        .ok_or_else(|| rejected("upload source closed"))?
                                        .verify(described, &mut check)?;
                                    check()?;
                                    source.take();
                                    status.send_modify(|s| {
                                        s.source_closed = true;
                                        s.source_verified = true;
                                    });
                                    Ok(Value::Verified)
                                }
                            }
                        })()
                        .and_then(|value| {
                            check()?;
                            Ok(value)
                        });
                        let terminal = result.is_err();
                        if let Err(error) = &result {
                            status.send_modify(|s| {
                                s.error.get_or_insert(error.kind());
                            });
                        }
                        if reply.send(result).is_err() || terminal {
                            return Ok(());
                        }
                    }
                }))
                .unwrap_or_else(|_| Err(io::Error::other("upload source worker panicked")));
                if let Err(error) = outcome {
                    status.send_modify(|s| {
                        s.error.get_or_insert(error.kind());
                    });
                }
                // Every actual source/factory was dropped before recording closure.
                status.send_modify(|s| {
                    s.source_closed = true;
                    s.finished = true;
                });
            })?;
        Ok(Self {
            jobs,
            cancelled,
            consent,
            monitor,
            thread: Some(thread),
            in_flight: false,
            lease,
            generation,
        })
    }
    pub fn monitor(&self) -> FileUploadSourceMonitor {
        self.monitor.clone()
    }
    pub fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.consent.clone()
    }
    async fn request(&mut self, operation: Operation) -> io::Result<Value> {
        if self.in_flight {
            return Err(rejected(
                "abandoned upload source request cannot be replaced",
            ));
        }
        self.consent.check()?;
        self.lease
            .check_channel_binding(Channel::FileWrite, self.generation)
            .map_err(|_| denied("upload source session stopped"))?;
        let submitted = Instant::now();
        let deadline = submitted + Duration::from_millis(FILE_OPERATION_MS);
        let (reply, response) = oneshot::channel();
        self.jobs
            .try_send(SourceWork {
                operation,
                submitted,
                reply,
            })
            .map_err(|_| io::Error::other("upload source worker unavailable"))?;
        self.in_flight = true;
        let mut stopped = self.lease.subscribe_stopped();
        let mut local = tokio::time::interval(Duration::from_millis(50));
        local.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let wait = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), response);
        tokio::pin!(wait);
        let result = loop {
            tokio::select! { biased;
                _ = stopped.changed() => break Err(denied("upload source session stopped")),
                _ = local.tick() => {
                    if let Err(error) = self.consent.check() { break Err(error); }
                    if self.lease.check_channel_binding(Channel::FileWrite, self.generation).is_err() { break Err(denied("upload source session stopped")); }
                }
                value = &mut wait => break value
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upload source deadline expired"))
                    .and_then(|value| value.map_err(|_| io::Error::other("upload source worker ended")))
                    .and_then(|value| value),
            }
        };
        let value = result
            .and_then(|value| {
                deadline_check(deadline)?;
                self.consent.check()?;
                self.lease
                    .check_channel_binding(Channel::FileWrite, self.generation)
                    .map_err(|_| denied("upload source session stopped"))?;
                Ok(value)
            })
            .inspect_err(|error| {
                self.cancelled.store(true, Ordering::Release);
                self.monitor.0.send_modify(|s| {
                    s.error.get_or_insert(error.kind());
                });
            })?;
        self.in_flight = false;
        Ok(value)
    }
    pub async fn describe(&mut self) -> io::Result<FileReadManifest> {
        match self.request(Operation::Describe).await? {
            Value::Manifest(manifest) => Ok(manifest),
            _ => Err(rejected("upload source reply kind differs")),
        }
    }
    pub async fn read(&mut self, offset: u64, maximum: usize) -> io::Result<Vec<u8>> {
        match self.request(Operation::Read(offset, maximum)).await? {
            Value::Data(data) => Ok(data),
            _ => Err(rejected("upload source reply kind differs")),
        }
    }
    pub async fn verify(&mut self) -> io::Result<()> {
        match self.request(Operation::Verify).await? {
            Value::Verified => Ok(()),
            _ => Err(rejected("upload source reply kind differs")),
        }
    }
    pub async fn shutdown(&mut self) -> FileShutdown {
        self.cancelled.store(true, Ordering::Release);
        let mut progress = self.monitor.subscribe();
        let wait = async {
            while !progress.borrow_and_update().finished {
                if progress.changed().await.is_err() {
                    break;
                }
            }
            while self.thread.as_ref().is_some_and(|t| !t.is_finished()) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        };
        match tokio::time::timeout(Duration::from_millis(FILE_WORKER_CLEANUP_MS), wait).await {
            Ok(()) => FileShutdown::Finished,
            Err(_) => {
                self.monitor.0.send_modify(|s| s.cleanup_timed_out = true);
                FileShutdown::TimedOut
            }
        }
    }
}
impl Drop for SourceWorker {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}
