#![allow(clippy::unwrap_used)]
mod support;

use nestlink_app_core::*;
use nestlink_protocol::{
    FileReadErrorCode, FileReadManifest, FileRoot, FileWriteOpen, Path, Permission, api::*,
};
use nestlink_remote::{
    audio::{
        AudioCaptureDevice, AudioChunk, AudioDevice, AudioPlaybackDevice, CHUNK_FRAMES,
        CapturedAudio,
    },
    files::{
        FileDestination, FileDestinationFactory, FileDestinationStatus, FileDownloadSnapshot,
        FileDownloadView, FileReadConsent, FileReadDevice, FileReadRootListing, FileReadSource,
    },
    input::{Button, InputDevice, InputLayout, PlatformInput},
    upload::{FileWriteConsent, FileWriteDestination, FileWriteDevice, FileWriteRootListing},
    video::{CaptureDevice, Display, RawFrame},
};
use nestlink_sdk::{
    DeviceIdentity, NetworkMonitor,
    files::{NativeDownloadError, NativeDownloadRequest},
};
use std::{
    collections::HashMap,
    io,
    net::UdpSocket,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use support::*;

struct CaptureProbe {
    resets: Arc<AtomicUsize>,
    emitted: bool,
}
struct InputProbe(Arc<Mutex<Vec<String>>>);
struct AudioCaptureProbe {
    resets: Arc<AtomicUsize>,
    pts: u64,
    next_chunk: Instant,
}
impl AudioCaptureProbe {
    fn new(resets: Arc<AtomicUsize>) -> Self {
        Self {
            resets,
            pts: 0,
            next_chunk: Instant::now(),
        }
    }
}
impl AudioDevice for AudioCaptureProbe {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.resets.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
impl AudioCaptureDevice for AudioCaptureProbe {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        if self.pts >= 4 * CHUNK_FRAMES as u64 || Instant::now() < self.next_chunk {
            return Ok(None);
        }
        let pts = self.pts;
        self.pts += CHUNK_FRAMES as u64;
        self.next_chunk = Instant::now() + Duration::from_millis(20);
        Ok(Some(CapturedAudio {
            captured_at: Instant::now(),
            chunk: AudioChunk {
                source: 0,
                channels: 2,
                pts_48khz: pts,
                samples: (0..CHUNK_FRAMES)
                    .flat_map(|frame| {
                        let phase = (pts + frame as u64) as f64 / 48_000.0;
                        [440.0, 880.0].map(|hz| {
                            (12_000.0 * (phase * hz * std::f64::consts::TAU).sin()) as i16
                        })
                    })
                    .collect(),
            },
        }))
    }
}
type AudioLog = Arc<Mutex<Vec<(u64, Vec<i16>)>>>;
struct AudioPlaybackProbe {
    resets: Arc<AtomicUsize>,
    log: AudioLog,
}
impl AudioDevice for AudioPlaybackProbe {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.resets.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
impl AudioPlaybackDevice for AudioPlaybackProbe {
    fn enqueue(&mut self, chunk: &AudioChunk) -> io::Result<()> {
        self.log
            .lock()
            .map_err(|_| io::Error::other("audio probe poisoned"))?
            .push((chunk.pts_48khz, chunk.samples.clone()));
        Ok(())
    }
}
impl InputDevice for InputProbe {
    fn select_source(&mut self, source: u32, _layout: InputLayout) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("input probe poisoned"))?
            .push(format!("select-source:{source}"));
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("input probe poisoned"))?
            .push("reset".into());
        Ok(())
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        let event = match input {
            PlatformInput::Release(Button::Key(code)) => format!("release-key:{code}"),
            PlatformInput::Release(Button::Pointer(button)) => format!("release-pointer:{button}"),
            PlatformInput::Action(action) => format!("{action:?}"),
        };
        self.0
            .lock()
            .map_err(|_| io::Error::other("input probe poisoned"))?
            .push(event);
        Ok(())
    }
}
async fn wait_input(log: &Arc<Mutex<Vec<String>>>, event: &str) -> Result {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if log
                .lock()
                .map_err(|_| "input probe poisoned")?
                .iter()
                .any(|entry| entry == event)
            {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    Ok(())
}
impl CaptureDevice for CaptureProbe {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        if std::mem::replace(&mut self.emitted, true) {
            return Ok(None);
        }
        Ok(Some(RawFrame {
            source: 1,
            width: 80,
            height: 40,
            captured_at: Instant::now(),
            pixels: [0, 255, 0, 255].repeat(80 * 40),
        }))
    }
    fn reset(&mut self) -> io::Result<()> {
        self.resets.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn routed_ipv4() -> Result<std::net::Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    // UDP connect selects the OS route without sending a packet.
    socket.connect("192.0.2.1:9")?;
    match socket.local_addr()?.ip() {
        std::net::IpAddr::V4(address) if !address.is_loopback() => Ok(address),
        _ => Err("no non-loopback IPv4 route is available for the session test".into()),
    }
}

fn native_core(identity: DeviceIdentity, prefix: String) -> Result<AppCore> {
    native_core_with_limits(identity, prefix, Limits::default())
}

fn native_core_with_limits(
    identity: DeviceIdentity,
    prefix: String,
    limits: Limits,
) -> Result<AppCore> {
    let monitor = Arc::new(NetworkMonitor::start()?);
    let mut config = NativeSessionConfig::new(monitor);
    config.private_network_prefixes.push(prefix);
    Ok(AppCore::with_identity_and_native_session(
        limits, identity, config,
    )?)
}

struct EmptyFileReadDevice;
impl FileReadDevice for EmptyFileReadDevice {
    fn open(&mut self, _root: &str, _relative_path: &str) -> io::Result<Box<dyn FileReadSource>> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "test source missing",
        ))
    }
}

struct TestFileConsent;
impl FileReadConsent for TestFileConsent {
    fn check(&self) -> io::Result<()> {
        Ok(())
    }
}
impl FileWriteConsent for TestFileConsent {
    fn check(&self) -> io::Result<()> {
        Ok(())
    }
}

struct RejectDestinationFactory;
impl FileDestinationFactory for RejectDestinationFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(TestFileConsent)
    }
    fn build(
        self: Box<Self>,
        _source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        Err(io::Error::other("unexpected test destination build"))
    }
}

struct DynamicFileReadDevice {
    roots: Arc<Mutex<Vec<FileRoot>>>,
    files: Arc<Mutex<HashMap<String, Arc<Vec<u8>>>>>,
}
impl FileReadDevice for DynamicFileReadDevice {
    fn list_roots(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadRootListing> {
        authorized()?;
        let roots = self
            .roots
            .lock()
            .map_err(|_| io::Error::other("file root registry poisoned"))?
            .clone();
        Ok(FileReadRootListing {
            roots,
            consent: Arc::new(TestFileConsent),
        })
    }
    fn open(&mut self, _root: &str, relative_path: &str) -> io::Result<Box<dyn FileReadSource>> {
        let bytes = self
            .files
            .lock()
            .map_err(|_| io::Error::other("file source registry poisoned"))?
            .get(relative_path)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "test source missing"))?;
        Ok(Box::new(MemoryFileReadSource { bytes }))
    }
}

struct MemoryFileReadSource {
    bytes: Arc<Vec<u8>>,
}
impl MemoryFileReadSource {
    fn manifest(&self) -> FileReadManifest {
        FileReadManifest {
            size: self.bytes.len() as u64,
            sha256: nestlink_identity::digest(self.bytes.as_slice()).to_vec(),
            offset: 0,
        }
    }
}
impl FileReadSource for MemoryFileReadSource {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(TestFileConsent)
    }
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        authorized()?;
        Ok(self.manifest())
    }
    fn read_chunk(
        &mut self,
        offset: u64,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        authorized()?;
        let start = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid source offset"))?;
        if start > self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "source offset exceeds file size",
            ));
        }
        let end = start.saturating_add(maximum).min(self.bytes.len());
        Ok(self.bytes[start..end].to_vec())
    }
    fn verify(
        &mut self,
        original: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        authorized()?;
        if original != &self.manifest() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "test source manifest changed",
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct DestinationGate {
    entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
}
impl DestinationGate {
    fn block(&self) {
        self.entered.store(true, Ordering::Release);
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.changed.wait(released).unwrap();
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
    async fn wait_entered(&self) -> Result {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !self.entered.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        Ok(())
    }
}

#[derive(Default)]
struct BudgetProbeDestinationFactory {
    expected_size: Option<u64>,
    gate: Option<Arc<DestinationGate>>,
    write_gate: Option<Arc<DestinationGate>>,
    fail_build: bool,
    fail_prepare: bool,
    fail_cleanup: bool,
}
impl FileDestinationFactory for BudgetProbeDestinationFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(TestFileConsent)
    }
    fn build(
        self: Box<Self>,
        source: &FileDownloadSnapshot,
    ) -> io::Result<Box<dyn FileDestination>> {
        if self
            .expected_size
            .is_some_and(|expected| source.manifest().size != expected)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected manifest size in budget test",
            ));
        }
        if self.fail_build {
            return Err(io::Error::other("uncertain destination factory failure"));
        }
        Ok(Box::new(BudgetProbeDestination {
            status: FileDestinationStatus::default(),
            gate: self.gate,
            write_gate: self.write_gate,
            fail_prepare: self.fail_prepare,
            fail_cleanup: self.fail_cleanup,
        }))
    }
}

struct BudgetProbeDestination {
    status: FileDestinationStatus,
    gate: Option<Arc<DestinationGate>>,
    write_gate: Option<Arc<DestinationGate>>,
    fail_prepare: bool,
    fail_cleanup: bool,
}
impl FileDestination for BudgetProbeDestination {
    fn status(&self) -> FileDestinationStatus {
        self.status
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        authorized()?;
        if let Some(gate) = &self.gate {
            gate.block();
        }
        if self.fail_prepare {
            return Err(io::Error::other(
                "uncertain destination preparation failure",
            ));
        }
        Ok(())
    }
    fn write(
        &mut self,
        _source: &FileDownloadSnapshot,
        chunk: &nestlink_protocol::FileReadChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        authorized()?;
        if let Some(gate) = &self.write_gate {
            gate.block();
            authorized()?;
        }
        self.status.confirmed_bytes = self
            .status
            .confirmed_bytes
            .saturating_add(chunk.data.len() as u64);
        Ok(())
    }
    fn resume(
        &mut self,
        _source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        authorized()
    }
    fn finish(
        &mut self,
        source: &FileDownloadSnapshot,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        authorized()?;
        self.status.confirmed_bytes = source.manifest().size;
        self.status.published = true;
        self.status.file_closed = true;
        self.status.temporary_removed = true;
        Ok(())
    }
    fn cleanup(&mut self) -> io::Result<()> {
        if self.fail_cleanup {
            return Err(io::Error::other("uncertain destination cleanup failure"));
        }
        self.status.file_closed = true;
        self.status.temporary_removed = true;
        Ok(())
    }
}

struct DynamicFileWriteDevice {
    roots: Arc<Mutex<Vec<FileRoot>>>,
}
impl FileWriteDevice for DynamicFileWriteDevice {
    fn list_roots(&mut self) -> io::Result<FileWriteRootListing> {
        let roots = self
            .roots
            .lock()
            .map_err(|_| io::Error::other("file root registry poisoned"))?
            .clone();
        Ok(FileWriteRootListing {
            roots,
            consent: Arc::new(TestFileConsent),
        })
    }
    fn build(
        &mut self,
        _open: &FileWriteOpen,
        _authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileWriteDestination>> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "test write destination missing",
        ))
    }
}

async fn wait_native_file_task(
    handle: &CoreHandle,
    binding: &NativeSessionBinding,
    core_generation: u64,
    task_id: &str,
) -> Result<NativeFileTaskStatus> {
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = handle.native_file_task_status(binding, core_generation, task_id)?;
            if status.finished {
                return Ok::<_, NativeFilesError>(status);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??)
}

async fn wait_native_download_status(
    handle: &CoreHandle,
    binding: &NativeSessionBinding,
    core_generation: u64,
    task_id: &str,
    mut matches: impl FnMut(&nestlink_sdk::files::NativeDownloadStatus) -> bool,
) -> Result<NativeFileTaskStatus> {
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = handle.native_file_task_status(binding, core_generation, task_id)?;
            if status.download.as_ref().is_some_and(&mut matches) {
                return Ok::<_, NativeFilesError>(status);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??)
}

async fn session_success(ticket: Ticket) -> Result<Completion> {
    let completion = tokio::time::timeout(Duration::from_secs(20), ticket.wait()).await??;
    assert_eq!(
        completion.result.status,
        OperationStatus::Succeeded,
        "{:?}",
        completion.result
    );
    Ok(completion)
}

#[tokio::test]
async fn proved_file_access_tracks_dynamic_roots_and_keeps_failed_tasks_session_scoped() -> Result {
    let server = Server::start(None).await?;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let host_id = host.device_id.clone();
    let prefix = format!("{}/32", routed_ipv4()?);
    let mut controller_core = native_core_with_limits(
        controller,
        prefix.clone(),
        Limits {
            native_downloads: NativeDownloadQueueLimits {
                active: 1,
                tasks: 2,
                reserved_bytes: 8,
            },
            ..Limits::default()
        },
    )?;
    let mut host_core = native_core(host, prefix)?;
    let controller_handle = connect(&controller_core, &server).await?;
    let host_handle = connect(&host_core, &server).await?;

    for (handle, role) in [(&controller_handle, "controller"), (&host_handle, "host")] {
        success(handle.submit(Action::EnrollLocalDevice {
            name: role.into(),
            platform: "linux-x11".into(),
            capabilities: vec![role.into(), "vp8".into(), "opus".into()],
            path_mode: "direct_only".into(),
        })?)
        .await?;
    }
    let permissions = vec![
        Permission::View as i32,
        Permission::FileRead as i32,
        Permission::FileWrite as i32,
    ];
    success(controller_handle.submit(Action::RequestRemote {
        host_device_id: host_id,
        permissions: permissions.clone(),
        path_mode: "direct_only".into(),
        access: RemoteAccess::LocalApproval,
    })?)
    .await?;
    let request = controller_handle
        .snapshot()
        .selected_request
        .data
        .as_ref()
        .ok_or("remote request was not selected")?
        .clone();
    success(host_handle.submit(Action::ApproveRemote {
        request_id: request.id.clone(),
        expected_nonce: request.nonce.clone(),
        expected_policy_revision: request.policy_revision,
        choice: ApprovalChoice {
            approved: true,
            permissions,
            paths: vec![Path::Direct as i32],
        },
    })?)
    .await?;
    success(controller_handle.submit(Action::IssueRemotePermit {
        request_id: request.id.clone(),
    })?)
    .await?;
    let (controller_started, host_started) = tokio::try_join!(
        session_success(controller_handle.submit(Action::StartNativeSession {
            request_id: request.id.clone(),
        })?),
        session_success(host_handle.submit(Action::StartNativeSession {
            request_id: request.id.clone(),
        })?),
    )?;
    assert_eq!(
        controller_started.result.kind,
        OperationKind::StartNativeSession
    );
    assert_eq!(host_started.result.kind, OperationKind::StartNativeSession);

    let controller_generation = controller_handle.snapshot().generation;
    let host_generation = host_handle.snapshot().generation;
    let controller_binding = controller_handle
        .native_file_session_binding()
        .ok_or("controller has no proved FileRead binding")?;
    let host_binding = host_handle
        .native_file_session_binding()
        .ok_or("host has no proved FileRead binding")?;
    assert_eq!(
        controller_handle.native_file_access(&controller_binding, controller_generation)?,
        NativeFileAccess {
            is_host: false,
            read: true,
            write: true,
        }
    );
    assert_eq!(
        host_handle.native_file_access(&host_binding, host_generation)?,
        NativeFileAccess {
            is_host: true,
            read: true,
            write: true,
        }
    );
    assert!(matches!(
        controller_handle
            .native_file_read_roots(&controller_binding, controller_generation + 1)
            .await,
        Err(NativeFilesError::StaleBinding)
    ));
    let stale_binding = NativeSessionBinding {
        request_id: nestlink_auth::random_id(),
        ..controller_binding.clone()
    };
    assert!(matches!(
        controller_handle.native_file_access(&stale_binding, controller_generation),
        Err(NativeFilesError::StaleBinding)
    ));
    assert!(matches!(
        controller_handle.native_file_task_status(
            &controller_binding,
            controller_generation,
            "unknown-task"
        ),
        Err(NativeFilesError::InvalidControl)
    ));
    assert!(matches!(
        host_handle
            .native_file_read_roots(&host_binding, host_generation)
            .await,
        Err(NativeFilesError::WrongEndpoint)
    ));

    let roots = Arc::new(Mutex::new(Vec::<FileRoot>::new()));
    let files = Arc::new(Mutex::new(HashMap::from([
        ("empty.bin".to_owned(), Arc::new(Vec::new())),
        ("four.bin".to_owned(), Arc::new(b"four".to_vec())),
        ("tiny.bin".to_owned(), Arc::new(vec![1])),
    ])));
    host_handle
        .native_host_start_file_read(
            &host_binding,
            host_generation,
            DynamicFileReadDevice {
                roots: roots.clone(),
                files: files.clone(),
            },
        )
        .await?;
    host_handle
        .native_host_start_file_write(
            &host_binding,
            host_generation,
            DynamicFileWriteDevice {
                roots: roots.clone(),
            },
        )
        .await?;
    assert!(matches!(
        controller_handle
            .native_host_start_file_read(
                &controller_binding,
                controller_generation,
                EmptyFileReadDevice,
            )
            .await,
        Err(NativeFilesError::WrongEndpoint)
    ));
    assert!(matches!(
        host_handle
            .native_host_start_file_read(&host_binding, host_generation, EmptyFileReadDevice)
            .await,
        Err(NativeFilesError::InvalidControl)
    ));
    assert!(matches!(
        controller_handle
            .native_host_start_file_write(
                &controller_binding,
                controller_generation,
                DynamicFileWriteDevice {
                    roots: roots.clone(),
                },
            )
            .await,
        Err(NativeFilesError::WrongEndpoint)
    ));
    assert!(matches!(
        host_handle
            .native_host_start_file_write(
                &host_binding,
                host_generation,
                DynamicFileWriteDevice {
                    roots: roots.clone(),
                },
            )
            .await,
        Err(NativeFilesError::InvalidControl)
    ));
    assert!(
        controller_handle
            .native_file_read_roots(&controller_binding, controller_generation)
            .await?
            .is_empty()
    );
    assert!(
        controller_handle
            .native_file_write_roots(&controller_binding, controller_generation)
            .await?
            .is_empty()
    );

    let root = FileRoot {
        root_id: nestlink_auth::random_id(),
        display_name: "Shared test root".into(),
    };
    roots
        .lock()
        .map_err(|_| "file root registry poisoned")?
        .push(root.clone());
    assert_eq!(
        controller_handle
            .native_file_read_roots(&controller_binding, controller_generation)
            .await?,
        vec![root.clone()]
    );
    assert_eq!(
        controller_handle
            .native_file_write_roots(&controller_binding, controller_generation)
            .await?,
        vec![root.clone()]
    );

    for _ in 0..2 {
        let task = controller_handle.native_download(
            &controller_binding,
            controller_generation,
            NativeDownloadRequest::new(&root.root_id, "missing.bin")?,
            RejectDestinationFactory,
        )?;
        let task_id = task.task_id().to_owned();
        drop(task);
        let status = wait_native_file_task(
            &controller_handle,
            &controller_binding,
            controller_generation,
            &task_id,
        )
        .await?;
        assert_eq!(status.phase, NativeFileTaskPhase::Failed);
        assert_eq!(
            status.error,
            Some(NativeFilesError::Download(NativeDownloadError::Source(
                FileReadErrorCode::FileReadNotFound
            )))
        );
    }

    // Keep a real destination prepare blocked while Core cancels the native
    // SDK actor. The actor must enter cancellation promptly, while the Core
    // task and its byte reservation remain owned by the original worker.
    let gate = Arc::new(DestinationGate::default());
    let blocked = controller_handle.native_download(
        &controller_binding,
        controller_generation,
        NativeDownloadRequest::new(&root.root_id, "four.bin")?,
        BudgetProbeDestinationFactory {
            expected_size: Some(4),
            gate: Some(gate.clone()),
            ..BudgetProbeDestinationFactory::default()
        },
    )?;
    let blocked_id = blocked.task_id().to_owned();
    gate.wait_entered().await?;
    assert_eq!(
        controller_handle.native_download_budget_status(),
        nestlink_sdk::download_queue::NativeDownloadQueueStatus {
            tasks: 1,
            active: 1,
            queued: 0,
            reserved_bytes: 4,
            closed: false,
        }
    );
    let queued = controller_handle.native_download(
        &controller_binding,
        controller_generation,
        NativeDownloadRequest::new(&root.root_id, "empty.bin")?,
        RejectDestinationFactory,
    )?;
    let queued_id = queued.task_id().to_owned();
    assert_eq!(controller_handle.native_download_budget_status().tasks, 2);
    assert!(matches!(
        controller_handle.native_download(
            &controller_binding,
            controller_generation,
            NativeDownloadRequest::new(&root.root_id, "empty.bin")?,
            RejectDestinationFactory,
        ),
        Err(NativeFilesError::QueueFull)
    ));
    controller_handle.native_file_task_control(
        &controller_binding,
        controller_generation,
        &blocked_id,
        NativeFileTaskAction::Cancel,
    )?;
    let cancelling_status = tokio::time::timeout(
        Duration::from_secs(2),
        wait_native_download_status(
            &controller_handle,
            &controller_binding,
            controller_generation,
            &blocked_id,
            |status| {
                status.local_stopped
                    && status
                        .destination
                        .is_some_and(|destination| !destination.finished)
            },
        ),
    )
    .await??;
    let cancelling_download = cancelling_status
        .download
        .as_ref()
        .ok_or("Core did not publish the SDK cancellation status")?;
    assert!(matches!(
        cancelling_download.phase,
        nestlink_sdk::files::NativeDownloadPhase::Cancelling
            | nestlink_sdk::files::NativeDownloadPhase::Cancelled
    ));
    assert!(!cancelling_status.finished);
    assert_eq!(
        controller_handle.native_download_budget_status(),
        nestlink_sdk::download_queue::NativeDownloadQueueStatus {
            tasks: 2,
            active: 1,
            queued: 1,
            reserved_bytes: 4,
            closed: false,
        }
    );
    gate.release();
    let blocked_status = wait_native_file_task(
        &controller_handle,
        &controller_binding,
        controller_generation,
        &blocked_id,
    )
    .await?;
    assert_eq!(blocked_status.phase, NativeFileTaskPhase::Cancelled);
    assert_eq!(blocked_status.error, None);
    let blocked_download = blocked_status
        .download
        .as_ref()
        .ok_or("cancelled Core task lost its SDK status")?;
    assert!(blocked_download.actor_finished);
    let destination = blocked_download
        .destination
        .ok_or("cancelled download lost its destination status")?;
    assert!(destination.finished);
    assert_eq!(destination.destination.confirmed_bytes, 0);
    assert!(!destination.destination.published);
    let queued_status = wait_native_file_task(
        &controller_handle,
        &controller_binding,
        controller_generation,
        &queued_id,
    )
    .await?;
    assert_eq!(queued_status.phase, NativeFileTaskPhase::Failed);
    assert_eq!(
        controller_handle.native_download_budget_status(),
        nestlink_sdk::download_queue::NativeDownloadQueueStatus::default()
    );

    // A later Cancel must also interrupt the SDK pause barrier while its
    // original destination write is still blocked on the owned worker thread.
    let write_gate = Arc::new(DestinationGate::default());
    let pausing = controller_handle.native_download(
        &controller_binding,
        controller_generation,
        NativeDownloadRequest::new(&root.root_id, "four.bin")?,
        BudgetProbeDestinationFactory {
            expected_size: Some(4),
            write_gate: Some(write_gate.clone()),
            ..BudgetProbeDestinationFactory::default()
        },
    )?;
    let pausing_id = pausing.task_id().to_owned();
    write_gate.wait_entered().await?;
    controller_handle.native_file_task_control(
        &controller_binding,
        controller_generation,
        &pausing_id,
        NativeFileTaskAction::Pause,
    )?;
    let pause_waiting = wait_native_download_status(
        &controller_handle,
        &controller_binding,
        controller_generation,
        &pausing_id,
        |status| {
            status.phase == nestlink_sdk::files::NativeDownloadPhase::Pausing
                && status
                    .destination
                    .is_some_and(|destination| !destination.finished)
        },
    )
    .await?;
    assert!(!pause_waiting.finished);
    controller_handle.native_file_task_control(
        &controller_binding,
        controller_generation,
        &pausing_id,
        NativeFileTaskAction::Cancel,
    )?;
    let pause_cancelled = wait_native_download_status(
        &controller_handle,
        &controller_binding,
        controller_generation,
        &pausing_id,
        |status| {
            status.local_stopped
                && status
                    .destination
                    .is_some_and(|destination| !destination.finished)
        },
    )
    .await?;
    assert!(!pause_cancelled.finished);
    assert_eq!(
        controller_handle.native_download_budget_status(),
        nestlink_sdk::download_queue::NativeDownloadQueueStatus {
            tasks: 1,
            active: 1,
            queued: 0,
            reserved_bytes: 4,
            closed: false,
        }
    );
    write_gate.release();
    let pause_cancelled = wait_native_file_task(
        &controller_handle,
        &controller_binding,
        controller_generation,
        &pausing_id,
    )
    .await?;
    assert_eq!(pause_cancelled.phase, NativeFileTaskPhase::Cancelled);
    assert_eq!(pause_cancelled.error, None);
    let paused_download = pause_cancelled
        .download
        .as_ref()
        .ok_or("pause cancellation lost its SDK status")?;
    let destination = paused_download
        .destination
        .ok_or("pause cancellation lost destination status")?;
    assert!(destination.finished);
    assert_eq!(destination.destination.confirmed_bytes, 0);
    assert!(!destination.destination.published);
    assert_eq!(
        controller_handle.native_download_budget_status(),
        nestlink_sdk::download_queue::NativeDownloadQueueStatus::default()
    );

    assert_eq!(
        controller_handle
            .native_file_read_roots(&controller_binding, controller_generation)
            .await?,
        vec![root.clone()],
        "cancelling one download must preserve the live viewing session"
    );

    let successful = controller_handle.native_download(
        &controller_binding,
        controller_generation,
        NativeDownloadRequest::new(&root.root_id, "four.bin")?,
        BudgetProbeDestinationFactory {
            expected_size: Some(4),
            ..BudgetProbeDestinationFactory::default()
        },
    )?;
    let successful_status = wait_native_file_task(
        &controller_handle,
        &controller_binding,
        controller_generation,
        successful.task_id(),
    )
    .await?;
    assert_eq!(successful_status.phase, NativeFileTaskPhase::Completed);
    assert_eq!(
        controller_handle
            .native_download_budget_status()
            .reserved_bytes,
        0,
        "confirmed publication, close and temporary removal release the byte charge"
    );

    // A factory error and a failed preparation cleanup leave the byte charges
    // held after their task/active slots settle. A later smaller file cannot
    // consume bytes whose temporary cleanup is uncertain.
    let factory_failed = controller_handle.native_download(
        &controller_binding,
        controller_generation,
        NativeDownloadRequest::new(&root.root_id, "four.bin")?,
        BudgetProbeDestinationFactory {
            expected_size: Some(4),
            fail_build: true,
            ..BudgetProbeDestinationFactory::default()
        },
    )?;
    let factory_failed_status = wait_native_file_task(
        &controller_handle,
        &controller_binding,
        controller_generation,
        factory_failed.task_id(),
    )
    .await?;
    assert_eq!(factory_failed_status.phase, NativeFileTaskPhase::Failed);
    assert_eq!(
        controller_handle
            .native_download_budget_status()
            .reserved_bytes,
        4
    );

    let preparation_failed = controller_handle.native_download(
        &controller_binding,
        controller_generation,
        NativeDownloadRequest::new(&root.root_id, "four.bin")?,
        BudgetProbeDestinationFactory {
            expected_size: Some(4),
            fail_prepare: true,
            fail_cleanup: true,
            ..BudgetProbeDestinationFactory::default()
        },
    )?;
    let preparation_failed_status = wait_native_file_task(
        &controller_handle,
        &controller_binding,
        controller_generation,
        preparation_failed.task_id(),
    )
    .await?;
    assert_eq!(preparation_failed_status.phase, NativeFileTaskPhase::Failed);
    assert_eq!(
        controller_handle
            .native_download_budget_status()
            .reserved_bytes,
        8
    );
    let budget_rejected = controller_handle.native_download(
        &controller_binding,
        controller_generation,
        NativeDownloadRequest::new(&root.root_id, "tiny.bin")?,
        BudgetProbeDestinationFactory::default(),
    )?;
    let budget_rejected_status = wait_native_file_task(
        &controller_handle,
        &controller_binding,
        controller_generation,
        budget_rejected.task_id(),
    )
    .await?;
    assert_eq!(budget_rejected_status.phase, NativeFileTaskPhase::Failed);
    assert_eq!(
        controller_handle.native_download_budget_status(),
        nestlink_sdk::download_queue::NativeDownloadQueueStatus {
            tasks: 0,
            active: 0,
            queued: 0,
            reserved_bytes: 8,
            closed: false,
        }
    );

    // Stopping and establishing a fresh native route on the same Core does
    // not reset its aggregate byte ledger.
    let controller_connection_generation = controller_handle
        .snapshot()
        .native_session
        .data
        .as_ref()
        .ok_or("controller native session disappeared")?
        .connection_generation;
    let host_connection_generation = host_handle
        .snapshot()
        .native_session
        .data
        .as_ref()
        .ok_or("host native session disappeared")?
        .connection_generation;
    session_success(controller_handle.submit(Action::StopNativeSession {
        request_id: request.id.clone(),
        connection_generation: controller_connection_generation,
    })?)
    .await?;
    session_success(host_handle.submit(Action::StopNativeSession {
        request_id: request.id.clone(),
        connection_generation: host_connection_generation,
    })?)
    .await?;
    for handle in [&controller_handle, &host_handle] {
        wait_view(handle, |snapshot| {
            snapshot
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| session.status == NativeSessionStatus::Stopped)
        })
        .await?;
    }
    session_success(controller_handle.submit(Action::IssueRemotePermit {
        request_id: request.id.clone(),
    })?)
    .await?;
    let (controller_restarted, host_restarted) = tokio::try_join!(
        session_success(controller_handle.submit(Action::StartNativeSession {
            request_id: request.id.clone(),
        })?),
        session_success(host_handle.submit(Action::StartNativeSession {
            request_id: request.id.clone(),
        })?),
    )?;
    assert_eq!(
        controller_restarted.result.kind,
        OperationKind::StartNativeSession
    );
    assert_eq!(
        host_restarted.result.kind,
        OperationKind::StartNativeSession
    );
    let controller_generation = controller_handle.snapshot().generation;
    let host_generation = host_handle.snapshot().generation;
    let controller_binding = controller_handle
        .native_file_session_binding()
        .ok_or("restarted controller has no proved FileRead binding")?;
    let host_binding = host_handle
        .native_file_session_binding()
        .ok_or("restarted host has no proved FileRead binding")?;
    host_handle
        .native_host_start_file_read(
            &host_binding,
            host_generation,
            DynamicFileReadDevice {
                roots: roots.clone(),
                files: files.clone(),
            },
        )
        .await?;
    let after_route_change = controller_handle.native_download(
        &controller_binding,
        controller_generation,
        NativeDownloadRequest::new(&root.root_id, "tiny.bin")?,
        BudgetProbeDestinationFactory::default(),
    )?;
    let after_route_change_status = wait_native_file_task(
        &controller_handle,
        &controller_binding,
        controller_generation,
        after_route_change.task_id(),
    )
    .await?;
    assert_eq!(after_route_change_status.phase, NativeFileTaskPhase::Failed);
    assert_eq!(
        controller_handle
            .native_download_budget_status()
            .reserved_bytes,
        8
    );

    assert_eq!(
        host_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        controller_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

struct UnprovedAudioProbe {
    resets: Arc<AtomicUsize>,
    fail_reset: bool,
}
impl AudioDevice for UnprovedAudioProbe {
    fn check(&mut self) -> io::Result<()> {
        panic!("unproved audio must not inspect or use a device");
    }
    fn reset(&mut self) -> io::Result<()> {
        self.resets.fetch_add(1, Ordering::SeqCst);
        if self.fail_reset {
            Err(io::Error::other("unproved probe reset failed"))
        } else {
            Ok(())
        }
    }
}
impl AudioCaptureDevice for UnprovedAudioProbe {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        panic!("unproved audio must not capture");
    }
}
impl AudioPlaybackDevice for UnprovedAudioProbe {
    fn enqueue(&mut self, _: &AudioChunk) -> io::Result<()> {
        panic!("unproved audio must not play");
    }
}

#[tokio::test]
async fn unauthorized_audio_devices_are_reset_and_cleanup_errors_remain_visible() -> Result {
    let mut core = AppCore::start(Limits::default())?;
    let handle = core.handle();
    let resets = Arc::new(AtomicUsize::new(0));
    let unproved_binding = NativeAudioBinding {
        request_id: nestlink_auth::random_id(),
        connection_generation: 1,
        role: NativeAudioRole::HostCapture,
    };
    assert!(matches!(
        handle.attach_native_audio_capture(
            &unproved_binding,
            UnprovedAudioProbe {
                resets: resets.clone(),
                fail_reset: false,
            }
        ),
        Err(NativeAudioError::Unauthorized)
    ));
    let error = handle
        .attach_native_audio_playback(
            &unproved_binding,
            UnprovedAudioProbe {
                resets: resets.clone(),
                fail_reset: true,
            },
        )
        .err()
        .ok_or("unproved playback unexpectedly attached")?;
    let NativeAudioError::Cleanup(error) = error else {
        return Err("audio cleanup failure was hidden by authorization rejection".into());
    };
    assert!(error.to_string().contains("unproved probe reset failed"));
    assert_eq!(resets.load(Ordering::SeqCst), 2);
    assert!(handle.native_audio_binding().is_none());
    assert_eq!(
        core.shutdown(Duration::from_secs(2)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn app_core_owns_proved_session_and_revocation_waits_for_cleanup() -> Result {
    let server = Server::start(None).await?;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let host_id = host.device_id.clone();
    let prefix = format!("{}/32", routed_ipv4()?);
    let mut controller_core = native_core(controller, prefix.clone())?;
    let mut host_core = native_core(host, prefix)?;
    let controller_handle = connect(&controller_core, &server).await?;
    let host_handle = connect(&host_core, &server).await?;

    for (handle, role) in [(&controller_handle, "controller"), (&host_handle, "host")] {
        success(handle.submit(Action::EnrollLocalDevice {
            name: role.into(),
            platform: "linux-x11".into(),
            capabilities: vec![role.into(), "vp8".into(), "opus".into()],
            path_mode: "direct_only".into(),
        })?)
        .await?;
    }

    success(controller_handle.submit(Action::RequestRemote {
        host_device_id: host_id,
        permissions: vec![
            Permission::View as i32,
            Permission::Input as i32,
            Permission::Audio as i32,
        ],
        path_mode: "direct_only".into(),
        access: RemoteAccess::LocalApproval,
    })?)
    .await?;
    let request = controller_handle
        .snapshot()
        .selected_request
        .data
        .as_ref()
        .unwrap()
        .clone();
    success(host_handle.submit(Action::ApproveRemote {
        request_id: request.id.clone(),
        expected_nonce: request.nonce.clone(),
        expected_policy_revision: request.policy_revision,
        choice: ApprovalChoice {
            approved: true,
            permissions: vec![
                Permission::View as i32,
                Permission::Input as i32,
                Permission::Audio as i32,
            ],
            paths: vec![Path::Direct as i32],
        },
    })?)
    .await?;
    success(controller_handle.submit(Action::IssueRemotePermit {
        request_id: request.id.clone(),
    })?)
    .await?;
    assert!(controller_handle.poll_native_video().is_err());
    assert!(host_handle.poll_native_video().is_err());
    assert!(controller_handle.native_audio_binding().is_none());
    assert!(host_handle.native_audio_binding().is_none());

    let controller_start = controller_handle.submit(Action::StartNativeSession {
        request_id: request.id.clone(),
    })?;
    let host_start = host_handle.submit(Action::StartNativeSession {
        request_id: request.id.clone(),
    })?;
    let (controller_started, host_started) = tokio::try_join!(
        session_success(controller_start),
        session_success(host_start)
    )?;
    assert_eq!(
        controller_started.result.kind,
        OperationKind::StartNativeSession
    );
    assert_eq!(host_started.result.kind, OperationKind::StartNativeSession);
    for (handle, expected_host_view_authorized) in
        [(&controller_handle, false), (&host_handle, true)]
    {
        let view = handle.snapshot();
        let session = view.native_session.data.as_ref().unwrap();
        assert_eq!(
            session.status,
            NativeSessionStatus::Connected,
            "{session:?}"
        );
        assert_eq!(session.request_id, request.id);
        assert_eq!(session.path, Some(Path::Direct as i32));
        assert_eq!(session.host_view_authorized, expected_host_view_authorized);
        assert!(session.stop_reason.is_none());
    }

    let session_binding = host_handle.native_host_session_binding().unwrap();
    assert_eq!(session_binding.request_id, request.id);
    let input_log = Arc::new(Mutex::new(Vec::new()));
    let initial_layout = InputLayout {
        left: 0,
        top: 0,
        width: 64,
        height: 48,
    };
    let candidates = vec![
        DisplayDescriptor {
            source: 0,
            left: 0,
            top: 0,
            width: 64,
            height: 48,
            label: "Main".into(),
        },
        DisplayDescriptor {
            source: 1,
            left: -80,
            top: 0,
            width: 80,
            height: 40,
            label: "Left".into(),
        },
    ];
    host_handle.publish_native_display_candidates(&session_binding, candidates, false)?;
    let candidate_key = host_handle
        .native_displays(&session_binding)?
        .catalog
        .ok_or("candidate catalogue missing")?;
    let mut wrong_key = candidate_key.clone();
    wrong_key.sha256[0] ^= 1;
    assert!(
        host_handle
            .approve_native_displays(&session_binding, &wrong_key, vec![0, 1], 0)
            .is_err()
    );
    assert!(
        host_handle
            .approve_native_displays(&session_binding, &candidate_key, vec![0, 99], 0)
            .is_err()
    );
    let displays = host_handle.native_displays(&session_binding)?;
    assert!(!displays.local_approval_required);
    assert_eq!(displays.approved_sources, vec![0, 1]);
    assert_eq!(displays.initial_source, Some(0));
    assert!(
        host_handle
            .approve_native_displays(&session_binding, &candidate_key, vec![0, 1], 0)
            .is_err(),
        "a late display approval cannot replace the session display set"
    );
    host_handle
        .configure_native_video_stream(&session_binding, 0, 64, 48, 1)
        .await?;
    host_handle
        .attach_native_input_device(
            &session_binding,
            0,
            1,
            InputProbe(input_log.clone()),
            initial_layout,
        )
        .await?;
    host_handle
        .advertise_native_displays(&session_binding)
        .await?;
    complete_display_switch(&host_handle, &controller_handle, &session_binding, 1).await?;
    let approved = controller_handle.native_displays(&session_binding)?;
    assert_eq!(approved.approved_sources, vec![0, 1]);
    let catalog = approved.catalog.ok_or("approved catalogue missing")?;
    for case in 0..5 {
        let mut forged = NativeDisplayRequest {
            catalog: catalog.clone(),
            sequence: 2,
            source: 1,
        };
        match case {
            0 => forged.catalog.sha256[0] ^= 1,
            1 => forged.catalog.connection_generation += 1,
            2 => forged.catalog.revision += 1,
            3 => forged.sequence += 1,
            _ => forged.source = 0,
        }
        assert!(
            controller_handle
                .select_native_display(&session_binding, forged)
                .await
                .is_err()
        );
        assert_eq!(
            controller_handle
                .native_displays(&session_binding)?
                .selected
                .as_ref()
                .unwrap()
                .layout_epoch,
            1
        );
    }
    assert!(
        controller_handle
            .select_native_display(
                &session_binding,
                NativeDisplayRequest {
                    catalog: catalog.clone(),
                    sequence: 2,
                    source: 99
                }
            )
            .await
            .is_err()
    );
    // Send actual VP8 through the product-owned QUIC session. The controller
    // cannot configure a host source; decoding and presentation keep the same
    // authorization and connection owner used by the core's stop receipts.
    assert!(
        controller_handle
            .configure_native_video_stream(&session_binding, 0, 64, 48, 1)
            .await
            .is_err()
    );
    assert!(host_handle.poll_native_video().is_err());
    for (source, width, height, layout_epoch, expected_sequence) in
        [(0, 64, 48, 1, 1), (1, 80, 40, 2, 1)]
    {
        if layout_epoch > 1 {
            let old_input = controller_handle
                .native_input_layout()?
                .ok_or("initial input layout missing")?
                .binding;
            controller_handle
                .send_native_input(
                    &old_input,
                    NativeInputAction::Key {
                        code: 8,
                        down: true,
                    },
                )
                .await?;
            wait_input(&input_log, "Key { code: 8, down: true }").await?;
            let request = NativeDisplayRequest {
                catalog: catalog.clone(),
                sequence: 2,
                source,
            };
            controller_handle
                .select_native_display(&session_binding, request.clone())
                .await?;
            // An identical retry consumes no additional epoch or platform open.
            controller_handle
                .select_native_display(&session_binding, request)
                .await?;
            assert!(controller_handle.native_input_layout()?.is_none());
            complete_display_switch(&host_handle, &controller_handle, &session_binding, 2).await?;
            assert_eq!(
                controller_handle
                    .send_native_input(
                        &old_input,
                        NativeInputAction::Key {
                            code: 9,
                            down: true
                        }
                    )
                    .await,
                Err(NativeInputError::Invalid)
            );
            controller_handle.release_native_input(&old_input).await?;
            let log = input_log.lock().unwrap();
            let released = log
                .iter()
                .position(|event| event == "release-key:8")
                .unwrap();
            let selected = log
                .iter()
                .position(|event| event == "select-source:1")
                .unwrap();
            assert!(released < selected);
            assert!(!log.iter().any(|event| event == "reset"));
        }
        let binding = NativeVideoBinding {
            source,
            width,
            height,
            layout_epoch,
        };
        let keyframe_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while !host_handle
            .native_video_keyframe_needed(&session_binding, binding)
            .await?
        {
            if tokio::time::Instant::now() >= keyframe_deadline {
                return Err("new layout keyframe did not become due".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut encoder =
            nestlink_media_codec::Vp8Encoder::new(nestlink_media_codec::VideoConfig {
                width,
                height,
                fps: 30,
                bitrate_kbps: 1000,
            })?;
        let capture_pts = host_handle.native_video_capture_pts(&session_binding, Instant::now())?;
        let encoded = encoder.encode(
            &[0, 255, 0, 255].repeat((width * height) as usize),
            capture_pts,
            true,
        )?;
        host_handle
            .send_native_video_frame(
                &session_binding,
                NativeVideoBinding {
                    source,
                    width,
                    height,
                    layout_epoch,
                },
                capture_pts,
                encoded.keyframe,
                encoded.data,
            )
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(frame) = controller_handle.poll_native_video()? {
                assert_eq!(frame.epoch.layout, layout_epoch);
                assert_eq!(frame.sequence, expected_sequence);
                assert_eq!((frame.width, frame.height), (width, height));
                assert_eq!(frame.pixels.len(), (width * height * 4) as usize);
                assert!(frame.pixels.chunks_exact(4).all(|pixel| pixel[1] > 240));
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("product video presentation timed out".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let layout = controller_handle
            .native_video_layout(source)?
            .ok_or("missing product video layout")?;
        assert_eq!(layout.epoch.layout, layout_epoch);
        assert_eq!((layout.width, layout.height), (width, height));
    }

    // An entropy failure is recovered by the product's feedback consumer, not
    // by a fixed periodic keyframe or a test-only sender attached to channels.
    let binding = NativeVideoBinding {
        source: 1,
        width: 80,
        height: 40,
        layout_epoch: 2,
    };
    let stale_session_binding = NativeSessionBinding {
        request_id: nestlink_auth::random_id(),
        ..session_binding.clone()
    };
    assert!(!host_handle.native_host_input_authorized(&stale_session_binding));
    assert!(matches!(
        host_handle
            .configure_native_video_stream(&stale_session_binding, 0, 80, 40, 2)
            .await,
        Err(NativeVideoError::Unauthorized)
    ));
    assert!(matches!(
        host_handle
            .native_video_keyframe_needed(&stale_session_binding, binding)
            .await,
        Err(NativeVideoError::Unauthorized)
    ));
    assert!(matches!(
        host_handle
            .send_native_video_frame(&stale_session_binding, binding, 3, true, vec![1, 2, 3])
            .await,
        Err(NativeVideoError::Unauthorized)
    ));
    assert!(matches!(
        host_handle.fail_native_video_capture(&stale_session_binding),
        Err(NativeVideoError::Unauthorized)
    ));
    host_handle.clear_native_video_stream_for(&stale_session_binding);
    assert!(
        controller_handle
            .native_video_keyframe_needed(&session_binding, binding)
            .await
            .is_err()
    );
    let corrupt_pts = host_handle.native_video_capture_pts(&session_binding, Instant::now())?;
    host_handle
        .send_native_video_frame(
            &session_binding,
            binding,
            corrupt_pts,
            true,
            vec![0x30, 0, 0, 0x9d, 1, 0x2a, 80, 0, 40, 0, 0, 0],
        )
        .await?;
    let feedback_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while !host_handle
        .native_video_keyframe_needed(&session_binding, binding)
        .await?
    {
        if tokio::time::Instant::now() >= feedback_deadline {
            return Err("product keyframe feedback did not reach its encoder".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(controller_handle.poll_native_video()?.is_none());
    let mut encoder = nestlink_media_codec::Vp8Encoder::new(nestlink_media_codec::VideoConfig {
        width: 80,
        height: 40,
        fps: 30,
        bitrate_kbps: 1000,
    })?;
    let recovery_pts = host_handle.native_video_capture_pts(&session_binding, Instant::now())?;
    let recovered = encoder.encode(&[0, 255, 0, 255].repeat(80 * 40), recovery_pts, true)?;
    host_handle
        .send_native_video_recovery_frame(&session_binding, binding, recovery_pts, recovered.data)
        .await?;
    let recovery_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(frame) = controller_handle.poll_native_video()? {
            assert_eq!(frame.sequence, 3);
            assert_eq!(frame.epoch.layout, 2);
            assert!(frame.pixels.chunks_exact(4).all(|pixel| pixel[1] > 240));
            break;
        }
        if tokio::time::Instant::now() >= recovery_deadline {
            return Err("product keyframe recovery did not present a fresh frame".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Attach an actual owned capture boundary to the proved product session.
    // The stop receipt must include its reset, and no stale controller may poll
    // pixels after the server-side revocation has completed.
    let generation = host_handle
        .snapshot()
        .native_session
        .data
        .as_ref()
        .unwrap()
        .connection_generation;
    let display = Display {
        source: 1,
        logical: InputLayout {
            left: -80,
            top: 0,
            width: 80,
            height: 40,
        },
    };
    let rejected_resets = Arc::new(AtomicUsize::new(0));
    assert!(
        controller_handle
            .attach_native_video_capture(
                &session_binding,
                2,
                CaptureProbe {
                    resets: rejected_resets.clone(),
                    emitted: false
                },
                display,
            )
            .is_err()
    );
    assert_eq!(rejected_resets.load(Ordering::SeqCst), 1);
    assert!(matches!(
        host_handle.attach_native_video_capture(
            &stale_session_binding,
            2,
            CaptureProbe {
                resets: rejected_resets.clone(),
                emitted: false,
            },
            display,
        ),
        Err(NativeVideoError::Unauthorized)
    ));
    assert_eq!(rejected_resets.load(Ordering::SeqCst), 2);
    let resets = Arc::new(AtomicUsize::new(0));
    let capture = host_handle.attach_native_video_capture(
        &session_binding,
        2,
        CaptureProbe {
            resets: resets.clone(),
            emitted: false,
        },
        display,
    )?;
    let raw = capture
        .poll()?
        .ok_or("capture boundary did not supply its first frame")?;
    assert_eq!(raw.epoch.connection, generation);
    assert_eq!(raw.logical_point(40, 20)?, (-40, 20));
    drop(raw);
    assert_eq!(resets.load(Ordering::SeqCst), 0);

    // Product-owned Audio over the proved QUIC session. Rejected devices must
    // be reset without retiring the valid route or claiming its consumer.
    let host_audio_binding = host_handle.native_audio_binding().unwrap();
    let controller_audio_binding = controller_handle.native_audio_binding().unwrap();
    assert_eq!(
        host_handle.native_audio_binding().unwrap().role,
        NativeAudioRole::HostCapture
    );
    assert_eq!(
        controller_handle.native_audio_binding().unwrap().role,
        NativeAudioRole::ControllerPlayback
    );
    let rejected_audio_resets = Arc::new(AtomicUsize::new(0));
    let audio_log = AudioLog::default();
    assert!(matches!(
        controller_handle.attach_native_audio_capture(
            &controller_audio_binding,
            AudioCaptureProbe::new(rejected_audio_resets.clone())
        ),
        Err(NativeAudioError::Unauthorized)
    ));
    assert!(matches!(
        host_handle.attach_native_audio_playback(
            &host_audio_binding,
            AudioPlaybackProbe {
                resets: rejected_audio_resets.clone(),
                log: audio_log.clone(),
            }
        ),
        Err(NativeAudioError::Unauthorized)
    ));
    let mut stale_audio_binding = controller_audio_binding.clone();
    stale_audio_binding.connection_generation += 1;
    assert!(matches!(
        controller_handle.attach_native_audio_playback(
            &stale_audio_binding,
            AudioPlaybackProbe {
                resets: rejected_audio_resets.clone(),
                log: audio_log.clone(),
            }
        ),
        Err(NativeAudioError::Unauthorized)
    ));
    assert_eq!(rejected_audio_resets.load(Ordering::SeqCst), 3);
    let playback_resets = Arc::new(AtomicUsize::new(0));
    let playback = controller_handle.attach_native_audio_playback(
        &controller_audio_binding,
        AudioPlaybackProbe {
            resets: playback_resets.clone(),
            log: audio_log.clone(),
        },
    )?;
    assert!(matches!(
        controller_handle.attach_native_audio_playback(
            &controller_audio_binding,
            AudioPlaybackProbe {
                resets: rejected_audio_resets.clone(),
                log: audio_log.clone(),
            }
        ),
        Err(NativeAudioError::Unauthorized)
    ));
    assert_eq!(rejected_audio_resets.load(Ordering::SeqCst), 4);
    let stale_audio_binding = NativeAudioBinding {
        request_id: stale_session_binding.request_id.clone(),
        ..controller_audio_binding.clone()
    };
    assert!(matches!(
        controller_handle.attach_native_audio_playback(
            &stale_audio_binding,
            UnprovedAudioProbe {
                resets: rejected_audio_resets.clone(),
                fail_reset: true,
            }
        ),
        Err(NativeAudioError::Cleanup(_))
    ));
    assert_eq!(rejected_audio_resets.load(Ordering::SeqCst), 5);
    assert!(matches!(
        controller_handle.fail_native_audio(&stale_audio_binding),
        Err(NativeAudioError::Unauthorized)
    ));
    let audio_capture_resets = Arc::new(AtomicUsize::new(0));
    let audio_capture = host_handle.attach_native_audio_capture(
        &host_audio_binding,
        AudioCaptureProbe::new(audio_capture_resets.clone()),
    )?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !audio_log.lock().unwrap().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    {
        let log = audio_log.lock().unwrap();
        assert!(log.iter().all(|(pts, samples)| {
            pts.is_multiple_of(CHUNK_FRAMES as u64) && samples.len() == CHUNK_FRAMES * 2
        }));
        assert!(
            log.iter()
                .any(|(_, samples)| samples.iter().any(|sample| *sample != 0))
        );
    }

    // Real product Input claim and host layout over the same proved QUIC
    // session, with a recording platform adapter rather than OS injection.
    assert!(host_handle.native_host_input_authorized(&session_binding));
    assert!(!controller_handle.native_host_input_authorized(&session_binding));
    assert!(controller_handle.native_input_layout()?.is_some());
    let rejected_input = Arc::new(Mutex::new(Vec::new()));
    assert_eq!(
        host_handle
            .attach_native_input_device(
                &stale_session_binding,
                0,
                2,
                InputProbe(rejected_input.clone()),
                display.logical,
            )
            .await,
        Err(NativeInputError::Unauthorized)
    );
    assert_eq!(*rejected_input.lock().unwrap(), vec!["reset"]);
    assert_eq!(
        input_log
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.as_str() == "select-source:1")
            .count(),
        1
    );
    let input_layout = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(layout) = controller_handle.native_input_layout()? {
                return Ok::<_, NativeInputError>(layout);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    assert_eq!((input_layout.left, input_layout.top), (-80, 0));
    assert_eq!((input_layout.width, input_layout.height), (80, 40));
    assert_eq!(input_layout.binding.layout_epoch, 2);
    let input_binding = input_layout.binding;
    controller_handle
        .send_native_input(
            &input_binding,
            NativeInputAction::Key {
                code: 4,
                down: true,
            },
        )
        .await?;
    controller_handle
        .send_native_input(
            &input_binding,
            NativeInputAction::Pointer {
                button: Some(1),
                down: true,
                x: -40,
                y: 20,
            },
        )
        .await?;
    controller_handle
        .send_native_input(&input_binding, NativeInputAction::Text("中文提交".into()))
        .await?;
    wait_input(&input_log, "Text(\"中文提交\")").await?;
    controller_handle
        .release_native_input(&input_binding)
        .await?;
    wait_input(&input_log, "release-key:4").await?;
    wait_input(&input_log, "release-pointer:1").await?;
    let mut stale_binding = input_binding.clone();
    stale_binding.layout_epoch += 1;
    assert_eq!(
        controller_handle
            .send_native_input(
                &stale_binding,
                NativeInputAction::Key {
                    code: 5,
                    down: true
                }
            )
            .await,
        Err(NativeInputError::Invalid)
    );
    assert_eq!(
        controller_handle.release_native_input(&stale_binding).await,
        Err(NativeInputError::Invalid)
    );
    for action in [
        NativeInputAction::Key {
            code: 0,
            down: true,
        },
        NativeInputAction::Text(String::new()),
        NativeInputAction::Text("invalid\u{7}".into()),
        NativeInputAction::Text("x".repeat(1801)),
    ] {
        assert_eq!(
            controller_handle
                .send_native_input(&input_binding, action)
                .await,
            Err(NativeInputError::Invalid)
        );
    }
    assert_eq!(
        controller_handle
            .send_native_input(
                &input_binding,
                NativeInputAction::Pointer {
                    button: None,
                    down: false,
                    x: 0,
                    y: 20
                }
            )
            .await,
        Err(NativeInputError::Invalid)
    );
    controller_handle
        .send_native_input(
            &input_binding,
            NativeInputAction::Key {
                code: 6,
                down: true,
            },
        )
        .await?;
    wait_input(&input_log, "Key { code: 6, down: true }").await?;

    success(controller_handle.submit(Action::RevokeRemote {
        request_id: request.id.clone(),
    })?)
    .await?;
    for handle in [&controller_handle, &host_handle] {
        wait_view(handle, |snapshot| {
            snapshot
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    session.request_id == request.id
                        && matches!(
                            session.status,
                            NativeSessionStatus::Stopped | NativeSessionStatus::Failed
                        )
                })
        })
        .await?;
        let session = handle
            .snapshot()
            .native_session
            .data
            .as_ref()
            .unwrap()
            .clone();
        assert_eq!(session.stop_reason, Some(NativeSessionStopReason::Revoked));
        assert!(!session.host_view_authorized);
        assert!(session.stop_effects.is_some());
        assert!(session.cleanup.is_some());
        assert_eq!(session.cleanup, Some(NativeSessionCleanup::Succeeded));
        assert!(handle.poll_native_video().is_err());
        assert!(handle.native_video_layout(0).is_err());
        assert!(
            handle
                .native_video_keyframe_needed(&session_binding, binding)
                .await
                .is_err()
        );
        assert!(handle.native_input_layout().is_err());
        assert!(handle.native_audio_binding().is_none());
    }
    assert_eq!(resets.load(Ordering::SeqCst), 1);
    assert_eq!(audio_capture_resets.load(Ordering::SeqCst), 1);
    assert_eq!(playback_resets.load(Ordering::SeqCst), 1);
    assert!(audio_capture.status().finished);
    assert!(playback.status().finished);
    assert!(!audio_capture.status().cleanup_timed_out);
    assert!(!playback.status().cleanup_timed_out);
    let delivered = audio_log.lock().unwrap().len();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(audio_log.lock().unwrap().len(), delivered);
    wait_input(&input_log, "release-key:6").await?;
    assert!(
        input_log
            .lock()
            .unwrap()
            .iter()
            .any(|event| event == "reset")
    );
    assert_eq!(
        controller_handle
            .send_native_input(
                &input_binding,
                NativeInputAction::Key {
                    code: 7,
                    down: true
                }
            )
            .await,
        Err(NativeInputError::Unauthorized)
    );
    assert!(capture.poll().is_err());
    assert_eq!(resets.load(Ordering::SeqCst), 1);

    assert_eq!(
        controller_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        host_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

async fn complete_display_switch(
    host: &CoreHandle,
    controller: &CoreHandle,
    binding: &NativeSessionBinding,
    sequence: u64,
) -> Result {
    let request = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(request) = host.native_display_switch_request(binding)? {
                break Ok::<_, io::Error>(request);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    assert_eq!(request.sequence, sequence);
    let prepared = host.commit_native_display_switch(binding, &request).await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let host_state = host.native_displays(binding)?;
            let controller_state = controller.native_displays(binding)?;
            if host_state.pending.is_none()
                && controller_state.pending.is_none()
                && host_state.selected.as_ref() == Some(&prepared)
                && controller_state.selected.as_ref() == Some(&prepared)
            {
                break Ok::<_, io::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    // Repeating a completed request must return the same selection without
    // releasing input again or advancing either epoch.
    assert_eq!(
        host.commit_native_display_switch(binding, &request).await?,
        prepared
    );
    Ok(())
}

#[tokio::test]
async fn os_granted_view_catalogue_rotation_preserves_authority_and_exact_epochs() -> Result {
    let server = Server::start(None).await?;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let host_id = host.device_id.clone();
    let prefix = format!("{}/32", routed_ipv4()?);
    let mut controller_core = native_core(controller, prefix.clone())?;
    let mut host_core = native_core(host, prefix)?;
    let controller = connect(&controller_core, &server).await?;
    let host = connect(&host_core, &server).await?;
    for (handle, role) in [(&controller, "controller"), (&host, "host")] {
        success(handle.submit(Action::EnrollLocalDevice {
            name: role.into(),
            platform: "android".into(),
            capabilities: vec![role.into(), "vp8".into()],
            path_mode: "direct_only".into(),
        })?)
        .await?;
    }
    success(controller.submit(Action::RequestRemote {
        host_device_id: host_id,
        permissions: vec![Permission::View as i32],
        path_mode: "direct_only".into(),
        access: RemoteAccess::LocalApproval,
    })?)
    .await?;
    let request = controller
        .snapshot()
        .selected_request
        .data
        .as_ref()
        .unwrap()
        .clone();
    success(host.submit(Action::ApproveRemote {
        request_id: request.id.clone(),
        expected_nonce: request.nonce.clone(),
        expected_policy_revision: request.policy_revision,
        choice: ApprovalChoice {
            approved: true,
            permissions: vec![Permission::View as i32],
            paths: vec![Path::Direct as i32],
        },
    })?)
    .await?;
    success(controller.submit(Action::IssueRemotePermit {
        request_id: request.id.clone(),
    })?)
    .await?;
    let controller_start = controller.submit(Action::StartNativeSession {
        request_id: request.id.clone(),
    })?;
    let host_start = host.submit(Action::StartNativeSession {
        request_id: request.id.clone(),
    })?;
    tokio::try_join!(
        session_success(controller_start),
        session_success(host_start)
    )?;
    let binding = host
        .native_host_session_binding()
        .ok_or("host grant missing")?;
    let initial = DisplayDescriptor {
        source: 0,
        left: 0,
        top: 0,
        width: 64,
        height: 48,
        label: "Android shared screen".into(),
    };
    host.publish_native_display_candidates(&binding, vec![initial.clone()], true)?;
    host.configure_native_video_stream(&binding, 0, 64, 48, 1)
        .await?;
    // A pending initial catalogue cannot be replaced before its exact ACK.
    let rotated = DisplayDescriptor {
        width: 48,
        height: 64,
        ..initial.clone()
    };
    assert!(
        host.refresh_system_native_display_layout(&binding, vec![rotated.clone()], 2)
            .await
            .is_err()
    );
    host.advertise_native_displays(&binding).await?;
    complete_display_switch(&host, &controller, &binding, 1).await?;
    let original = host
        .native_displays(&binding)?
        .catalog
        .ok_or("catalogue missing")?;
    let extra = DisplayDescriptor {
        source: 1,
        ..initial.clone()
    };
    assert!(
        host.refresh_system_native_display_layout(&binding, vec![initial.clone(), extra], 2)
            .await
            .is_err()
    );
    assert!(
        host.refresh_system_native_display_layout(&binding, vec![rotated.clone()], 3)
            .await
            .is_err()
    );
    assert_eq!(
        host.native_displays(&binding)?.catalog.as_ref(),
        Some(&original)
    );
    host.refresh_system_native_display_layout(&binding, vec![rotated.clone()], 2)
        .await?;
    let pending = host.native_displays(&binding)?;
    assert!(!pending.catalog_acknowledged);
    assert_eq!(
        pending.pending.as_ref().map(|request| request.sequence),
        Some(2)
    );
    assert!(host.native_display_switch_request(&binding)?.is_none());
    assert!(
        host.refresh_system_native_display_layout(&binding, vec![initial], 3)
            .await
            .is_err()
    );
    host.advertise_native_displays(&binding).await?;
    complete_display_switch(&host, &controller, &binding, 2).await?;
    for handle in [&host, &controller] {
        let state = handle.native_displays(&binding)?;
        assert_eq!(state.approved_sources, vec![0]);
        assert_eq!(state.displays, vec![rotated.clone()]);
        let key = state.catalog.ok_or("rotated catalogue missing")?;
        assert_eq!(key.revision, 2);
        assert_eq!(key.request_id, original.request_id);
        assert_eq!(key.connection_generation, original.connection_generation);
        assert_ne!(key.sha256, original.sha256);
        let selected = state.selected.ok_or("rotated selection missing")?;
        assert_eq!(
            (
                selected.source,
                selected.sequence,
                selected.layout_epoch,
                selected.input_epoch
            ),
            (0, 2, 2, 0)
        );
    }
    let layout = controller
        .native_video_layout(0)?
        .ok_or("rotated video layout missing")?;
    assert_eq!(
        (layout.width, layout.height, layout.epoch.layout),
        (48, 64, 2)
    );
    assert_eq!(
        controller
            .snapshot()
            .native_session
            .data
            .as_ref()
            .unwrap()
            .status,
        NativeSessionStatus::Connected
    );
    assert_eq!(
        controller_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        host_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}
