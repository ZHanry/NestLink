//! Text clipboard RPCs on separate proved channels. One owned worker performs
//! bounded OS calls outside lease locks; a reply never invents an OS effect.
use crate::{
    ChannelReceiver, ChannelRuntime, ChannelSender, DeliveryGuard, LeaseControl, RemoteError,
};
use nestlink_protocol::{
    CLIPBOARD_OPERATION_MS, CLIPBOARD_WORKER_CLEANUP_MS, ClipboardErrorCode, ClipboardFailure,
    ClipboardText, ClipboardWriteEffect, NativeClipboard, SCHEMA_VERSION, native_clipboard::Action,
};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};
use zeroize::{Zeroize, Zeroizing};
mod client;
pub use client::{
    ClipboardReadClient, ClipboardReadResult, ClipboardRpcError, ClipboardWriteClient,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipboardDirection {
    Read,
    Write,
}
impl ClipboardDirection {
    pub fn channel(self) -> Channel {
        match self {
            Self::Read => Channel::ClipboardRead,
            Self::Write => Channel::ClipboardWrite,
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Read => 0,
            Self::Write => 1,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipboardBinding {
    pub session_id: String,
    pub connection_generation: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct ClipboardDirections {
    pub read: bool,
    pub write: bool,
}
impl ClipboardDirections {
    pub fn allows(self, direction: ClipboardDirection) -> bool {
        match direction {
            ClipboardDirection::Read => self.read,
            ClipboardDirection::Write => self.write,
        }
    }

    pub fn is_empty(self) -> bool {
        !self.read && !self.write
    }

    fn contains(self, other: Self) -> bool {
        (!other.read || self.read) && (!other.write || self.write)
    }
}

/// Exclusive clipboard channel claims made for one proved session. A Core
/// route can retain this before a user grants local OS directions, then pass
/// it to exactly one SDK client owner or remote server when those directions
/// are selected. Dropping an unconsumed claim intentionally stops its lease.
pub struct ClaimedClipboardTransport {
    lease: LeaseControl,
    sender: ChannelSender,
    binding: ClipboardBinding,
    directions: ClipboardDirections,
    read: Option<ChannelReceiver>,
    write: Option<ChannelReceiver>,
}

impl ClaimedClipboardTransport {
    /// Claim every direction already authorized by the proved session. This
    /// must happen once, while the newly established channel runtime is still
    /// available to Core; local consent is supplied later to the owner.
    pub fn claim(
        runtime: &mut ChannelRuntime,
        binding: ClipboardBinding,
        directions: ClipboardDirections,
    ) -> Result<Self, RemoteError> {
        if directions.is_empty() {
            return Err(rejected("session has no clipboard direction").into());
        }
        let lease = runtime.lease_control();
        for direction in [ClipboardDirection::Read, ClipboardDirection::Write] {
            if directions.allows(direction) {
                lease.check_clipboard_binding(
                    &binding.session_id,
                    direction.channel(),
                    binding.connection_generation,
                )?;
            }
        }
        let read = if directions.read {
            Some(runtime.claim_channel(Channel::ClipboardRead)?)
        } else {
            None
        };
        let write = if directions.write {
            Some(runtime.claim_channel(Channel::ClipboardWrite)?)
        } else {
            None
        };
        Ok(Self {
            lease,
            sender: runtime.sender(),
            binding,
            directions,
            read,
            write,
        })
    }

    /// Construct the same one-shot claim from independent bounded external
    /// DataChannel pipes after the exact session, generation and directions
    /// have already been selected by the proved host owner.
    pub(crate) fn from_external_parts(
        lease: LeaseControl,
        sender: ChannelSender,
        binding: ClipboardBinding,
        directions: ClipboardDirections,
        read: Option<ChannelReceiver>,
        write: Option<ChannelReceiver>,
    ) -> Result<Self, RemoteError> {
        if directions.is_empty()
            || directions.read != read.is_some()
            || directions.write != write.is_some()
        {
            return Err(rejected("external clipboard claim directions are inconsistent").into());
        }
        for direction in [ClipboardDirection::Read, ClipboardDirection::Write] {
            if directions.allows(direction) {
                lease.check_clipboard_binding(
                    &binding.session_id,
                    direction.channel(),
                    binding.connection_generation,
                )?;
            }
        }
        Ok(Self {
            lease,
            sender,
            binding,
            directions,
            read,
            write,
        })
    }

    pub fn binding(&self) -> &ClipboardBinding {
        &self.binding
    }

    pub fn directions(&self) -> ClipboardDirections {
        self.directions
    }

    pub fn lease_control(&self) -> LeaseControl {
        self.lease.clone()
    }

    fn has_receiver(&self, direction: ClipboardDirection) -> bool {
        match direction {
            ClipboardDirection::Read => self.read.is_some(),
            ClipboardDirection::Write => self.write.is_some(),
        }
    }

    fn take_receiver(
        &mut self,
        direction: ClipboardDirection,
    ) -> Result<ChannelReceiver, RemoteError> {
        if !self.directions.allows(direction) {
            return Err(rejected("clipboard direction was not claimed").into());
        }
        match direction {
            ClipboardDirection::Read => self.read.take(),
            ClipboardDirection::Write => self.write.take(),
        }
        .ok_or_else(|| rejected("clipboard direction claim was already consumed").into())
    }

    /// Permanently retire directions the selected owner will not use. They
    /// remain claimed and cannot fall through to another consumer.
    pub fn retire_unused(mut self) -> Result<(), RemoteError> {
        if let Some(receiver) = self.read.take() {
            receiver.retire_clipboard()?;
        }
        if let Some(receiver) = self.write.take() {
            receiver.retire_clipboard()?;
        }
        Ok(())
    }
}
/// Observe original direction/local consent/current authority without OS I/O.
/// The absolute deadline cannot be refreshed by retrying this check.
pub trait ClipboardConsent: Send + Sync {
    fn check_until(&self, original_deadline: Instant) -> io::Result<()>;
}
/// Record effects before a post-operation authority check. An OS method which
/// can fail after setting the clipboard must report Unknown on that failure.
pub struct ClipboardWriteOutcome {
    pub effect: ClipboardWriteEffect,
    pub error: Option<io::Error>,
}
pub trait ClipboardDevice: Send + 'static {
    fn binding(&self) -> &ClipboardBinding;
    fn consent(&self, direction: ClipboardDirection) -> Arc<dyn ClipboardConsent>;
    fn read_text(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Option<String>>;
    fn write_text(
        &mut self,
        text: &str,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> ClipboardWriteOutcome;
    /// Runs on the owner thread after requests are fenced, also after revocation.
    fn close(&mut self) -> io::Result<()>;
    /// True only when every resource owned by this device has been released.
    /// A false result after close keeps the owner alive for a later cleanup pass.
    fn cleanup_complete(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClipboardWorkerStatus {
    pub finished: bool,
    pub cleanup_timed_out: bool,
    pub error: Option<io::ErrorKind>,
    pub cleanup_error: Option<io::ErrorKind>,
}
#[derive(Clone)]
pub struct ClipboardWorkerMonitor(watch::Sender<ClipboardWorkerStatus>);
impl ClipboardWorkerMonitor {
    pub fn status(&self) -> ClipboardWorkerStatus {
        *self.0.borrow()
    }
    pub fn subscribe(&self) -> watch::Receiver<ClipboardWorkerStatus> {
        self.0.subscribe()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipboardShutdown {
    Finished,
    Pending,
}

const SELECTED_READ: u8 = 1;
const SELECTED_WRITE: u8 = 2;

struct SwitchableClipboardDeviceState {
    binding: ClipboardBinding,
    permitted: ClipboardDirections,
    selected: AtomicU8,
    retired: AtomicBool,
    devices: Mutex<SwitchableDevices>,
}

#[derive(Default)]
struct SwitchableDevices {
    active: Option<Box<dyn ClipboardDevice>>,
    pending_cleanup: Vec<Box<dyn ClipboardDevice>>,
}

/// Controls a stable host clipboard RPC owner. The owner can answer denied
/// requests before a local adapter has been opened, then accept one adapter
/// after explicit local selection without releasing or reclaiming channels.
#[derive(Clone)]
pub struct ClipboardServerDeviceControl {
    state: Arc<SwitchableClipboardDeviceState>,
}

impl ClipboardServerDeviceControl {
    fn selected_mask(directions: ClipboardDirections) -> u8 {
        (if directions.read { SELECTED_READ } else { 0 })
            | (if directions.write { SELECTED_WRITE } else { 0 })
    }

    /// Installs the one platform adapter opened for an explicit local choice.
    /// The directions are enabled only after the adapter has been stored.
    pub fn install(
        &self,
        device: impl ClipboardDevice,
        directions: ClipboardDirections,
    ) -> Result<(), RemoteError> {
        let mut devices = self
            .state
            .devices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let device: Box<dyn ClipboardDevice> = Box::new(device);
        if self.state.retired.load(Ordering::Acquire) {
            Self::close_or_retain(&mut devices, device);
            return Err(rejected("clipboard owner was retired before adapter installation").into());
        }
        if directions.is_empty() || !self.state.permitted.contains(directions) {
            Self::close_or_retain(&mut devices, device);
            return Err(rejected("selected clipboard direction was not permitted").into());
        }
        if device.binding() != &self.state.binding {
            Self::close_or_retain(&mut devices, device);
            return Err(rejected("clipboard device binding differs from its claim").into());
        }
        if devices.active.is_some() {
            Self::close_or_retain(&mut devices, device);
            return Err(rejected("clipboard device was already installed").into());
        }
        devices.active = Some(device);
        self.state
            .selected
            .store(Self::selected_mask(directions), Ordering::Release);
        if self.state.retired.load(Ordering::Acquire) {
            self.state.selected.store(0, Ordering::Release);
            return Err(rejected("clipboard owner was retired during adapter installation").into());
        }
        Ok(())
    }

    fn close_or_retain(devices: &mut SwitchableDevices, mut device: Box<dyn ClipboardDevice>) {
        if !device.cleanup_complete() {
            let _ = device.close();
        }
        if !device.cleanup_complete() {
            devices.pending_cleanup.push(device);
        }
    }

    /// Revocation only removes directions. A removed direction cannot be
    /// re-enabled within this native session.
    pub fn revoke(&self, read: bool, write: bool) {
        let revoked = Self::selected_mask(ClipboardDirections { read, write });
        self.state.selected.fetch_and(!revoked, Ordering::AcqRel);
    }

    pub fn revoke_all(&self) {
        self.state.retired.store(true, Ordering::Release);
        self.state.selected.store(0, Ordering::Release);
    }

    /// Attempts platform cleanup without dropping a device whose close has
    /// not been proven complete. A later owner reap may call this again.
    pub fn close_device(&self) -> io::Result<()> {
        self.revoke_all();
        let mut current = self
            .state
            .devices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut failure = None;
        let remove_active = if let Some(device) = current.active.as_mut() {
            if !device.cleanup_complete() {
                let result = device.close();
                if result.is_err() || !device.cleanup_complete() {
                    failure = Some(result.err().unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "clipboard cleanup is not confirmed",
                        )
                    }));
                }
            }
            device.cleanup_complete()
        } else {
            false
        };
        if remove_active {
            current.active.take();
        }

        let mut pending = Vec::new();
        for mut device in std::mem::take(&mut current.pending_cleanup) {
            if !device.cleanup_complete() {
                let result = device.close();
                if (result.is_err() || !device.cleanup_complete()) && failure.is_none() {
                    failure = Some(result.err().unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "clipboard cleanup is not confirmed",
                        )
                    }));
                }
            }
            if !device.cleanup_complete() {
                pending.push(device);
            }
        }
        current.pending_cleanup = pending;
        failure.map_or(Ok(()), Err)
    }

    pub fn cleanup_pending(&self) -> bool {
        self.state
            .devices
            .try_lock()
            .map(|devices| {
                devices
                    .active
                    .iter()
                    .chain(devices.pending_cleanup.iter())
                    .any(|device| !device.cleanup_complete())
            })
            .unwrap_or(true)
    }
}

struct SwitchableDirectionConsent {
    state: Arc<SwitchableClipboardDeviceState>,
    direction: ClipboardDirection,
    inner: Option<Arc<dyn ClipboardConsent>>,
}
impl ClipboardConsent for SwitchableDirectionConsent {
    fn check_until(&self, deadline: Instant) -> io::Result<()> {
        let bit = match self.direction {
            ClipboardDirection::Read => SELECTED_READ,
            ClipboardDirection::Write => SELECTED_WRITE,
        };
        if self.state.selected.load(Ordering::Acquire) & bit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "clipboard direction was not selected locally",
            ));
        }
        if self.state.retired.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "clipboard owner was retired",
            ));
        }
        self.inner
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "clipboard platform adapter is not installed",
                )
            })?
            .check_until(deadline)
    }
}

struct SwitchableClipboardDevice {
    state: Arc<SwitchableClipboardDeviceState>,
}
impl ClipboardDevice for SwitchableClipboardDevice {
    fn binding(&self) -> &ClipboardBinding {
        &self.state.binding
    }

    fn consent(&self, direction: ClipboardDirection) -> Arc<dyn ClipboardConsent> {
        let inner = self.state.devices.lock().ok().and_then(|devices| {
            devices
                .active
                .as_ref()
                .map(|device| device.consent(direction))
        });
        Arc::new(SwitchableDirectionConsent {
            state: self.state.clone(),
            direction,
            inner,
        })
    }

    fn read_text(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        authorized()?;
        let mut current = self
            .state
            .devices
            .lock()
            .map_err(|_| io::Error::other("clipboard device state poisoned"))?;
        let device = current.active.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "clipboard platform adapter is not installed",
            )
        })?;
        authorized()?;
        let text = device.read_text(authorized)?.map(Zeroizing::new);
        authorized()?;
        Ok(text.map(|mut text| std::mem::take(&mut *text)))
    }

    fn write_text(
        &mut self,
        text: &str,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> ClipboardWriteOutcome {
        if let Err(error) = authorized() {
            return ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
                error: Some(error),
            };
        }
        let mut current = match self.state.devices.lock() {
            Ok(current) => current,
            Err(_) => {
                return ClipboardWriteOutcome {
                    effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
                    error: Some(io::Error::other("clipboard device state poisoned")),
                };
            }
        };
        let Some(device) = current.active.as_mut() else {
            return ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
                error: Some(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "clipboard platform adapter is not installed",
                )),
            };
        };
        if let Err(error) = authorized() {
            return ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
                error: Some(error),
            };
        }
        let mut outcome = device.write_text(text, authorized);
        if let Err(error) = authorized()
            && outcome.error.is_none()
        {
            outcome.error = Some(error);
        }
        outcome
    }

    fn close(&mut self) -> io::Result<()> {
        ClipboardServerDeviceControl {
            state: self.state.clone(),
        }
        .close_device()
    }

    fn cleanup_complete(&self) -> bool {
        self.state
            .devices
            .lock()
            .map(|devices| {
                devices
                    .active
                    .iter()
                    .chain(devices.pending_cleanup.iter())
                    .all(|device| device.cleanup_complete())
            })
            .unwrap_or(false)
    }
}

/// Typed wire text is never added to logs, histories, or retry caches.
struct ProtectedMessage(NativeClipboard);
impl Drop for ProtectedMessage {
    fn drop(&mut self) {
        clear_message(&mut self.0);
    }
}
fn clear_message(message: &mut NativeClipboard) {
    match message.action.as_mut() {
        Some(Action::Write(text)) => text.zeroize(),
        Some(Action::Text(text)) => {
            if let Some(text) = text.text.as_mut() {
                text.zeroize();
            }
        }
        _ => {}
    }
}
fn rejected(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}
fn deadline_check(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original clipboard operation expired",
        ))
    } else {
        Ok(())
    }
}
fn error_code(error: &io::Error) -> ClipboardErrorCode {
    match error.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::Interrupted => {
            ClipboardErrorCode::ClipboardDenied
        }
        io::ErrorKind::TimedOut => ClipboardErrorCode::ClipboardExpired,
        io::ErrorKind::FileTooLarge | io::ErrorKind::OutOfMemory => {
            ClipboardErrorCode::ClipboardCapacity
        }
        io::ErrorKind::Unsupported | io::ErrorKind::NotFound | io::ErrorKind::NotConnected => {
            ClipboardErrorCode::ClipboardUnavailable
        }
        _ => ClipboardErrorCode::ClipboardIoFailed,
    }
}
fn failure(code: ClipboardErrorCode, effect: ClipboardWriteEffect) -> Action {
    Action::Failure(ClipboardFailure {
        code: code as i32,
        write_effect: effect as i32,
    })
}
struct DispatchGuard {
    consent: Arc<dyn ClipboardConsent>,
    lease: LeaseControl,
    binding: ClipboardBinding,
    direction: ClipboardDirection,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

struct SelectedDirectionConsent {
    selected: bool,
    inner: Arc<dyn ClipboardConsent>,
}
impl ClipboardConsent for SelectedDirectionConsent {
    fn check_until(&self, original_deadline: Instant) -> io::Result<()> {
        if !self.selected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "clipboard direction was not selected locally",
            ));
        }
        self.inner.check_until(original_deadline)
    }
}
impl DispatchGuard {
    fn check(&self) -> io::Result<()> {
        deadline_check(self.deadline)?;
        if self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "clipboard owner stopped",
            ));
        }
        self.lease
            .check_clipboard_binding(
                &self.binding.session_id,
                self.direction.channel(),
                self.binding.connection_generation,
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "clipboard business authority ended",
                )
            })?;
        self.consent.check_until(self.deadline)?;
        deadline_check(self.deadline)
    }
}
impl DeliveryGuard for DispatchGuard {
    fn check(&self) -> io::Result<()> {
        self.check()
    }
}
struct Work {
    direction: ClipboardDirection,
    request: ProtectedMessage,
    deadline: Instant,
    reply: oneshot::Sender<io::Result<WorkerReply>>,
}
struct WorkerReply {
    message: ProtectedMessage,
    disclosure: Option<Arc<dyn DeliveryGuard>>,
}
fn handle<D: ClipboardDevice>(
    device: &mut D,
    sequence: &mut [u64; 2],
    mut request: ProtectedMessage,
    guard: Arc<DispatchGuard>,
) -> io::Result<WorkerReply> {
    let index = guard.direction.index();
    if request.0.sequence != sequence[index] + 1 {
        return Err(rejected("clipboard request is not the strict successor"));
    }
    // Consume even a refused request. There is no retry which can reapply a write.
    sequence[index] = request.0.sequence;
    let action = request
        .0
        .action
        .take()
        .ok_or_else(|| rejected("missing clipboard request"))?;
    let mut disclosure = None;
    let action = match (guard.direction, action) {
        (_, Action::Cancel(true)) => Action::Cancelled(true),
        (ClipboardDirection::Read, Action::Read(true)) => {
            let result = (|| {
                guard.check()?;
                let mut check = || guard.check();
                let text = device.read_text(&mut check)?.map(Zeroizing::new);
                guard.check()?;
                Ok::<_, io::Error>(text)
            })();
            match result {
                Ok(text) => {
                    disclosure = Some(guard.clone() as Arc<dyn DeliveryGuard>);
                    Action::Text(ClipboardText {
                        text: text.map(|mut text| std::mem::take(&mut *text)),
                    })
                }
                Err(error) => failure(
                    error_code(&error),
                    ClipboardWriteEffect::ClipboardWriteNotApplied,
                ),
            }
        }
        (ClipboardDirection::Write, Action::Write(text)) => {
            let text = Zeroizing::new(text);
            match guard.check() {
                Err(error) => failure(
                    error_code(&error),
                    ClipboardWriteEffect::ClipboardWriteNotApplied,
                ),
                Ok(()) => {
                    let mut check = || guard.check();
                    let outcome = device.write_text(&text, &mut check);
                    let post = guard.check();
                    if let Some(error) = outcome.error.or_else(|| post.err()) {
                        failure(error_code(&error), outcome.effect)
                    } else if outcome.effect == ClipboardWriteEffect::ClipboardWriteApplied {
                        Action::Written(true)
                    } else {
                        failure(
                            ClipboardErrorCode::ClipboardIoFailed,
                            ClipboardWriteEffect::ClipboardWriteUnknown,
                        )
                    }
                }
            }
        }
        (_, mut action) => {
            match &mut action {
                Action::Write(text) => text.zeroize(),
                Action::Text(text) => {
                    if let Some(text) = text.text.as_mut() {
                        text.zeroize();
                    }
                }
                _ => {}
            }
            return Err(rejected(
                "clipboard action is for another direction or endpoint",
            ));
        }
    };
    request.0.action = Some(action);
    // Check the complete response, including UTF-8 and protobuf overhead. The
    // full-size local platform text is refused rather than truncated silently.
    if let Err(error) = request.0.validate() {
        clear_message(&mut request.0);
        request.0.action = Some(failure(
            if error.code == nestlink_protocol::ErrorCode::CapacityExceeded {
                ClipboardErrorCode::ClipboardCapacity
            } else {
                ClipboardErrorCode::ClipboardIoFailed
            },
            ClipboardWriteEffect::ClipboardWriteNotApplied,
        ));
        disclosure = None;
    }
    Ok(WorkerReply {
        message: request,
        disclosure,
    })
}

pub struct ClipboardServer {
    lease: LeaseControl,
    cancelled: Arc<AtomicBool>,
    stop: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<Result<(), RemoteError>>>,
    thread: Option<thread::JoinHandle<()>>,
    monitor: ClipboardWorkerMonitor,
}
impl ClipboardServer {
    pub fn start(
        runtime: &mut ChannelRuntime,
        directions: ClipboardDirections,
        device: impl ClipboardDevice,
    ) -> Result<Self, RemoteError> {
        let binding = device.binding().clone();
        let transport = ClaimedClipboardTransport::claim(runtime, binding, directions)?;
        Self::start_claimed(transport, directions, device)
    }

    /// Start the OS owner only after Core has already claimed the channels for
    /// this exact proved session and the user has selected local directions.
    /// Selected directions must be a subset of the original remote permit.
    pub fn start_claimed(
        mut transport: ClaimedClipboardTransport,
        directions: ClipboardDirections,
        device: impl ClipboardDevice,
    ) -> Result<Self, RemoteError> {
        if directions.is_empty() {
            return Err(rejected("no clipboard direction selected").into());
        }
        if !transport.directions.contains(directions) {
            return Err(rejected("selected clipboard direction was not claimed").into());
        }
        let binding = transport.binding.clone();
        if device.binding() != &binding {
            return Err(rejected("clipboard device binding differs from its claim").into());
        }
        let lease = transport.lease.clone();
        for direction in [ClipboardDirection::Read, ClipboardDirection::Write] {
            if directions.allows(direction) {
                lease.check_clipboard_binding(
                    &binding.session_id,
                    direction.channel(),
                    binding.connection_generation,
                )?;
            }
        }
        if directions.read && !transport.has_receiver(ClipboardDirection::Read)
            || directions.write && !transport.has_receiver(ClipboardDirection::Write)
        {
            return Err(rejected("selected clipboard claim was already consumed").into());
        }
        // Keep the complete proved claim under one owner. A permitted but
        // locally unselected direction is drained and refused by the worker;
        // dropping or retiring it here would poison the still-live session.
        let read = transport.read.take();
        let write = transport.write.take();
        let sender = transport.sender.clone();
        let selected = directions;
        let (jobs, work) = mpsc::sync_channel::<Work>(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let (status, _) = watch::channel(ClipboardWorkerStatus::default());
        let monitor = ClipboardWorkerMonitor(status.clone());
        let worker_cancelled = cancelled.clone();
        let worker_lease = lease.clone();
        let worker_binding = binding.clone();
        let thread = thread::Builder::new()
            .name("nestlink-clipboard-rpc".into())
            .spawn(move || {
                let mut device = device;
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut sequence = [0; 2];
                    loop {
                        if worker_cancelled.load(Ordering::Acquire)
                            || worker_lease.remaining().is_err()
                        {
                            return Ok::<_, io::Error>(());
                        }
                        let work = match work.recv_timeout(Duration::from_millis(20)) {
                            Ok(work) => work,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                        };
                        let guard = Arc::new(DispatchGuard {
                            consent: Arc::new(SelectedDirectionConsent {
                                selected: selected.allows(work.direction),
                                inner: device.consent(work.direction),
                            }),
                            lease: worker_lease.clone(),
                            binding: worker_binding.clone(),
                            direction: work.direction,
                            cancelled: worker_cancelled.clone(),
                            deadline: work.deadline,
                        });
                        let result = handle(&mut device, &mut sequence, work.request, guard);
                        let terminal = result.is_err();
                        if work.reply.send(result).is_err() || terminal {
                            return Ok(());
                        }
                    }
                }))
                .unwrap_or_else(|_| Err(io::Error::other("clipboard adapter panicked")));
                let cleanup =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| device.close()))
                        .unwrap_or_else(|_| Err(io::Error::other("clipboard cleanup panicked")));
                drop(device);
                if outcome.is_err() || cleanup.is_err() {
                    let _ = worker_lease.stop(StopReason::PlatformChanged);
                }
                status.send_modify(|status| {
                    status.error = outcome.err().map(|error| error.kind());
                    status.cleanup_error = cleanup.err().map(|error| error.kind());
                    status.finished = true;
                });
            })?;
        let (stop, stopping) = watch::channel(false);
        let task_lease = lease.clone();
        let task_cancelled = cancelled.clone();
        let task = tokio::spawn(async move {
            let result = serve(
                read,
                write,
                sender,
                jobs,
                binding,
                task_lease.clone(),
                stopping,
            )
            .await;
            task_cancelled.store(true, Ordering::Release);
            if result.is_err() {
                crate::queues::stop_io_result(&task_lease, &result);
            }
            result
        });
        Ok(Self {
            lease,
            cancelled,
            stop,
            task: Some(task),
            thread: Some(thread),
            monitor,
        })
    }

    /// Start a stable owner for every remotely permitted direction before a
    /// local clipboard adapter is approved. Until a device is installed, the
    /// owner consumes requests and returns `ClipboardDenied` without touching
    /// an OS clipboard. A later explicit local choice installs a device into
    /// this same owner and never reclaims its channels.
    pub fn start_claimed_switchable(
        transport: ClaimedClipboardTransport,
        directions: ClipboardDirections,
    ) -> Result<(Self, ClipboardServerDeviceControl), RemoteError> {
        if directions.is_empty() {
            return Err(rejected("no clipboard direction was permitted").into());
        }
        if !transport.directions.contains(directions) {
            return Err(rejected("clipboard direction was not claimed").into());
        }
        let binding = transport.binding.clone();
        let state = Arc::new(SwitchableClipboardDeviceState {
            binding,
            permitted: directions,
            selected: AtomicU8::new(0),
            retired: AtomicBool::new(false),
            devices: Mutex::new(SwitchableDevices::default()),
        });
        let control = ClipboardServerDeviceControl {
            state: state.clone(),
        };
        let server =
            Self::start_claimed(transport, directions, SwitchableClipboardDevice { state })?;
        Ok((server, control))
    }

    pub fn monitor(&self) -> ClipboardWorkerMonitor {
        self.monitor.clone()
    }
    pub async fn shutdown(&mut self, reason: StopReason) -> Result<ClipboardShutdown, RemoteError> {
        self.cancelled.store(true, Ordering::Release);
        self.stop.send_replace(true);
        self.lease.stop(reason)?;
        let mut status = self.monitor.subscribe();
        let wait = async {
            while !status.borrow_and_update().finished {
                status.changed().await.map_err(|_| RemoteError::Stopped)?;
            }
            if let Some(task) = self.task.as_mut() {
                let _ = task.await;
            }
            self.task.take();
            while self
                .thread
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if let Some(worker) = self.thread.take() {
                worker
                    .join()
                    .map_err(|_| io::Error::other("clipboard thread panicked"))?;
            }
            Ok::<_, RemoteError>(())
        };
        match tokio::time::timeout(Duration::from_millis(CLIPBOARD_WORKER_CLEANUP_MS), wait).await {
            Ok(result) => {
                result?;
                Ok(ClipboardShutdown::Finished)
            }
            Err(_) => {
                self.monitor
                    .0
                    .send_modify(|status| status.cleanup_timed_out = true);
                Ok(ClipboardShutdown::Pending)
            }
        }
    }
}
impl Drop for ClipboardServer {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.stop.send_replace(true);
        let _ = self.lease.stop_if_running(StopReason::ExplicitExit);
    }
}
async fn receive_optional(
    receiver: &mut Option<ChannelReceiver>,
) -> Result<nestlink_transport_stream::Frame, RemoteError> {
    match receiver {
        Some(receiver) => receiver.receive().await,
        None => std::future::pending().await,
    }
}
async fn serve(
    mut read: Option<ChannelReceiver>,
    mut write: Option<ChannelReceiver>,
    sender: ChannelSender,
    jobs: mpsc::SyncSender<Work>,
    binding: ClipboardBinding,
    lease: LeaseControl,
    mut stopping: watch::Receiver<bool>,
) -> Result<(), RemoteError> {
    let mut stopped = lease.subscribe_stopped();
    loop {
        let (direction, frame) = tokio::select! { biased;
            _ = stopping.changed() => return Err(RemoteError::Stopped),
            _ = stopped.changed() => return Err(RemoteError::Stopped),
            frame = receive_optional(&mut read) => (ClipboardDirection::Read, frame?),
            frame = receive_optional(&mut write) => (ClipboardDirection::Write, frame?),
        };
        let deadline = Instant::now() + Duration::from_millis(CLIPBOARD_OPERATION_MS);
        let mut bytes = Zeroizing::new(frame.payload);
        let request =
            ProtectedMessage(NativeClipboard::decode_validated(&bytes).inspect_err(|_| {
                let _ = lease.stop(StopReason::ProtocolViolation);
            })?);
        bytes.zeroize();
        if request.0.connection_generation != binding.connection_generation {
            let _ = lease.stop(StopReason::ProtocolViolation);
            return Err(rejected("clipboard request belongs to another generation").into());
        }
        let (reply, response) = oneshot::channel();
        jobs.try_send(Work {
            direction,
            request,
            deadline,
            reply,
        })
        .map_err(|_| io::Error::other("clipboard worker unavailable"))?;
        let reply = tokio::select! { biased;
            _ = stopping.changed() => return Err(RemoteError::Stopped),
            _ = stopped.changed() => return Err(RemoteError::Stopped),
            response = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), response) => {
                response.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "clipboard OS operation did not finish"))?
                    .map_err(|_| io::Error::other("clipboard worker ended without reply"))??
            },
        };
        lease.check_clipboard_binding(
            &binding.session_id,
            direction.channel(),
            binding.connection_generation,
        )?;
        let bytes = Zeroizing::new(reply.message.0.encode_validated()?);
        let send = async {
            if let Some(guard) = reply.disclosure {
                let fallback = |code| {
                    NativeClipboard {
                        schema_version: SCHEMA_VERSION,
                        connection_generation: binding.connection_generation,
                        sequence: reply.message.0.sequence,
                        action: Some(failure(
                            code,
                            ClipboardWriteEffect::ClipboardWriteNotApplied,
                        )),
                    }
                    .encode_validated()
                };
                sender
                    .send_checked_delivery(
                        direction.channel(),
                        &bytes,
                        guard,
                        fallback(ClipboardErrorCode::ClipboardDenied)?,
                        fallback(ClipboardErrorCode::ClipboardExpired)?,
                    )
                    .await
            } else {
                sender.send(direction.channel(), &bytes).await
            }
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), send)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "clipboard reply queue expired")
            })??;
    }
}
