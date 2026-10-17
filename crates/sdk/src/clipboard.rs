//! Application-owned clipboard RPCs and explicit native platform bridges.
//! Text is one-shot data, never product state, logs, or a reconnect retry cache.
use nestlink_platform_clipboard::{
    ClipboardAuthority, ClipboardBinding as PlatformBinding, ClipboardCleanup,
    ClipboardDirection as PlatformDirection, ClipboardDirectionGuard,
    NativeClipboard as PlatformClipboard,
};
use nestlink_protocol::{
    CLIPBOARD_OPERATION_MS, ClipboardErrorCode, ClipboardWriteEffect, ErrorCode, NativeClipboard,
    SCHEMA_VERSION, native_clipboard::Action,
};
use nestlink_remote::{
    ChannelRuntime, LeaseControl, RemoteError,
    clipboard::{
        ClaimedClipboardTransport, ClipboardBinding, ClipboardConsent, ClipboardDevice,
        ClipboardDirection, ClipboardDirections, ClipboardReadClient, ClipboardRpcError,
        ClipboardServer, ClipboardWriteClient, ClipboardWriteOutcome,
    },
};
use nestlink_transport_stream::Channel;
use std::{
    io,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeClipboardError {
    #[error("clipboard operation refused: {code:?}, effect: {effect:?}")]
    Refused {
        code: ClipboardErrorCode,
        effect: ClipboardWriteEffect,
    },
    #[error("clipboard transport failed: {0:?}")]
    Transport(io::ErrorKind),
    #[error("clipboard platform cleanup failed: {0:?}")]
    Cleanup(io::ErrorKind),
    #[error("clipboard authority failed ({code:?}): {reason}")]
    Authorization {
        code: ErrorCode,
        reason: &'static str,
    },
    #[error("clipboard owner stopped")]
    Stopped,
    #[error("clipboard operation/text capacity reached")]
    Capacity,
    #[error("clipboard direction was not selected")]
    Unselected,
    #[error("clipboard operation cancelled, effect: {effect:?}")]
    Cancelled { effect: ClipboardWriteEffect },
    #[error("clipboard completion is no longer current")]
    Stale,
}
impl From<RemoteError> for NativeClipboardError {
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
impl From<ClipboardRpcError> for NativeClipboardError {
    fn from(error: ClipboardRpcError) -> Self {
        match error {
            ClipboardRpcError::Remote(error) => error.into(),
            ClipboardRpcError::Refused { code, effect } => Self::Refused { code, effect },
            ClipboardRpcError::Cancelled => Self::Cancelled {
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
            },
        }
    }
}
fn local_error(error: io::Error, effect: ClipboardWriteEffect) -> NativeClipboardError {
    let code = match error.kind() {
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
    };
    NativeClipboardError::Refused { code, effect }
}
fn effect_of(
    result: &Result<NativeClipboardOutput, NativeClipboardError>,
    write: bool,
) -> ClipboardWriteEffect {
    match result {
        Ok(NativeClipboardOutput::Written) => ClipboardWriteEffect::ClipboardWriteApplied,
        Err(
            NativeClipboardError::Refused { effect, .. }
            | NativeClipboardError::Cancelled { effect },
        ) => *effect,
        Err(_) if write => ClipboardWriteEffect::ClipboardWriteUnknown,
        _ => ClipboardWriteEffect::ClipboardWriteNotApplied,
    }
}
fn expired(deadline: Instant) -> Result<(), NativeClipboardError> {
    if Instant::now() >= deadline {
        Err(NativeClipboardError::Refused {
            code: ClipboardErrorCode::ClipboardExpired,
            effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
        })
    } else {
        Ok(())
    }
}

/// A captured text keeps its original local Read approval and absolute deadline
/// until a matching transport writer starts it. There is no plaintext Debug,
/// Clone, Serialize or constructor without a current consent capability.
pub struct NativeClipboardPayload {
    text: Zeroizing<String>,
    consent: Arc<dyn ClipboardConsent>,
    deadline: Instant,
}
impl NativeClipboardPayload {
    pub fn new(
        text: Zeroizing<String>,
        consent: Arc<dyn ClipboardConsent>,
        original_deadline: Instant,
    ) -> Result<Self, NativeClipboardError> {
        expired(original_deadline)?;
        consent
            .check_until(original_deadline)
            .map_err(|error| local_error(error, ClipboardWriteEffect::ClipboardWriteNotApplied))?;
        let mut probe = NativeClipboard {
            schema_version: SCHEMA_VERSION,
            connection_generation: i64::MAX as u64,
            sequence: i64::MAX as u64,
            action: Some(Action::Write(text.to_string())),
        };
        // Avoid retaining the validation copy; the wire budget includes maximal
        // legal generation/sequence overhead, so every later envelope fits.
        let result = probe.validate();
        if let Some(Action::Write(text)) = probe.action.take() {
            drop(Zeroizing::new(text));
        }
        result.map_err(|error| NativeClipboardError::Authorization {
            code: error.code,
            reason: error.reason,
        })?;
        Ok(Self {
            text,
            consent,
            deadline: original_deadline,
        })
    }
}

struct TextState {
    text: Option<Zeroizing<String>>,
    unread: bool,
    _permit: Option<OwnedSemaphorePermit>,
}
struct TextSlot(Mutex<TextState>);
impl TextSlot {
    fn clear(&self) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.text.take();
        state.unread = false;
        state._permit.take();
    }
}
struct Shared {
    closing: AtomicBool,
    operations: Arc<Semaphore>,
    secret_slots: Arc<Semaphore>,
    texts: Mutex<Vec<Weak<TextSlot>>>,
}
impl Shared {
    fn clear_texts(&self) {
        let mut texts = self
            .texts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for text in texts.drain(..).filter_map(|text| text.upgrade()) {
            text.clear();
        }
    }
    fn close(&self) {
        self.closing.store(true, Ordering::Release);
        self.clear_texts();
    }
}
/// A successful remote read is consumed once. Closing the owner or ending its
/// original lease actively clears an unread result even when UI holds it.
pub struct NativeClipboardText {
    slot: Arc<TextSlot>,
    shared: Arc<Shared>,
    lease: LeaseControl,
    binding: ClipboardBinding,
}
impl NativeClipboardText {
    pub fn binding(&self) -> &ClipboardBinding {
        &self.binding
    }
    pub fn take_text(&mut self) -> Result<Option<Zeroizing<String>>, NativeClipboardError> {
        if self.shared.closing.load(Ordering::Acquire) {
            self.slot.clear();
            return Err(NativeClipboardError::Stale);
        }
        self.lease
            .check_clipboard_binding(
                &self.binding.session_id,
                Channel::ClipboardRead,
                self.binding.connection_generation,
            )
            .inspect_err(|_| self.slot.clear())?;
        let mut state = self
            .slot
            .0
            .lock()
            .map_err(|_| NativeClipboardError::Stopped)?;
        if !state.unread {
            return Err(NativeClipboardError::Stale);
        }
        state.unread = false;
        let text = state.text.take();
        state._permit.take();
        // This is the consume linearization point. The receiver now owns the
        // plaintext and must clear it if its own later UI generation changes.
        if self.shared.closing.load(Ordering::Acquire) {
            drop(text);
            return Err(NativeClipboardError::Stale);
        }
        Ok(text)
    }
}
pub enum NativeClipboardOutput {
    Text(NativeClipboardText),
    Written,
}
pub struct NativeClipboardCompletion {
    pub result: Result<NativeClipboardOutput, NativeClipboardError>,
    pub write_effect: ClipboardWriteEffect,
}
pub struct NativeClipboardTicket {
    cancelled: Arc<AtomicBool>,
    text: Option<Arc<TextSlot>>,
    reply: oneshot::Receiver<NativeClipboardCompletion>,
}
impl NativeClipboardTicket {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(text) = &self.text {
            text.clear();
        }
    }
    pub async fn wait(self) -> Result<NativeClipboardCompletion, NativeClipboardError> {
        self.reply.await.map_err(|_| NativeClipboardError::Stopped)
    }
}
enum Operation {
    Read {
        slot: Arc<TextSlot>,
        consent: Option<Arc<dyn ClipboardConsent>>,
    },
    Write(NativeClipboardPayload),
}
struct Command {
    operation: Operation,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    reply: oneshot::Sender<NativeClipboardCompletion>,
    _permit: OwnedSemaphorePermit,
}
#[derive(Clone)]
pub struct NativeClipboardHandle {
    commands: mpsc::Sender<Command>,
    shared: Arc<Shared>,
    lease: LeaseControl,
    binding: ClipboardBinding,
    directions: ClipboardDirections,
}
impl NativeClipboardHandle {
    fn submit(
        &self,
        operation: Operation,
        deadline: Instant,
    ) -> Result<NativeClipboardTicket, NativeClipboardError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(NativeClipboardError::Stopped);
        }
        let direction = match &operation {
            Operation::Read { .. } => ClipboardDirection::Read,
            Operation::Write(_) => ClipboardDirection::Write,
        };
        if !self.directions.allows(direction) {
            return Err(NativeClipboardError::Unselected);
        }
        expired(deadline)?;
        self.lease.check_clipboard_binding(
            &self.binding.session_id,
            direction.channel(),
            self.binding.connection_generation,
        )?;
        let permit = self
            .shared
            .operations
            .clone()
            .try_acquire_owned()
            .map_err(|_| NativeClipboardError::Capacity)?;
        let text = match &operation {
            Operation::Read { slot, .. } => Some(slot.clone()),
            _ => None,
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let (reply, receive) = oneshot::channel();
        self.commands
            .try_send(Command {
                operation,
                deadline,
                cancelled: cancelled.clone(),
                reply,
                _permit: permit,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => NativeClipboardError::Capacity,
                mpsc::error::TrySendError::Closed(_) => NativeClipboardError::Stopped,
            })?;
        Ok(NativeClipboardTicket {
            cancelled,
            text,
            reply: receive,
        })
    }
    pub fn read_remote(&self) -> Result<NativeClipboardTicket, NativeClipboardError> {
        self.read_remote_inner(None)
    }

    /// Reads the remote clipboard only while the local OS write direction is
    /// still approved. The consent is checked before dispatch and after the
    /// matching reply is consumed, so revocation cannot strand the channel.
    pub fn read_remote_with_consent(
        &self,
        consent: Arc<dyn ClipboardConsent>,
    ) -> Result<NativeClipboardTicket, NativeClipboardError> {
        self.read_remote_inner(Some(consent))
    }

    fn read_remote_inner(
        &self,
        consent: Option<Arc<dyn ClipboardConsent>>,
    ) -> Result<NativeClipboardTicket, NativeClipboardError> {
        let permit = self
            .shared
            .secret_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| NativeClipboardError::Capacity)?;
        let slot = Arc::new(TextSlot(Mutex::new(TextState {
            text: None,
            unread: false,
            _permit: Some(permit),
        })));
        let mut texts = self
            .shared
            .texts
            .lock()
            .map_err(|_| NativeClipboardError::Stopped)?;
        texts.retain(|text| text.strong_count() > 0);
        texts.push(Arc::downgrade(&slot));
        drop(texts);
        self.submit(
            Operation::Read { slot, consent },
            Instant::now() + Duration::from_millis(CLIPBOARD_OPERATION_MS),
        )
    }
    pub fn send(
        &self,
        payload: NativeClipboardPayload,
    ) -> Result<NativeClipboardTicket, NativeClipboardError> {
        let deadline = payload.deadline;
        self.submit(Operation::Write(payload), deadline)
    }
}
struct SourceGuard {
    original: Arc<dyn ClipboardConsent>,
    shared: Arc<Shared>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}
impl ClipboardConsent for SourceGuard {
    fn check_until(&self, deadline: Instant) -> io::Result<()> {
        if self.shared.closing.load(Ordering::Acquire) || self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "clipboard owner/source cancelled",
            ));
        }
        self.original.check_until(deadline.min(self.deadline))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeClipboardShutdown {
    Complete,
    Pending,
    Failed,
}
pub struct NativeClipboardOwner {
    handle: NativeClipboardHandle,
    stop: watch::Sender<bool>,
    finished: watch::Receiver<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl NativeClipboardOwner {
    pub fn attach(
        runtime: &mut ChannelRuntime,
        generation: u64,
        directions: ClipboardDirections,
    ) -> Result<Self, NativeClipboardError> {
        if !directions.read && !directions.write {
            return Err(NativeClipboardError::Unselected);
        }
        let lease = runtime.lease_control();
        let channel = if directions.read {
            Channel::ClipboardRead
        } else {
            Channel::ClipboardWrite
        };
        let binding = ClipboardBinding {
            session_id: lease.clipboard_session_id(channel, generation)?,
            connection_generation: generation,
        };
        let transport = ClaimedClipboardTransport::claim(runtime, binding, directions)?;
        Self::attach_claimed(transport, directions)
    }

    /// Consume claims retained by Core at session establishment after local
    /// clipboard directions have been selected. The selected set can only
    /// narrow the proved permit; all remaining claims are permanently retired.
    pub fn attach_claimed(
        mut transport: ClaimedClipboardTransport,
        directions: ClipboardDirections,
    ) -> Result<Self, NativeClipboardError> {
        if !directions.read && !directions.write {
            return Err(NativeClipboardError::Unselected);
        }
        let claimed = transport.directions();
        if (directions.read && !claimed.read) || (directions.write && !claimed.write) {
            return Err(NativeClipboardError::Unselected);
        }
        let lease = transport.lease_control();
        let binding = transport.binding().clone();
        let read = if claimed.read {
            Some(ClipboardReadClient::attach_claimed(&mut transport)?)
        } else {
            None
        };
        let write = if claimed.write {
            Some(ClipboardWriteClient::attach_claimed(&mut transport)?)
        } else {
            None
        };
        let shared = Arc::new(Shared {
            closing: AtomicBool::new(false),
            operations: Arc::new(Semaphore::new(2)),
            secret_slots: Arc::new(Semaphore::new(2)),
            texts: Mutex::new(Vec::new()),
        });
        let (commands, incoming) = mpsc::channel(2);
        let (stop, stopping) = watch::channel(false);
        let (finish, finished) = watch::channel(false);
        let handle = NativeClipboardHandle {
            commands,
            shared,
            lease,
            binding,
            directions,
        };
        let actor_handle = handle.clone();
        let task = tokio::spawn(run(incoming, stopping, finish, actor_handle, read, write));
        Ok(Self {
            handle,
            stop,
            finished,
            task: Some(task),
        })
    }
    pub fn handle(&self) -> NativeClipboardHandle {
        self.handle.clone()
    }
    pub fn finished(&self) -> watch::Receiver<bool> {
        self.finished.clone()
    }
    pub fn request_shutdown(&self) {
        self.handle.shared.close();
        self.stop.send_replace(true);
    }
    pub async fn shutdown(&mut self, timeout: Duration) -> NativeClipboardShutdown {
        self.request_shutdown();
        let Some(task) = self.task.as_mut() else {
            return NativeClipboardShutdown::Complete;
        };
        match tokio::time::timeout(timeout, task).await {
            Ok(Ok(())) => {
                self.task.take();
                NativeClipboardShutdown::Complete
            }
            Ok(Err(_)) => {
                self.task.take();
                NativeClipboardShutdown::Failed
            }
            Err(_) => NativeClipboardShutdown::Pending,
        }
    }
}
impl Drop for NativeClipboardOwner {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}
async fn run(
    mut incoming: mpsc::Receiver<Command>,
    mut stopping: watch::Receiver<bool>,
    finish: watch::Sender<bool>,
    handle: NativeClipboardHandle,
    mut read: Option<ClipboardReadClient>,
    mut write: Option<ClipboardWriteClient>,
) {
    let mut stopped = handle.lease.subscribe_stopped();
    loop {
        if handle.shared.closing.load(Ordering::Acquire) {
            break;
        }
        let command = tokio::select! { biased;
            _ = stopping.changed() => break,
            _ = stopped.changed() => break,
            command = incoming.recv() => match command { Some(command) => command, None => break },
        };
        let is_write = matches!(&command.operation, Operation::Write(_));
        let read_slot = match &command.operation {
            Operation::Read { slot, .. } => Some(slot.clone()),
            Operation::Write(_) => None,
        };
        let mut result = if command.cancelled.load(Ordering::Acquire) {
            Err(NativeClipboardError::Cancelled {
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
            })
        } else if let Err(error) = expired(command.deadline) {
            Err(error)
        } else {
            match command.operation {
                Operation::Read { slot, consent } => match read.as_mut() {
                    Some(client) => client
                        .read_text_until_with_consent(command.deadline, consent)
                        .await
                        .map_err(NativeClipboardError::from)
                        .and_then(|value| {
                            if handle.shared.closing.load(Ordering::Acquire)
                                || command.cancelled.load(Ordering::Acquire)
                            {
                                drop(value);
                                slot.clear();
                                return Err(NativeClipboardError::Cancelled {
                                    effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
                                });
                            }
                            let mut state =
                                slot.0.lock().map_err(|_| NativeClipboardError::Stopped)?;
                            state.text = value.text;
                            state.unread = true;
                            drop(state);
                            Ok(NativeClipboardOutput::Text(NativeClipboardText {
                                slot,
                                shared: handle.shared.clone(),
                                lease: handle.lease.clone(),
                                binding: handle.binding.clone(),
                            }))
                        }),
                    None => Err(NativeClipboardError::Unselected),
                },
                Operation::Write(payload) => match write.as_mut() {
                    Some(client) => client
                        .write_text_until(
                            payload.text,
                            Arc::new(SourceGuard {
                                original: payload.consent,
                                shared: handle.shared.clone(),
                                cancelled: command.cancelled.clone(),
                                deadline: command.deadline,
                            }),
                            command.deadline,
                        )
                        .await
                        .map(|()| NativeClipboardOutput::Written)
                        .map_err(NativeClipboardError::from),
                    None => Err(NativeClipboardError::Unselected),
                },
            }
        };
        let effect = effect_of(&result, is_write);
        if result.is_err()
            && let Some(slot) = &read_slot
        {
            slot.clear();
        }
        if command.cancelled.load(Ordering::Acquire)
            || handle.shared.closing.load(Ordering::Acquire)
        {
            if let Ok(NativeClipboardOutput::Text(text)) = &result {
                text.slot.clear();
            }
            result = Err(NativeClipboardError::Cancelled { effect });
        }
        let _ = command.reply.send(NativeClipboardCompletion {
            result,
            write_effect: effect,
        });
    }
    handle.shared.close();
    incoming.close();
    while let Some(command) = incoming.recv().await {
        if let Operation::Read { slot, .. } = &command.operation {
            slot.clear();
        }
        let _ = command.reply.send(NativeClipboardCompletion {
            result: Err(NativeClipboardError::Cancelled {
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
            }),
            write_effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
        });
    }
    if let Some(read) = read
        && handle
            .lease
            .check_clipboard_binding(
                &handle.binding.session_id,
                Channel::ClipboardRead,
                handle.binding.connection_generation,
            )
            .is_ok()
    {
        let _ = read.retire();
    }
    if let Some(write) = write
        && handle
            .lease
            .check_clipboard_binding(
                &handle.binding.session_id,
                Channel::ClipboardWrite,
                handle.binding.connection_generation,
            )
            .is_ok()
    {
        let _ = write.retire();
    }
    finish.send_replace(true);
}

/// OS direction is local. Controller Read feeds ClipboardWrite; controller
/// Write consumes ClipboardRead. Host directions keep the business names.
#[derive(Clone, Copy, Debug)]
pub enum ClipboardEndpoint {
    Host,
    Controller,
}
pub struct PlatformClipboardAuthority {
    lease: LeaseControl,
    endpoint: ClipboardEndpoint,
}
impl PlatformClipboardAuthority {
    pub fn new(lease: LeaseControl, endpoint: ClipboardEndpoint) -> Self {
        Self { lease, endpoint }
    }
}
impl ClipboardAuthority for PlatformClipboardAuthority {
    fn check(&self, binding: &PlatformBinding, direction: PlatformDirection) -> io::Result<()> {
        let channel = match (self.endpoint, direction) {
            (ClipboardEndpoint::Host, PlatformDirection::Read)
            | (ClipboardEndpoint::Controller, PlatformDirection::Write) => Channel::ClipboardRead,
            (ClipboardEndpoint::Host, PlatformDirection::Write)
            | (ClipboardEndpoint::Controller, PlatformDirection::Read) => Channel::ClipboardWrite,
        };
        self.lease
            .check_clipboard_binding(&binding.session_id, channel, binding.connection_generation)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "original clipboard session/permission ended",
                )
            })
    }
}
struct PlatformGuard(ClipboardDirectionGuard);
impl ClipboardConsent for PlatformGuard {
    fn check_until(&self, deadline: Instant) -> io::Result<()> {
        self.0.check_until(deadline)
    }
}
struct PlatformHost<D: PlatformClipboard> {
    native: D,
    binding: ClipboardBinding,
}
impl<D: PlatformClipboard + 'static> ClipboardDevice for PlatformHost<D> {
    fn binding(&self) -> &ClipboardBinding {
        &self.binding
    }
    fn consent(&self, direction: ClipboardDirection) -> Arc<dyn ClipboardConsent> {
        Arc::new(PlatformGuard(self.native.direction_guard(
            match direction {
                ClipboardDirection::Read => PlatformDirection::Read,
                ClipboardDirection::Write => PlatformDirection::Write,
            },
        )))
    }
    fn read_text(
        &mut self,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        check()?;
        let text = self.native.read_text()?.map(Zeroizing::new);
        check()?;
        Ok(text.map(|mut text| std::mem::take(&mut *text)))
    }
    fn write_text(
        &mut self,
        text: &str,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> ClipboardWriteOutcome {
        if let Err(error) = check() {
            return ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
                error: Some(error),
            };
        }
        match self.native.write_text(text) {
            Ok(()) => ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteApplied,
                error: check().err(),
            },
            Err(error) => ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteUnknown,
                error: Some(error),
            },
        }
    }
    fn close(&mut self) -> io::Result<()> {
        self.native.close()
    }
    fn cleanup_complete(&self) -> bool {
        matches!(
            self.native.monitor().status().cleanup,
            ClipboardCleanup::Complete
        )
    }
}
pub fn start_native_clipboard_server(
    runtime: &mut ChannelRuntime,
    directions: ClipboardDirections,
    native: impl PlatformClipboard + 'static,
) -> Result<ClipboardServer, NativeClipboardError> {
    let binding = ClipboardBinding {
        session_id: native.binding().session_id.clone(),
        connection_generation: native.binding().connection_generation,
    };
    Ok(ClipboardServer::start(
        runtime,
        directions,
        PlatformHost { native, binding },
    )?)
}

/// Start a host platform owner with clipboard channels already claimed by the
/// Core route at session establishment. This lets local consent arrive later
/// without exposing an unclaimed channel to another consumer.
pub fn start_native_clipboard_server_claimed(
    transport: ClaimedClipboardTransport,
    directions: ClipboardDirections,
    native: impl PlatformClipboard + 'static,
) -> Result<ClipboardServer, NativeClipboardError> {
    let binding = ClipboardBinding {
        session_id: native.binding().session_id.clone(),
        connection_generation: native.binding().connection_generation,
    };
    Ok(ClipboardServer::start_claimed(
        transport,
        directions,
        PlatformHost { native, binding },
    )?)
}
/// Own this with the original native controller session, outside UI rebuilds.
/// Its synchronous methods invoke the platform's finite owned worker; use a
/// dedicated caller worker instead of running them on the Tokio I/O thread.
pub struct ControllerClipboard<D: PlatformClipboard> {
    native: D,
}
impl<D: PlatformClipboard> ControllerClipboard<D> {
    pub fn new(native: D) -> Self {
        Self { native }
    }
    pub fn capture_for_remote(&mut self) -> Result<NativeClipboardPayload, NativeClipboardError> {
        let deadline = Instant::now() + Duration::from_millis(CLIPBOARD_OPERATION_MS);
        let guard = self.native.direction_guard(PlatformDirection::Read);
        guard
            .check_until(deadline)
            .map_err(|error| local_error(error, ClipboardWriteEffect::ClipboardWriteNotApplied))?;
        let text = self
            .native
            .read_text()
            .map_err(|error| local_error(error, ClipboardWriteEffect::ClipboardWriteNotApplied))?
            .map(Zeroizing::new)
            .ok_or(NativeClipboardError::Refused {
                code: ClipboardErrorCode::ClipboardUnavailable,
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
            })?;
        NativeClipboardPayload::new(text, Arc::new(PlatformGuard(guard)), deadline)
    }
    pub fn apply_remote(
        &mut self,
        mut text: NativeClipboardText,
    ) -> Result<ClipboardWriteEffect, NativeClipboardError> {
        if self.native.binding().session_id != text.binding.session_id
            || self.native.binding().connection_generation != text.binding.connection_generation
        {
            text.slot.clear();
            return Err(NativeClipboardError::Stale);
        }
        let guard = self.native.direction_guard(PlatformDirection::Write);
        guard
            .check()
            .map_err(|error| local_error(error, ClipboardWriteEffect::ClipboardWriteNotApplied))?;
        let text = text.take_text()?.ok_or(NativeClipboardError::Refused {
            code: ClipboardErrorCode::ClipboardUnavailable,
            effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
        })?;
        guard
            .check()
            .map_err(|error| local_error(error, ClipboardWriteEffect::ClipboardWriteNotApplied))?;
        self.native
            .write_text(&text)
            .map_err(|error| local_error(error, ClipboardWriteEffect::ClipboardWriteUnknown))?;
        guard
            .check()
            .map_err(|error| local_error(error, ClipboardWriteEffect::ClipboardWriteApplied))?;
        Ok(ClipboardWriteEffect::ClipboardWriteApplied)
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.native.close()
    }
}
