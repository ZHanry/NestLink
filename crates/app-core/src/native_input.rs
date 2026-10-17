//! One Input claimant per proved native session. Layout comes from the host's
//! platform adapter; UI messages cannot choose a device, sequence, or lease.
use super::*;
use nestlink_protocol::{
    INPUT_BYTES, InputCommand, KeyInput, NativeInputLayout as WireInputLayout, PointerInput,
    decode_bounded, input_command::Action as WireAction,
};
use nestlink_remote::input::{InputController, InputDevice, InputEpoch, InputLayout};
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

const INPUT_SEND_BUDGET: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInputBinding {
    pub request_id: String,
    pub connection_generation: u64,
    pub source: u32,
    pub input_epoch: u64,
    pub layout_epoch: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInputLayout {
    pub binding: NativeInputBinding,
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum NativeInputAction {
    Key {
        code: u16,
        down: bool,
    },
    Pointer {
        button: Option<u8>,
        down: bool,
        x: i32,
        y: i32,
    },
    Text(String),
}
impl Drop for NativeInputAction {
    fn drop(&mut self) {
        if let Self::Text(text) = self {
            text.zeroize();
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeInputError {
    #[error("no matching proved Input session is authorized")]
    Unauthorized,
    #[error("input does not match the current host layout or capability")]
    Invalid,
    #[error("input delivery failed")]
    Transport,
    #[error("platform input cleanup failed: {0:?}")]
    Cleanup(io::ErrorKind),
}

struct InputCursor {
    layout: Option<NativeInputLayout>,
    sequence: u64,
}
pub(super) struct NativeInputRoute {
    request_id: String,
    connection_generation: u64,
    generation: u64,
    is_host: bool,
    active: AtomicBool,
    input_ready: AtomicBool,
    input_committed: Notify,
    lease: LeaseControl,
    sender: ChannelSender,
    receiver: Mutex<Option<ChannelReceiver>>,
    cursor: Mutex<InputCursor>,
    send_order: AsyncMutex<()>,
    worker: AsyncMutex<Option<JoinHandle<io::Result<()>>>>,
    host_input: Mutex<Option<Arc<dyn HostInputSwitch>>>,
}
trait HostInputSwitch: Send + Sync {
    fn switch(&self, source: u32, layout: InputLayout) -> io::Result<InputEpoch>;
}
impl<D: InputDevice> HostInputSwitch for InputController<D> {
    fn switch(&self, source: u32, layout: InputLayout) -> io::Result<InputEpoch> {
        self.select_source(source, layout).map_err(io::Error::other)
    }
}
impl NativeInputRoute {
    pub(super) fn commit_display_layout(
        &self,
        selection: &DisplaySelection,
        display: &DisplayDescriptor,
    ) -> io::Result<()> {
        self.check().map_err(io::Error::other)?;
        if self.is_host
            || selection.catalog.request_id != self.request_id
            || selection.catalog.connection_generation != self.connection_generation
            || selection.input_epoch == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "display input binding differs",
            ));
        }
        let layout = NativeInputLayout {
            binding: NativeInputBinding {
                request_id: self.request_id.clone(),
                connection_generation: self.connection_generation,
                source: selection.source,
                input_epoch: selection.input_epoch,
                layout_epoch: selection.layout_epoch,
            },
            left: display.left,
            top: display.top,
            width: display.width,
            height: display.height,
        };
        let mut cursor = self
            .cursor
            .lock()
            .map_err(|_| io::Error::other("input cursor poisoned"))?;
        if let Some(current) = &cursor.layout {
            if current == &layout {
                return Ok(());
            }
            if current.binding.input_epoch.checked_add(1) != Some(selection.input_epoch)
                || current.binding.layout_epoch.checked_add(1) != Some(selection.layout_epoch)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "input display epoch skipped or replayed",
                ));
            }
        } else if selection.input_epoch != 1 || selection.layout_epoch != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid first input display epoch",
            ));
        }
        cursor.layout = Some(layout);
        cursor.sequence = 0;
        Ok(())
    }
    pub(super) fn switch_display(
        &self,
        binding: &NativeSessionBinding,
        source: u32,
        layout: InputLayout,
        layout_epoch: u64,
    ) -> io::Result<u64> {
        self.check().map_err(io::Error::other)?;
        if !self.is_host
            || !self.matches_session(binding)
            || !self.input_ready.load(Ordering::Acquire)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "host input owner changed",
            ));
        }
        let result = (|| {
            let mut cursor = self
                .cursor
                .lock()
                .map_err(|_| io::Error::other("input cursor poisoned"))?;
            let current = cursor
                .layout
                .as_ref()
                .ok_or_else(|| io::Error::other("host input layout missing"))?;
            if current.binding.layout_epoch == layout_epoch
                && current.binding.source == source
                && current.left == layout.left
                && current.top == layout.top
                && current.width == layout.width
                && current.height == layout.height
            {
                return Ok(current.binding.input_epoch);
            }
            if current.binding.layout_epoch.checked_add(1) != Some(layout_epoch) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "input layout epoch differs from switch",
                ));
            }
            let owner = self
                .host_input
                .lock()
                .map_err(|_| io::Error::other("host input owner poisoned"))?
                .clone()
                .ok_or_else(|| io::Error::other("host input owner missing"))?;
            let epoch = owner.switch(source, layout)?;
            if epoch.layout != layout_epoch
                || epoch.connection != self.connection_generation
                || current.binding.input_epoch.checked_add(1) != Some(epoch.input)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "platform input epoch differs",
                ));
            }
            cursor.layout = Some(NativeInputLayout {
                binding: NativeInputBinding {
                    request_id: self.request_id.clone(),
                    connection_generation: self.connection_generation,
                    source,
                    input_epoch: epoch.input,
                    layout_epoch,
                },
                left: layout.left,
                top: layout.top,
                width: layout.width,
                height: layout.height,
            });
            cursor.sequence = 0;
            Ok(epoch.input)
        })();
        if result.is_err() {
            self.retire();
            let _ = self.lease.stop(StopReason::PlatformChanged);
        }
        result
    }
    pub(super) fn matches_session(&self, binding: &NativeSessionBinding) -> bool {
        self.request_id == binding.request_id
            && self.connection_generation == binding.connection_generation
    }
    pub(super) fn attach(
        channels: &mut ChannelRuntime,
        key: &NativeSessionKey,
        generation: u64,
    ) -> Result<Arc<Self>, nestlink_remote::RemoteError> {
        let receiver = channels.claim_channel(Channel::Input)?;
        let route = Arc::new(Self {
            request_id: key.request_id.clone(),
            connection_generation: key.connection_generation,
            generation,
            is_host: key.host_view_authorized,
            active: AtomicBool::new(true),
            input_ready: AtomicBool::new(false),
            input_committed: Notify::new(),
            lease: channels.lease_control(),
            sender: channels.sender(),
            receiver: Mutex::new(Some(receiver)),
            cursor: Mutex::new(InputCursor {
                layout: None,
                sequence: 0,
            }),
            send_order: AsyncMutex::new(()),
            worker: AsyncMutex::new(None),
            host_input: Mutex::new(None),
        });
        if !route.is_host {
            let receiver = route
                .receiver
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .ok_or(nestlink_remote::RemoteError::Stopped)?;
            let owned = route.clone();
            let worker = tokio::spawn(async move {
                let result = receive_layout(receiver, &owned).await;
                if result.is_err() {
                    let _ = owned.lease.stop(StopReason::ProtocolViolation);
                }
                result
            });
            *route
                .worker
                .try_lock()
                .map_err(|_| nestlink_remote::RemoteError::Stopped)? = Some(worker);
        }
        Ok(route)
    }
    fn check(&self) -> Result<(), NativeInputError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(NativeInputError::Unauthorized);
        }
        self.lease
            .check_channel_binding(Channel::Input, self.connection_generation)
            .map_err(|_| NativeInputError::Unauthorized)
    }
    fn retire(&self) {
        self.active.store(false, Ordering::Release);
        self.cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .layout = None;
    }
    pub(super) fn has_attached_host_input(&self) -> bool {
        self.is_host && self.input_ready.load(Ordering::Acquire)
    }
    pub(super) fn stop_for_capture_change(&self) {
        self.retire();
        let _ = self.lease.stop(StopReason::PlatformChanged);
    }
    // Called by the session owner after the lease's terminal cleanup report.
    // No blocking platform call is aborted; retain and await its consumer.
    pub(super) async fn shutdown(&self) -> io::Result<()> {
        self.retire();
        let mut owner = self.worker.lock().await;
        if let Some(worker) = owner.as_mut() {
            let result = match tokio::time::timeout(INPUT_SEND_BUDGET, &mut *worker).await {
                Ok(joined) => joined.unwrap_or_else(|error| Err(io::Error::other(error))),
                Err(_) => {
                    let _ = worker.await;
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "input cleanup exceeded budget",
                    ))
                }
            };
            owner.take();
            self.host_input
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            result
        } else {
            // An authorized host may stop before a local Input device opens.
            self.receiver
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            Ok(())
        }
    }
}
impl Shared {
    pub(super) fn set_native_input_route(&self, route: Option<Arc<NativeInputRoute>>) {
        let mut current = self
            .native_input
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(previous) = std::mem::replace(&mut *current, route) {
            previous.retire();
        }
    }
}
impl CoreHandle {
    fn input_route(&self, host: bool) -> Result<Arc<NativeInputRoute>, NativeInputError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(NativeInputError::Unauthorized);
        }
        let snapshot = self.snapshot();
        let session = snapshot
            .native_session
            .data
            .as_ref()
            .filter(|session| session.status == NativeSessionStatus::Connected)
            .ok_or(NativeInputError::Unauthorized)?;
        let route = self
            .shared
            .native_input
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|route| {
                route.is_host == host
                    && route.request_id == session.request_id
                    && route.connection_generation == session.connection_generation
                    && route.generation == snapshot.generation
                    && route.generation == self.shared.generation.load(Ordering::Acquire)
            })
            .cloned()
            .ok_or(NativeInputError::Unauthorized)?;
        route.check()?;
        Ok(route)
    }
    pub fn native_host_input_authorized(&self, binding: &NativeSessionBinding) -> bool {
        self.input_route(true)
            .is_ok_and(|route| route.matches_session(binding))
    }
    /// The exact host Input lease; platform owners subscribe to real accepted
    /// signed permit renewals outside all input/cleanup callbacks.
    pub fn native_host_input_lease(
        &self,
        binding: &NativeSessionBinding,
    ) -> Result<LeaseControl, NativeInputError> {
        let route = self.input_route(true)?;
        if !route.matches_session(binding) {
            return Err(NativeInputError::Unauthorized);
        }
        Ok(route.lease.clone())
    }
    pub fn native_input_layout(&self) -> Result<Option<NativeInputLayout>, NativeInputError> {
        let route = self.input_route(false)?;
        let layout = route
            .cursor
            .lock()
            .map_err(|_| NativeInputError::Transport)?
            .layout
            .clone();
        route.check()?;
        let displays = self
            .shared
            .native_displays
            .lock()
            .map_err(|_| NativeInputError::Transport)?
            .clone();
        if displays.is_some() {
            let binding = NativeSessionBinding {
                request_id: route.request_id.clone(),
                connection_generation: route.connection_generation,
            };
            let selected = self
                .native_displays(&binding)
                .map_err(|_| NativeInputError::Unauthorized)?;
            if selected.pending.is_some() {
                return Ok(None);
            }
            return Ok(layout.filter(|layout| {
                selected.selected.as_ref().is_some_and(|selection| {
                    layout.binding.source == selection.source
                        && layout.binding.input_epoch == selection.input_epoch
                        && layout.binding.layout_epoch == selection.layout_epoch
                })
            }));
        }
        Ok(layout)
    }
    pub async fn send_native_input(
        &self,
        binding: &NativeInputBinding,
        action: NativeInputAction,
    ) -> Result<(), NativeInputError> {
        self.send_input_command(binding, Some(action)).await
    }
    pub async fn release_native_input(
        &self,
        binding: &NativeInputBinding,
    ) -> Result<(), NativeInputError> {
        let session = NativeSessionBinding {
            request_id: binding.request_id.clone(),
            connection_generation: binding.connection_generation,
        };
        if self.native_displays(&session).is_ok_and(|state| {
            state.approved_sources.contains(&binding.source)
                && state.selected.as_ref().is_some_and(|selected| {
                    selected.input_epoch > binding.input_epoch
                        && selected.layout_epoch > binding.layout_epoch
                        && selected.input_epoch - binding.input_epoch
                            == selected.layout_epoch - binding.layout_epoch
                })
        }) {
            // The exact switch ACK proves that the host already released all
            // input from this retired binding. An old IPC owner may finish now.
            return Ok(());
        }
        self.send_input_command(binding, None).await
    }
    async fn send_input_command(
        &self,
        binding: &NativeInputBinding,
        action: Option<NativeInputAction>,
    ) -> Result<(), NativeInputError> {
        let route = self.input_route(false)?;
        if action.is_some()
            && !self
                .native_input_layout()?
                .as_ref()
                .is_some_and(|layout| &layout.binding == binding)
        {
            return Err(NativeInputError::Invalid);
        }
        // Reject invalid UI messages before acquiring cancellation ownership.
        // Only an otherwise valid operation waiting for delivery may stop the
        // lease on cancellation; invalid coordinates must leave it usable.
        let mut command = {
            let cursor = route
                .cursor
                .lock()
                .map_err(|_| NativeInputError::Transport)?;
            let layout = cursor
                .layout
                .as_ref()
                .filter(|layout| &layout.binding == binding)
                .ok_or(NativeInputError::Invalid)?;
            let wire_action = match action.as_ref() {
                Some(NativeInputAction::Key { code, down }) => WireAction::Key(KeyInput {
                    hid_usage: u32::from(*code),
                    down: *down,
                }),
                Some(NativeInputAction::Pointer { button, down, x, y }) => {
                    if i64::from(*x) < i64::from(layout.left)
                        || i64::from(*y) < i64::from(layout.top)
                        || i64::from(*x) >= i64::from(layout.left) + i64::from(layout.width)
                        || i64::from(*y) >= i64::from(layout.top) + i64::from(layout.height)
                    {
                        return Err(NativeInputError::Invalid);
                    }
                    WireAction::Pointer(PointerInput {
                        button: button.map(u32::from),
                        down: *down,
                        x: *x,
                        y: *y,
                    })
                }
                Some(NativeInputAction::Text(text)) if text.len() <= 1800 => {
                    WireAction::Text(text.clone())
                }
                Some(NativeInputAction::Text(_)) => return Err(NativeInputError::Invalid),
                None => WireAction::ReleaseAll(true),
            };
            let command = SensitiveInputCommand(InputCommand {
                schema_version: SCHEMA_VERSION,
                input_epoch: binding.input_epoch,
                layout_epoch: binding.layout_epoch,
                connection_generation: binding.connection_generation,
                // Validate using the largest encoded sequence. The actual
                // sequence is reserved under send_order immediately below.
                sequence: i64::MAX as u64,
                action: Some(wire_action),
            });
            command
                .0
                .validate()
                .map_err(|_| NativeInputError::Invalid)?;
            command
        };
        let mut cancelled = InputAttachGuard {
            route: route.clone(),
            committed: false,
            reason: StopReason::TransportLost,
        };
        let mut stopped = route.lease.subscribe_stopped();
        let _order = tokio::select! { biased;
            _ = stopped.changed() => return Err(NativeInputError::Unauthorized),
            guard = route.send_order.lock() => guard,
        };
        route.check()?;
        {
            let mut cursor = route
                .cursor
                .lock()
                .map_err(|_| NativeInputError::Transport)?;
            if !cursor
                .layout
                .as_ref()
                .is_some_and(|layout| &layout.binding == binding)
            {
                cancelled.committed = true;
                return Err(NativeInputError::Invalid);
            }
            let sequence = cursor
                .sequence
                .checked_add(1)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(NativeInputError::Invalid)?;
            command.0.sequence = sequence;
            cursor.sequence = sequence;
        }
        let bytes = Zeroizing::new(command.0.encode_to_vec());
        drop(command);
        if !Arc::ptr_eq(&route, &self.input_route(false)?) {
            return Err(NativeInputError::Unauthorized);
        }
        let sent =
            tokio::time::timeout(INPUT_SEND_BUDGET, route.sender.send(Channel::Input, &bytes))
                .await;
        if !matches!(sent, Ok(Ok(()))) {
            // Reliable key-up or release-all cannot be silently lost to a full queue.
            let lease = route.lease.clone();
            let _ =
                tokio::task::spawn_blocking(move || lease.stop(StopReason::TransportLost)).await;
            return Err(NativeInputError::Transport);
        }
        route.check()?;
        cancelled.committed = true;
        Ok(())
    }
    /// The caller supplies an already approved platform device and the actual
    /// logical bounds of the same captured source. Core owns it until stop.
    pub fn attach_native_input_device<D: InputDevice>(
        &self,
        binding: &NativeSessionBinding,
        source: u32,
        layout_epoch: u64,
        device: D,
        layout: InputLayout,
    ) -> impl Future<Output = Result<(), NativeInputError>> + Send {
        // Register synchronously, before returning a future: even an unpolled
        // or cancelled attach cannot abandon the already-open platform device.
        let prepared =
            self.prepare_native_input_device(binding, source, layout_epoch, device, layout);
        async move {
            let (route, wire, mut guard) = prepared?;
            let sent = tokio::time::timeout(
                INPUT_SEND_BUDGET,
                route.sender.send(Channel::Input, &wire.encode_to_vec()),
            )
            .await;
            if !matches!(sent, Ok(Ok(()))) {
                return Err(NativeInputError::Transport);
            }
            route.check()?;
            route.input_ready.store(true, Ordering::Release);
            route.input_committed.notify_one();
            guard.committed = true;
            Ok(())
        }
    }
    fn prepare_native_input_device<D: InputDevice>(
        &self,
        binding: &NativeSessionBinding,
        source: u32,
        layout_epoch: u64,
        device: D,
        layout: InputLayout,
    ) -> Result<(Arc<NativeInputRoute>, WireInputLayout, InputAttachGuard), NativeInputError> {
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => return Err(reject_device(device, NativeInputError::Transport)),
        };
        let route = match self.input_route(true) {
            Ok(route) if route.matches_session(binding) => route,
            _ => return Err(reject_device(device, NativeInputError::Unauthorized)),
        };
        let wire = WireInputLayout {
            schema_version: SCHEMA_VERSION,
            connection_generation: binding.connection_generation,
            input_epoch: 1,
            layout_epoch,
            source,
            left: layout.left,
            top: layout.top,
            width: layout.width,
            height: layout.height,
        };
        if wire.validate().is_err() {
            return Err(reject_device(device, NativeInputError::Invalid));
        }
        // The video adapter must have attached/configured this same source.
        let video = self
            .shared
            .native_video_route()
            .ok_or(NativeInputError::Unauthorized);
        let matches_video = video.as_ref().is_ok_and(|video| {
            video.request_id == binding.request_id
                && video.connection_generation == binding.connection_generation
                && video.cursor.lock().is_ok_and(|cursor| {
                    cursor.binding.is_some_and(|binding| {
                        binding.source == source && binding.layout_epoch == layout_epoch
                    })
                })
        });
        if !matches_video {
            return Err(reject_device(device, NativeInputError::Invalid));
        }
        let mut worker_slot = match route.worker.try_lock() {
            Ok(slot) => slot,
            Err(_) => return Err(reject_device(device, NativeInputError::Invalid)),
        };
        let receiver = match route.receiver.lock() {
            Ok(mut slot) => slot.take(),
            Err(_) => return Err(reject_device(device, NativeInputError::Transport)),
        };
        let Some(receiver) = receiver else {
            return Err(reject_device(device, NativeInputError::Invalid));
        };
        // Taking the sole receiver transfers the terminal cleanup duty even
        // if platform selection/registration fails before a worker exists.
        let guard = InputAttachGuard {
            route: route.clone(),
            committed: false,
            reason: StopReason::PlatformChanged,
        };
        let mut device = device;
        if let Err(error) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            device.select_source(source, layout)
        }))
        .unwrap_or_else(|_| Err(io::Error::other("input source selection panicked")))
        {
            return Err(reject_device(
                device,
                NativeInputError::Cleanup(error.kind()),
            ));
        }
        let input = InputController::attach(
            route.lease.clone(),
            device,
            InputEpoch {
                input: 1,
                layout: layout_epoch,
                connection: binding.connection_generation,
            },
            layout,
        )
        .map_err(|error| match error {
            nestlink_remote::RemoteError::Cleanup(error) => NativeInputError::Cleanup(error.kind()),
            _ => NativeInputError::Unauthorized,
        })?;
        let input = Arc::new(input);
        *route
            .host_input
            .lock()
            .map_err(|_| NativeInputError::Transport)? = Some(input.clone());
        route
            .cursor
            .lock()
            .map_err(|_| NativeInputError::Transport)?
            .layout = Some(NativeInputLayout {
            binding: NativeInputBinding {
                request_id: binding.request_id.clone(),
                connection_generation: binding.connection_generation,
                source,
                input_epoch: 1,
                layout_epoch,
            },
            left: layout.left,
            top: layout.top,
            width: layout.width,
            height: layout.height,
        });
        let owned = route.clone();
        *worker_slot = Some(runtime.spawn(async move {
            let result = receive_input(receiver, input, owned.clone()).await;
            if result.is_err() {
                let lease = owned.lease.clone();
                let _ = tokio::task::spawn_blocking(move || lease.stop(StopReason::TransportLost))
                    .await;
            }
            result
        }));
        drop(worker_slot);
        Ok((route.clone(), wire, guard))
    }
}
struct SensitiveInputCommand(InputCommand);
impl Drop for SensitiveInputCommand {
    fn drop(&mut self) {
        if let Some(WireAction::Text(text)) = &mut self.0.action {
            text.zeroize();
        }
    }
}
struct InputAttachGuard {
    route: Arc<NativeInputRoute>,
    committed: bool,
    reason: StopReason,
}
impl Drop for InputAttachGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.route.retire();
            // No injection is enabled until this attach commits. Platform
            // adapters promise bounded synchronous reset; the lease owns and
            // reports that reset before its stop receipt is published.
            let _ = self.route.lease.stop(self.reason);
        }
    }
}
fn reject_device<D: InputDevice>(mut device: D, error: NativeInputError) -> NativeInputError {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| device.reset()))
        .unwrap_or_else(|_| Err(io::Error::other("input cleanup panicked")))
        .err()
        .map_or(error, |error| NativeInputError::Cleanup(error.kind()))
}
async fn receive_layout(mut receiver: ChannelReceiver, route: &NativeInputRoute) -> io::Result<()> {
    let mut stopped = route.lease.subscribe_stopped();
    loop {
        if stopped.borrow().is_some() {
            return Ok(());
        }
        let Some(frame) = native_channel::receive(receiver.receive(), &mut stopped).await? else {
            return Ok(());
        };
        let payload = Zeroizing::new(frame.payload);
        if let Err(error) = route.check() {
            if native_channel::completed_stop(&stopped) {
                return Ok(());
            }
            return Err(io::Error::other(error));
        }
        let layout: WireInputLayout =
            decode_bounded(&payload, INPUT_BYTES).map_err(io::Error::other)?;
        layout.validate().map_err(io::Error::other)?;
        if layout.connection_generation != route.connection_generation {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "input layout changed approved connection or source",
            ));
        }
        let layout = NativeInputLayout {
            binding: NativeInputBinding {
                request_id: route.request_id.clone(),
                connection_generation: layout.connection_generation,
                source: layout.source,
                input_epoch: layout.input_epoch,
                layout_epoch: layout.layout_epoch,
            },
            left: layout.left,
            top: layout.top,
            width: layout.width,
            height: layout.height,
        };
        let mut cursor = route
            .cursor
            .lock()
            .map_err(|_| io::Error::other("input cursor poisoned"))?;
        if let Some(current) = &cursor.layout {
            // Selected control messages own epoch changes. The initial layout
            // stream may arrive late on another reliable QUIC channel.
            if layout.binding.input_epoch < current.binding.input_epoch
                && layout.binding.layout_epoch < current.binding.layout_epoch
                && current.binding.input_epoch - layout.binding.input_epoch
                    == current.binding.layout_epoch - layout.binding.layout_epoch
            {
                continue;
            }
            if current != &layout {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "input layout changed without a new owner",
                ));
            }
        } else {
            cursor.layout = Some(layout);
        }
    }
}
async fn receive_input<D: InputDevice>(
    mut receiver: ChannelReceiver,
    input: Arc<InputController<D>>,
    route: Arc<NativeInputRoute>,
) -> io::Result<()> {
    let mut stopped = route.lease.subscribe_stopped();
    // A fast controller may reply as soon as its layout arrives, before the
    // host's send future resumes. Keep its bounded queue pending until attach
    // commits instead of treating that scheduler race as an invalid message.
    while !route.input_ready.load(Ordering::Acquire) {
        if stopped.borrow().is_some() {
            return Ok(());
        }
        tokio::select! { biased;
            _ = stopped.changed() => return Ok(()),
            _ = route.input_committed.notified() => {},
        }
    }
    loop {
        if stopped.borrow().is_some() {
            return Ok(());
        }
        let Some(frame) = native_channel::receive(receiver.receive(), &mut stopped).await? else {
            return Ok(());
        };
        let input = input.clone();
        let active_route = route.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut frame = frame;
            if !active_route.input_ready.load(Ordering::Acquire) {
                frame.payload.zeroize();
                if native_channel::completed_stop(&active_route.lease.subscribe_stopped()) {
                    return Ok(());
                }
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "input handshake not completed",
                ));
            }
            if let Err(error) = active_route.check() {
                frame.payload.zeroize();
                if native_channel::completed_stop(&active_route.lease.subscribe_stopped()) {
                    return Ok(());
                }
                return Err(io::Error::other(error));
            }
            let result = input
                .apply_frame(&frame)
                .map(|_| ())
                .map_err(io::Error::other);
            frame.payload.zeroize();
            result
        })
        .await
        .map_err(io::Error::other)?;
        if let Err(error) = result {
            let lease = route.lease.clone();
            let _ = tokio::task::spawn_blocking(move || lease.stop(StopReason::ProtocolViolation))
                .await;
            return Err(error);
        }
    }
}
