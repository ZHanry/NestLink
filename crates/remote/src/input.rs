//! Epoch-bound input state. OS adapters implement only bounded synchronous
//! injection; this layer owns pressed buttons, replay checks and revocation.
use crate::{LeaseControl, RemoteError, StopHandler};
use nestlink_protocol::{
    INPUT_BYTES, InputCommand, KeyInput, Permission, PointerInput, SCHEMA_VERSION, ScrollInput,
    decode_bounded, input_command::Action,
};
use nestlink_session::{StopEffects, StopReason};
use nestlink_transport_stream::{Channel, Frame};
use prost::Message;
use std::{
    collections::BTreeSet,
    io,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Button {
    Key(u16),
    Pointer(u8),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEpoch {
    pub input: u64,
    pub layout: u64,
    pub connection: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputLayout {
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
}
impl InputLayout {
    fn valid(self) -> bool {
        self.width > 0
            && self.height > 0
            && self.width <= 32768
            && self.height <= 32768
            && self.left.checked_add_unsigned(self.width).is_some()
            && self.top.checked_add_unsigned(self.height).is_some()
    }
    fn contains(self, x: i32, y: i32) -> bool {
        i64::from(x) >= i64::from(self.left)
            && i64::from(x) < i64::from(self.left) + i64::from(self.width)
            && i64::from(y) >= i64::from(self.top)
            && i64::from(y) < i64::from(self.top) + i64::from(self.height)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputAction {
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
    Scroll {
        x: i32,
        y: i32,
    },
    Text(String),
}
/// Reliable button messages always include their matching layout coordinates.
pub struct InputEvent {
    pub epoch: InputEpoch,
    pub sequence: u64,
    pub action: InputAction,
}
impl InputEvent {
    pub fn encode(&self) -> Result<Vec<u8>, RemoteError> {
        if matches!(&self.action, InputAction::Text(text) if text.len() > INPUT_BYTES as usize) {
            return Err(nestlink_protocol::ContractError::new(
                nestlink_protocol::ErrorCode::CapacityExceeded,
                "input text exceeds budget",
            )
            .into());
        }
        let action = match &self.action {
            InputAction::Key { code, down } => Action::Key(KeyInput {
                hid_usage: u32::from(*code),
                down: *down,
            }),
            InputAction::Pointer { button, down, x, y } => Action::Pointer(PointerInput {
                button: button.map(u32::from),
                down: *down,
                x: *x,
                y: *y,
            }),
            InputAction::Scroll { x, y } => Action::Scroll(ScrollInput { x: *x, y: *y }),
            InputAction::Text(text) => Action::Text(text.clone()),
        };
        let command = InputCommand {
            schema_version: SCHEMA_VERSION,
            input_epoch: self.epoch.input,
            layout_epoch: self.epoch.layout,
            connection_generation: self.epoch.connection,
            sequence: self.sequence,
            action: Some(action),
        };
        command.validate()?;
        Ok(command.encode_to_vec())
    }
}
pub enum PlatformInput<'a> {
    Action(&'a InputAction),
    Release(Button),
}
/// Never reenter the lease or block_on the caller's async runtime. Adapters
/// requiring async system IPC use a separately owned worker and a finite IPC
/// deadline; all effects and their cleanup remain serialized by this boundary.
pub trait InputDevice: Send + 'static {
    /// Check layout, lock/permission and device facts with a bounded OS call.
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    /// Release adapter-owned transient state (Unicode packets or temporary
    /// mappings) in addition to the buttons tracked by InputController.
    fn reset(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn begin_reset(&mut self) -> io::Result<()> {
        Ok(())
    }
    /// Nonterminal switch inside the existing locally approved source set.
    /// The controller releases all held input first. Portal adapters must
    /// select the exact granted node here, retaining the original OS grant.
    fn select_source(&mut self, _source: u32, _layout: InputLayout) -> io::Result<()> {
        self.check()
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()>;
}
struct State<D: InputDevice> {
    device: D,
    epoch: InputEpoch,
    layout: InputLayout,
    held: BTreeSet<Button>,
    sequence: u64,
    last_action: Option<LastAction>,
    retired_from: Option<InputEpoch>,
    cleanup_complete: bool,
}
#[derive(Clone, PartialEq, Eq)]
enum LastAction {
    Event(InputAction),
    ReleaseAll,
}
impl<D: InputDevice> State<D> {
    fn retired_epoch(&self, epoch: InputEpoch) -> bool {
        self.retired_from.is_some_and(|first| {
            epoch.connection == self.epoch.connection
                && epoch.input >= first.input
                && epoch.layout >= first.layout
                && epoch.input < self.epoch.input
                && epoch.layout < self.epoch.layout
                && self.epoch.input - epoch.input == self.epoch.layout - epoch.layout
        })
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.device.inject(input)))
            .map_err(|_| io::Error::other("platform input adapter panicked"))?
    }
    fn release(&mut self) -> io::Result<()> {
        // The stop handler owns the terminal cleanup receipt. Dropping the
        // final state is a fallback for interrupted/failed cleanup, not a
        // second reset of an already joined platform input owner.
        if self.cleanup_complete {
            return Ok(());
        }
        let mut first_error =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.device.begin_reset()))
                .unwrap_or_else(|_| {
                    Err(io::Error::other("platform cleanup initialization panicked"))
                })
                .err();
        if let Some(error) = self.release_held()
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        let reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.device.reset()))
            .unwrap_or_else(|_| Err(io::Error::other("platform reset panicked")));
        if first_error.is_none() {
            first_error = reset.err();
        }
        self.last_action = None;
        self.cleanup_complete = first_error.is_none();
        first_error.map_or(Ok(()), Err)
    }
    fn release_held(&mut self) -> Option<io::Error> {
        let mut first_error = None;
        for button in self.held.iter().copied().collect::<Vec<_>>() {
            match self.inject(PlatformInput::Release(button)) {
                Ok(()) => {
                    self.held.remove(&button);
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        self.last_action = None;
        first_error
    }
    fn apply(&mut self, event: &InputEvent) -> io::Result<bool> {
        // Reliable frames queued before an acknowledged switch cannot inject
        // into the new source. Future/mixed/foreign epochs still fail closed.
        if self.retired_epoch(event.epoch) {
            return Ok(false);
        }
        if event.epoch != self.epoch || event.sequence == 0 || event.sequence > i64::MAX as u64 {
            return Err(rejected("stale input epoch or sequence"));
        }
        if event.sequence <= self.sequence {
            return if event.sequence == self.sequence
                && self.last_action.as_ref() == Some(&LastAction::Event(event.action.clone()))
            {
                Ok(false)
            } else {
                Err(rejected("input replay rejected"))
            };
        }
        let button = match &event.action {
            InputAction::Scroll { x, y } if nestlink_protocol::valid_scroll(*x, *y) => None,
            InputAction::Key { code, down } if (4..=0xe7).contains(code) => {
                Some((Button::Key(*code), *down))
            }
            InputAction::Pointer { button, down, x, y }
                if self.layout.contains(*x, *y)
                    && (button.is_some() || !down)
                    && button.is_none_or(|b| (1..=5).contains(&b)) =>
            {
                button.map(|b| (Button::Pointer(b), *down))
            }
            InputAction::Text(text)
                if !text.is_empty()
                    && text.len() <= INPUT_BYTES as usize
                    && !text
                        .chars()
                        .any(|c| c.is_control() && c != '\n' && c != '\t') =>
            {
                None
            }
            _ => return Err(rejected("input outside declared capability or layout")),
        };
        if let Some((button, true)) = button {
            // Track before injection: an OS call may fail after a partial effect.
            self.held.insert(button);
        }
        self.inject(PlatformInput::Action(&event.action))
            .map_err(io::Error::other)?;
        if let Some((button, false)) = button {
            self.held.remove(&button);
        }
        self.sequence = event.sequence;
        self.last_action = Some(LastAction::Event(event.action.clone()));
        Ok(true)
    }
    fn release_sequenced(&mut self, epoch: InputEpoch, sequence: u64) -> io::Result<bool> {
        if self.retired_epoch(epoch) {
            return Ok(false);
        }
        if epoch != self.epoch || sequence == 0 || sequence > i64::MAX as u64 {
            return Err(rejected("stale input release epoch or sequence"));
        }
        if sequence <= self.sequence {
            return if sequence == self.sequence && self.last_action == Some(LastAction::ReleaseAll)
            {
                Ok(false)
            } else {
                Err(rejected("input release replay rejected"))
            };
        }
        self.release_held().map_or(Ok(()), Err)?;
        self.sequence = sequence;
        self.last_action = Some(LastAction::ReleaseAll);
        Ok(true)
    }
}
impl<D: InputDevice> Drop for State<D> {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
struct Cleanup<D: InputDevice>(Arc<Mutex<State<D>>>);
impl<D: InputDevice> StopHandler for Cleanup<D> {
    fn check(&mut self) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("input state poisoned"))?;
        // Catch while the guard is alive: a platform panic must not poison the
        // state mutex and prevent the same owned buttons from being released.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.device.check()))
            .unwrap_or_else(|_| Err(io::Error::other("platform fact check panicked")))
    }
    fn stop(&mut self, _: StopReason, effects: StopEffects) -> io::Result<()> {
        if effects.release_inputs {
            self.0
                .lock()
                .map_err(|_| io::Error::other("input state poisoned"))?
                .release()?;
        }
        Ok(())
    }
}
pub struct InputController<D: InputDevice> {
    lease: LeaseControl,
    shared: Arc<Mutex<State<D>>>,
}
impl<D: InputDevice> InputController<D> {
    pub fn apply_frame(&self, frame: &Frame) -> Result<bool, RemoteError> {
        if frame.channel != Channel::Input {
            return Err(rejected("expected authorized input channel").into());
        }
        let command: InputCommand = decode_bounded(&frame.payload, INPUT_BYTES)?;
        command.validate()?;
        if command.action == Some(Action::ReleaseAll(true)) {
            return self.release_all_sequenced(
                InputEpoch {
                    input: command.input_epoch,
                    layout: command.layout_epoch,
                    connection: command.connection_generation,
                },
                command.sequence,
            );
        }
        let action = match command
            .action
            .ok_or_else(|| rejected("missing input action"))?
        {
            Action::Key(key) => InputAction::Key {
                code: u16::try_from(key.hid_usage).map_err(|_| rejected("invalid key usage"))?,
                down: key.down,
            },
            Action::Pointer(pointer) => InputAction::Pointer {
                button: pointer
                    .button
                    .map(u8::try_from)
                    .transpose()
                    .map_err(|_| rejected("invalid pointer button"))?,
                down: pointer.down,
                x: pointer.x,
                y: pointer.y,
            },
            Action::Scroll(s) => InputAction::Scroll { x: s.x, y: s.y },
            Action::Text(text) => InputAction::Text(text),
            Action::ReleaseAll(_) => return Err(rejected("invalid input release command").into()),
        };
        self.apply(&InputEvent {
            epoch: InputEpoch {
                input: command.input_epoch,
                layout: command.layout_epoch,
                connection: command.connection_generation,
            },
            sequence: command.sequence,
            action,
        })
    }
    pub fn attach(
        lease: LeaseControl,
        mut device: D,
        epoch: InputEpoch,
        layout: InputLayout,
    ) -> Result<Self, RemoteError> {
        if !layout.valid()
            || [epoch.input, epoch.layout, epoch.connection]
                .iter()
                .any(|v| *v == 0 || *v > i64::MAX as u64)
        {
            let reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| device.reset()))
                .unwrap_or_else(|_| Err(io::Error::other("input cleanup panicked")));
            return Err(reset.err().map_or_else(
                || RemoteError::from(rejected("invalid input layout or epoch")),
                RemoteError::Cleanup,
            ));
        }
        let shared = Arc::new(Mutex::new(State {
            device,
            epoch,
            layout,
            held: BTreeSet::new(),
            sequence: 0,
            last_action: None,
            retired_from: None,
            cleanup_complete: false,
        }));
        if let Err(error) = lease.attach_input(epoch.connection, Box::new(Cleanup(shared.clone())))
        {
            let reset = shared
                .lock()
                .map_err(|_| io::Error::other("input cleanup state poisoned"))
                .and_then(|mut state| state.release());
            return Err(reset.err().map_or(error, RemoteError::Cleanup));
        }
        Ok(Self { lease, shared })
    }
    /// Returns false for an identical latest event or an actually retired
    /// epoch. Future/mixed epochs and sequence collisions with changed text fail.
    pub fn apply(&self, event: &InputEvent) -> Result<bool, RemoteError> {
        self.apply_limited(event, None)
    }
    /// Narrow an input frame to its retained original permit deadlines. Current
    /// lease authorization, epochs and replay state are still checked normally.
    /// The extra limits are checked after all managed/platform lock waits.
    pub fn apply_with_deadline(
        &self,
        event: &InputEvent,
        deadline: Instant,
        expires_at_unix_ms: u64,
    ) -> Result<bool, RemoteError> {
        self.apply_limited(event, Some((deadline, expires_at_unix_ms)))
    }
    fn apply_limited(
        &self,
        event: &InputEvent,
        deadline: Option<(Instant, u64)>,
    ) -> Result<bool, RemoteError> {
        let result = self.lease.operation(Permission::Input, || {
            let mut state = self
                .shared
                .lock()
                .map_err(|_| io::Error::other("input state poisoned"))?;
            check_input_deadline(deadline)?;
            state.apply(event)
        });
        if matches!(&result, Err(RemoteError::Io(error)) if error.kind() != io::ErrorKind::PermissionDenied)
        {
            self.lease.stop(StopReason::Revoked)?;
        }
        result
    }
    /// Release currently held keys and buttons without ending the platform
    /// adapter. Browser focus loss uses this before the next authorized action.
    pub fn release_all(&self, epoch: InputEpoch) -> Result<(), RemoteError> {
        self.release_all_limited(epoch, None)
    }
    /// The release envelope also keeps its original permit horizons across
    /// renewal and lock waits. Rejection retains the normal stop/cleanup path.
    pub fn release_all_with_deadline(
        &self,
        epoch: InputEpoch,
        deadline: Instant,
        expires_at_unix_ms: u64,
    ) -> Result<(), RemoteError> {
        self.release_all_limited(epoch, Some((deadline, expires_at_unix_ms)))
    }
    fn release_all_limited(
        &self,
        epoch: InputEpoch,
        deadline: Option<(Instant, u64)>,
    ) -> Result<(), RemoteError> {
        let result = self.lease.operation(Permission::Input, || {
            let mut state = self
                .shared
                .lock()
                .map_err(|_| io::Error::other("input state poisoned"))?;
            check_input_deadline(deadline)?;
            if state.epoch != epoch {
                return Err(rejected("stale input release epoch"));
            }
            state.release_held().map_or(Ok(()), Err)
        });
        if result.is_err() {
            self.lease.stop(StopReason::Revoked)?;
        }
        result
    }
    pub fn release_all_sequenced(
        &self,
        epoch: InputEpoch,
        sequence: u64,
    ) -> Result<bool, RemoteError> {
        let result = self.lease.operation(Permission::Input, || {
            self.shared
                .lock()
                .map_err(|_| io::Error::other("input state poisoned"))?
                .release_sequenced(epoch, sequence)
        });
        if result.is_err() {
            self.lease.stop(StopReason::Revoked)?;
        }
        result
    }
    /// A local display/control handoff releases held buttons before advancing
    /// epochs. A changed connection always requires a new authorized runtime.
    pub fn change_layout(&self, layout: InputLayout) -> Result<InputEpoch, RemoteError> {
        self.change_source(None, layout)
    }
    pub fn select_source(
        &self,
        source: u32,
        layout: InputLayout,
    ) -> Result<InputEpoch, RemoteError> {
        self.change_source(Some(source), layout)
    }
    fn change_source(
        &self,
        source: Option<u32>,
        layout: InputLayout,
    ) -> Result<InputEpoch, RemoteError> {
        if !layout.valid() {
            return Err(rejected("invalid input layout").into());
        }
        let result = self.lease.operation(Permission::Input, || {
            let mut state = self
                .shared
                .lock()
                .map_err(|_| io::Error::other("input state poisoned"))?;
            state.release_held().map_or(Ok(()), Err)?;
            state.device.check()?;
            if let Some(source) = source {
                state.device.select_source(source, layout)?;
            }
            let input = state
                .epoch
                .input
                .checked_add(1)
                .filter(|v| *v <= i64::MAX as u64)
                .ok_or_else(|| io::Error::other("input epoch exhausted"))?;
            let epoch = state
                .epoch
                .layout
                .checked_add(1)
                .filter(|v| *v <= i64::MAX as u64)
                .ok_or_else(|| io::Error::other("layout epoch exhausted"))?;
            if state.retired_from.is_none() {
                state.retired_from = Some(state.epoch);
            }
            state.epoch.input = input;
            state.epoch.layout = epoch;
            state.layout = layout;
            state.sequence = 0;
            state.last_action = None;
            Ok(state.epoch)
        });
        if result.is_err() {
            self.lease.stop(StopReason::Revoked)?;
        }
        result
    }
}
impl<D: InputDevice> Drop for InputController<D> {
    fn drop(&mut self) {
        let _ = self.lease.stop_if_running(StopReason::ExplicitExit);
    }
}
fn rejected(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

fn check_input_deadline(deadline: Option<(Instant, u64)>) -> io::Result<()> {
    let Some((deadline, expires_at_unix_ms)) = deadline else {
        return Ok(());
    };
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .ok_or_else(|| rejected("input permit clock is invalid"))?;
    if Instant::now() >= deadline || unix_ms >= expires_at_unix_ms {
        return Err(rejected("input permit original deadline expired"));
    }
    Ok(())
}
