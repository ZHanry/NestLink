//! Live hardware HEVC workers. Closed diagnostic probes cannot create receipts.
#![allow(unsafe_code)]
use crate::{
    ExecutionDirection, HevcDecodedOutput, HevcMain8Contract, HevcOwnerOutput,
    MfHevcHardwareDecoder, MfHevcTextureEncoder, OwnerObservation,
};
use sha2::{Digest, Sha256};
use std::{
    ffi::c_void,
    io,
    ptr::NonNull,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const COMMAND_CAPACITY: usize = 2;
const COMMAND_BUDGET: Duration = Duration::from_millis(500);
const START_BUDGET: Duration = Duration::from_secs(2);
const JOIN_BUDGET: Duration = Duration::from_millis(250);
unsafe extern "C" {
    fn nl_hevc_decoder_device_open(adapter_luid: u64, result: *mut *mut c_void) -> i32;
    fn nl_hevc_decoder_device_borrow(source: *mut c_void, device: *mut *mut c_void) -> i32;
    fn nl_hevc_decoder_device_close(source: *mut c_void) -> i32;
}
fn device_checked(code: i32) -> io::Result<()> {
    if code < 0 {
        Err(io::Error::other(format!(
            "HEVC original decoder device failed ({code:#010x})"
        )))
    } else {
        Ok(())
    }
}
struct DecoderDeviceSource(NonNull<c_void>);
impl DecoderDeviceSource {
    fn open(adapter_luid: u64) -> io::Result<Self> {
        let mut device = std::ptr::null_mut();
        // SAFETY: initialized output, constructed on the actual decode worker.
        device_checked(unsafe { nl_hevc_decoder_device_open(adapter_luid, &mut device) })?;
        Ok(Self(NonNull::new(device).ok_or_else(|| {
            io::Error::other("null HEVC decoder device")
        })?))
    }
}
// SAFETY: this !Send source is constructed, checked, used and closed only by
// the original codec worker. It never exposes a texture or capture operation.
unsafe impl HevcTextureSource for DecoderDeviceSource {
    fn device(&self) -> io::Result<*mut c_void> {
        let mut device = std::ptr::null_mut();
        // SAFETY: same-thread live native owner checks thread and device loss.
        device_checked(unsafe { nl_hevc_decoder_device_borrow(self.0.as_ptr(), &mut device) })?;
        Ok(device)
    }
    fn capture(&mut self, _: bool) -> io::Result<Option<NonNull<c_void>>> {
        Err(io::Error::other("decode-only HEVC owner cannot capture"))
    }
    fn check_current(&self) -> io::Result<()> {
        self.device().map(|_| ())
    }
    fn close(self: Box<Self>) -> io::Result<()> {
        // SAFETY: the MF transform completed checked close before this call.
        device_checked(unsafe { nl_hevc_decoder_device_close(self.0.as_ptr()) })
    }
}

/// The factory runs on the native worker. No COM object, device or texture may
/// be moved from the calling thread into it.
///
/// # Safety
/// Implementors retain a live original ID3D11Device and same-device, exact-size
/// NV12 textures on their creating worker until checked owner shutdown. Borrowed
/// pointers remain valid through the next synchronous codec call. `check_current`
/// must reject changed platform/session/source state, including after capture.
pub unsafe trait HevcTextureSource {
    fn device(&self) -> io::Result<*mut c_void>;
    fn capture(&mut self, repeated: bool) -> io::Result<Option<NonNull<c_void>>>;
    fn check_current(&self) -> io::Result<()>;
    fn close(self: Box<Self>) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HevcExecutionTarget {
    contract: HevcMain8Contract,
    format_sha256: [u8; 32],
    adapter_luid: u64,
    driver_version: u64,
}
impl HevcExecutionTarget {
    /// `contract` comes from actual accepted SPS, never a requested profile.
    /// The caller must separately compare the canonical signed format digest.
    pub fn new(
        contract: HevcMain8Contract,
        format_sha256: [u8; 32],
        adapter_luid: u64,
        driver_version: u64,
    ) -> io::Result<Self> {
        if format_sha256 == [0; 32] {
            return Err(io::Error::other("HEVC signed format digest is absent"));
        }
        Ok(Self {
            contract,
            format_sha256,
            adapter_luid,
            driver_version,
        })
    }
    pub fn contract(self) -> HevcMain8Contract {
        self.contract
    }
    pub fn format_digest(self) -> [u8; 32] {
        self.format_sha256
    }
    pub fn adapter_luid(self) -> u64 {
        self.adapter_luid
    }
    pub fn driver_version(self) -> u64 {
        self.driver_version
    }
    pub(crate) fn check_owner(self, owner: OwnerObservation) -> io::Result<()> {
        if owner.resource_id == [0; 16]
            || owner.adapter_luid != Some(self.adapter_luid)
            || owner.driver_version != Some(self.driver_version)
        {
            return Err(io::Error::other(
                "HEVC execution original adapter/driver differs from frozen direction",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HevcExecutionIdentity {
    direction: ExecutionDirection,
    generation: u64,
    resource_id: [u8; 16],
    adapter_luid: u64,
    driver_version: u64,
}
impl HevcExecutionIdentity {
    pub fn direction(self) -> ExecutionDirection {
        self.direction
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
    pub fn resource_id(self) -> [u8; 16] {
        self.resource_id
    }
    pub fn adapter_luid(self) -> u64 {
        self.adapter_luid
    }
    pub fn driver_version(self) -> u64 {
        self.driver_version
    }
    pub fn backend(self) -> &'static str {
        match self.direction {
            ExecutionDirection::Encode => "gpu-hevc-encoder",
            ExecutionDirection::Decode => "gpu-hevc-decoder",
        }
    }
}
struct State {
    fence: Mutex<()>,
    active: Arc<AtomicBool>,
    authority: Arc<AtomicBool>,
    joined: AtomicBool,
    identity: OnceLock<HevcExecutionIdentity>,
    target: HevcExecutionTarget,
}
impl State {
    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire) && self.authority.load(Ordering::Acquire)
    }
    fn retire(&self) {
        let _guard = self
            .fence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.active.store(false, Ordering::Release);
    }
}
struct ExitFence(Arc<State>);
impl Drop for ExitFence {
    fn drop(&mut self) {
        self.0.retire();
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Registration,
    Encoded { pts: u64, digest: [u8; 32] },
    Decoded { pts: u64, digest: [u8; 32] },
}
/// Only this actual worker seals an output after hardware identity and complete
/// AU admission. Copies share the original generation's revocation/join fence.
#[derive(Clone)]
pub struct HevcExecutionReceipt {
    state: Arc<State>,
    kind: Kind,
}
impl std::fmt::Debug for HevcExecutionReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HevcExecutionReceipt")
            .field("identity", &self.state.identity)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
impl HevcExecutionReceipt {
    pub fn identity(&self) -> io::Result<HevcExecutionIdentity> {
        self.state
            .identity
            .get()
            .copied()
            .ok_or_else(|| io::Error::other("HEVC execution is not prepared"))
    }
    pub fn target(&self) -> HevcExecutionTarget {
        self.state.target
    }
    pub fn check_current(&self) -> io::Result<()> {
        if !self.state.is_active() || self.state.joined.load(Ordering::Acquire) {
            return Err(io::Error::other("HEVC execution generation retired"));
        }
        self.identity().map(|_| ())
    }
    pub fn with_current<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        let _guard = self
            .state
            .fence
            .lock()
            .map_err(|_| io::Error::other("HEVC execution fence poisoned"))?;
        self.check_current()?;
        operation()
    }
    pub fn fence(&self) {
        self.state.retire();
    }
    pub fn retired_joined(&self) -> bool {
        self.state.joined.load(Ordering::Acquire) && !self.state.active.load(Ordering::Acquire)
    }
    pub fn is_encoded_output(&self) -> bool {
        matches!(self.kind, Kind::Encoded { .. })
    }
    pub fn check_encoded(&self, pts: u64, bytes: &[u8]) -> io::Result<()> {
        self.check_current()?;
        if self.identity()?.direction != ExecutionDirection::Encode
            || self.kind
                != (Kind::Encoded {
                    pts,
                    digest: Sha256::digest(bytes).into(),
                })
        {
            return Err(io::Error::other(
                "HEVC AU differs from sealed live owner output",
            ));
        }
        Ok(())
    }
    pub fn check_decoded(&self, pts: u64, pixels: &[u8]) -> io::Result<()> {
        self.check_current()?;
        if self.identity()?.direction != ExecutionDirection::Decode
            || self.kind
                != (Kind::Decoded {
                    pts,
                    digest: Sha256::digest(pixels).into(),
                })
        {
            return Err(io::Error::other(
                "HEVC pixels differ from sealed live owner output",
            ));
        }
        Ok(())
    }
}
#[derive(Default)]
struct Slot {
    generation: u64,
    occupied: bool,
    poisoned: bool,
    quarantine: Option<(JoinHandle<io::Result<()>>, Arc<State>)>,
}
fn slot(direction: ExecutionDirection) -> &'static Mutex<Slot> {
    static ENCODE: OnceLock<Mutex<Slot>> = OnceLock::new();
    static DECODE: OnceLock<Mutex<Slot>> = OnceLock::new();
    match direction {
        ExecutionDirection::Encode => &ENCODE,
        ExecutionDirection::Decode => &DECODE,
    }
    .get_or_init(|| Mutex::new(Slot::default()))
}
fn apply_join(slot: &mut Slot, state: &State, result: thread::Result<io::Result<()>>) -> bool {
    if matches!(result, Ok(Ok(()))) {
        state.joined.store(true, Ordering::Release);
        slot.occupied = false;
        true
    } else {
        slot.poisoned = true;
        false
    }
}
fn reserve(direction: ExecutionDirection) -> io::Result<u64> {
    let mut slot = slot(direction)
        .lock()
        .map_err(|_| io::Error::other("HEVC execution slot poisoned"))?;
    if slot
        .quarantine
        .as_ref()
        .is_some_and(|(worker, _)| worker.is_finished())
        && let Some((worker, state)) = slot.quarantine.take()
    {
        apply_join(&mut slot, &state, worker.join());
    }
    if slot.occupied || slot.poisoned {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "HEVC execution original owner active or quarantined",
        ));
    }
    slot.generation = slot
        .generation
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(|| io::Error::other("HEVC execution generation exhausted"))?;
    slot.occupied = true;
    Ok(slot.generation)
}
enum Operation {
    Capture { pts: u64, repeated: bool },
    Decode(Zeroizing<Vec<u8>>, u64),
    Poll,
    BeginDrain,
}
struct Command {
    deadline: Instant,
    operation: Operation,
    reply: mpsc::SyncSender<io::Result<HevcExecutionOutput>>,
}
pub enum HevcExecutionOutput {
    Encoded {
        accepted: bool,
        output: Option<(HevcOwnerOutput, HevcExecutionReceipt)>,
    },
    Decoded {
        accepted: bool,
        output: Option<(HevcDecodedOutput, HevcExecutionReceipt)>,
    },
    Draining,
}
// Payload containers zeroize even when a timed-out worker fails to return them.
pub struct HevcExecutionTicket {
    reply: mpsc::Receiver<io::Result<HevcExecutionOutput>>,
    deadline: Instant,
    state: Arc<State>,
    completed: bool,
}
impl HevcExecutionTicket {
    pub fn try_poll(&mut self) -> io::Result<Option<HevcExecutionOutput>> {
        if self.completed {
            return Err(io::Error::other("HEVC execution ticket already consumed"));
        }
        if Instant::now() >= self.deadline || !self.state.is_active() {
            self.state.retire();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HEVC execution reply expired or retired",
            ));
        }
        match self.reply.try_recv() {
            Ok(value) => {
                self.completed = true;
                if Instant::now() >= self.deadline || !self.state.is_active() {
                    self.state.retire();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "HEVC execution reply expired after receive",
                    ));
                }
                value.map(Some)
            }
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(_) => {
                self.state.retire();
                Err(io::Error::other("HEVC execution worker stopped"))
            }
        }
    }
}
impl Drop for HevcExecutionTicket {
    fn drop(&mut self) {
        if !self.completed {
            self.state.retire();
        }
    }
}

pub struct HardwareHevcExecution {
    direction: ExecutionDirection,
    state: Arc<State>,
    commands: Option<mpsc::SyncSender<Command>>,
    worker: Option<JoinHandle<io::Result<()>>>,
}
impl HardwareHevcExecution {
    pub fn start_decode(
        target: HevcExecutionTarget,
        authority: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        Self::start(ExecutionDirection::Decode, target, authority, move || {
            Ok(Box::new(DecoderDeviceSource::open(target.adapter_luid())?)
                as Box<dyn HevcTextureSource>)
        })
    }
    /// The source factory must enumerate and open the approved original device
    /// on this new worker. Passing an old closed probe is intentionally impossible.
    pub fn start<F>(
        direction: ExecutionDirection,
        target: HevcExecutionTarget,
        authority: Arc<AtomicBool>,
        factory: F,
    ) -> io::Result<Self>
    where
        F: FnOnce() -> io::Result<Box<dyn HevcTextureSource>> + Send + 'static,
    {
        if !authority.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HEVC original session authority is revoked",
            ));
        }
        let generation = reserve(direction)?;
        let state = Arc::new(State {
            fence: Mutex::new(()),
            active: Arc::new(AtomicBool::new(true)),
            authority,
            joined: AtomicBool::new(false),
            identity: OnceLock::new(),
            target,
        });
        let (send, receive) = mpsc::sync_channel(COMMAND_CAPACITY);
        let (ready, initial) = mpsc::sync_channel(1);
        let owner = state.clone();
        let spawned = thread::Builder::new()
            .name(format!("hevc-execution-{direction:?}-{generation}"))
            .spawn(move || run(direction, generation, owner, factory, receive, ready));
        let worker = match spawned {
            Ok(worker) => worker,
            Err(error) => {
                if let Ok(mut slot) = slot(direction).lock() {
                    slot.occupied = false;
                }
                return Err(error);
            }
        };
        let mut execution = Self {
            direction,
            state,
            commands: Some(send),
            worker: Some(worker),
        };
        match initial.recv_timeout(START_BUDGET) {
            Ok(Ok(())) => Ok(execution),
            Ok(Err(error)) => {
                let _ = execution.shutdown();
                Err(error)
            }
            Err(_) => {
                let _ = execution.shutdown();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HEVC execution preparation deadline",
                ))
            }
        }
    }
    pub fn current(&self) -> io::Result<HevcExecutionReceipt> {
        let value = HevcExecutionReceipt {
            state: self.state.clone(),
            kind: Kind::Registration,
        };
        value.check_current()?;
        Ok(value)
    }
    fn submit(&self, operation: Operation) -> io::Result<HevcExecutionTicket> {
        self.current()?;
        let (reply, receive) = mpsc::sync_channel(1);
        let deadline = Instant::now() + COMMAND_BUDGET;
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("HEVC execution stopped"))?
            .try_send(Command {
                deadline,
                operation,
                reply,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "HEVC execution queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::other("HEVC execution worker disconnected")
                }
            })?;
        Ok(HevcExecutionTicket {
            reply: receive,
            deadline,
            state: self.state.clone(),
            completed: false,
        })
    }
    pub fn submit_capture(&self, pts: u64, repeated: bool) -> io::Result<HevcExecutionTicket> {
        self.submit(Operation::Capture { pts, repeated })
    }
    pub fn submit_decode(&self, bytes: Vec<u8>, pts: u64) -> io::Result<HevcExecutionTicket> {
        self.submit(Operation::Decode(Zeroizing::new(bytes), pts))
    }
    pub fn poll_output(&self) -> io::Result<HevcExecutionTicket> {
        self.submit(Operation::Poll)
    }
    pub fn begin_drain(&self) -> io::Result<HevcExecutionTicket> {
        self.submit(Operation::BeginDrain)
    }
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.state.retire();
        self.commands.take();
        let Some(worker) = self.worker.take() else {
            return if self.state.joined.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(io::Error::other("HEVC execution retirement pending"))
            };
        };
        let deadline = Instant::now() + JOIN_BUDGET;
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let mut slot = slot(self.direction)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if worker.is_finished() {
            if apply_join(&mut slot, &self.state, worker.join()) {
                Ok(())
            } else {
                Err(io::Error::other(
                    "HEVC execution checked close or join failed",
                ))
            }
        } else {
            slot.quarantine = Some((worker, self.state.clone()));
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HEVC execution owner quarantined until actual join",
            ))
        }
    }
}
impl Drop for HardwareHevcExecution {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

enum Engine {
    Encode(MfHevcTextureEncoder),
    Decode(MfHevcHardwareDecoder),
}
impl Engine {
    unsafe fn open(
        direction: ExecutionDirection,
        state: &State,
        device: *mut c_void,
    ) -> io::Result<Self> {
        // SAFETY: source's unsafe contract retains the original worker-thread device.
        unsafe {
            match direction {
                ExecutionDirection::Encode => MfHevcTextureEncoder::with_gpu_device(
                    state.target.contract,
                    device,
                    state.active.clone(),
                )
                .map(Self::Encode),
                ExecutionDirection::Decode => MfHevcHardwareDecoder::with_gpu_device(
                    state.target.contract,
                    device,
                    state.active.clone(),
                )
                .map(Self::Decode),
            }
        }
    }
    fn observation(&self) -> io::Result<OwnerObservation> {
        match self {
            Self::Encode(owner) => owner.owner_observation(),
            Self::Decode(owner) => owner.owner_observation(),
        }
    }
    fn close(self) -> io::Result<()> {
        match self {
            Self::Encode(owner) => owner.close(),
            Self::Decode(owner) => owner.close(),
        }
    }
}
fn encoded(
    state: &Arc<State>,
    original: OwnerObservation,
    accepted: bool,
    packet: Option<HevcOwnerOutput>,
) -> io::Result<HevcExecutionOutput> {
    let output = packet
        .map(|packet| {
            packet.owner.require_hardware_identity()?;
            if !original.same_identity(packet.owner)
                || packet.local_contract_sha256 != state.target.contract.digest()
            {
                return Err(io::Error::other(
                    "HEVC output differs from original execution owner/contract",
                ));
            }
            let receipt = HevcExecutionReceipt {
                state: state.clone(),
                kind: Kind::Encoded {
                    pts: packet.pts_90khz,
                    digest: Sha256::digest(packet.data.as_slice()).into(),
                },
            };
            Ok((packet, receipt))
        })
        .transpose()?;
    Ok(HevcExecutionOutput::Encoded { accepted, output })
}
fn decoded(
    state: &Arc<State>,
    original: OwnerObservation,
    accepted: bool,
    picture: Option<HevcDecodedOutput>,
) -> io::Result<HevcExecutionOutput> {
    let output = picture
        .map(|picture| {
            picture.owner.require_hardware_identity()?;
            if !original.same_identity(picture.owner)
                || picture.local_contract_sha256 != state.target.contract.digest()
            {
                return Err(io::Error::other(
                    "HEVC pixels differ from original execution owner/contract",
                ));
            }
            let receipt = HevcExecutionReceipt {
                state: state.clone(),
                kind: Kind::Decoded {
                    pts: picture.pts_90khz,
                    digest: Sha256::digest(picture.bgra.as_slice()).into(),
                },
            };
            Ok((picture, receipt))
        })
        .transpose()?;
    Ok(HevcExecutionOutput::Decoded { accepted, output })
}
fn run<F>(
    direction: ExecutionDirection,
    generation: u64,
    state: Arc<State>,
    factory: F,
    commands: mpsc::Receiver<Command>,
    ready: mpsc::SyncSender<io::Result<()>>,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<Box<dyn HevcTextureSource>>,
{
    let _entry = ExitFence(state.clone());
    let mut source = match factory() {
        Ok(source) => source,
        Err(error) => {
            let reason = error.to_string();
            let _ = ready.send(Err(error));
            return Err(io::Error::other(format!(
                "HEVC source startup cleanup unverified: {reason}"
            )));
        }
    };
    let mut engine = match source
        .check_current()
        .and_then(|()| source.device())
        .and_then(|device| {
            // SAFETY: the factory created/retains the original source on this worker.
            unsafe { Engine::open(direction, &state, device) }
        }) {
        Ok(engine) => engine,
        Err(error) => {
            let reason = error.to_string();
            let _ = ready.send(Err(error));
            let _ = source.close();
            return Err(io::Error::other(format!(
                "HEVC native startup cleanup unverified: {reason}"
            )));
        }
    };
    let _owner_exit = ExitFence(state.clone());
    let prepared = engine.observation().and_then(|owner| {
        state.target.check_owner(owner)?;
        source.check_current()?;
        Ok(owner)
    });
    let original = match prepared {
        Ok(owner) => owner,
        Err(error) => {
            let _ = ready.send(Err(error));
            state.retire();
            let close = engine.close();
            let source_close = source.close();
            return close.and(source_close);
        }
    };
    let _ = state.identity.set(HevcExecutionIdentity {
        direction,
        generation,
        resource_id: original.resource_id,
        adapter_luid: state.target.adapter_luid,
        driver_version: state.target.driver_version,
    });
    if !state.is_active() || ready.send(Ok(())).is_err() {
        state.retire();
        let close = engine.close();
        let source_close = source.close();
        return close.and(source_close);
    }
    while state.is_active() {
        if source.check_current().is_err() {
            state.retire();
            break;
        }
        let command = match commands.recv_timeout(Duration::from_millis(10)) {
            Ok(command) => command,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        let result = (|| {
            if Instant::now() >= command.deadline || !state.is_active() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HEVC command expired before native call",
                ));
            }
            source.check_current()?;
            if !original.same_identity(engine.observation()?) {
                return Err(io::Error::other("HEVC original resource changed"));
            }
            let output = match (&mut engine, command.operation) {
                (Engine::Encode(owner), Operation::Capture { pts, repeated }) => {
                    if let Some(texture) = source.capture(repeated)? {
                        source.check_current()?;
                        // SAFETY: original source retains its same-device exact NV12 texture until this call ends.
                        let (accepted, packet) =
                            unsafe { owner.submit_texture(texture.as_ptr(), pts) }?;
                        encoded(&state, original, accepted, packet)?
                    } else {
                        encoded(&state, original, false, owner.poll()?)?
                    }
                }
                (Engine::Encode(owner), Operation::Poll) => {
                    encoded(&state, original, false, owner.poll()?)?
                }
                (Engine::Decode(owner), Operation::Decode(bytes, pts)) => {
                    let (accepted, picture) = owner.submit(&bytes, pts)?;
                    decoded(&state, original, accepted, picture)?
                }
                (Engine::Decode(owner), Operation::Poll) => {
                    decoded(&state, original, false, owner.poll()?)?
                }
                (Engine::Encode(owner), Operation::BeginDrain) => {
                    owner.begin_drain()?;
                    HevcExecutionOutput::Draining
                }
                (Engine::Decode(owner), Operation::BeginDrain) => {
                    owner.begin_drain()?;
                    HevcExecutionOutput::Draining
                }
                _ => {
                    return Err(io::Error::other(
                        "HEVC execution operation has wrong direction",
                    ));
                }
            };
            source.check_current()?;
            if !original.same_identity(engine.observation()?)
                || Instant::now() >= command.deadline
                || !state.is_active()
            {
                return Err(io::Error::other(
                    "HEVC owner retired during native operation",
                ));
            }
            Ok(output)
        })();
        let failed = result.is_err();
        if failed {
            state.retire();
        }
        if command.reply.send(result).is_err() || failed {
            state.retire();
            break;
        }
    }
    state.retire();
    // Both native owners are destroyed on this exact original thread, even if
    // the first checked shutdown fails. The failed generation remains poisoned.
    let close = engine.close();
    let source_close = source.close();
    close.and(source_close)
}

#[cfg(test)]
mod tests {
    use super::*;
    // These are lifecycle/byte-binding fixtures. They do not open a codec or
    // constitute hardware, capture, GPU cadence or platform acceptance evidence.
    fn lifecycle_fixture(direction: ExecutionDirection) -> io::Result<Arc<State>> {
        let target =
            HevcExecutionTarget::new(crate::hevc_probe::tests::main8_fixture()?, [9; 32], 7, 8)?;
        let identity = OnceLock::new();
        let _ = identity.set(HevcExecutionIdentity {
            direction,
            generation: 3,
            resource_id: [1; 16],
            adapter_luid: 7,
            driver_version: 8,
        });
        Ok(Arc::new(State {
            fence: Mutex::new(()),
            active: Arc::new(AtomicBool::new(true)),
            authority: Arc::new(AtomicBool::new(true)),
            joined: AtomicBool::new(false),
            identity,
            target,
        }))
    }
    #[test]
    fn registration_is_not_output_and_exact_bytes_pts_direction_are_sealed() -> io::Result<()> {
        let state = lifecycle_fixture(ExecutionDirection::Encode)?;
        let data = b"actual output binding fixture";
        let mut receipt = HevcExecutionReceipt {
            state: state.clone(),
            kind: Kind::Registration,
        };
        assert!(receipt.check_encoded(10, data).is_err());
        receipt.kind = Kind::Encoded {
            pts: 10,
            digest: Sha256::digest(data).into(),
        };
        receipt.check_encoded(10, data)?;
        assert!(receipt.check_encoded(11, data).is_err());
        assert!(receipt.check_encoded(10, b"changed bytes").is_err());
        assert!(receipt.check_decoded(10, data).is_err());
        let copy = receipt.clone();
        state.authority.store(false, Ordering::Release);
        assert!(copy.check_encoded(10, data).is_err());
        assert!(receipt.check_current().is_err());
        assert!(!receipt.retired_joined());
        Ok(())
    }
    #[test]
    fn abandoned_and_late_command_fence_the_original_generation() -> io::Result<()> {
        for late in [false, true] {
            let state = lifecycle_fixture(ExecutionDirection::Decode)?;
            let receipt = HevcExecutionReceipt {
                state: state.clone(),
                kind: Kind::Registration,
            };
            let (_send, receive) = mpsc::sync_channel(1);
            let mut ticket = HevcExecutionTicket {
                reply: receive,
                deadline: if late {
                    Instant::now()
                } else {
                    Instant::now() + COMMAND_BUDGET
                },
                state,
                completed: false,
            };
            if late {
                assert!(ticket.try_poll().is_err());
            }
            drop(ticket);
            assert!(receipt.check_current().is_err());
            assert!(!receipt.retired_joined());
        }
        Ok(())
    }
    #[test]
    fn checked_native_close_failure_poisoned_slot_never_becomes_joined() -> io::Result<()> {
        let state = lifecycle_fixture(ExecutionDirection::Decode)?;
        state.retire();
        let receipt = HevcExecutionReceipt {
            state: state.clone(),
            kind: Kind::Registration,
        };
        let mut slot = Slot {
            occupied: true,
            ..Slot::default()
        };
        let worker = thread::spawn(|| Err(io::Error::other("native checked close failure")));
        assert!(!apply_join(&mut slot, &state, worker.join()));
        assert!(slot.occupied && slot.poisoned);
        assert!(!receipt.retired_joined());
        let state = lifecycle_fixture(ExecutionDirection::Encode)?;
        state.retire();
        let worker = thread::spawn(|| Ok(()));
        let mut slot = Slot {
            occupied: true,
            ..Slot::default()
        };
        assert!(apply_join(&mut slot, &state, worker.join()));
        assert!(!slot.occupied && !slot.poisoned);
        assert!(state.joined.load(Ordering::Acquire));
        Ok(())
    }
    #[test]
    fn revoked_start_never_constructs_a_native_source() -> io::Result<()> {
        let target = lifecycle_fixture(ExecutionDirection::Encode)?.target;
        let called = Arc::new(AtomicBool::new(false));
        let witness = called.clone();
        let result = HardwareHevcExecution::start(
            ExecutionDirection::Encode,
            target,
            Arc::new(AtomicBool::new(false)),
            move || {
                witness.store(true, Ordering::Release);
                Err(io::Error::other("must not open"))
            },
        );
        assert!(result.is_err());
        assert!(!called.load(Ordering::Acquire));
        Ok(())
    }
}
