//! Executable software owners. Historical probe receipts do not enter this API.
use crate::{
    H264EncodingLimits, H264Geometry, H264SpsInfo, H264Validator, VideoCodec, VideoConfig,
    VideoDecoder, VideoEncodeStep, VideoEncoder,
};
use sha2::{Digest, Sha256};
use std::{
    io,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const COMMAND_CAPACITY: usize = 2;
const COMMAND_BUDGET: Duration = Duration::from_millis(500);
const START_BUDGET: Duration = Duration::from_secs(2);
const JOIN_BUDGET: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionDirection {
    Encode,
    Decode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H264ExecutionTarget {
    width: u32,
    height: u32,
    fps: u32,
    kbps: u32,
    sps: H264SpsInfo,
    geometry: H264Geometry,
    digest: [u8; 32],
}
impl H264ExecutionTarget {
    pub fn new(
        config: VideoConfig,
        sps: H264SpsInfo,
        geometry: H264Geometry,
        digest: [u8; 32],
    ) -> io::Result<Self> {
        let width = config
            .width
            .checked_add(config.width & 1)
            .ok_or_else(|| io::Error::other("execution width overflow"))?;
        let height = config
            .height
            .checked_add(config.height & 1)
            .ok_or_else(|| io::Error::other("execution height overflow"))?;
        let limits = H264EncodingLimits {
            max_level_idc: sps.level_idc,
            require_constrained_baseline: sps.constraints & 0x40 != 0,
        };
        limits.validate_config(VideoConfig {
            width,
            height,
            ..config
        })?;
        limits.validate_sps(sps)?;
        if digest == [0; 32]
            || geometry
                .coded_width
                .checked_sub(geometry.crop[0])
                .and_then(|w| w.checked_sub(geometry.crop[1]))
                != Some(width)
            || geometry
                .coded_height
                .checked_sub(geometry.crop[2])
                .and_then(|h| h.checked_sub(geometry.crop[3]))
                != Some(height)
        {
            return Err(io::Error::other(
                "execution target differs from actual signed geometry",
            ));
        }
        Ok(Self {
            width: config.width,
            height: config.height,
            fps: config.fps,
            kbps: config.bitrate_kbps,
            sps,
            geometry,
            digest,
        })
    }
    pub fn config(self) -> VideoConfig {
        VideoConfig {
            width: self.width,
            height: self.height,
            fps: self.fps,
            bitrate_kbps: self.kbps,
        }
    }
    pub fn sps(self) -> H264SpsInfo {
        self.sps
    }
    pub fn geometry(self) -> H264Geometry {
        self.geometry
    }
    pub fn format_digest(self) -> [u8; 32] {
        self.digest
    }
    fn limits(self) -> H264EncodingLimits {
        H264EncodingLimits {
            max_level_idc: self.sps.level_idc,
            require_constrained_baseline: self.sps.constraints & 0x40 != 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionIdentity {
    direction: ExecutionDirection,
    generation: u64,
    resource_id: [u8; 16],
}
impl ExecutionIdentity {
    pub fn direction(self) -> ExecutionDirection {
        self.direction
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
    pub fn resource_id(self) -> [u8; 16] {
        self.resource_id
    }
    pub fn adapter_luid(self) -> Option<u64> {
        None
    }
    pub fn driver_version(self) -> Option<u64> {
        None
    }
    pub fn backend(self) -> &'static str {
        "cpu-software"
    }
}
struct Lifecycle {
    fence: Mutex<()>,
    active: AtomicBool,
    joined: AtomicBool,
    identity: OnceLock<ExecutionIdentity>,
    target: H264ExecutionTarget,
}
impl Lifecycle {
    fn fence(&self) {
        let _guard = self
            .fence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.active.store(false, Ordering::Release);
    }
}
/// The entry guard covers all exits; a second guard declared after the native
/// owner fences before that owner's destructor during unwind.
struct ExitFence(Arc<Lifecycle>);
impl Drop for ExitFence {
    fn drop(&mut self) {
        self.0.fence();
    }
}
fn apply_join_result(slot: &mut Slot, state: &Lifecycle, result: thread::Result<io::Result<()>>) {
    match result {
        Ok(Ok(())) => {
            state.joined.store(true, Ordering::Release);
            slot.occupied = false;
        }
        _ => {
            slot.poisoned = true;
        }
    }
}
impl std::fmt::Debug for Lifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lifecycle")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptKind {
    Registration,
    Encoded {
        pts: u64,
        keyframe: bool,
        digest: [u8; 32],
    },
    Decoded {
        pts: u64,
        digest: [u8; 32],
    },
}
/// Construction is private to the owner worker. Copies share its actual fence.
#[derive(Clone, Debug)]
pub struct ExecutionReceipt {
    state: Arc<Lifecycle>,
    kind: ReceiptKind,
}
impl ExecutionReceipt {
    pub fn identity(&self) -> io::Result<ExecutionIdentity> {
        self.state
            .identity
            .get()
            .copied()
            .ok_or_else(|| io::Error::other("execution is not prepared"))
    }
    pub fn target(&self) -> H264ExecutionTarget {
        self.state.target
    }
    pub fn check_current(&self) -> io::Result<()> {
        if !self.state.active.load(Ordering::Acquire) || self.state.joined.load(Ordering::Acquire) {
            return Err(io::Error::other("execution generation retired"));
        }
        self.identity().map(|_| ())
    }
    pub fn with_current<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        let _guard = self
            .state
            .fence
            .lock()
            .map_err(|_| io::Error::other("execution fence poisoned"))?;
        self.check_current()?;
        operation()
    }
    pub fn is_encoded_output(&self) -> bool {
        matches!(self.kind, ReceiptKind::Encoded { .. })
    }
    pub fn retired_joined(&self) -> bool {
        self.state.joined.load(Ordering::Acquire) && !self.state.active.load(Ordering::Acquire)
    }
    pub fn fence(&self) {
        self.state.fence();
    }
    pub fn check_encoded(&self, pts: u64, keyframe: bool, bytes: &[u8]) -> io::Result<()> {
        self.check_current()?;
        if self.identity()?.direction != ExecutionDirection::Encode
            || self.kind
                != (ReceiptKind::Encoded {
                    pts,
                    keyframe,
                    digest: Sha256::digest(bytes).into(),
                })
        {
            return Err(io::Error::other("AU differs from sealed owner output"));
        }
        Ok(())
    }
    pub fn check_decoded(&self, pts: u64, pixels: &[u8]) -> io::Result<()> {
        self.check_current()?;
        if self.identity()?.direction != ExecutionDirection::Decode
            || self.kind
                != (ReceiptKind::Decoded {
                    pts,
                    digest: Sha256::digest(pixels).into(),
                })
        {
            return Err(io::Error::other("pixels differ from sealed owner output"));
        }
        Ok(())
    }
}
struct Slot {
    generation: u64,
    occupied: bool,
    poisoned: bool,
    quarantine: Option<(JoinHandle<io::Result<()>>, Arc<Lifecycle>)>,
}
fn slot(direction: ExecutionDirection) -> &'static Mutex<Slot> {
    static ENCODE: OnceLock<Mutex<Slot>> = OnceLock::new();
    static DECODE: OnceLock<Mutex<Slot>> = OnceLock::new();
    let selected = match direction {
        ExecutionDirection::Encode => &ENCODE,
        ExecutionDirection::Decode => &DECODE,
    };
    selected.get_or_init(|| {
        Mutex::new(Slot {
            generation: 0,
            occupied: false,
            poisoned: false,
            quarantine: None,
        })
    })
}
fn joined_slot(
    direction: ExecutionDirection,
    state: &Arc<Lifecycle>,
    result: thread::Result<io::Result<()>>,
) {
    if let Ok(mut slot) = slot(direction).lock() {
        apply_join_result(&mut slot, state, result);
    }
}
fn reserve(direction: ExecutionDirection) -> io::Result<u64> {
    // Reap a timed-out actual thread only after it really finished.
    let retired = {
        let mut slot = slot(direction)
            .lock()
            .map_err(|_| io::Error::other("execution slot poisoned"))?;
        if slot
            .quarantine
            .as_ref()
            .is_some_and(|(worker, _)| worker.is_finished())
        {
            slot.quarantine.take()
        } else {
            None
        }
    };
    if let Some((worker, state)) = retired {
        joined_slot(direction, &state, worker.join());
    }
    let mut slot = slot(direction)
        .lock()
        .map_err(|_| io::Error::other("execution slot poisoned"))?;
    if slot.occupied || slot.poisoned {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "execution owner active or quarantined",
        ));
    }
    slot.generation = slot
        .generation
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(|| io::Error::other("execution generation exhausted"))?;
    slot.occupied = true;
    Ok(slot.generation)
}
enum CommandKind {
    Encode(Zeroizing<Vec<u8>>, u64, bool),
    Decode(Zeroizing<Vec<u8>>, u64),
    Drain,
    Reset,
}
struct Command {
    deadline: Instant,
    kind: CommandKind,
    reply: mpsc::SyncSender<io::Result<ExecutionOutput>>,
}
pub enum ExecutionOutput {
    Encoded(VideoEncodeStep, Option<ExecutionReceipt>),
    Decoded(Option<(Vec<u8>, u64, ExecutionReceipt)>),
    Reset,
}
impl ExecutionOutput {
    fn scrub(&mut self) {
        match self {
            Self::Encoded(step, _) => {
                if let Some(packet) = step.output.as_mut() {
                    packet.data.zeroize();
                }
            }
            Self::Decoded(Some((pixels, _, _))) => pixels.zeroize(),
            _ => {}
        }
    }
}
pub struct ExecutionTicket {
    reply: mpsc::Receiver<io::Result<ExecutionOutput>>,
    deadline: Instant,
    state: Arc<Lifecycle>,
    completed: AtomicBool,
}
impl ExecutionTicket {
    fn complete(&self, mut value: io::Result<ExecutionOutput>) -> io::Result<ExecutionOutput> {
        self.completed.store(true, Ordering::Release);
        if Instant::now() >= self.deadline || !self.state.active.load(Ordering::Acquire) {
            if let Ok(output) = &mut value {
                output.scrub();
            }
            self.state.fence();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "execution reply expired or retired",
            ));
        }
        value
    }
    pub fn try_poll(&self) -> io::Result<Option<ExecutionOutput>> {
        if Instant::now() >= self.deadline {
            self.state.fence();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "execution command deadline",
            ));
        }
        match self.reply.try_recv() {
            Ok(value) => self.complete(value).map(Some),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(_) => Err(io::Error::other("execution worker stopped")),
        }
    }
    pub fn wait(self) -> io::Result<ExecutionOutput> {
        let duration = self.deadline.saturating_duration_since(Instant::now());
        match self.reply.recv_timeout(duration) {
            Ok(value) => self.complete(value),
            Err(_) => {
                self.state.fence();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "execution command did not finish",
                ))
            }
        }
    }
}
impl Drop for ExecutionTicket {
    fn drop(&mut self) {
        if !self.completed.load(Ordering::Acquire) {
            self.state.fence();
        }
        while let Ok(mut value) = self.reply.try_recv() {
            if let Ok(output) = &mut value {
                output.scrub();
            }
        }
    }
}
pub struct SoftwareH264Execution {
    direction: ExecutionDirection,
    state: Arc<Lifecycle>,
    commands: Option<mpsc::SyncSender<Command>>,
    worker: Option<JoinHandle<io::Result<()>>>,
}
impl SoftwareH264Execution {
    pub fn start(direction: ExecutionDirection, target: H264ExecutionTarget) -> io::Result<Self> {
        let generation = reserve(direction)?;
        let state = Arc::new(Lifecycle {
            fence: Mutex::new(()),
            active: AtomicBool::new(true),
            joined: AtomicBool::new(false),
            identity: OnceLock::new(),
            target,
        });
        let (send, receive) = mpsc::sync_channel(COMMAND_CAPACITY);
        let (ready, initial) = mpsc::sync_channel(1);
        let owner = state.clone();
        let spawned = thread::Builder::new()
            .name(format!("h264-execution-{direction:?}-{generation}"))
            .spawn(move || run(direction, generation, target, owner, receive, ready));
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
                    "execution preparation deadline",
                ))
            }
        }
    }
    pub fn current(&self) -> io::Result<ExecutionReceipt> {
        let value = ExecutionReceipt {
            state: self.state.clone(),
            kind: ReceiptKind::Registration,
        };
        value.check_current()?;
        Ok(value)
    }
    fn submit(&self, kind: CommandKind) -> io::Result<ExecutionTicket> {
        self.current()?;
        let (reply, receive) = mpsc::sync_channel(1);
        let deadline = Instant::now() + COMMAND_BUDGET;
        let command = Command {
            deadline,
            kind,
            reply,
        };
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("execution stopped"))?
            .try_send(command)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "execution queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::other("execution worker disconnected")
                }
            })?;
        Ok(ExecutionTicket {
            reply: receive,
            deadline,
            state: self.state.clone(),
            completed: AtomicBool::new(false),
        })
    }
    pub fn submit_encode(
        &self,
        pixels: Vec<u8>,
        pts: u64,
        keyframe: bool,
    ) -> io::Result<ExecutionTicket> {
        self.submit(CommandKind::Encode(Zeroizing::new(pixels), pts, keyframe))
    }
    pub fn submit_drain(&self) -> io::Result<ExecutionTicket> {
        self.submit(CommandKind::Drain)
    }
    pub fn submit_decode(&self, bytes: Vec<u8>, pts: u64) -> io::Result<ExecutionTicket> {
        self.submit(CommandKind::Decode(Zeroizing::new(bytes), pts))
    }
    pub fn reset(&self) -> io::Result<()> {
        match self.submit(CommandKind::Reset)?.wait()? {
            ExecutionOutput::Reset => Ok(()),
            _ => Err(io::Error::other("execution reset response differs")),
        }
    }
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.state.fence();
        self.commands.take();
        let Some(worker) = self.worker.take() else {
            return if self.state.joined.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(io::Error::other("execution retirement pending"))
            };
        };
        let deadline = Instant::now() + JOIN_BUDGET;
        while !worker.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        if worker.is_finished() {
            let result = worker.join();
            let success = matches!(&result, Ok(Ok(())));
            joined_slot(self.direction, &self.state, result);
            if success {
                Ok(())
            } else {
                Err(io::Error::other("execution checked close or join failed"))
            }
        } else {
            let mut slot = slot(self.direction)
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slot.quarantine = Some((worker, self.state.clone()));
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "execution owner quarantined until actual join",
            ))
        }
    }
}
impl Drop for SoftwareH264Execution {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

enum Engine {
    Encode(VideoEncoder),
    Decode(VideoDecoder),
}
impl Engine {
    fn new(direction: ExecutionDirection, target: H264ExecutionTarget) -> io::Result<Self> {
        match direction {
            ExecutionDirection::Encode => Ok(Self::Encode(VideoEncoder::new_h264_software(
                target.config(),
                target.limits(),
            )?)),
            ExecutionDirection::Decode => Ok(Self::Decode(VideoDecoder::with_config_software(
                VideoCodec::H264Baseline,
                target.config(),
            )?)),
        }
    }
    fn observation(&self) -> io::Result<[u8; 16]> {
        #[cfg(windows)]
        {
            let owner = match self {
                Self::Encode(value) => value.owner_observation()?,
                Self::Decode(value) => value.owner_observation()?,
            };
            if owner.resource_id == [0; 16]
                || owner.hardware_output
                || owner.adapter_luid.is_some()
                || owner.driver_version.is_some()
            {
                return Err(io::Error::other(
                    "execution software owner has unknown or hardware metadata",
                ));
            }
            Ok(owner.resource_id)
        }
        #[cfg(not(windows))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "software H264 execution unavailable",
            ))
        }
    }
    fn close(self) -> io::Result<()> {
        match self {
            Self::Encode(value) => value.close(),
            Self::Decode(value) => value.close(),
        }
    }
}
fn verify_au(
    validator: &mut H264Validator,
    target: H264ExecutionTarget,
    bytes: &[u8],
    keyframe: bool,
) -> io::Result<()> {
    let unit = validator.validate(bytes)?;
    if unit.keyframe != keyframe
        || validator.sps_info() != Some(target.sps)
        || validator.sps_geometry() != Some(target.geometry)
    {
        return Err(io::Error::other(
            "actual owner AU differs from exact signed target",
        ));
    }
    Ok(())
}
fn run(
    direction: ExecutionDirection,
    generation: u64,
    target: H264ExecutionTarget,
    state: Arc<Lifecycle>,
    commands: mpsc::Receiver<Command>,
    ready: mpsc::SyncSender<io::Result<()>>,
) -> io::Result<()> {
    let _entry_fence = ExitFence(state.clone());
    let mut engine = match Engine::new(direction, target) {
        Ok(engine) => engine,
        Err(error) => {
            state.fence();
            let reason = error.to_string();
            let _ = ready.send(Err(error));
            // A failed constructor does not certify checked native cleanup.
            return Err(io::Error::other(format!(
                "execution startup cleanup unverified: {reason}"
            )));
        }
    };
    let _owner_exit_fence = ExitFence(state.clone());
    let observed = match engine.observation() {
        Ok(observed) => observed,
        Err(error) => {
            state.fence();
            let _ = ready.send(Err(error));
            return engine.close();
        }
    };
    let _ = state.identity.set(ExecutionIdentity {
        direction,
        generation,
        resource_id: observed,
    });
    let config = target.config();
    let width = config.width + (config.width & 1);
    let height = config.height + (config.height & 1);
    let mut validator = match H264Validator::new_sdr(width, height) {
        Ok(value) => value,
        Err(error) => {
            state.fence();
            let _ = ready.send(Err(error));
            return engine.close();
        }
    };
    if !state.active.load(Ordering::Acquire) || ready.send(Ok(())).is_err() {
        state.fence();
        return engine.close();
    }
    while state.active.load(Ordering::Acquire) {
        let command = match commands.recv_timeout(Duration::from_millis(10)) {
            Ok(command) => command,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        let result = (|| {
            if Instant::now() >= command.deadline || !state.active.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "execution command expired before native call",
                ));
            }
            if engine.observation()? != observed {
                return Err(io::Error::other("execution owner changed before operation"));
            }
            let mut result = match (&mut engine, command.kind) {
                (
                    Engine::Encode(encoder),
                    kind @ (CommandKind::Encode(..) | CommandKind::Drain),
                ) => {
                    let mut step = match kind {
                        CommandKind::Encode(pixels, pts, keyframe) => {
                            encoder.encode_step(&pixels, pts, keyframe)?
                        }
                        CommandKind::Drain => encoder.drain_encoded()?,
                        _ => unreachable!(),
                    };
                    let receipt = if let Some(packet) = &mut step.output {
                        if let Err(error) =
                            verify_au(&mut validator, target, &packet.data, packet.keyframe)
                        {
                            packet.data.zeroize();
                            return Err(error);
                        }
                        Some(ExecutionReceipt {
                            state: state.clone(),
                            kind: ReceiptKind::Encoded {
                                pts: packet.pts_90khz,
                                keyframe: packet.keyframe,
                                digest: Sha256::digest(&packet.data).into(),
                            },
                        })
                    } else {
                        None
                    };
                    ExecutionOutput::Encoded(step, receipt)
                }
                (Engine::Decode(decoder), CommandKind::Decode(bytes, pts)) => {
                    // Parsed keyframe flag comes from this exact access unit.
                    let unit = validator.validate(&bytes)?;
                    if validator.sps_info() != Some(target.sps)
                        || validator.sps_geometry() != Some(target.geometry)
                    {
                        return Err(io::Error::other(
                            "decode AU differs from exact signed target",
                        ));
                    }
                    let _ = unit;
                    ExecutionOutput::Decoded(decoder.decode(&bytes, pts)?.map(|(pixels, pts)| {
                        let receipt = ExecutionReceipt {
                            state: state.clone(),
                            kind: ReceiptKind::Decoded {
                                pts,
                                digest: Sha256::digest(&pixels).into(),
                            },
                        };
                        (pixels, pts, receipt)
                    }))
                }
                (Engine::Decode(decoder), CommandKind::Reset) => {
                    if !decoder.reset_for_keyframe()? {
                        return Err(io::Error::other("execution decoder cannot reset"));
                    }
                    validator = H264Validator::new_sdr(width, height)?;
                    ExecutionOutput::Reset
                }
                _ => return Err(io::Error::other("execution direction command differs")),
            };
            if engine.observation().ok() != Some(observed)
                || Instant::now() >= command.deadline
                || !state.active.load(Ordering::Acquire)
            {
                result.scrub();
                return Err(io::Error::other(
                    "execution owner retired or operation deadline expired",
                ));
            }
            Ok(result)
        })();
        let failed = result.is_err();
        if failed {
            state.fence();
        }
        let abandoned = match command.reply.send(result) {
            Ok(()) => false,
            Err(mut error) => {
                if let Ok(output) = &mut error.0 {
                    output.scrub();
                }
                true
            }
        };
        if failed || abandoned {
            state.fence();
            break;
        }
    }
    state.fence();
    engine.close()
}

#[cfg(test)]
mod tests {
    use super::*;
    // These synthetic lifecycle markers test fencing only; they are not native evidence.
    fn lifecycle() -> Arc<Lifecycle> {
        let identity = OnceLock::new();
        let _ = identity.set(ExecutionIdentity {
            direction: ExecutionDirection::Encode,
            generation: 1,
            resource_id: [1; 16],
        });
        Arc::new(Lifecycle {
            fence: Mutex::new(()),
            active: AtomicBool::new(true),
            joined: AtomicBool::new(false),
            identity,
            target: H264ExecutionTarget {
                width: 16,
                height: 16,
                fps: 30,
                kbps: 100,
                sps: H264SpsInfo {
                    profile_idc: 66,
                    constraints: 0xc0,
                    level_idc: 31,
                },
                geometry: H264Geometry {
                    coded_width: 16,
                    coded_height: 16,
                    crop: [0; 4],
                },
                digest: [2; 32],
            },
        })
    }
    #[test]
    fn cancelled_ticket_fences_shared_marker_without_claiming_join() {
        let state = lifecycle();
        let (_send, receive) = mpsc::sync_channel(1);
        drop(ExecutionTicket {
            reply: receive,
            deadline: Instant::now() + COMMAND_BUDGET,
            state: state.clone(),
            completed: AtomicBool::new(false),
        });
        let receipt = ExecutionReceipt {
            state,
            kind: ReceiptKind::Registration,
        };
        assert!(receipt.check_current().is_err());
        assert!(!receipt.retired_joined());
    }
    #[test]
    fn expired_ticket_fences_even_if_reply_already_queued() -> io::Result<()> {
        let state = lifecycle();
        let (send, receive) = mpsc::sync_channel(1);
        send.send(Ok(ExecutionOutput::Reset))
            .map_err(|_| io::Error::other("test reply closed"))?;
        let ticket = ExecutionTicket {
            reply: receive,
            deadline: Instant::now(),
            state: state.clone(),
            completed: AtomicBool::new(false),
        };
        assert!(ticket.try_poll().is_err());
        assert!(!state.active.load(Ordering::Acquire));
        assert!(!state.joined.load(Ordering::Acquire));
        Ok(())
    }
    #[test]
    fn sealed_output_binds_bytes_pts_and_keyframe_and_retirement() -> io::Result<()> {
        let receipt = ExecutionReceipt {
            state: lifecycle(),
            kind: ReceiptKind::Encoded {
                pts: 90,
                keyframe: true,
                digest: Sha256::digest(b"sealed").into(),
            },
        };
        receipt.check_encoded(90, true, b"sealed")?;
        assert!(receipt.check_encoded(91, true, b"sealed").is_err());
        assert!(receipt.check_encoded(90, false, b"sealed").is_err());
        assert!(receipt.check_encoded(90, true, b"altered").is_err());
        receipt.with_current(|| Ok(()))?;
        receipt.fence();
        assert!(receipt.with_current(|| Ok(())).is_err());
        assert!(receipt.check_encoded(90, true, b"sealed").is_err());
        Ok(())
    }
    #[test]
    fn directional_slots_are_distinct() {
        assert!(!std::ptr::eq(
            slot(ExecutionDirection::Encode),
            slot(ExecutionDirection::Decode)
        ));
    }
    #[test]
    fn unverified_startup_failure_poisons_slot_without_join_or_release() {
        let state = lifecycle();
        let mut slot = Slot {
            generation: 1,
            occupied: true,
            poisoned: false,
            quarantine: None,
        };
        apply_join_result(
            &mut slot,
            &state,
            Ok(Err(io::Error::other("startup cleanup unverified"))),
        );
        assert!(slot.occupied);
        assert!(slot.poisoned);
        assert!(!state.joined.load(Ordering::Acquire));
    }
    #[test]
    fn panic_fences_before_owner_cleanup_and_invalidates_shared_receipts() {
        struct CleanupObservation {
            state: Arc<Lifecycle>,
            fenced: Arc<AtomicBool>,
        }
        impl Drop for CleanupObservation {
            fn drop(&mut self) {
                self.fenced.store(
                    !self.state.active.load(Ordering::Acquire),
                    Ordering::Release,
                );
            }
        }
        let state = lifecycle();
        let receipt = ExecutionReceipt {
            state: state.clone(),
            kind: ReceiptKind::Registration,
        };
        let fenced = Arc::new(AtomicBool::new(false));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _entry = ExitFence(state.clone());
            let _owner = CleanupObservation {
                state: state.clone(),
                fenced: fenced.clone(),
            };
            let _owner_exit = ExitFence(state.clone());
            panic!("synthetic owner panic");
        }));
        assert!(result.is_err());
        assert!(fenced.load(Ordering::Acquire));
        assert!(receipt.check_current().is_err());
        assert!(receipt.with_current(|| Ok(())).is_err());
        assert!(!receipt.retired_joined());
    }
    #[test]
    fn normal_worker_exit_also_fences_before_receipt_reuse() {
        let state = lifecycle();
        {
            let _entry = ExitFence(state.clone());
        }
        let receipt = ExecutionReceipt {
            state,
            kind: ReceiptKind::Registration,
        };
        assert!(receipt.with_current(|| Ok(())).is_err());
        assert!(!receipt.retired_joined());
    }
}
