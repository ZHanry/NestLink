//! One thread owns capture, conversion and MF. Only bounded commands/bytes leave it.
#![allow(unsafe_code)]
use super::*;
use nestlink_media_codec::{
    H264EncoderProbe, H264EncodingLimits, H264SpsInfo, MfH264Decoder, MfH264Encoder, VideoConfig,
    VideoEncoder,
};
use nestlink_remote::video::{HostEncodeStep, HostFrame, HostPacket, HostVideoConfig};
use std::{
    collections::{BTreeMap, VecDeque},
    ffi::c_void,
    marker::PhantomData,
    ptr::NonNull,
    rc::Rc,
};

unsafe extern "C" {
    fn nl_capture_gpu_open(
        monitor: usize,
        width: u32,
        height: u32,
        fps: u32,
        result: *mut *mut c_void,
    ) -> i32;
    fn nl_capture_gpu_synthetic_open(
        width: u32,
        height: u32,
        fps: u32,
        result: *mut *mut c_void,
    ) -> i32;
    fn nl_capture_gpu_device(state: *mut c_void, device: *mut *mut c_void, luid: *mut u64) -> i32;
    fn nl_capture_gpu_frame(state: *mut c_void, repeated: u32, texture: *mut *mut c_void) -> i32;
    fn nl_capture_gpu_probe(
        state: *mut c_void,
        pixels: *const u8,
        length: usize,
        texture: *mut *mut c_void,
    ) -> i32;
    fn nl_capture_gpu_discard(state: *mut c_void);
    fn nl_capture_gpu_close(state: *mut c_void);
}
struct GpuCapture {
    handle: NonNull<c_void>,
    _owner: PhantomData<Rc<()>>,
}
impl Drop for GpuCapture {
    fn drop(&mut self) {
        // SAFETY: owned handle is !Send and dropped on its creating worker.
        unsafe { nl_capture_gpu_close(self.handle.as_ptr()) };
    }
}
fn bridge(stage: &str, code: i32) -> io::Error {
    io::Error::other(format!("GPU {stage} failed ({code:#010x})"))
}
impl GpuCapture {
    fn open(monitor: &Monitor, config: HostVideoConfig) -> io::Result<Self> {
        let mut handle = null_mut();
        // SAFETY: exact enumerated approved HMONITOR, bounded config, out pointer.
        let hr = unsafe {
            nl_capture_gpu_open(
                monitor.handle,
                config.width,
                config.height,
                config.fps,
                &mut handle,
            )
        };
        if hr < 0 {
            return Err(bridge("open", hr));
        }
        Ok(Self {
            handle: NonNull::new(handle).ok_or_else(|| bridge("null capture", hr))?,
            _owner: PhantomData,
        })
    }
    fn synthetic(config: VideoConfig) -> io::Result<Self> {
        let mut handle = null_mut();
        // SAFETY: bounded synthetic-only factory creates no desktop source.
        let hr = unsafe {
            nl_capture_gpu_synthetic_open(config.width, config.height, config.fps, &mut handle)
        };
        if hr < 0 {
            return Err(bridge("synthetic device", hr));
        }
        Ok(Self {
            handle: NonNull::new(handle).ok_or_else(|| bridge("null synthetic device", hr))?,
            _owner: PhantomData,
        })
    }
    fn device(&self) -> io::Result<*mut c_void> {
        let mut device = null_mut();
        let mut luid = 0;
        // SAFETY: owner-local borrowed device; never sent through a command.
        let hr = unsafe { nl_capture_gpu_device(self.handle.as_ptr(), &mut device, &mut luid) };
        if hr < 0 || device.is_null() {
            return Err(bridge("device", hr));
        }
        eprintln!(
            "host_gpu_adapter_luid={luid:016x} same_device=true cursor=gdi_surface driver_internal_readback=unknown"
        );
        Ok(device)
    }
    fn frame(&mut self, repeated: bool) -> io::Result<Option<NonNull<c_void>>> {
        let mut texture = null_mut();
        // SAFETY: owner-local handle and synchronous out pointer.
        let hr =
            unsafe { nl_capture_gpu_frame(self.handle.as_ptr(), repeated.into(), &mut texture) };
        if hr < 0 {
            return Err(bridge("capture", hr));
        }
        if hr == 1 {
            return Ok(None);
        }
        Ok(Some(
            NonNull::new(texture).ok_or_else(|| bridge("null texture", hr))?,
        ))
    }
    fn discard(&mut self) {
        // SAFETY: merely invalidates retained recovery content on this owner.
        unsafe { nl_capture_gpu_discard(self.handle.as_ptr()) };
    }
}
struct GpuPipeline {
    encoder: MfH264Encoder,
    probed_sps: H264SpsInfo,
    capture: GpuCapture,
    texture: Option<NonNull<c_void>>,
}
enum Pipeline {
    Gpu(GpuPipeline),
    Cpu {
        encoder: VideoEncoder,
        source: Box<NativeSource>,
        retained: Option<RawFrame>,
    },
}
impl Pipeline {
    fn close(self) -> io::Result<()> {
        match self {
            Self::Gpu(p) => {
                let result = p.encoder.close();
                drop(p.capture);
                result
            }
            Self::Cpu { encoder, .. } => encoder.close(),
        }
    }
}
fn codec_config(c: HostVideoConfig) -> VideoConfig {
    VideoConfig {
        width: c.width,
        height: c.height,
        fps: c.fps,
        bitrate_kbps: c.bitrate_kbps,
    }
}
fn codec_limits(c: HostVideoConfig) -> H264EncodingLimits {
    H264EncodingLimits {
        max_level_idc: c.max_level_idc,
        require_constrained_baseline: c.require_constrained_baseline,
    }
}
fn software(monitor: &Monitor, display: Display, c: HostVideoConfig) -> io::Result<Pipeline> {
    eprintln!(
        "host_capture_encode=cpu_fallback encoder=software source={} target={}x{}@{}",
        c.source,
        c.width,
        c.height,
        c.fps.min(30)
    );
    let mut config = codec_config(c);
    config.fps = config.fps.min(30);
    let encoder = VideoEncoder::new_h264_software(config, codec_limits(c))?;
    Ok(Pipeline::Cpu {
        encoder,
        source: Box::new(NativeSource::open(
            Target::Monitor(monitor.clone()),
            display,
        )?),
        retained: None,
    })
}
fn gpu_pipeline(
    monitor: &Monitor,
    c: HostVideoConfig,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<Pipeline> {
    gpu_pipeline_with_capture(GpuCapture::open(monitor, c)?, c, check)
}
fn gpu_pipeline_with_capture(
    capture: GpuCapture,
    c: HostVideoConfig,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<Pipeline> {
    let device = capture.device()?;
    // SAFETY: capture and MF are created/used/dropped on this worker with one device.
    let mut encoder =
        unsafe { MfH264Encoder::with_gpu_device(codec_config(c), codec_limits(c), device) }
            .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    let mut pixels = zeroize::Zeroizing::new(vec![0u8; frame_bytes(c.width, c.height)?]);
    for pixel in pixels.chunks_exact_mut(4) {
        pixel.copy_from_slice(&[32, 96, 192, 255]);
    }
    let mut texture = null_mut();
    // SAFETY: bounded synthetic CPU upload; no desktop capture before activation.
    let hr = unsafe {
        nl_capture_gpu_probe(
            capture.handle.as_ptr(),
            pixels.as_ptr(),
            pixels.len(),
            &mut texture,
        )
    };
    if hr < 0 || texture.is_null() {
        return Err(bridge("synthetic conversion", hr));
    }
    // A fresh software decoder sees only hardware IDRs from this probe. Keep
    // the real stream alive: a decoder may release its first picture only once
    // it has seen the next independent AU, without requiring an EOS shortcut.
    let mut decoder = MfH264Decoder::new(c.width, c.height, false)?;
    let mut expected_pts = VecDeque::new();
    let started = Instant::now();
    let mut pts = 1;
    let mut verified = false;
    let mut attempts = 0u32;
    let mut accepted = 0u32;
    let mut outputs = 0u32;
    let mut hardware_idrs = 0u32;
    let mut decoder_empty = 0u32;
    for _ in 0..64 {
        check()?;
        if started.elapsed() > Duration::from_millis(1500) {
            break;
        }
        attempts += 1;
        // SAFETY: validated same-device NV12 synthetic surface owned by capture.
        let step = unsafe { encoder.encode_texture(texture, pts, true)? };
        if step.accepted {
            accepted += 1;
            pts += 90_000 / u64::from(c.fps);
        }
        if let Some(packet) = step.output {
            outputs += 1;
            eprintln!(
                "host_gpu_probe_stage=encoded pts={} keyframe={} hardware={} bytes={} actual_sps={}",
                packet.pts_90khz,
                packet.keyframe,
                encoder.hardware(),
                packet.data.len(),
                encoder
                    .sps_info()
                    .map_or_else(|| "missing".into(), |s| s.profile_level_id())
            );
            if !packet.keyframe || !encoder.hardware() {
                continue;
            }
            hardware_idrs += 1;
            eprintln!(
                "host_gpu_probe_stage=independent_decode_begin pts={}",
                packet.pts_90khz
            );
            if expected_pts.len() >= 16 {
                return Err(io::Error::other(
                    "GPU probe independent decoder ledger full",
                ));
            }
            expected_pts.push_back(packet.pts_90khz);
            let mut decoded = decoder.decode_frame(&packet.data, packet.pts_90khz)?;
            for _ in 0..8 {
                if decoded.is_some() {
                    break;
                }
                check()?;
                decoded = decoder.drain_frame()?;
            }
            eprintln!(
                "host_gpu_probe_stage=independent_decode_end pts={} image={}",
                packet.pts_90khz,
                decoded.is_some()
            );
            let Some((decoded, decoded_pts)) = decoded else {
                decoder_empty += 1;
                continue;
            };
            let expected = expected_pts.pop_front().ok_or_else(|| {
                io::Error::other("GPU probe independent output without submitted IDR")
            })?;
            eprintln!(
                "host_gpu_probe_stage=independent_output actual_pts={decoded_pts} expected_pts={expected}"
            );
            let decoded = zeroize::Zeroizing::new(decoded);
            if decoded_pts != expected
                || decoded.len() != pixels.len()
                || decoded.chunks_exact(4).any(|p| {
                    (i32::from(p[0]) - 32).abs() > 40
                        || (i32::from(p[1]) - 96).abs() > 40
                        || (i32::from(p[2]) - 192).abs() > 40
                        || p[3] != 255
                })
            {
                return Err(io::Error::other(
                    "GPU synthetic independent decoded colors/PTS mismatch",
                ));
            }
            verified = true;
            break;
        }
    }
    eprintln!(
        "host_gpu_probe_stage=summary attempts={attempts} accepted={accepted} outputs={outputs} hardware_idrs={hardware_idrs} independent_decoder_empty={decoder_empty} elapsed_ms={} verified={verified}",
        started.elapsed().as_millis()
    );
    if !verified {
        let stage = if accepted == 0 {
            "input_not_accepted"
        } else if outputs == 0 {
            "encoder_no_output"
        } else if hardware_idrs == 0 {
            "no_hardware_idr"
        } else {
            "independent_decoder_no_image"
        };
        encoder.close()?;
        return Err(io::Error::other(format!(
            "GPU actual-target surface probe failed stage={stage} accepted={accepted} outputs={outputs} hardware_idrs={hardware_idrs} independent_decoder_empty={decoder_empty}"
        )));
    }
    let info = encoder
        .sps_info()
        .ok_or_else(|| io::Error::other("GPU probe missing SPS"))?;
    eprintln!(
        "host_gpu_probe=passed target={}x{}@{} actual_sps={} performance_qualified=false",
        c.width,
        c.height,
        c.fps,
        info.profile_level_id()
    );
    encoder.close()?;
    check()?;
    // A clean transform separates synthetic PTS/reference state from real media.
    let encoder =
        unsafe { MfH264Encoder::with_gpu_device(codec_config(c), codec_limits(c), device)? };
    Ok(Pipeline::Gpu(GpuPipeline {
        encoder,
        probed_sps: info,
        capture,
        texture: None,
    }))
}

enum Operation {
    Configure(HostVideoConfig),
    Capture(u32, bool),
    Encode(u64, u64, bool),
    Bitrate(u32),
    Drain,
    Raw(Option<u32>),
    Discard,
}
enum Reply {
    Configured,
    Frame(Option<HostFrame>),
    Step(HostEncodeStep),
    Raw(Option<RawFrame>),
    Done,
}
struct Command {
    operation: Operation,
    reply: mpsc::SyncSender<io::Result<Reply>>,
}
// Keep timed-out JoinHandles rather than detach a driver-stalled owner. Admission
// is bounded across active and quarantined workers; only finished handles join.
struct WorkerRegistry {
    count: usize,
    retired: Vec<(thread::JoinHandle<()>, WorkerReservation)>,
}
struct WorkerReservation;
fn workers() -> &'static Mutex<WorkerRegistry> {
    static REGISTRY: std::sync::OnceLock<Mutex<WorkerRegistry>> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        Mutex::new(WorkerRegistry {
            count: 0,
            retired: Vec::new(),
        })
    })
}
impl Drop for WorkerReservation {
    fn drop(&mut self) {
        if let Ok(mut state) = workers().lock() {
            state.count = state.count.saturating_sub(1);
        }
    }
}
fn reserve_worker() -> io::Result<WorkerReservation> {
    let mut finished = Vec::new();
    {
        let mut state = workers()
            .lock()
            .map_err(|_| io::Error::other("host worker registry poisoned"))?;
        let mut i = 0;
        while i < state.retired.len() {
            if state.retired[i].0.is_finished() {
                finished.push(state.retired.swap_remove(i));
            } else {
                i += 1;
            }
        }
    }
    for (handle, reservation) in finished {
        let _ = handle.join();
        drop(reservation);
    }
    let mut state = workers()
        .lock()
        .map_err(|_| io::Error::other("host worker registry poisoned"))?;
    if state.count >= 4 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "host GPU owner cleanup still pending",
        ));
    }
    state.count += 1;
    Ok(WorkerReservation)
}
/// Send facade; its worker owns every COM object, texture, capture and encoder.
pub struct WindowsHostCapture {
    capture: WindowsCapture,
    commands: mpsc::SyncSender<Command>,
    reservation: Option<WorkerReservation>,
}
impl WindowsHostCapture {
    pub fn open(sources: Vec<WindowsCaptureSource>) -> io::Result<Self> {
        let original = sources
            .first()
            .ok_or_else(|| denied("no approved display"))?
            .original
            .clone();
        let mut ids = BTreeSet::new();
        if sources.len() > 64
            || sources
                .iter()
                .any(|s| *s.original != *original || !ids.insert(s.index))
        {
            return Err(denied("mixed or duplicate approved sources"));
        }
        let targets = sources
            .into_iter()
            .map(|s| (original.monitors[s.index].clone(), s.display()))
            .collect::<Vec<_>>();
        let displays = targets.iter().map(|(_, d)| *d).collect::<Vec<_>>();
        let total = displays.iter().try_fold(0usize, |sum, d| {
            sum.checked_add(frame_bytes(d.logical.width, d.logical.height)?)
                .ok_or_else(|| io::Error::other("capture size overflow"))
        })?;
        if total > QUEUE_BYTES {
            return Err(io::Error::other("approved capture budget exceeded"));
        }
        let reservation = reserve_worker()?;
        let shared = Arc::new(Shared::new());
        let worker_shared = shared.clone();
        let (commands, receiver) = mpsc::sync_channel(1);
        let (ready, readiness) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nestlink-windows-host-video".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    owner(
                        worker_shared.clone(),
                        original,
                        targets,
                        receiver,
                        ready.clone(),
                    )
                }))
                .unwrap_or_else(|_| Err(io::Error::other("Windows host video worker panicked")));
                if let Err(e) = &result {
                    let _ = ready.try_send(Err(io::Error::new(e.kind(), e.to_string())));
                }
                worker_shared.finish(result);
            })?;
        let mut this = Self {
            capture: WindowsCapture {
                shared,
                displays,
                worker: Some(worker),
                cleanup_deadline: None,
            },
            commands,
            reservation: Some(reservation),
        };
        match readiness.recv_timeout(STARTUP) {
            Ok(Ok(())) => Ok(this),
            Ok(Err(e)) => {
                let cleanup = this.reset();
                Err(cleanup.err().unwrap_or(e))
            }
            Err(e) => {
                let cleanup = this.reset();
                Err(cleanup
                    .err()
                    .unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, e)))
            }
        }
    }
    pub fn displays(&self) -> &[Display] {
        self.capture.displays()
    }
    fn call(&mut self, operation: Operation) -> io::Result<Reply> {
        self.check()?;
        let (reply, receive) = mpsc::sync_channel(1);
        self.commands
            .try_send(Command { operation, reply })
            .map_err(|_| io::Error::other("host command queue unavailable"))?;
        let value = receive
            .recv_timeout(STARTUP)
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "host command deadline"))??;
        self.check()?;
        Ok(value)
    }
}
impl Drop for WindowsHostCapture {
    fn drop(&mut self) {
        let _ = self.capture.reset();
        if let Some(handle) = self.capture.worker.take() {
            if handle.is_finished() {
                let _ = handle.join();
            } else if let Some(reservation) = self.reservation.take() {
                // Registry count includes this retained owner; no more than four
                // live/unfinished workers can be created by these facades.
                match workers().lock() {
                    Ok(mut state) => state.retired.push((handle, reservation)),
                    Err(poison) => poison.into_inner().retired.push((handle, reservation)),
                }
            }
        }
    }
}
impl CaptureDevice for WindowsHostCapture {
    fn check(&mut self) -> io::Result<()> {
        self.capture.check()
    }
    fn cancellation(&self) -> Option<Arc<AtomicBool>> {
        Some(self.capture.shared.stopped.clone())
    }
    fn host_configure(&mut self, config: HostVideoConfig) -> io::Result<bool> {
        match self.call(Operation::Configure(config))? {
            Reply::Configured => Ok(true),
            _ => Err(io::Error::other("host configure reply")),
        }
    }
    fn host_capture(&mut self, source: u32, repeated: bool) -> io::Result<Option<HostFrame>> {
        match self.call(Operation::Capture(source, repeated))? {
            Reply::Frame(f) => Ok(f),
            _ => Err(io::Error::other("host capture reply")),
        }
    }
    fn host_encode(&mut self, ticket: u64, pts: u64, keyframe: bool) -> io::Result<HostEncodeStep> {
        match self.call(Operation::Encode(ticket, pts, keyframe))? {
            Reply::Step(s) => Ok(s),
            _ => Err(io::Error::other("host encode reply")),
        }
    }
    fn host_drain(&mut self) -> io::Result<HostEncodeStep> {
        match self.call(Operation::Drain)? {
            Reply::Step(s) => Ok(s),
            _ => Err(io::Error::other("host drain reply")),
        }
    }
    fn host_set_bitrate(&mut self, kbps: u32) -> io::Result<()> {
        match self.call(Operation::Bitrate(kbps))? {
            Reply::Done => Ok(()),
            _ => Err(io::Error::other("host bitrate reply")),
        }
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        match self.call(Operation::Raw(None))? {
            Reply::Raw(f) => Ok(f),
            _ => Err(io::Error::other("host raw reply")),
        }
    }
    fn poll_frame_for(&mut self, source: u32) -> io::Result<Option<RawFrame>> {
        match self.call(Operation::Raw(Some(source)))? {
            Reply::Raw(f) => Ok(f),
            _ => Err(io::Error::other("host raw reply")),
        }
    }
    fn discard_pending_frames(&mut self) -> io::Result<()> {
        match self.call(Operation::Discard)? {
            Reply::Done => Ok(()),
            _ => Err(io::Error::other("host discard reply")),
        }
    }
    fn reset_before(&mut self, deadline: Instant) -> io::Result<()> {
        let current = self.capture.cleanup_deadline.get_or_insert(deadline);
        *current = (*current).min(deadline);
        self.capture.reset()
    }
    fn reset(&mut self) -> io::Result<()> {
        self.capture.reset()
    }
}
struct Owner {
    targets: Vec<(Monitor, Display)>,
    raw: BTreeMap<u32, NativeSource>,
    raw_index: usize,
    pipeline: Option<Pipeline>,
    config: Option<HostVideoConfig>,
    generation: u64,
    serial: u64,
    ticket: Option<HostFrame>,
    retained_at: Option<Instant>,
    retry: Instant,
    activated: bool,
    retry_gpu: bool,
}
impl Owner {
    fn close(&mut self) -> io::Result<()> {
        self.raw.clear();
        if let Some(p) = self.pipeline.take() {
            p.close()?;
        }
        Ok(())
    }
    fn advance(&mut self) -> io::Result<()> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("GPU generation exhausted"))?;
        self.ticket = None;
        self.retained_at = None;
        Ok(())
    }
    fn recover(
        &mut self,
        error: io::Error,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<Reply> {
        check()?;
        let c = self
            .config
            .ok_or_else(|| io::Error::other("lost encoder config absent"))?;
        let (monitor, display) = self
            .targets
            .iter()
            .find(|(_, d)| d.source == c.source)
            .cloned()
            .ok_or_else(|| denied("lost source unapproved"))?;
        eprintln!("host_encoder_loss={error}");
        self.close()?;
        self.advance()?;
        self.pipeline = Some(software(&monitor, display, c)?);
        self.retry = Instant::now() + Duration::from_secs(2);
        self.retry_gpu = true;
        Ok(Reply::Step(HostEncodeStep {
            accepted: false,
            hardware: false,
            output: None,
        }))
    }
    fn process(
        &mut self,
        op: Operation,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<Reply> {
        match op {
            Operation::Configure(c) => {
                let (monitor, display) = self
                    .targets
                    .iter()
                    .find(|(_, d)| d.source == c.source)
                    .cloned()
                    .ok_or_else(|| denied("unapproved host source"))?;
                if (c.width, c.height) != (display.logical.width, display.logical.height) {
                    return Err(denied("host dimensions differ"));
                }
                self.close()?;
                self.config = None;
                self.advance()?;
                codec_limits(c)
                    .validate_config(codec_config(c))
                    .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
                let pipeline = match gpu_pipeline(&monitor, c, check) {
                    Ok(p) => p,
                    Err(e) => {
                        check()?;
                        eprintln!("host_gpu_fallback={e}");
                        software(&monitor, display, c)
                            .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?
                    }
                };
                self.activated = false;
                self.retry_gpu = false;
                self.config = Some(c);
                self.pipeline = Some(pipeline);
                self.retry = Instant::now() + Duration::from_secs(2);
                Ok(Reply::Configured)
            }
            Operation::Capture(source, repeated) => {
                let c = self
                    .config
                    .ok_or_else(|| io::Error::other("host unconfigured"))?;
                if c.source != source {
                    return Err(denied("host source differs from prepared source"));
                }
                if self.retry_gpu
                    && !repeated
                    && matches!(self.pipeline, Some(Pipeline::Cpu { .. }))
                    && Instant::now() >= self.retry
                {
                    self.retry = Instant::now() + Duration::from_secs(2);
                    let (monitor, display) = self
                        .targets
                        .iter()
                        .find(|(_, d)| d.source == source)
                        .cloned()
                        .ok_or_else(|| denied("host source absent"))?;
                    // Retire CPU allocations before probing GPU so retry cannot
                    // briefly exceed the aggregate surface budget.
                    self.close()?;
                    self.advance()?;
                    self.pipeline = Some(match gpu_pipeline(&monitor, c, check) {
                        Ok(p) => p,
                        Err(e) => {
                            check()?;
                            eprintln!("host_gpu_retry_fallback={e}");
                            software(&monitor, display, c)?
                        }
                    });
                }
                self.activated = true;
                let at = Instant::now();
                let mut cached = false;
                let capture = match self
                    .pipeline
                    .as_mut()
                    .ok_or_else(|| io::Error::other("host pipeline absent"))?
                {
                    Pipeline::Gpu(p) => match p.capture.frame(false) {
                        Ok(Some(t)) => {
                            p.texture = Some(t);
                            Ok(true)
                        }
                        Ok(None) if repeated => p.capture.frame(true).map(|t| {
                            cached = t.is_some();
                            p.texture = t;
                            t.is_some()
                        }),
                        Ok(None) => Ok(false),
                        Err(e) => Err(e),
                    },
                    Pipeline::Cpu {
                        source, retained, ..
                    } => source.capture().map(|f| {
                        if let Some(f) = f {
                            *retained = Some(f);
                            true
                        } else {
                            cached = repeated && retained.is_some();
                            cached
                        }
                    }),
                };
                let available = match capture {
                    Ok(v) => v,
                    Err(e) => {
                        check()?;
                        eprintln!("host_gpu_device_loss={e}");
                        self.close()?;
                        self.advance()?;
                        let (m, d) = self
                            .targets
                            .iter()
                            .find(|(_, d)| d.source == source)
                            .ok_or_else(|| denied("source absent"))?;
                        self.pipeline = Some(software(m, *d, c)?);
                        self.retry = Instant::now() + Duration::from_secs(2);
                        self.retry_gpu = true;
                        return Ok(Reply::Frame(None));
                    }
                };
                if !available {
                    return Ok(Reply::Frame(None));
                }
                self.serial = self
                    .serial
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("host ticket exhausted"))?;
                if !cached {
                    self.retained_at = Some(at);
                }
                let captured_at = self
                    .retained_at
                    .ok_or_else(|| io::Error::other("recovery capture time absent"))?;
                let f = HostFrame {
                    ticket: self.serial,
                    generation: self.generation,
                    source,
                    width: c.width,
                    height: c.height,
                    captured_at,
                    encode_at: at,
                    repeated: cached,
                };
                self.ticket = Some(f);
                Ok(Reply::Frame(Some(f)))
            }
            Operation::Encode(ticket, pts, keyframe) => {
                let f = self
                    .ticket
                    .ok_or_else(|| io::Error::other("host ticket absent"))?;
                if f.ticket != ticket
                    || f.generation != self.generation
                    || f.encode_at.elapsed() > nestlink_remote::video::RAW_FRAME_AGE
                {
                    return Err(denied("stale host ticket"));
                }
                let progress = (|| {
                    match self
                        .pipeline
                        .as_mut()
                        .ok_or_else(|| io::Error::other("host pipeline absent"))?
                    {
                        Pipeline::Gpu(p) => {
                            let t = p
                                .texture
                                .ok_or_else(|| io::Error::other("GPU texture absent"))?;
                            // SAFETY: capture owns this exact-device NV12 texture on this owner.
                            let step = unsafe {
                                p.encoder
                                    .encode_texture(t.as_ptr(), pts, keyframe || f.repeated)?
                            };
                            Ok((step, p.encoder.hardware()))
                        }
                        Pipeline::Cpu {
                            encoder, retained, ..
                        } => {
                            let raw = retained
                                .as_ref()
                                .ok_or_else(|| io::Error::other("CPU recovery absent"))?;
                            Ok((
                                encoder.encode_step(&raw.pixels, pts, keyframe || f.repeated)?,
                                false,
                            ))
                        }
                    }
                })();
                let (step, hardware) = match progress {
                    Ok(value) => value,
                    Err(error) => return self.recover(error, check),
                };
                if step.accepted {
                    self.ticket = None;
                }
                Ok(Reply::Step(HostEncodeStep {
                    accepted: step.accepted,
                    hardware,
                    output: step.output.map(|p| HostPacket {
                        pts_90khz: p.pts_90khz,
                        keyframe: p.keyframe,
                        data: p.data,
                    }),
                }))
            }
            Operation::Drain => {
                let (step, hardware) = match self.pipeline.as_mut() {
                    Some(Pipeline::Gpu(p)) => (p.encoder.drain_encoded()?, p.encoder.hardware()),
                    Some(Pipeline::Cpu { encoder, .. }) => (encoder.drain_encoded()?, false),
                    None => {
                        return Ok(Reply::Step(HostEncodeStep {
                            accepted: false,
                            hardware: false,
                            output: None,
                        }));
                    }
                };
                Ok(Reply::Step(HostEncodeStep {
                    accepted: false,
                    hardware,
                    output: step.output.map(|p| HostPacket {
                        pts_90khz: p.pts_90khz,
                        keyframe: p.keyframe,
                        data: p.data,
                    }),
                }))
            }
            Operation::Bitrate(kbps) => {
                match self
                    .pipeline
                    .as_mut()
                    .ok_or_else(|| io::Error::other("host pipeline absent"))?
                {
                    Pipeline::Gpu(p) => p.encoder.set_bitrate(kbps)?,
                    Pipeline::Cpu { encoder, .. } => encoder.set_bitrate(kbps)?,
                }
                if let Some(c) = &mut self.config {
                    c.bitrate_kbps = kbps;
                }
                Ok(Reply::Done)
            }
            Operation::Raw(selected) => {
                if self.pipeline.is_some() {
                    return Ok(Reply::Raw(None));
                }
                let index = if let Some(source) = selected {
                    self.targets
                        .iter()
                        .position(|(_, d)| d.source == source)
                        .ok_or_else(|| denied("raw source unapproved"))?
                } else {
                    let i = self.raw_index % self.targets.len();
                    self.raw_index += 1;
                    i
                };
                let (m, d) = &self.targets[index];
                if let std::collections::btree_map::Entry::Vacant(entry) = self.raw.entry(d.source)
                {
                    entry.insert(NativeSource::open(Target::Monitor(m.clone()), *d)?);
                }
                Ok(Reply::Raw(
                    self.raw
                        .get_mut(&d.source)
                        .ok_or_else(|| io::Error::other("raw source absent"))?
                        .capture()?,
                ))
            }
            Operation::Discard => {
                self.ticket = None;
                self.retained_at = None;
                match &mut self.pipeline {
                    Some(Pipeline::Gpu(p)) => {
                        p.capture.discard();
                        p.texture = None;
                    }
                    Some(Pipeline::Cpu { retained, .. }) => *retained = None,
                    None => {}
                }
                if self.activated {
                    let c = self
                        .config
                        .ok_or_else(|| io::Error::other("active config absent"))?;
                    if let Some(p) = self.pipeline.take() {
                        self.pipeline = Some(match p {
                            Pipeline::Gpu(p) => {
                                p.encoder.close()?;
                                let device = p.capture.device()?;
                                // No old pool remains while allocating replacement.
                                let encoder = unsafe {
                                    MfH264Encoder::with_gpu_device(
                                        codec_config(c),
                                        codec_limits(c),
                                        device,
                                    )?
                                };
                                Pipeline::Gpu(GpuPipeline {
                                    encoder,
                                    probed_sps: p.probed_sps,
                                    capture: p.capture,
                                    texture: None,
                                })
                            }
                            Pipeline::Cpu {
                                encoder, source, ..
                            } => {
                                encoder.close()?;
                                let mut config = codec_config(c);
                                config.fps = config.fps.min(30);
                                let encoder =
                                    VideoEncoder::new_h264_software(config, codec_limits(c))?;
                                Pipeline::Cpu {
                                    encoder,
                                    source,
                                    retained: None,
                                }
                            }
                        });
                    }
                    self.advance()?;
                    self.activated = false;
                }
                self.raw.clear();
                Ok(Reply::Done)
            }
        }
    }
}
fn facts(shared: &Shared, original: &Context, observer: &WindowsSessionObserver) -> io::Result<()> {
    observer.pump();
    if !shared.active() || context()? != *original {
        return Err(denied(
            "host desktop/session/monitor/DPI changed or revoked",
        ));
    }
    shared.checked()
}
fn owner(
    shared: Arc<Shared>,
    original: Arc<Context>,
    targets: Vec<(Monitor, Display)>,
    commands: mpsc::Receiver<Command>,
    ready: mpsc::SyncSender<io::Result<()>>,
) -> io::Result<()> {
    let _dpi = DpiScope::enter()?;
    let mut observer = WindowsSessionObserver::open(shared.invalidated.clone(), true)?;
    let result = (|| {
        facts(&shared, &original, &observer)?;
        let mut owner = Owner {
            targets,
            raw: BTreeMap::new(),
            raw_index: 0,
            pipeline: None,
            config: None,
            generation: 0,
            serial: 0,
            ticket: None,
            retained_at: None,
            retry: Instant::now(),
            activated: false,
            retry_gpu: false,
        };
        ready
            .send(Ok(()))
            .map_err(|_| denied("host caller ended"))?;
        let work = (|| {
            loop {
                if shared.stopped.load(Ordering::SeqCst) {
                    return Ok(());
                }
                facts(&shared, &original, &observer)?;
                match commands.recv_timeout(FRAME_INTERVAL) {
                    Ok(command) => {
                        let mut check = || facts(&shared, &original, &observer);
                        check()?;
                        let value = owner.process(command.operation, &mut check);
                        check()?; // Never publish a reply after revocation/fact change.
                        let failed = value
                            .as_ref()
                            .is_err_and(|e| e.kind() != io::ErrorKind::Unsupported);
                        let _ = command.reply.try_send(value);
                        if failed {
                            return Err(io::Error::other("host operation failed"));
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                }
            }
        })();
        let cleanup = owner.close();
        work.and(cleanup)
    })();
    result.and(observer.close())
}

/// Synthetic-only same-device GPU conversion/MF probe. Opens no desktop source.
/// Call on a disposable blocking worker; returned data contains no COM objects.
pub fn probe_windows_gpu_h264(
    config: VideoConfig,
    limits: H264EncodingLimits,
) -> io::Result<H264EncoderProbe> {
    limits.validate_config(config)?;
    let capture = GpuCapture::synthetic(config)
        .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    let c = HostVideoConfig {
        source: 0,
        width: config.width,
        height: config.height,
        fps: config.fps,
        bitrate_kbps: config.bitrate_kbps,
        max_level_idc: limits.max_level_idc,
        require_constrained_baseline: limits.require_constrained_baseline,
    };
    let p = gpu_pipeline_with_capture(capture, c, &mut || Ok(()))?;
    let sps = match &p {
        Pipeline::Gpu(p) => p.probed_sps,
        Pipeline::Cpu { .. } => {
            return Err(io::Error::other("synthetic GPU unexpectedly fell back"));
        }
    };
    p.close()?;
    Ok(H264EncoderProbe {
        config,
        sps,
        hardware: true,
    })
}
