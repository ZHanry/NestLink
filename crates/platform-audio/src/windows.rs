//! WASAPI clients owned by individual MTA workers; no COM pointer crosses threads.
#![allow(unsafe_code)]
use crate::pcm::Assembler;
use nestlink_platform_session::{WindowsSessionObserver, WindowsSessionSnapshot};
use nestlink_remote::audio::{
    AudioBinding, AudioCaptureDevice, AudioChunk, AudioDevice, AudioPlaybackDevice,
    AudioPlaybackTiming, CAPTURE_AGE, CHUNK_FRAMES, CapturedAudio,
};
use std::{
    collections::VecDeque,
    ffi::c_void,
    io,
    ptr::{NonNull, null_mut},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const STARTUP: Duration = Duration::from_secs(3);
const HEARTBEAT: Duration = Duration::from_millis(250);
const CLEANUP: Duration = Duration::from_millis(150);
const TICK: Duration = Duration::from_millis(5);
const MAX_PACKET_FRAMES: usize = CHUNK_FRAMES * 2;
const PLAYBACK_QUEUED: usize = 2; // + one active 20ms chunk + <=40ms WASAPI = <=100ms.
const CAPTURE_QUEUED: usize = 5;
unsafe extern "C" {
    fn nl_audio_enumerate(
        callback: unsafe extern "C" fn(*mut c_void, *const u16, usize, *const u16, usize) -> i32,
        context: *mut c_void,
    ) -> i32;
    fn nl_audio_default_render_id(output: *mut u16, capacity: usize, written: *mut usize) -> i32;
    fn nl_audio_open(id: *const u16, channels: u32, loopback: i32, out: *mut *mut c_void) -> i32;
    fn nl_audio_check(audio: *mut c_void) -> i32;
    fn nl_audio_start(audio: *mut c_void) -> i32;
    fn nl_audio_capture(
        audio: *mut c_void,
        out: *mut i16,
        capacity: usize,
        frames: *mut u32,
        position: *mut u64,
        age_100ns: *mut u64,
        flags: *mut u32,
    ) -> i32;
    fn nl_audio_write(audio: *mut c_void, input: *const i16, frames: u32, written: *mut u32)
    -> i32;
    fn nl_audio_timing(audio: *mut c_void, padding: *mut u32, latency_100ns: *mut i64) -> i32;
    fn nl_audio_close(audio: *mut c_void) -> i32;
    fn nl_audio_started(audio: *mut c_void) -> i32;
}
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn hresult(code: i32, operation: &'static str) -> io::Result<()> {
    if code >= 0 {
        return Ok(());
    }
    let kind = match code as u32 {
        0x88890008 | 0x88890016 => io::ErrorKind::Unsupported,
        0x88890004 | 0x88890026 => io::ErrorKind::NotConnected,
        0x80070005 => io::ErrorKind::PermissionDenied,
        0x8007000d => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::Other,
    };
    Err(io::Error::new(
        kind,
        format!("{operation}: HRESULT 0x{:08x}", code as u32),
    ))
}

/// Opaque render endpoint selected locally. Enumerating never starts audio.
#[derive(Clone)]
pub struct WindowsAudioEndpoint {
    original: WindowsSessionSnapshot,
    id: Vec<u16>,
    name: String,
}
impl WindowsAudioEndpoint {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn device_id(&self) -> String {
        String::from_utf16_lossy(&self.id[..self.id.len() - 1])
    }
    pub fn enumerate() -> io::Result<Vec<Self>> {
        let original = WindowsSessionSnapshot::current()?;
        let (ready, wait) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nestlink-audio-endpoints".into())
            .spawn(move || {
                let result = (|| {
                    if WindowsSessionSnapshot::current()? != original {
                        return Err(denied("audio session changed before enumeration"));
                    }
                    let mut output = Enumeration {
                        values: Vec::new(),
                        failed: false,
                    };
                    // SAFETY: synchronous callback borrows this stack object only until return.
                    hresult(
                        unsafe {
                            nl_audio_enumerate(
                                endpoint_callback,
                                (&mut output as *mut Enumeration).cast(),
                            )
                        },
                        "enumerate render endpoints",
                    )?;
                    if output.failed || WindowsSessionSnapshot::current()? != original {
                        return Err(denied(
                            "audio endpoint enumeration changed or exceeded budget",
                        ));
                    }
                    let mut ids = std::collections::BTreeSet::new();
                    output
                        .values
                        .into_iter()
                        .map(|(id, name)| {
                            if !ids.insert(id.clone()) {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "duplicate render endpoint",
                                ));
                            }
                            Ok(Self {
                                original: original.clone(),
                                id,
                                name,
                            })
                        })
                        .collect::<io::Result<Vec<_>>>()
                })();
                let _ = ready.send(result);
            })?;
        let result = wait.recv_timeout(STARTUP).map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "audio endpoint enumeration timed out",
            )
        })?;
        if worker.is_finished() {
            worker
                .join()
                .map_err(|_| io::Error::other("audio endpoint worker panicked"))?;
        }
        result
    }
    /// Resolve the actual Windows multimedia render default from local OS
    /// state. The endpoint remains opaque and fixed after selection.
    pub fn default_render() -> io::Result<Self> {
        let mut endpoints = Self::enumerate()?;
        let id = default_render_id()?;
        endpoints
            .drain(..)
            .find(|endpoint| endpoint.id == id)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Windows default render endpoint is not active in the local inventory",
                )
            })
    }
}
fn default_render_id() -> io::Result<Vec<u16>> {
    let original = WindowsSessionSnapshot::current()?;
    let (ready, wait) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("nestlink-default-audio-endpoint".into())
        .spawn(move || {
            let result = (|| {
                if WindowsSessionSnapshot::current()? != original {
                    return Err(denied("audio session changed before default lookup"));
                }
                let mut id = vec![0u16; 1024];
                let mut length = 0usize;
                hresult(
                    unsafe { nl_audio_default_render_id(id.as_mut_ptr(), id.len(), &mut length) },
                    "resolve default render endpoint",
                )?;
                if length == 0
                    || length >= id.len()
                    || id[length] != 0
                    || id[..length].contains(&0)
                    || WindowsSessionSnapshot::current()? != original
                {
                    return Err(denied("default render endpoint changed or is malformed"));
                }
                id.truncate(length + 1);
                Ok(id)
            })();
            let _ = ready.send(result);
        })?;
    let result = wait.recv_timeout(STARTUP).map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "default audio endpoint lookup timed out",
        )
    })?;
    if worker.is_finished() {
        worker
            .join()
            .map_err(|_| io::Error::other("default audio endpoint worker panicked"))?;
    }
    result
}
struct Enumeration {
    values: Vec<(Vec<u16>, String)>,
    failed: bool,
}
unsafe extern "C" fn endpoint_callback(
    context: *mut c_void,
    id: *const u16,
    id_len: usize,
    name: *const u16,
    name_len: usize,
) -> i32 {
    // SAFETY: C synchronously borrows the exact stack Enumeration from enumerate.
    let output = unsafe { &mut *context.cast::<Enumeration>() };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if id.is_null()
            || name.is_null()
            || !(1..1024).contains(&id_len)
            || !(1..1024).contains(&name_len)
            || output.values.len() >= 64
        {
            return Err(());
        }
        // SAFETY: lengths/pointers bounded here, C owns these SDK allocations for the call.
        let id = unsafe { std::slice::from_raw_parts(id, id_len) };
        let name = unsafe { std::slice::from_raw_parts(name, name_len) };
        if id.contains(&0) || name.contains(&0) || String::from_utf16(id).is_err() {
            return Err(());
        }
        let name = String::from_utf16(name).map_err(|_| ())?;
        let mut id = id.to_vec();
        id.push(0);
        output.values.push((id, name));
        Ok(())
    }));
    if !matches!(result, Ok(Ok(()))) {
        output.failed = true;
        1
    } else {
        0
    }
}

#[derive(Clone)]
struct Failure {
    kind: io::ErrorKind,
    message: String,
}
impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}
impl Failure {
    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}
struct State {
    output_timing: AudioPlaybackTiming,
    playing_frames: u32,
    queue: VecDeque<CapturedAudio>,
    heartbeat: Instant,
    ended: bool,
    failure: Option<Failure>,
    cleanup: Option<Result<(), Failure>>,
}
struct Shared {
    stopped: AtomicBool,
    armed: AtomicBool,
    invalidated: Arc<AtomicBool>,
    state: Mutex<State>,
    wake: Condvar,
}
impl Shared {
    fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            armed: AtomicBool::new(false),
            invalidated: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(State {
                output_timing: AudioPlaybackTiming::default(),
                playing_frames: 0,
                queue: VecDeque::new(),
                heartbeat: Instant::now(),
                ended: false,
                failure: None,
                cleanup: None,
            }),
            wake: Condvar::new(),
        }
    }
    fn active(&self) -> bool {
        !self.stopped.load(Ordering::SeqCst) && !self.invalidated.load(Ordering::SeqCst)
    }
    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("system audio state poisoned"))
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Ok(mut state) = self.state.lock() {
            state.queue.clear();
        }
        self.wake.notify_all();
    }
    fn check(&self) -> io::Result<()> {
        let state = self.lock()?;
        if let Some(error) = &state.failure {
            return Err(error.error());
        }
        if !self.active() {
            return Err(denied("system audio stopped or user session changed"));
        }
        if state.ended || state.heartbeat.elapsed() > HEARTBEAT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "system audio worker lost its heartbeat",
            ));
        }
        Ok(())
    }
    fn publish(&self, chunk: CapturedAudio, capacity: usize) -> io::Result<()> {
        let mut state = self.lock()?;
        if !self.active() {
            return Err(denied("audio stopped before PCM enqueue"));
        }
        if chunk.captured_at > Instant::now() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PCM time is in the future",
            ));
        }
        while state
            .queue
            .front()
            .is_some_and(|v| v.captured_at.elapsed() > CAPTURE_AGE)
        {
            state.queue.pop_front();
        }
        if chunk.captured_at.elapsed() <= CAPTURE_AGE {
            while state.queue.len() >= capacity {
                state.queue.pop_front();
            }
            state.queue.push_back(chunk);
        }
        self.wake.notify_all();
        Ok(())
    }
    fn pop(&self) -> io::Result<Option<CapturedAudio>> {
        let mut state = self.lock()?;
        if !self.active() {
            return Err(denied("audio stopped before PCM delivery"));
        }
        while state
            .queue
            .front()
            .is_some_and(|v| v.captured_at.elapsed() > CAPTURE_AGE)
        {
            state.queue.pop_front();
        }
        Ok(state.queue.pop_front())
    }
    fn finish(&self, result: io::Result<()>) {
        if let Ok(mut state) = self.state.lock() {
            state.queue.clear();
            if state.failure.is_none() {
                state.failure = result.err().map(Failure::from);
            }
            state.ended = true;
            state.cleanup.get_or_insert(Ok(()));
        }
        self.stopped.store(true, Ordering::SeqCst);
        self.wake.notify_all();
    }
    fn record_cleanup(&self, result: io::Result<()>) {
        if let Ok(mut state) = self.state.lock()
            && state.cleanup.as_ref().is_none_or(Result::is_ok)
        {
            state.cleanup = Some(result.map_err(Failure::from));
        }
    }
}
struct SessionObserver {
    observer: WindowsSessionObserver,
    shared: Arc<Shared>,
}
impl SessionObserver {
    fn pump(&self) {
        self.observer.pump();
    }
}
impl Drop for SessionObserver {
    fn drop(&mut self) {
        self.shared.record_cleanup(self.observer.close());
    }
}
struct Native {
    pointer: Option<NonNull<c_void>>,
    shared: Arc<Shared>,
}
impl Native {
    fn open(
        endpoint: &WindowsAudioEndpoint,
        channels: u8,
        capture: bool,
        shared: Arc<Shared>,
    ) -> io::Result<Self> {
        let mut pointer = null_mut();
        // SAFETY: private NUL-terminated local selection, checked channels, owned output.
        hresult(
            unsafe {
                nl_audio_open(
                    endpoint.id.as_ptr(),
                    u32::from(channels),
                    i32::from(capture),
                    &mut pointer,
                )
            },
            "initialize WASAPI 48kHz PCM",
        )?;
        Ok(Self {
            pointer: Some(
                NonNull::new(pointer)
                    .ok_or_else(|| io::Error::other("WASAPI returned a null client"))?,
            ),
            shared,
        })
    }
    fn pointer(&self) -> io::Result<*mut c_void> {
        self.pointer
            .map(NonNull::as_ptr)
            .ok_or_else(|| denied("native audio client closed"))
    }
    fn check(&self) -> io::Result<()> {
        // SAFETY: this MTA worker exclusively owns the live client.
        hresult(
            unsafe { nl_audio_check(self.pointer()?) },
            "check original WASAPI endpoint",
        )
    }
    fn start(&self) -> io::Result<()> {
        // SAFETY: same worker; capture call is armed only by authorized poll.
        hresult(
            unsafe { nl_audio_start(self.pointer()?) },
            "start WASAPI stream",
        )
    }
    fn capture(&self, buffer: &mut [i16]) -> io::Result<(usize, u64, Duration, bool)> {
        let (mut frames, mut position, mut age, mut flags) = (0, 0, 0, 0);
        // SAFETY: initialized fixed buffer with exact sample capacity; stack scalar outputs.
        hresult(
            unsafe {
                nl_audio_capture(
                    self.pointer()?,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut frames,
                    &mut position,
                    &mut age,
                    &mut flags,
                )
            },
            "read WASAPI loopback",
        )?;
        if frames as usize > MAX_PACKET_FRAMES || age > 50_000_000 || flags & !3 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WASAPI packet exceeded format/clock budget",
            ));
        }
        Ok((
            frames as usize,
            position,
            Duration::from_nanos(age * 100),
            flags & 1 != 0,
        ))
    }
    fn timing(&self) -> io::Result<AudioPlaybackTiming> {
        let (mut padding, mut latency) = (0, 0);
        // SAFETY: worker-owned initialized client and exact scalar outputs.
        hresult(
            unsafe { nl_audio_timing(self.pointer()?, &mut padding, &mut latency) },
            "read WASAPI output timing",
        )?;
        Ok(AudioPlaybackTiming {
            software_queued_frames: None,
            hardware_queued_frames: Some(padding),
            hardware_latency: Some(Duration::from_nanos((latency as u64) * 100)),
            observed_at: Some(Instant::now()),
        })
    }
    fn write(&self, samples: &[i16], channels: u8) -> io::Result<usize> {
        if samples.is_empty()
            || !samples.len().is_multiple_of(usize::from(channels))
            || samples.len() > CHUNK_FRAMES * usize::from(channels)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid WASAPI playback packet",
            ));
        }
        let frames = samples.len() / usize::from(channels);
        let mut written = 0;
        // SAFETY: borrowed validated PCM, synchronous copy, private worker-owned client.
        hresult(
            unsafe {
                nl_audio_write(
                    self.pointer()?,
                    samples.as_ptr(),
                    frames as u32,
                    &mut written,
                )
            },
            "queue WASAPI playback",
        )?;
        if written as usize > frames {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WASAPI wrote more than the submitted budget",
            ));
        }
        Ok(written as usize)
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        if let Some(pointer) = self.pointer.take() {
            // SAFETY: same worker stops, resets and releases each original COM interface once.
            let result = hresult(
                unsafe { nl_audio_close(pointer.as_ptr()) },
                "stop/reset WASAPI",
            );
            self.shared.record_cleanup(result);
        }
    }
}
trait Backend {
    fn timing(&self) -> io::Result<AudioPlaybackTiming> {
        Ok(AudioPlaybackTiming::default())
    }
    fn check(&self) -> io::Result<()>;
    fn start(&self) -> io::Result<()>;
    fn capture(&self, buffer: &mut [i16]) -> io::Result<(usize, u64, Duration, bool)>;
    fn write(&self, samples: &[i16], channels: u8) -> io::Result<usize>;
}
impl Backend for Native {
    fn timing(&self) -> io::Result<AudioPlaybackTiming> {
        Native::timing(self)
    }
    fn check(&self) -> io::Result<()> {
        Native::check(self)
    }
    fn start(&self) -> io::Result<()> {
        Native::start(self)
    }
    fn capture(&self, buffer: &mut [i16]) -> io::Result<(usize, u64, Duration, bool)> {
        Native::capture(self, buffer)
    }
    fn write(&self, samples: &[i16], channels: u8) -> io::Result<usize> {
        Native::write(self, samples, channels)
    }
}
struct Device {
    shared: Arc<Shared>,
    binding: AudioBinding,
    worker: Option<thread::JoinHandle<()>>,
    cleanup_deadline: Option<Instant>,
    cleanup_failure: Option<Failure>,
}
impl Device {
    fn open(
        endpoint: WindowsAudioEndpoint,
        binding: AudioBinding,
        capture: bool,
    ) -> io::Result<Self> {
        binding.validate()?;
        let shared = Arc::new(Shared::new());
        let work = shared.clone();
        let (ready, wait) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name(
                if capture {
                    "nestlink-wasapi-capture"
                } else {
                    "nestlink-wasapi-playback"
                }
                .into(),
            )
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(&work, endpoint, binding, capture, &ready)
                }))
                .unwrap_or_else(|_| Err(io::Error::other("WASAPI worker panicked")));
                if let Err(error) = &result {
                    let _ = ready.try_send(Err(io::Error::new(error.kind(), error.to_string())));
                }
                work.finish(result);
            })?;
        let mut device = Self {
            shared,
            binding,
            worker: Some(worker),
            cleanup_deadline: None,
            cleanup_failure: None,
        };
        match wait.recv_timeout(STARTUP) {
            Ok(Ok(())) => {
                device.check()?;
                Ok(device)
            }
            Ok(Err(error)) => {
                let _ = device.reset();
                Err(error)
            }
            Err(_) => {
                let _ = device.reset();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "WASAPI startup timed out",
                ))
            }
        }
    }
    fn check(&mut self) -> io::Result<()> {
        let result = self.shared.check();
        if let Err(error) = &result {
            if let Ok(mut state) = self.shared.state.lock()
                && state.failure.is_none()
            {
                state.failure = Some(Failure {
                    kind: error.kind(),
                    message: error.to_string(),
                });
            }
            self.shared.stop();
        }
        result
    }
    fn reset(&mut self) -> io::Result<()> {
        self.shared.stop();
        let deadline = *self
            .cleanup_deadline
            .get_or_insert_with(|| Instant::now() + CLEANUP);
        let mut state = self.shared.lock()?;
        while !state.ended {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.cleanup_failure.get_or_insert_with(|| {
                    Failure::from(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "original WASAPI cleanup exceeded its deadline",
                    ))
                });
                break;
            }
            state = self
                .shared
                .wake
                .wait_timeout(state, remaining)
                .map_err(|_| io::Error::other("audio cleanup wait poisoned"))?
                .0;
        }
        if state.ended
            && let Some(Err(error)) = &state.cleanup
        {
            self.cleanup_failure.get_or_insert_with(|| error.clone());
        }
        drop(state);
        if self.worker.as_ref().is_some_and(|v| v.is_finished())
            && let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            self.cleanup_failure.get_or_insert_with(|| {
                Failure::from(io::Error::other(
                    "original WASAPI worker panicked during cleanup",
                ))
            });
        }
        self.cleanup_failure
            .as_ref()
            .map_or(Ok(()), |error| Err(error.error()))
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.reset();
    }
}

fn run(
    shared: &Arc<Shared>,
    endpoint: WindowsAudioEndpoint,
    binding: AudioBinding,
    capture: bool,
    ready: &mpsc::SyncSender<io::Result<()>>,
) -> io::Result<()> {
    let observer = SessionObserver {
        observer: WindowsSessionObserver::open(shared.invalidated.clone(), false)?,
        shared: shared.clone(),
    };
    if !shared.active() || WindowsSessionSnapshot::current()? != endpoint.original {
        return Err(denied(
            "audio selection belongs to a different user session",
        ));
    }
    let native = Native::open(&endpoint, binding.channels, capture, shared.clone())?;
    // SAFETY: own client on its creating worker; this query never reads PCM.
    if unsafe { nl_audio_started(native.pointer()?) } != 0 {
        return Err(io::Error::other(
            "WASAPI initialized an already started stream",
        ));
    }
    observer.pump();
    if !shared.active() || WindowsSessionSnapshot::current()? != endpoint.original {
        return Err(denied("audio user session changed during initialization"));
    }
    native.check()?;
    shared.lock()?.heartbeat = Instant::now();
    ready
        .send(Ok(()))
        .map_err(|_| denied("audio caller ended during initialization"))?;
    drive(shared, binding, capture, &native, || {
        observer.pump();
        if !shared.active() || WindowsSessionSnapshot::current()? != endpoint.original {
            return Err(denied(
                "audio user session locked, disconnected or changed desktop",
            ));
        }
        Ok(())
    })
}
fn drive(
    shared: &Shared,
    binding: AudioBinding,
    capture: bool,
    native: &impl Backend,
    mut facts: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    let mut assembler = Assembler::new(binding.source, binding.channels)?;
    let mut buffer = vec![0; MAX_PACKET_FRAMES * usize::from(binding.channels)];
    let mut playing: Option<(CapturedAudio, usize)> = None;
    while !shared.stopped.load(Ordering::SeqCst) {
        facts()?;
        native.check()?;
        shared.lock()?.heartbeat = Instant::now();
        if !capture {
            shared.lock()?.output_timing = native.timing()?;
        }
        if shared.armed.load(Ordering::SeqCst) {
            if !shared.active() {
                break;
            }
            native.start()?;
            // A driver can return from Start after the lease/platform was stopped.
            // Observe cancellation and session events before another native call.
            if shared.stopped.load(Ordering::SeqCst) {
                break;
            }
            facts()?;
            if !shared.active() {
                break;
            }
            if capture {
                let before = Instant::now();
                let (frames, position, age, discontinuity) = native.capture(&mut buffer)?;
                facts()?;
                if !shared.active() {
                    break;
                }
                if frames > 0 {
                    let captured_at = before
                        .checked_sub(age)
                        .ok_or_else(|| io::Error::other("WASAPI sample timestamp underflow"))?;
                    for chunk in assembler.push(
                        position,
                        captured_at,
                        discontinuity,
                        &buffer[..frames * usize::from(binding.channels)],
                    )? {
                        shared.publish(chunk, CAPTURE_QUEUED)?;
                    }
                }
            } else {
                if playing
                    .as_ref()
                    .is_some_and(|(chunk, _)| chunk.captured_at.elapsed() > CAPTURE_AGE)
                {
                    playing = None;
                }
                if playing.is_none() {
                    playing = shared.pop()?.map(|chunk| (chunk, 0));
                }
                if let Some((chunk, offset)) = &mut playing {
                    if !shared.active() {
                        break;
                    }
                    let written =
                        native.write(&chunk.chunk.samples[*offset..], binding.channels)?;
                    *offset += written * usize::from(binding.channels);
                    if *offset == chunk.chunk.samples.len() {
                        playing = None;
                    }
                }
            }
        }
        let mut state = shared.lock()?;
        state.playing_frames = playing.as_ref().map_or(0, |(chunk, offset)| {
            ((chunk.chunk.samples.len() - offset) / usize::from(binding.channels)) as u32
        });
        if shared.stopped.load(Ordering::SeqCst) {
            break;
        }
        let _ = shared
            .wake
            .wait_timeout(state, TICK)
            .map_err(|_| io::Error::other("audio worker wait poisoned"))?;
    }
    Ok(())
}

pub struct WindowsAudioCapture(Device);
impl WindowsAudioCapture {
    /// Initialize only. The first poll under AudioCaptureController arms loopback.
    pub fn open(endpoint: WindowsAudioEndpoint, binding: AudioBinding) -> io::Result<Self> {
        Device::open(endpoint, binding, true).map(Self)
    }
}
impl AudioDevice for WindowsAudioCapture {
    fn check(&mut self) -> io::Result<()> {
        self.0.check()
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0.reset()
    }
}
impl AudioCaptureDevice for WindowsAudioCapture {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        self.check()?;
        self.0.shared.armed.store(true, Ordering::SeqCst);
        self.0.shared.wake.notify_all();
        self.0.shared.pop()
    }
}
pub struct WindowsAudioPlayback(Device);
impl WindowsAudioPlayback {
    pub fn open(endpoint: WindowsAudioEndpoint, binding: AudioBinding) -> io::Result<Self> {
        Device::open(endpoint, binding, false).map(Self)
    }
}
impl AudioDevice for WindowsAudioPlayback {
    fn check(&mut self) -> io::Result<()> {
        self.0.check()
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0.reset()
    }
}
impl AudioPlaybackDevice for WindowsAudioPlayback {
    fn timing(&mut self) -> io::Result<AudioPlaybackTiming> {
        self.check()?;
        let state = self.0.shared.lock()?;
        let mut facts = state.output_timing;
        facts.software_queued_frames =
            Some((state.queue.len() * CHUNK_FRAMES) as u32 + state.playing_frames);
        Ok(facts)
    }
    fn enqueue(&mut self, chunk: &AudioChunk) -> io::Result<()> {
        self.check()?;
        chunk.validate(self.0.binding)?;
        self.0.shared.publish(
            CapturedAudio {
                captured_at: Instant::now(),
                chunk: AudioChunk {
                    source: chunk.source,
                    channels: chunk.channels,
                    pts_48khz: chunk.pts_48khz,
                    samples: chunk.samples.clone(),
                },
            },
            PLAYBACK_QUEUED,
        )?;
        self.0.shared.armed.store(true, Ordering::SeqCst);
        self.0.shared.wake.notify_all();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
