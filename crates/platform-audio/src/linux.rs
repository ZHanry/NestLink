//! Original local PipeWire sink, checked graph links, and terminal PCM workers.
#![allow(unsafe_code)]
use crate::pcm::Assembler;
use nestlink_platform_session::LinuxDesktopSession;
use nestlink_remote::audio::{
    AudioBinding, AudioCaptureDevice, AudioChunk, AudioDevice, AudioPlaybackDevice,
    AudioPlaybackTiming, CAPTURE_AGE, CHUNK_FRAMES, CapturedAudio,
};
use std::{
    collections::VecDeque,
    ffi::{CStr, CString, c_char, c_void},
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    sync::{
        Arc, Condvar, Mutex, Once,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const STARTUP: Duration = Duration::from_secs(3);
const HEARTBEAT: Duration = Duration::from_millis(250);
const CLEANUP: Duration = Duration::from_millis(150);
const CAPTURE_QUEUED: usize = 5;
const PLAYBACK_QUEUED: usize = 1; // plus current chunk <=40ms; native queue <=60ms.
#[repr(C)]
struct Target {
    node: u32,
    cookie: u32,
    serial: u64,
    name: *const c_char,
}
#[repr(C)]
struct Packet {
    position: u64,
    age_ns: u64,
    frames: u32,
    discontinuity: u32,
    graph_rate_num: u32,
    graph_rate_denom: u32,
}
type EndpointCallback =
    unsafe extern "C" fn(*mut c_void, u32, u32, u64, *const c_char, *const c_char) -> i32;
type ControlCallback = unsafe extern "C" fn(*mut c_void, i32, i32) -> i32;
type CaptureCallback = unsafe extern "C" fn(*mut c_void, *const Packet, *const i16) -> i32;
#[repr(C)]
struct PlaybackTiming {
    latency_ns: u64,
    queued_frames: u32,
    latency_known: u32,
}
type PlaybackCallback =
    unsafe extern "C" fn(*mut c_void, *mut i16, u32, *const PlaybackTiming) -> i32;
unsafe extern "C" {
    fn nl_pw_audio_init();
    fn nl_pw_audio_enumerate(
        fd: i32,
        cancel: i32,
        endpoint: EndpointCallback,
        control: ControlCallback,
        user: *mut c_void,
        cookie: *mut u32,
    ) -> i32;
    fn nl_pw_audio_run(
        fd: i32,
        cancel: i32,
        target: *const Target,
        channels: u32,
        capture: i32,
        control: ControlCallback,
        read: CaptureCallback,
        write: PlaybackCallback,
        user: *mut c_void,
        cleanup: *mut i32,
    ) -> i32;
}
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn native(code: i32, operation: &'static str) -> io::Result<()> {
    if code >= 0 {
        return Ok(());
    }
    let kind = match -code {
        libc::ESTALE | libc::ECANCELED => io::ErrorKind::PermissionDenied,
        libc::ENOENT | libc::EPIPE => io::ErrorKind::NotConnected,
        libc::EINVAL | libc::EOVERFLOW => io::ErrorKind::InvalidData,
        libc::ENOTSUP => io::ErrorKind::Unsupported,
        libc::ENOSPC | libc::ENOBUFS => io::ErrorKind::OutOfMemory,
        _ => io::ErrorKind::Other,
    };
    Err(io::Error::new(
        kind,
        format!(
            "{operation}: {} (errno {})",
            io::Error::from_raw_os_error(-code),
            -code
        ),
    ))
}
fn eventfd() -> io::Result<OwnedFd> {
    // SAFETY: scalar flags; each successful fd is wrapped once and owned.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh owned descriptor returned above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
fn signal(fd: &OwnedFd) {
    let value = 1u64;
    // SAFETY: owned nonblocking eventfd; the scalar is borrowed for this call.
    unsafe {
        libc::write(
            fd.as_raw_fd(),
            (&value as *const u64).cast(),
            size_of::<u64>(),
        );
    }
}
fn init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: process-wide PipeWire initialization, serialized once.
        unsafe {
            nl_pw_audio_init();
        }
    });
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    pid: i32,
    uid: u32,
}
struct Server {
    directory: File,
    identity: SocketIdentity,
    desktop: Arc<LinuxDesktopSession>,
}
impl Server {
    fn is_current(&self) -> bool {
        self.desktop.is_active()
            && socket_stat(&self.directory, self.identity.uid).is_ok_and(|stat| {
                stat.st_dev == self.identity.device && stat.st_ino == self.identity.inode
            })
    }
    fn open(desktop: Arc<LinuxDesktopSession>, runtime: &Path) -> io::Result<(Arc<Self>, OwnedFd)> {
        if !runtime.is_absolute() || runtime.as_os_str().len() > 4096 || !desktop.is_active() {
            return Err(denied(
                "a current local desktop and absolute audio runtime directory are required",
            ));
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(runtime)?;
        let meta = directory.metadata()?;
        // SAFETY: scalar UID query, no memory or ownership involved.
        let uid = unsafe { libc::geteuid() };
        if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
            return Err(denied(
                "PipeWire runtime directory must be private and owned by this user",
            ));
        }
        let (fd, identity) = connect(&directory, uid)?;
        if !desktop.is_active() {
            return Err(denied("desktop ended while connecting to audio server"));
        }
        Ok((
            Arc::new(Self {
                directory,
                identity,
                desktop,
            }),
            fd,
        ))
    }
    fn connect(&self) -> io::Result<OwnedFd> {
        if !self.is_current() {
            return Err(denied("original audio desktop ended"));
        }
        let (fd, identity) = connect(&self.directory, self.identity.uid)?;
        if identity != self.identity || !self.is_current() {
            return Err(denied("original PipeWire socket or peer changed"));
        }
        Ok(fd)
    }
}
/// Connect through the retained directory descriptor, so a pathname replacement
/// cannot redirect a selected endpoint. Peer credentials and inode are pinned.
fn socket_stat(directory: &File, uid: u32) -> io::Result<libc::stat> {
    let socket = c"pipewire-0";
    // SAFETY: initialized output and NUL-terminated basename, owned directory fd.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            socket.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK || stat.st_uid != uid {
        return Err(denied("audio service must be this user's Unix socket"));
    }
    Ok(stat)
}
fn connect(directory: &File, uid: u32) -> io::Result<(OwnedFd, SocketIdentity)> {
    let stat = socket_stat(directory, uid)?;
    let path = format!("/proc/self/fd/{}/pipewire-0", directory.as_raw_fd());
    // SAFETY: POD sockaddr output initialized before copying bounded pathname.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path.len() >= address.sun_path.len() {
        return Err(denied("audio socket path exceeds ABI budget"));
    }
    address.sun_family = libc::AF_UNIX as _;
    for (out, value) in address.sun_path.iter_mut().zip(path.bytes()) {
        *out = value as c_char;
    }
    // SAFETY: scalar arguments; fresh fd wrapped once below.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh descriptor from socket.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: valid initialized sockaddr with its exact native length.
    if unsafe {
        libc::connect(
            raw,
            (&address as *const libc::sockaddr_un).cast(),
            size_of::<libc::sockaddr_un>() as _,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let mut poll = libc::pollfd {
            fd: raw,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one initialized descriptor entry; bounded local wait.
        if unsafe { libc::poll(&mut poll, 1, 150) } <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local audio socket connect timed out",
            ));
        }
        let mut status: i32 = 0;
        let mut length = size_of::<i32>() as libc::socklen_t;
        // SAFETY: exact scalar output length; owned socket descriptor.
        if unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut status as *mut i32).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if length as usize != size_of::<i32>() || status != 0 {
            return Err(io::Error::from_raw_os_error(status.max(libc::EIO)));
        }
    }
    // SAFETY: initialized POD output; exact SO_PEERCRED output capacity.
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::ucred>() || peer.uid != uid || peer.pid <= 0 {
        return Err(denied("audio Unix peer identity mismatch"));
    }
    let after = socket_stat(directory, uid)?;
    if stat.st_dev != after.st_dev || stat.st_ino != after.st_ino {
        return Err(denied("audio socket changed while connecting"));
    }
    Ok((
        fd,
        SocketIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            pid: peer.pid,
            uid,
        },
    ))
}

/// Opaque sink selected from a local inventory. It cannot identify a microphone.
#[derive(Clone)]
pub struct LinuxAudioEndpoint {
    server: Arc<Server>,
    node: u32,
    cookie: u32,
    serial: u64,
    name: CString,
    description: String,
}
impl LinuxAudioEndpoint {
    pub fn name(&self) -> &str {
        self.name.to_str().unwrap_or("invalid local endpoint")
    }
    pub fn description(&self) -> &str {
        &self.description
    }
    pub fn serial(&self) -> u64 {
        self.serial
    }
    /// Read inventory only. Use the real graphical GUI PID to open `desktop`;
    /// selecting an endpoint never starts recording or playback.
    pub fn enumerate(desktop: Arc<LinuxDesktopSession>) -> io::Result<Vec<Self>> {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .ok_or_else(|| denied("XDG_RUNTIME_DIR is required for local PipeWire inventory"))?;
        Self::enumerate_at(desktop, Path::new(&runtime))
    }
    /// A trusted local GUI may choose a different private runtime directory.
    /// No network address or arbitrary node ID is accepted.
    pub fn enumerate_at(
        desktop: Arc<LinuxDesktopSession>,
        runtime: &Path,
    ) -> io::Result<Vec<Self>> {
        let (server, fd) = Server::open(desktop, runtime)?;
        let cancel = Arc::new(eventfd()?);
        let cancel_worker = cancel.clone();
        let endpoint_server = server.clone();
        let (ready, wait) = mpsc::sync_channel(1);
        let deadline = Instant::now() + STARTUP;
        let worker = thread::Builder::new()
            .name("nestlink-audio-inventory".into())
            .spawn(move || {
                let mut enumeration = Enumeration {
                    server: endpoint_server,
                    values: Vec::new(),
                    deadline,
                    failure: None,
                };
                let mut cookie = 0;
                init();
                // SAFETY: fd consumed on all paths; cancel and context retained until
                // C returns; stack context is only accessed by synchronous callbacks.
                let code = unsafe {
                    nl_pw_audio_enumerate(
                        fd.into_raw_fd(),
                        cancel_worker.as_raw_fd(),
                        endpoint_callback,
                        enumeration_control,
                        (&mut enumeration as *mut Enumeration).cast(),
                        &mut cookie,
                    )
                };
                let result = (|| {
                    if let Some(error) = enumeration.failure {
                        return Err(error);
                    }
                    native(code, "PipeWire sink inventory")?;
                    if !enumeration.server.is_current() {
                        return Err(denied("desktop ended during audio inventory"));
                    }
                    Ok(enumeration.values)
                })();
                let _ = ready.send(result);
            })?;
        let result = wait.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        if result.is_err() {
            signal(&cancel);
        }
        if worker.is_finished() {
            let _ = worker.join();
        }
        result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "audio inventory timed out"))?
    }
}
struct Enumeration {
    server: Arc<Server>,
    values: Vec<LinuxAudioEndpoint>,
    deadline: Instant,
    failure: Option<io::Error>,
}
unsafe extern "C" fn enumeration_control(context: *mut c_void, _timer: i32, _ready: i32) -> i32 {
    // SAFETY: exact stack Enumeration synchronously borrowed by C.
    let output = unsafe { &mut *context.cast::<Enumeration>() };
    if Instant::now() >= output.deadline || !output.server.is_current() {
        -libc::ECANCELED
    } else {
        0
    }
}
unsafe extern "C" fn endpoint_callback(
    context: *mut c_void,
    node: u32,
    cookie: u32,
    serial: u64,
    name: *const c_char,
    description: *const c_char,
) -> i32 {
    // SAFETY: exact stack Enumeration, sequential synchronous native callbacks.
    let output = unsafe { &mut *context.cast::<Enumeration>() };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if node == 0
            || node == u32::MAX
            || serial == 0
            || name.is_null()
            || description.is_null()
            || output.values.len() >= 64
            || output
                .values
                .iter()
                .any(|v| v.node == node || v.serial == serial)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid or duplicate audio endpoint",
            ));
        }
        // SAFETY: C validates NUL termination and bounds in its own 1024-byte storage.
        let name = unsafe { CStr::from_ptr(name) }
            .to_str()
            .map_err(io::Error::other)?;
        // SAFETY: same validated C-owned bounded storage, borrowed until callback returns.
        let description = unsafe { CStr::from_ptr(description) }
            .to_str()
            .map_err(io::Error::other)?;
        if name.is_empty()
            || name.len() >= 1024
            || description.len() >= 1024
            || name.chars().any(char::is_control)
            || description.chars().any(char::is_control)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid audio endpoint text",
            ));
        }
        output.values.push(LinuxAudioEndpoint {
            server: output.server.clone(),
            node,
            cookie,
            serial,
            name: CString::new(name).map_err(io::Error::other)?,
            description: description.to_owned(),
        });
        Ok(())
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            output.failure.get_or_insert(error);
            -libc::EINVAL
        }
        Err(_) => {
            output
                .failure
                .get_or_insert(io::Error::other("audio inventory callback panicked"));
            -libc::EIO
        }
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
    queue: VecDeque<CapturedAudio>,
    playing: Option<(CapturedAudio, usize)>,
    heartbeat: Instant,
    ready: bool,
    native_progress: i32,
    #[cfg(test)]
    graph_rate: Option<(u32, u32)>,
    armed_at: Option<Instant>,
    ended: bool,
    failure: Option<Failure>,
    cleanup: Option<Result<(), Failure>>,
}
struct Shared {
    stopped: AtomicBool,
    armed: AtomicBool,
    cancel: OwnedFd,
    state: Mutex<State>,
    changed: Condvar,
    active: Box<dyn Fn() -> bool + Send + Sync>,
    started: Instant,
}
impl Shared {
    fn new(active: Box<dyn Fn() -> bool + Send + Sync>) -> io::Result<Self> {
        Ok(Self {
            stopped: AtomicBool::new(false),
            armed: AtomicBool::new(false),
            cancel: eventfd()?,
            state: Mutex::new(State {
                output_timing: AudioPlaybackTiming::default(),
                queue: VecDeque::new(),
                playing: None,
                heartbeat: Instant::now(),
                ready: false,
                native_progress: 0,
                #[cfg(test)]
                graph_rate: None,
                armed_at: None,
                ended: false,
                failure: None,
                cleanup: None,
            }),
            changed: Condvar::new(),
            active,
            started: Instant::now(),
        })
    }
    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("PipeWire audio state poisoned"))
    }
    fn facts(&self, state: &State) -> io::Result<()> {
        if let Some(error) = &state.failure {
            return Err(error.error());
        }
        if self.stopped.load(Ordering::SeqCst) || !(self.active)() {
            return Err(denied("original audio desktop or stream ended"));
        }
        if state.ended || state.heartbeat.elapsed() > HEARTBEAT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original PipeWire audio worker stalled",
            ));
        }
        Ok(())
    }
    fn fail(&self, error: io::Error) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Ok(mut state) = self.state.lock() {
            state.failure.get_or_insert_with(|| error.into());
            state.queue.clear();
            state.playing = None;
        }
        signal(&self.cancel);
        self.changed.notify_all();
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Ok(mut state) = self.state.lock() {
            state.queue.clear();
            state.playing = None;
        }
        signal(&self.cancel);
        self.changed.notify_all();
    }
    fn check(&self) -> io::Result<()> {
        let result = self.lock().and_then(|state| self.facts(&state));
        if let Err(error) = &result {
            self.fail(io::Error::new(error.kind(), error.to_string()));
        }
        result
    }
    fn control(&self, timer: bool, progress: i32) -> io::Result<i32> {
        if self.stopped.load(Ordering::SeqCst) {
            return Ok(2);
        }
        let mut state = self.lock()?;
        self.facts(&state)?;
        // Timer callbacks exclusively renew worker progress. Late callbacks
        // cannot restore facts that have already expired.
        if timer {
            state.heartbeat = Instant::now();
        }
        state.native_progress = progress;
        if progress & 1 != 0 && !state.ready {
            state.ready = true;
            self.changed.notify_all();
        }
        if !state.ready && self.started.elapsed() > STARTUP {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "selected audio sink did not become ready",
            ));
        }
        let armed = self.armed.load(Ordering::SeqCst);
        if armed
            && progress & 32 == 0
            && state.armed_at.get_or_insert_with(Instant::now).elapsed() > HEARTBEAT
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "selected audio stream did not negotiate PCM after activation",
            ));
        }
        Ok(i32::from(armed))
    }
    fn complete(&self, result: io::Result<()>, cleanup: io::Result<()>) {
        if let Err(error) = result {
            self.fail(error);
        }
        if let Ok(mut state) = self.state.lock() {
            state.queue.clear();
            state.playing = None;
            state.ended = true;
            state
                .cleanup
                .get_or_insert_with(|| cleanup.map_err(Failure::from));
        }
        self.changed.notify_all();
    }
    fn captured(&self, chunks: Vec<CapturedAudio>) -> io::Result<()> {
        let mut state = self.lock()?;
        self.facts(&state)?;
        for chunk in chunks {
            if chunk.captured_at.elapsed() > CAPTURE_AGE {
                continue;
            }
            while state.queue.len() >= CAPTURE_QUEUED {
                state.queue.pop_front();
            }
            state.queue.push_back(chunk);
        }
        Ok(())
    }
    fn fill(&self, output: &mut [i16], channels: usize) -> io::Result<()> {
        let mut state = self.lock()?;
        self.facts(&state)?;
        output.fill(0);
        let mut offset = 0;
        while offset < output.len() {
            if state
                .playing
                .as_ref()
                .is_some_and(|(chunk, _)| chunk.captured_at.elapsed() > CAPTURE_AGE)
            {
                state.playing = None;
            }
            if state.playing.is_none() {
                while let Some(chunk) = state.queue.pop_front() {
                    if chunk.captured_at.elapsed() <= CAPTURE_AGE {
                        state.playing = Some((chunk, 0));
                        break;
                    }
                }
            }
            let Some((chunk, cursor)) = state.playing.as_mut() else {
                break;
            };
            let count = (output.len() - offset).min(chunk.chunk.samples.len() - *cursor);
            if !count.is_multiple_of(channels) {
                return Err(io::Error::other("audio callback split a sample frame"));
            }
            output[offset..offset + count]
                .copy_from_slice(&chunk.chunk.samples[*cursor..*cursor + count]);
            offset += count;
            *cursor += count;
            if *cursor == chunk.chunk.samples.len() {
                state.playing = None;
            }
        }
        Ok(())
    }
}
struct Context {
    shared: Arc<Shared>,
    server: Arc<Server>,
    assembler: Assembler,
    channels: u8,
}
fn guarded(shared: &Shared, call: impl FnOnce() -> io::Result<i32>) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(call)) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            shared.fail(error);
            -libc::ECANCELED
        }
        Err(_) => {
            shared.fail(io::Error::other("PipeWire audio callback panicked"));
            -libc::EIO
        }
    }
}
unsafe extern "C" fn control_callback(context: *mut c_void, timer: i32, ready: i32) -> i32 {
    // SAFETY: exact worker Context, exclusively synchronous callbacks from its loop.
    let context = unsafe { &*context.cast::<Context>() };
    guarded(&context.shared, || {
        // Filesystem facts stay on this worker, outside shared/lease locks.
        // A stalled local syscall cannot hide the cached heartbeat deadline.
        if !context.server.is_current() {
            return Err(denied("original PipeWire socket or desktop ended"));
        }
        context.shared.control(timer != 0, ready)
    })
}
unsafe extern "C" fn capture_callback(
    context: *mut c_void,
    packet: *const Packet,
    samples: *const i16,
) -> i32 {
    // SAFETY: exact worker Context, sequential non-RT callbacks, no Rust reference
    // survives a callback or overlaps another callback.
    let context = unsafe { &mut *context.cast::<Context>() };
    let shared = context.shared.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
        if packet.is_null()
            || samples.is_null()
            || !samples.addr().is_multiple_of(align_of::<i16>())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native PCM pointers",
            ));
        }
        // SAFETY: C borrows this initialized fixed-size packet for the callback.
        let packet = unsafe { &*packet };
        if packet.frames == 0
            || packet.frames as usize > CHUNK_FRAMES * 2
            || packet.discontinuity > 1
            || packet.age_ns > 100_000_000
            || packet.graph_rate_num == 0
            || packet.graph_rate_denom == 0
            || packet.graph_rate_num > 1_000_000
            || packet.graph_rate_denom > 1_000_000
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native PCM packet exceeds budget",
            ));
        }
        let age = Duration::from_nanos(packet.age_ns)
            + Duration::from_nanos(u64::from(packet.frames) * 1_000_000_000 / 48_000);
        let captured_at = Instant::now()
            .checked_sub(age)
            .ok_or_else(|| io::Error::other("audio timestamp underflow"))?;
        // SAFETY: C validates mapped data, stride, offset and size before callback.
        let samples = unsafe {
            std::slice::from_raw_parts(
                samples,
                packet.frames as usize * usize::from(context.channels),
            )
        };
        shared.check()?;
        #[cfg(test)]
        {
            shared.lock()?.graph_rate = Some((packet.graph_rate_num, packet.graph_rate_denom));
        }
        let chunks = context.assembler.push(
            packet.position,
            captured_at,
            packet.discontinuity != 0,
            samples,
        )?;
        shared.captured(chunks)
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            shared.fail(error);
            -libc::ECANCELED
        }
        Err(_) => {
            shared.fail(io::Error::other("audio capture callback panicked"));
            -libc::EIO
        }
    }
}
unsafe extern "C" fn playback_callback(
    context: *mut c_void,
    samples: *mut i16,
    frames: u32,
    timing: *const PlaybackTiming,
) -> i32 {
    // SAFETY: exact worker Context exclusively borrowed during this callback.
    let context = unsafe { &*context.cast::<Context>() };
    guarded(&context.shared, || {
        if samples.is_null()
            || !samples.addr().is_multiple_of(align_of::<i16>())
            || frames == 0
            || frames as usize > CHUNK_FRAMES * 2
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native playback buffer exceeds budget",
            ));
        }
        if timing.is_null() || !timing.addr().is_multiple_of(align_of::<PlaybackTiming>()) {
            return Err(io::Error::other("native playback timing missing"));
        }
        // SAFETY: exact same C/Rust narrow ABI, borrowed for this callback.
        let timing = unsafe { &*timing };
        if timing.queued_frames > 2880
            || timing.latency_known > 1
            || timing.latency_ns > 250_000_000
        {
            return Err(io::Error::other("native playback timing exceeds budget"));
        }
        context.shared.lock()?.output_timing = AudioPlaybackTiming {
            software_queued_frames: None,
            hardware_queued_frames: Some(timing.queued_frames),
            hardware_latency: (timing.latency_known == 1)
                .then_some(Duration::from_nanos(timing.latency_ns)),
            observed_at: Some(Instant::now()),
        };
        // SAFETY: bounded native mapped output; C validates full writable capacity.
        let output = unsafe {
            std::slice::from_raw_parts_mut(samples, frames as usize * usize::from(context.channels))
        };
        context.shared.fill(output, usize::from(context.channels))?;
        Ok(0)
    })
}
struct Device {
    shared: Arc<Shared>,
    worker: Option<thread::JoinHandle<()>>,
    cleanup_until: Option<Instant>,
}
impl Device {
    fn open(
        endpoint: LinuxAudioEndpoint,
        binding: AudioBinding,
        capture: bool,
    ) -> io::Result<Self> {
        binding.validate()?;
        let session = endpoint.server.desktop.state();
        let shared = Arc::new(Shared::new(Box::new(move || session.is_active()))?);
        let context_shared = shared.clone();
        let worker = thread::Builder::new()
            .name(
                if capture {
                    "nestlink-audio-capture"
                } else {
                    "nestlink-audio-playback"
                }
                .into(),
            )
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
                        let fd = endpoint.server.connect()?;
                        let mut context = Context {
                            shared: context_shared.clone(),
                            server: endpoint.server.clone(),
                            assembler: Assembler::new(binding.source, binding.channels)?,
                            channels: binding.channels,
                        };
                        let target = Target {
                            node: endpoint.node,
                            cookie: endpoint.cookie,
                            serial: endpoint.serial,
                            name: endpoint.name.as_ptr(),
                        };
                        let mut cleanup = 0;
                        init();
                        // SAFETY: fd transferred on every path; all pointers and callback
                        // contexts remain alive on this worker until C finishes cleanup.
                        let code = unsafe {
                            nl_pw_audio_run(
                                fd.into_raw_fd(),
                                context_shared.cancel.as_raw_fd(),
                                &target,
                                u32::from(binding.channels),
                                i32::from(capture),
                                control_callback,
                                capture_callback,
                                playback_callback,
                                (&mut context as *mut Context).cast(),
                                &mut cleanup,
                            )
                        };
                        context_shared.complete(
                            native(code, "PipeWire audio stream"),
                            native(cleanup, "PipeWire audio cleanup"),
                        );
                        Ok(())
                    }));
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => context_shared.complete(Err(error), Ok(())),
                    Err(_) => context_shared.complete(
                        Err(io::Error::other("audio worker panicked")),
                        Err(io::Error::other("audio cleanup could not be proven")),
                    ),
                }
            })?;
        let mut device = Self {
            shared,
            worker: Some(worker),
            cleanup_until: None,
        };
        let result = (|| {
            let state = device.shared.lock()?;
            let (state, _) = device
                .shared
                .changed
                .wait_timeout_while(state, STARTUP, |state| {
                    !state.ready && !state.ended && state.failure.is_none()
                })
                .map_err(|_| io::Error::other("audio startup state poisoned"))?;
            if let Some(error) = &state.failure {
                return Err(error.error());
            }
            if !state.ready || state.ended {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "selected audio sink startup failed (native facts 0x{:02x})",
                        state.native_progress
                    ),
                ));
            }
            device.shared.facts(&state)
        })();
        if let Err(error) = result {
            let _ = device.reset();
            return Err(error);
        }
        Ok(device)
    }
    fn reset(&mut self) -> io::Result<()> {
        self.shared.stop();
        let until = *self
            .cleanup_until
            .get_or_insert_with(|| Instant::now() + CLEANUP);
        let state = self.shared.lock()?;
        let (mut state, _) = self
            .shared
            .changed
            .wait_timeout_while(
                state,
                until.saturating_duration_since(Instant::now()),
                |state| state.cleanup.is_none(),
            )
            .map_err(|_| io::Error::other("audio cleanup state poisoned"))?;
        if state.cleanup.is_none() {
            state.cleanup = Some(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original PipeWire audio cleanup exceeded deadline",
            )
            .into()));
        }
        let result = match &state.cleanup {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(error.error()),
            None => Err(io::Error::other("audio cleanup result missing")),
        };
        drop(state);
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
            && let Some(worker) = self.worker.take()
        {
            let _ = worker.join();
        }
        result
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.reset();
    }
}
pub struct LinuxAudioCapture(Device);
impl LinuxAudioCapture {
    pub fn open(endpoint: LinuxAudioEndpoint, binding: AudioBinding) -> io::Result<Self> {
        Device::open(endpoint, binding, true).map(Self)
    }
}
impl AudioDevice for LinuxAudioCapture {
    fn check(&mut self) -> io::Result<()> {
        self.0.shared.check()
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0.reset()
    }
}
impl AudioCaptureDevice for LinuxAudioCapture {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        self.check()?;
        self.0.shared.armed.store(true, Ordering::SeqCst);
        let mut state = self.0.shared.lock()?;
        self.0.shared.facts(&state)?;
        while let Some(chunk) = state.queue.pop_front() {
            if chunk.captured_at.elapsed() <= CAPTURE_AGE {
                return Ok(Some(chunk));
            }
        }
        Ok(None)
    }
}
pub struct LinuxAudioPlayback {
    device: Device,
    binding: AudioBinding,
}
impl LinuxAudioPlayback {
    pub fn open(endpoint: LinuxAudioEndpoint, binding: AudioBinding) -> io::Result<Self> {
        Ok(Self {
            device: Device::open(endpoint, binding, false)?,
            binding,
        })
    }
}
impl AudioDevice for LinuxAudioPlayback {
    fn check(&mut self) -> io::Result<()> {
        self.device.shared.check()
    }
    fn reset(&mut self) -> io::Result<()> {
        self.device.reset()
    }
}
impl AudioPlaybackDevice for LinuxAudioPlayback {
    fn timing(&mut self) -> io::Result<AudioPlaybackTiming> {
        self.check()?;
        let state = self.device.shared.lock()?;
        self.device.shared.facts(&state)?;
        let mut facts = state.output_timing;
        let active = state.playing.as_ref().map_or(0, |(chunk, offset)| {
            (chunk.chunk.samples.len() - offset) / usize::from(self.binding.channels)
        });
        facts.software_queued_frames = Some((state.queue.len() * CHUNK_FRAMES + active) as u32);
        Ok(facts)
    }
    fn enqueue(&mut self, chunk: &AudioChunk) -> io::Result<()> {
        self.check()?;
        chunk.validate(self.binding)?;
        let mut state = self.device.shared.lock()?;
        self.device.shared.facts(&state)?;
        while state.queue.len() >= PLAYBACK_QUEUED {
            state.queue.pop_front();
        }
        state.queue.push_back(CapturedAudio {
            captured_at: Instant::now(),
            chunk: AudioChunk {
                source: chunk.source,
                channels: chunk.channels,
                pts_48khz: chunk.pts_48khz,
                samples: chunk.samples.clone(),
            },
        });
        self.device.shared.armed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;
