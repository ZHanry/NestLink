//! PipeWire's C ABI is isolated here. OS grants constrain, never issue, permits.
#![allow(unsafe_code)]
use nestlink_platform_input::portal::{
    PortalControl, PortalInfo, PortalInput, PortalStream, PortalView,
};
use nestlink_remote::video::{CaptureDevice, Display, RAW_FRAME_BYTES, RawFrame};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::c_void,
    io,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
    sync::{
        Arc, Condvar, Mutex, Once,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
const QUEUE_BYTES: usize = 128 * 1024 * 1024;
const CLEANUP: Duration = Duration::from_millis(150);
const HEARTBEAT: Duration = Duration::from_millis(250);
const STARTUP: Duration = Duration::from_secs(5);
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct FrameDescription {
    kind: u32,
    node: u32,
    width: u32,
    height: u32,
    format: u32,
    stride: i32,
    first_row: u32,
    crop_x: u32,
    crop_y: u32,
    crop_width: u32,
    crop_height: u32,
    transform: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameView {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    transform: u32,
}
impl FrameDescription {
    fn view(self) -> io::Result<FrameView> {
        if self.width == 0
            || self.height == 0
            || self.width > 8192
            || self.height > 8192
            || !(1..=6).contains(&self.format)
            || u64::from(self.width) * u64::from(self.height) * 4 > RAW_FRAME_BYTES as u64
            || self.crop_width == 0
            || self.crop_height == 0
            || self.transform > 7
            || u64::from(self.crop_x) + u64::from(self.crop_width) > u64::from(self.width)
            || u64::from(self.crop_y) + u64::from(self.crop_height) > u64::from(self.height)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid capture geometry",
            ));
        }
        Ok(FrameView {
            x: self.crop_x,
            y: self.crop_y,
            width: self.crop_width,
            height: self.crop_height,
            transform: self.transform,
        })
    }
}
impl FrameView {
    fn dimensions(self) -> (u32, u32) {
        if self.transform & 1 == 0 {
            (self.width, self.height)
        } else {
            (self.height, self.width)
        }
    }
}
type Callback = unsafe extern "C" fn(*mut c_void, *const FrameDescription, *const u8, usize) -> i32;
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct CaptureTarget {
    node: u32,
    reserved: u32,
    // Zero is the legacy grant without a serial, never a supplied serial.
    serial: u64,
}
unsafe extern "C" {
    fn nl_pw_init();
    fn nl_pw_capture(
        fd: i32,
        cancel: i32,
        targets: *const CaptureTarget,
        count: u32,
        callback: Callback,
        user: *mut c_void,
    ) -> i32;
}
struct Frames {
    queue: VecDeque<RawFrame>,
    bytes: usize,
    formats: BTreeMap<u32, (u32, u32, u32)>,
    views: BTreeMap<u32, FrameView>,
    seen: BTreeSet<u32>,
}
#[derive(Default)]
struct WorkerEnd {
    finished: bool,
    failure: Option<io::ErrorKind>,
}
struct Shared {
    stopped: AtomicBool,
    cancel: OwnedFd,
    frames: Mutex<Frames>,
    ended: Mutex<WorkerEnd>,
    done: Condvar,
    nodes: BTreeSet<u32>,
    started: Instant,
    heartbeat: Mutex<Instant>,
    active: Box<dyn Fn() -> bool + Send + Sync>,
    portal: Option<PortalControl>,
}
impl Shared {
    fn record_failure(&self, kind: io::ErrorKind) {
        if let Ok(mut ended) = self.ended.lock() {
            ended.failure.get_or_insert(kind);
        }
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Ok(mut frames) = self.frames.lock() {
            frames.queue.clear();
            frames.bytes = 0;
        }
        let value = 1u64;
        // SAFETY: owned eventfd is valid; a fixed scalar is borrowed for this write.
        // Nonblocking eventfd saturation already means a cancellation is pending.
        unsafe {
            libc::write(
                self.cancel.as_raw_fd(),
                (&value as *const u64).cast(),
                size_of::<u64>(),
            );
        }
        if let Some(portal) = &self.portal {
            portal.invalidate();
        }
    }
    fn check(&self) -> io::Result<()> {
        self.check_progress(false)
    }
    fn check_progress(&self, from_worker_heartbeat: bool) -> io::Result<()> {
        let result = (|| {
            if self.stopped.load(Ordering::SeqCst) || !(self.active)() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "capture or OS consent ended",
                ));
            }
            {
                let mut heartbeat = self
                    .heartbeat
                    .lock()
                    .map_err(|_| io::Error::other("capture heartbeat poisoned"))?;
                // Expiry and renewal share the lock. A callback arriving after
                // its deadline cannot revive a worker, even when the caller
                // has not yet observed the stall. Only C's timer callback is
                // allowed to renew; polling frames never proves worker health.
                if self.stopped.load(Ordering::SeqCst) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "capture ended during heartbeat check",
                    ));
                }
                if heartbeat.elapsed() > HEARTBEAT {
                    // Record the failure before cancellation can let the C
                    // loop finish successfully through its eventfd callback.
                    self.record_failure(io::ErrorKind::TimedOut);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "PipeWire capture worker lost its heartbeat",
                    ));
                }
                if from_worker_heartbeat {
                    *heartbeat = Instant::now();
                }
            }
            if self.started.elapsed() > STARTUP
                && self
                    .frames
                    .lock()
                    .map_err(|_| io::Error::other("capture queue poisoned"))?
                    .seen
                    .len()
                    != self.nodes.len()
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "approved monitors did not provide initial frames",
                ));
            }
            Ok(())
        })();
        if let Err(error) = &result {
            if error.kind() != io::ErrorKind::PermissionDenied {
                self.record_failure(error.kind());
            }
            // Release all fact/heartbeat locks before clearing frame storage.
            self.stop();
        }
        result
    }
    fn finish(&self, result: io::Result<()>) {
        if let Err(error) = result {
            self.record_failure(error.kind());
        }
        self.stop();
        if let Ok(mut ended) = self.ended.lock() {
            ended.finished = true;
        }
        self.done.notify_all();
    }
    fn receive(&self, description: FrameDescription, data: &[u8]) -> io::Result<()> {
        let FrameDescription {
            kind,
            node,
            width,
            height,
            format,
            stride,
            ..
        } = description;
        self.check_progress(kind == 0)?;
        if kind == 0 {
            return Ok(());
        }
        let view = description.view()?;
        if !self.nodes.contains(&node) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PipeWire format/source exceeds budget",
            ));
        }
        {
            let mut frames = self
                .frames
                .lock()
                .map_err(|_| io::Error::other("capture queue poisoned"))?;
            let size = (width, height, format);
            if kind == 1 {
                if frames
                    .formats
                    .insert(node, size)
                    .is_some_and(|old| old != size)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "PipeWire format changed",
                    ));
                }
                let total = frames.formats.values().try_fold(0u64, |sum, (w, h, _)| {
                    sum.checked_add(u64::from(*w) * u64::from(*h) * 4)
                });
                if total.is_none_or(|bytes| bytes > QUEUE_BYTES as u64) {
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "approved capture formats exceed aggregate budget",
                    ));
                }
                return Ok(());
            }
            if !matches!(kind, 2 | 3) || frames.formats.get(&node) != Some(&size) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame before matching format",
                ));
            }
            // Crop position and orientation affect the mapping from pixels to
            // portal logical coordinates even when final dimensions match.
            if frames
                .views
                .insert(node, view)
                .is_some_and(|old| old != view)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PipeWire crop/transform changed",
                ));
            }
        }
        let (width, height) = view.dimensions();
        let captured_at = Instant::now();
        let pixels = if kind == 3 {
            if stride != 0 || description.first_row != 0 || !data.is_empty() {
                return Err(io::Error::other(
                    "neutral frame has unexpected pixel payload",
                ));
            }
            let total = width as usize * height as usize * 4;
            let mut pixels = Vec::new();
            pixels.try_reserve_exact(total).map_err(io::Error::other)?;
            pixels.resize(total, 0);
            for alpha in pixels.iter_mut().skip(3).step_by(4) {
                *alpha = 255;
            }
            pixels
        } else {
            packed_bgra(description, data)?
        };
        self.check()?;
        let mut frames = self
            .frames
            .lock()
            .map_err(|_| io::Error::other("capture queue poisoned"))?;
        // Recheck under the queue lock: reset must never be followed by enqueue.
        if self.stopped.load(Ordering::SeqCst) || !(self.active)() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "capture ended while copying",
            ));
        }
        let frame = RawFrame {
            source: node,
            width,
            height,
            captured_at,
            pixels,
        };
        if let Some(index) = frames.queue.iter().position(|old| old.source == node) {
            let bytes = frames.bytes - frames.queue[index].pixels.len() + frame.pixels.len();
            if bytes > QUEUE_BYTES {
                return Err(io::Error::other("capture replacement budget invariant"));
            }
            frames.bytes = bytes;
            // New pixels replace the pending source in place, preserving its
            // turn even when other monitors publish at a different frequency.
            frames.queue[index] = frame;
            return Ok(());
        }
        while frames.bytes + frame.pixels.len() > QUEUE_BYTES {
            let Some(old) = frames.queue.pop_front() else {
                return Err(io::Error::other("capture queue budget invariant"));
            };
            frames.bytes -= old.pixels.len();
        }
        frames.bytes += frame.pixels.len();
        frames.seen.insert(node);
        frames.queue.push_back(frame);
        Ok(())
    }
}
fn packed_bgra(frame: FrameDescription, data: &[u8]) -> io::Result<Vec<u8>> {
    let view = frame.view()?;
    let bpp = if frame.format <= 4 { 4 } else { 3 };
    let row = i64::from(frame.width) * bpp;
    let stride = i64::from(frame.stride);
    let first = i64::from(frame.first_row);
    let last = first + i64::from(frame.height - 1) * stride;
    let low = first.min(last);
    let high = first.max(last);
    if data.len() > RAW_FRAME_BYTES
        || stride.abs() < row
        || low < 0
        || high + row > data.len() as i64
        || high - low + row > RAW_FRAME_BYTES as i64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid packed pixel buffer",
        ));
    }
    let (width, height) = view.dimensions();
    let total = width as usize * height as usize * 4;
    let mut result = Vec::new();
    result.try_reserve_exact(total).map_err(io::Error::other)?;
    result.resize(total, 0);
    for cy in 0..view.height {
        let start = first + i64::from(view.y + cy) * stride + i64::from(view.x) * bpp;
        let line = &data[start as usize..(start + i64::from(view.width) * bpp) as usize];
        for (cx, p) in line.chunks_exact(bpp as usize).enumerate() {
            let cx = cx as u32;
            // SPA describes the transform already applied to the buffer.
            // Undo that transform after cropping, without an intermediate copy.
            let (x, y) = match view.transform {
                0 => (cx, cy),
                1 => (view.height - 1 - cy, cx),
                2 => (view.width - 1 - cx, view.height - 1 - cy),
                3 => (cy, view.width - 1 - cx),
                4 => (view.width - 1 - cx, cy),
                5 => (cy, cx),
                6 => (cx, view.height - 1 - cy),
                7 => (view.height - 1 - cy, view.width - 1 - cx),
                _ => unreachable!(),
            };
            let pixel = match frame.format {
                1 | 6 => [p[0], p[1], p[2], 255],
                2 => [p[0], p[1], p[2], p[3]],
                3 | 5 => [p[2], p[1], p[0], 255],
                4 => [p[2], p[1], p[0], p[3]],
                _ => unreachable!(),
            };
            let index = (y as usize * width as usize + x as usize) * 4;
            result[index..index + 4].copy_from_slice(&pixel);
        }
    }
    Ok(result)
}
unsafe extern "C" fn receive(
    user: *mut c_void,
    description: *const FrameDescription,
    pointer: *const u8,
    length: usize,
) -> i32 {
    // SAFETY: nl_pw_capture borrows Shared during its synchronous call, and C
    // invokes callbacks only on that worker before returning/destroying buffers.
    let shared = unsafe { &*user.cast::<Shared>() };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if description.is_null() || length > RAW_FRAME_BYTES || (length != 0 && pointer.is_null()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "capture ABI buffer invalid",
            ));
        }
        // SAFETY: C borrows a fully initialized, aligned nl_frame for this call.
        let description = unsafe { *description };
        if description.kind == 2 && length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty capture ABI buffer",
            ));
        }
        // SAFETY: C checks the mapped plane's type, pointer, maxsize, offset,
        // chunk size and stride range before calling. The buffer stays dequeued
        // throughout this callback; Rust copies it and never retains this slice.
        let data = if length == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(pointer, length) }
        };
        shared.receive(description, data)
    }))
    .unwrap_or_else(|_| Err(io::Error::other("capture callback panicked")));
    match result {
        Ok(()) => 0,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            shared.stop();
            // Positive is an ordinary stop, regardless of callback kind.
            1
        }
        Err(error) => {
            shared.record_failure(error.kind());
            shared.stop();
            // Negative is a failure. Keep the original Rust kind in Shared,
            // even when no exact errno represents it at this ABI boundary.
            -match error.kind() {
                io::ErrorKind::TimedOut => libc::ETIMEDOUT,
                io::ErrorKind::InvalidData => libc::EINVAL,
                io::ErrorKind::OutOfMemory => libc::ENOMEM,
                _ => libc::EIO,
            }
        }
    }
}
pub struct PortalCapture {
    shared: Arc<Shared>,
    displays: Vec<Display>,
    worker: Option<thread::JoinHandle<()>>,
    cleanup_deadline: Option<Instant>,
}
impl PortalCapture {
    pub fn open(input: &mut PortalInput) -> io::Result<Self> {
        let fd = input.take_pipewire_fd()?;
        Self::open_grant(input.control(), input.info(), fd)
    }
    /// Capture only streams inside the already-consented Portal grant. The
    /// selected source set can narrow OS authority but can never add streams.
    pub fn open_selected(input: &mut PortalInput, selected: &[u32]) -> io::Result<Self> {
        let streams = selected_streams(input.info(), selected)?;
        let fd = input.take_pipewire_fd()?;
        Self::open_grant_streams(input.control(), streams, fd)
    }
    pub fn open_view(view: &mut PortalView) -> io::Result<Self> {
        let fd = view.take_pipewire_fd()?;
        Self::open_grant(view.control(), view.info(), fd)
    }
    /// ScreenCast-only counterpart to `open_selected`.
    pub fn open_view_selected(view: &mut PortalView, selected: &[u32]) -> io::Result<Self> {
        let streams = selected_streams(view.info(), selected)?;
        let fd = view.take_pipewire_fd()?;
        Self::open_grant_streams(view.control(), streams, fd)
    }
    fn open_grant(control: PortalControl, info: &PortalInfo, fd: OwnedFd) -> io::Result<Self> {
        Self::open_grant_streams(control, info.streams.clone(), fd)
    }
    fn open_grant_streams(
        control: PortalControl,
        streams: Vec<PortalStream>,
        fd: OwnedFd,
    ) -> io::Result<Self> {
        if !control.is_active() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "portal consent ended",
            ));
        }
        let displays = streams
            .iter()
            .map(|s| Display {
                source: s.node_id,
                logical: s.layout,
            })
            .collect();
        let active = control.clone();
        let targets = streams
            .iter()
            .map(|s| CaptureTarget {
                node: s.node_id,
                reserved: 0,
                serial: s.pipewire_serial.unwrap_or(0),
            })
            .collect();
        let result = Self::start(
            fd,
            displays,
            targets,
            Box::new(move || active.is_active()),
            Some(control.clone()),
        );
        // This attempt has consumed the one-shot fd. A startup error must end
        // its input grant too; another take_fd error never reaches this path.
        if result.is_err() {
            control.invalidate();
        }
        result
    }
    fn start(
        fd: OwnedFd,
        displays: Vec<Display>,
        targets: Vec<CaptureTarget>,
        active: Box<dyn Fn() -> bool + Send + Sync>,
        portal: Option<PortalControl>,
    ) -> io::Result<Self> {
        if displays.is_empty() || displays.len() > 64 {
            return Err(io::Error::other("invalid authorized monitor count"));
        }
        let nodes: BTreeSet<u32> = displays.iter().map(|d| d.source).collect();
        if nodes.len() != displays.len() || nodes.contains(&0) || nodes.contains(&u32::MAX) {
            return Err(io::Error::other("invalid/duplicate monitor node"));
        }
        let target_nodes: BTreeSet<u32> = targets.iter().map(|target| target.node).collect();
        let serial_count = targets.iter().filter(|target| target.serial != 0).count();
        let serials: BTreeSet<u64> = targets
            .iter()
            .filter_map(|target| (target.serial != 0).then_some(target.serial))
            .collect();
        if targets.len() != nodes.len()
            || target_nodes != nodes
            || serial_count != serials.len()
            || targets.iter().any(|target| target.reserved != 0)
        {
            return Err(io::Error::other(
                "capture targets differ from approved monitors",
            ));
        }
        verify_unix_socket(&fd)?;
        // SAFETY: scalar eventfd constructor; successful fd gets one Rust owner.
        let cancel = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if cancel < 0 {
            return Err(io::Error::last_os_error());
        }
        let cancel = unsafe { OwnedFd::from_raw_fd(cancel) };
        let started = Instant::now();
        let shared = Arc::new(Shared {
            stopped: AtomicBool::new(false),
            cancel,
            frames: Mutex::new(Frames {
                queue: VecDeque::new(),
                bytes: 0,
                formats: BTreeMap::new(),
                views: BTreeMap::new(),
                seen: BTreeSet::new(),
            }),
            ended: Mutex::new(WorkerEnd::default()),
            done: Condvar::new(),
            nodes,
            started,
            heartbeat: Mutex::new(started),
            active,
            portal,
        });
        let worker_shared = shared.clone();
        let worker = thread::Builder::new()
            .name("nestlink-pipewire-capture".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    static INIT: Once = Once::new();
                    // SAFETY: system library init called once for the process; no args.
                    INIT.call_once(|| unsafe { nl_pw_init() });
                    // SAFETY: fd transfers once to C, all other objects are borrowed
                    // across this synchronous call. C has no RT callback and destroys
                    // streams before returning, including failed startup paths.
                    let result = unsafe {
                        nl_pw_capture(
                            fd.into_raw_fd(),
                            worker_shared.cancel.as_raw_fd(),
                            targets.as_ptr(),
                            targets.len() as u32,
                            receive,
                            Arc::as_ptr(&worker_shared).cast_mut().cast(),
                        )
                    };
                    if result < 0 {
                        Err(io::Error::from_raw_os_error(-result))
                    } else {
                        Ok(())
                    }
                }))
                .unwrap_or_else(|_| Err(io::Error::other("PipeWire worker panicked")));
                worker_shared.finish(result);
            })?;
        Ok(Self {
            shared,
            displays,
            worker: Some(worker),
            cleanup_deadline: None,
        })
    }
    pub fn displays(&self) -> &[Display] {
        &self.displays
    }
}

fn selected_streams(info: &PortalInfo, selected: &[u32]) -> io::Result<Vec<PortalStream>> {
    if selected.is_empty()
        || selected.len() > info.streams.len()
        || selected.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid selected Portal stream set",
        ));
    }
    selected
        .iter()
        .map(|source| {
            info.streams
                .iter()
                .find(|stream| stream.node_id == *source)
                .cloned()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "selected stream is outside the original Portal grant",
                    )
                })
        })
        .collect()
}
impl CaptureDevice for PortalCapture {
    fn check(&mut self) -> io::Result<()> {
        self.shared.check()
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        self.shared.check()?;
        let mut frames = self
            .shared
            .frames
            .lock()
            .map_err(|_| io::Error::other("capture queue poisoned"))?;
        if self.shared.stopped.load(Ordering::SeqCst) || !(self.shared.active)() {
            drop(frames);
            self.shared.stop();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "capture or OS consent ended",
            ));
        }
        let next = frames.queue.pop_front();
        if let Some(frame) = &next {
            frames.bytes -= frame.pixels.len();
        }
        Ok(next)
    }
    fn reset(&mut self) -> io::Result<()> {
        self.shared.stop();
        let until = *self
            .cleanup_deadline
            .get_or_insert_with(|| Instant::now() + CLEANUP);
        let ended = self
            .shared
            .ended
            .lock()
            .map_err(|_| io::Error::other("capture cleanup state poisoned"))?;
        let (ended, _) = self
            .shared
            .done
            .wait_timeout_while(
                ended,
                until.saturating_duration_since(Instant::now()),
                |v| !v.finished,
            )
            .map_err(|_| io::Error::other("capture cleanup state poisoned"))?;
        match (ended.finished, ended.failure) {
            (true, None) => Ok(()),
            (true, Some(kind)) => Err(io::Error::new(kind, "PipeWire cleanup failed")),
            (false, _) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PipeWire cleanup exceeded budget",
            )),
        }
    }
}
impl Drop for PortalCapture {
    fn drop(&mut self) {
        let _ = self.reset();
        if let Some(worker) = self.worker.take()
            && worker.is_finished()
        {
            let _ = worker.join();
        }
    }
}
fn verify_unix_socket(fd: &OwnedFd) -> io::Result<()> {
    for (option, expected) in [
        (libc::SO_DOMAIN, libc::AF_UNIX),
        (libc::SO_TYPE, libc::SOCK_STREAM),
    ] {
        let mut actual: i32 = 0;
        let mut len = size_of::<i32>() as libc::socklen_t;
        // SAFETY: valid borrowed fd and correctly sized writable scalar buffers.
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&mut actual as *mut i32).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if actual != expected || len as usize != size_of::<i32>() {
            return Err(io::Error::other(
                "capture requires a local connected Unix stream socket",
            ));
        }
    }
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: owned socket, ABI-sized writable credential struct; scalar UID query.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<libc::ucred>() || credentials.uid != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PipeWire peer does not belong to this OS user",
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod heartbeat_tests {
    use super::*;

    #[test]
    fn polling_cannot_renew_worker_and_late_heartbeat_cannot_revive_it() -> io::Result<()> {
        for caller_observes_stall in [false, true] {
            // SAFETY: successful eventfd gets exactly one Rust owner below.
            let cancel = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if cancel < 0 {
                return Err(io::Error::last_os_error());
            }
            let started = Instant::now();
            let shared = Shared {
                stopped: AtomicBool::new(false),
                cancel: unsafe { OwnedFd::from_raw_fd(cancel) },
                frames: Mutex::new(Frames {
                    queue: VecDeque::new(),
                    bytes: 0,
                    formats: BTreeMap::new(),
                    views: BTreeMap::new(),
                    seen: BTreeSet::new(),
                }),
                ended: Mutex::new(WorkerEnd::default()),
                done: Condvar::new(),
                nodes: BTreeSet::from([42]),
                started,
                heartbeat: Mutex::new(started),
                active: Box::new(|| true),
                portal: None,
            };
            let mut description = FrameDescription {
                kind: 1,
                node: 42,
                width: 1,
                height: 1,
                format: 2,
                crop_width: 1,
                crop_height: 1,
                ..Default::default()
            };
            shared.receive(description, &[])?;
            description.kind = 2;
            description.stride = 4;
            shared.receive(description, &[1, 2, 3, 255])?;
            // Every approved source has supplied pixels: the old initial-frame
            // deadline would no longer detect a stuck C event loop here.
            for _ in 0..3 {
                shared.check()?;
            }
            assert_eq!(
                *shared
                    .heartbeat
                    .lock()
                    .map_err(|_| io::Error::other("fixture poisoned"))?,
                started
            );
            shared.receive(FrameDescription::default(), &[])?;
            assert!(
                *shared
                    .heartbeat
                    .lock()
                    .map_err(|_| io::Error::other("fixture poisoned"))?
                    >= started
            );
            let expired = Instant::now() - HEARTBEAT - Duration::from_millis(1);
            *shared
                .heartbeat
                .lock()
                .map_err(|_| io::Error::other("fixture poisoned"))? = expired;
            if caller_observes_stall {
                assert_eq!(
                    shared.check().err().map(|e| e.kind()),
                    Some(io::ErrorKind::TimedOut)
                );
            }
            assert!(shared.receive(FrameDescription::default(), &[]).is_err());
            assert!(shared.stopped.load(Ordering::SeqCst));
            assert!(shared.check().is_err());
            assert_eq!(
                *shared
                    .heartbeat
                    .lock()
                    .map_err(|_| io::Error::other("fixture poisoned"))?,
                expired
            );
            let frames = shared
                .frames
                .lock()
                .map_err(|_| io::Error::other("fixture poisoned"))?;
            assert!(frames.queue.is_empty());
            assert_eq!(frames.bytes, 0);
        }
        Ok(())
    }
}
