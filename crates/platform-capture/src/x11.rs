//! Bounded first-party X11 capture worker. OS facts never issue application permits.
use nestlink_platform_input::X11CaptureSource;
use nestlink_remote::video::{CaptureDevice, Display, RAW_FRAME_AGE, RAW_FRAME_BYTES, RawFrame};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const QUEUE_BYTES: usize = 128 * 1024 * 1024;
const ROUND: Duration = Duration::from_millis(150);
const CLEANUP: Duration = Duration::from_millis(150);
const HEARTBEAT: Duration = Duration::from_millis(250);
const STARTUP: Duration = Duration::from_millis(500);
const FRAME_INTERVAL: Duration = Duration::from_millis(33);

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "X11 capture ended")
}
fn timeout(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

// This seam is private. The public constructor only accepts the real local
// X11CaptureSource, never a caller-supplied authority/facts implementation.
trait Source: Send + 'static {
    fn displays(&self) -> &[Display];
    fn active(&self) -> Box<dyn Fn() -> bool + Send + Sync>;
    fn check_until(&mut self, until: Instant) -> io::Result<()>;
    fn capture_until(&mut self, source: u32, until: Instant) -> io::Result<RawFrame>;
    fn close(&mut self) -> io::Result<()>;
}
impl Source for X11CaptureSource {
    fn displays(&self) -> &[Display] {
        self.displays()
    }
    fn active(&self) -> Box<dyn Fn() -> bool + Send + Sync> {
        let control = self.control();
        Box::new(move || control.is_active())
    }
    fn check_until(&mut self, until: Instant) -> io::Result<()> {
        self.check_until(until)
    }
    fn capture_until(&mut self, source: u32, until: Instant) -> io::Result<RawFrame> {
        self.capture_until(source, until)
    }
    fn close(&mut self) -> io::Result<()> {
        self.close()
    }
}

struct State {
    frames: VecDeque<RawFrame>,
    bytes: usize,
    geometry: BTreeMap<u32, (u32, u32)>,
    checked: Instant,
    ended: Option<Result<(), io::ErrorKind>>,
}
struct Shared {
    stopped: AtomicBool,
    active: Box<dyn Fn() -> bool + Send + Sync>,
    selected: BTreeSet<u32>,
    state: Mutex<State>,
    wake: Condvar,
}
impl Shared {
    fn new(selected: BTreeSet<u32>, active: Box<dyn Fn() -> bool + Send + Sync>) -> Self {
        Self {
            stopped: AtomicBool::new(false),
            active,
            selected,
            state: Mutex::new(State {
                frames: VecDeque::new(),
                bytes: 0,
                geometry: BTreeMap::new(),
                checked: Instant::now(),
                ended: None,
            }),
            wake: Condvar::new(),
        }
    }
    fn clear(state: &mut State) {
        state.frames.clear();
        state.bytes = 0;
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Ok(mut state) = self.state.lock() {
            Self::clear(&mut state);
        }
        self.wake.notify_all();
    }
    fn available(&self, state: &mut State, now: Instant) -> io::Result<()> {
        if self.stopped.load(Ordering::SeqCst) || state.ended.is_some() {
            return Err(stopped());
        }
        if !(self.active)() {
            self.stopped.store(true, Ordering::SeqCst);
            Self::clear(state);
            self.wake.notify_all();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "X11 local authority ended",
            ));
        }
        if now.saturating_duration_since(state.checked) > HEARTBEAT {
            self.stopped.store(true, Ordering::SeqCst);
            Self::clear(state);
            self.wake.notify_all();
            return Err(timeout("X11 capture worker lost its heartbeat"));
        }
        Ok(())
    }
    fn check(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("X11 capture state poisoned"))?;
        self.available(&mut state, Instant::now())
    }
    fn refresh(&self, until: Instant) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("X11 capture state poisoned"))?;
        let now = Instant::now();
        self.available(&mut state, now)?;
        if now >= until {
            self.stopped.store(true, Ordering::SeqCst);
            Self::clear(&mut state);
            self.wake.notify_all();
            return Err(timeout("X11 capture facts returned after their deadline"));
        }
        state.checked = now;
        Ok(())
    }
    fn publish(&self, frames: Vec<RawFrame>, until: Instant) -> io::Result<()> {
        let mut observed = BTreeSet::new();
        let mut bytes = 0usize;
        let now = Instant::now();
        for frame in &frames {
            frame.validate()?;
            if !self.selected.contains(&frame.source)
                || !observed.insert(frame.source)
                || frame.captured_at > now
                || now.duration_since(frame.captured_at) > RAW_FRAME_AGE
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid source or age in X11 capture round",
                ));
            }
            bytes = bytes
                .checked_add(frame.pixels.len())
                .ok_or_else(|| io::Error::other("X11 capture queue size overflow"))?;
        }
        if observed != self.selected || bytes > QUEUE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete or oversized X11 capture round",
            ));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("X11 capture state poisoned"))?;
        let now = Instant::now();
        self.available(&mut state, now)?;
        // A blocked/paused worker cannot overwrite its late heartbeat, even if no
        // consumer was polling while it stalled. Stop also wins the queue lock.
        if now >= until {
            self.stopped.store(true, Ordering::SeqCst);
            Self::clear(&mut state);
            self.wake.notify_all();
            return Err(timeout("X11 pixels returned after the round deadline"));
        }
        for frame in &frames {
            if state
                .geometry
                .get(&frame.source)
                .is_some_and(|old| *old != (frame.width, frame.height))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "X11 capture geometry changed",
                ));
            }
        }
        // Replace each source's frame without moving its unread position. A slower
        // consumer must not starve the second monitor every time a new round lands.
        // Pending worker pixels are a separate bounded round.
        for frame in frames {
            state
                .geometry
                .insert(frame.source, (frame.width, frame.height));
            if let Some(previous) = state
                .frames
                .iter_mut()
                .find(|previous| previous.source == frame.source)
            {
                *previous = frame;
            } else {
                state.frames.push_back(frame);
            }
        }
        state.bytes = bytes;
        state.checked = now;
        Ok(())
    }
    fn take(&self) -> io::Result<Option<RawFrame>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("X11 capture state poisoned"))?;
        self.available(&mut state, Instant::now())?;
        while let Some(frame) = state.frames.pop_front() {
            state.bytes -= frame.pixels.len();
            if frame.captured_at.elapsed() <= RAW_FRAME_AGE {
                return Ok(Some(frame));
            }
        }
        Ok(None)
    }
    fn finish(&self, result: io::Result<()>) {
        self.stop();
        if let Ok(mut state) = self.state.lock() {
            state.ended = Some(result.map_err(|e| e.kind()));
        }
        self.wake.notify_all();
    }
}

/// Owns a single local X11 connection on a dedicated worker. Attach this device
/// to VideoController with the current View permit and its original connection.
pub struct X11Capture {
    shared: Arc<Shared>,
    displays: Vec<Display>,
    worker: Option<thread::JoinHandle<()>>,
    cleanup_deadline: Option<Instant>,
}
impl X11Capture {
    pub fn open(source: X11CaptureSource, selected: Vec<u32>) -> io::Result<Self> {
        Self::start(source, selected)
    }
    fn start<S: Source>(mut source: S, selected: Vec<u32>) -> io::Result<Self> {
        let mut available = BTreeMap::new();
        let offered = source.displays();
        if offered.is_empty() || offered.len() > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "X11 monitor count exceeds its budget",
            ));
        }
        for display in offered {
            let logical = display.logical;
            if logical.width == 0
                || logical.height == 0
                || logical.width > 32768
                || logical.height > 32768
                || logical.left.checked_add_unsigned(logical.width).is_none()
                || logical.top.checked_add_unsigned(logical.height).is_none()
                || available.insert(display.source, *display).is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "X11 enumerated monitor layout is invalid",
                ));
            }
        }
        let mut ids = BTreeSet::new();
        let mut displays = Vec::new();
        let mut total = 0usize;
        for id in selected {
            let display = available
                .get(&id)
                .filter(|_| ids.insert(id))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unknown or duplicate X11 monitor selection",
                    )
                })?;
            let width = display.logical.width;
            let height = display.logical.height;
            let bytes = u64::from(width) * u64::from(height) * 4;
            if width > 8192 || height > 8192 || bytes > RAW_FRAME_BYTES as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "selected X11 monitor exceeds its frame budget",
                ));
            }
            total = total
                .checked_add(bytes as usize)
                .ok_or_else(|| io::Error::other("X11 selected display size overflow"))?;
            displays.push(*display);
        }
        if displays.is_empty() || total > QUEUE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty or oversized X11 monitor selection",
            ));
        }
        let shared = Arc::new(Shared::new(ids, source.active()));
        let worker_shared = shared.clone();
        let selected = displays.iter().map(|display| display.source).collect();
        let (ready, readiness) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nestlink-x11-capture".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(&mut source, &worker_shared, selected, ready.clone())
                }))
                .unwrap_or_else(|_| Err(io::Error::other("X11 capture worker panicked")));
                // Revoke delivery before any potentially slow source cleanup.
                worker_shared.stop();
                if let Err(error) = &result {
                    let _ = ready.try_send(Err(io::Error::new(error.kind(), error.to_string())));
                }
                // Cleanup remains on the connection's owning worker after failure/panic.
                let closed =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| source.close()))
                        .unwrap_or_else(|_| {
                            Err(io::Error::other("X11 capture source cleanup panicked"))
                        });
                let result = result.and(closed);
                if let Err(error) = &result {
                    let _ = ready.try_send(Err(io::Error::new(error.kind(), error.to_string())));
                }
                worker_shared.finish(result);
            })?;
        let mut capture = Self {
            shared,
            displays,
            worker: Some(worker),
            cleanup_deadline: None,
        };
        match readiness.recv_timeout(STARTUP) {
            Ok(Ok(())) => {
                capture.check()?;
                Ok(capture)
            }
            Ok(Err(error)) => {
                let _ = capture.reset();
                Err(error)
            }
            Err(error) => {
                let _ = capture.reset();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("X11 capture did not start: {error}"),
                ))
            }
        }
    }
    pub fn displays(&self) -> &[Display] {
        &self.displays
    }
}
fn run<S: Source>(
    source: &mut S,
    shared: &Shared,
    selected: Vec<u32>,
    ready: mpsc::SyncSender<io::Result<()>>,
) -> io::Result<()> {
    let until = Instant::now() + ROUND;
    shared.check()?;
    source.check_until(until)?;
    shared.refresh(until)?;
    ready.send(Ok(())).map_err(|_| stopped())?;
    while !shared.stopped.load(Ordering::SeqCst) {
        let started = Instant::now();
        let until = started + ROUND;
        shared.check()?;
        source.check_until(until)?;
        let mut frames = Vec::with_capacity(selected.len());
        let mut pending_bytes = 0usize;
        for id in &selected {
            if shared.stopped.load(Ordering::SeqCst) {
                return Ok(());
            }
            if Instant::now() >= until {
                return Err(timeout("X11 capture round deadline exhausted"));
            }
            let frame = source.capture_until(*id, until)?;
            if frame.source != *id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "X11 capture returned a different source",
                ));
            }
            frame.validate()?;
            pending_bytes = pending_bytes
                .checked_add(frame.pixels.len())
                .ok_or_else(|| io::Error::other("X11 pending frame budget overflow"))?;
            if pending_bytes > QUEUE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "X11 pending frames exceed aggregate budget",
                ));
            }
            frames.push(frame);
        }
        if shared.stopped.load(Ordering::SeqCst) {
            return Ok(());
        }
        if Instant::now() >= until {
            return Err(timeout("X11 capture frame arrived after its deadline"));
        }
        source.check_until(until)?;
        if shared.stopped.load(Ordering::SeqCst) {
            return Ok(());
        }
        shared.publish(frames, until)?;
        let state = shared
            .state
            .lock()
            .map_err(|_| io::Error::other("X11 capture state poisoned"))?;
        if shared.stopped.load(Ordering::SeqCst) {
            break;
        }
        let _ = shared
            .wake
            .wait_timeout(state, FRAME_INTERVAL.saturating_sub(started.elapsed()))
            .map_err(|_| io::Error::other("X11 capture wait poisoned"))?;
    }
    Ok(())
}
impl CaptureDevice for X11Capture {
    fn check(&mut self) -> io::Result<()> {
        let result = self.shared.check();
        if result.is_err() {
            self.shared.stop();
        }
        result
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        let result = self.shared.take();
        if result.is_err() {
            self.shared.stop();
        }
        result
    }
    fn reset(&mut self) -> io::Result<()> {
        let until = *self
            .cleanup_deadline
            .get_or_insert_with(|| Instant::now() + CLEANUP);
        self.shared.stop();
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| io::Error::other("X11 capture state poisoned"))?;
        while state.ended.is_none() {
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(timeout("X11 capture cleanup deadline exhausted"));
            }
            state = self
                .shared
                .wake
                .wait_timeout(state, remaining)
                .map_err(|_| io::Error::other("X11 capture cleanup wait poisoned"))?
                .0;
        }
        let result = state.ended.unwrap_or(Err(io::ErrorKind::Other));
        drop(state);
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
            && let Some(worker) = self.worker.take()
        {
            worker
                .join()
                .map_err(|_| io::Error::other("X11 capture worker join failed"))?;
        }
        result.map_err(|kind| io::Error::new(kind, "X11 capture worker failed"))
    }
}
impl Drop for X11Capture {
    fn drop(&mut self) {
        let _ = self.reset();
    }
}

#[cfg(test)]
mod tests;
