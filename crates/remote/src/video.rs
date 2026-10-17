//! Local raw capture boundary; encoded/wire media remains a separate layer.
use crate::input::InputLayout;
use crate::{LeaseControl, RemoteError, StopHandler};
use nestlink_protocol::Permission;
use nestlink_session::{StopEffects, StopReason};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroize;

pub const RAW_FRAME_BYTES: usize = 64 * 1024 * 1024;
pub const RAW_FRAME_AGE: Duration = Duration::from_millis(250);
/// Packed BGRA pixels owned by Rust, independent of a platform's reused buffer.
pub struct RawFrame {
    pub source: u32,
    pub width: u32,
    pub height: u32,
    pub captured_at: Instant,
    pub pixels: Vec<u8>,
}
impl Drop for RawFrame {
    fn drop(&mut self) {
        self.pixels.zeroize();
    }
}
impl RawFrame {
    pub fn validate(&self) -> io::Result<()> {
        let bytes = (self.width as usize)
            .checked_mul(self.height as usize)
            .and_then(|n| n.checked_mul(4));
        if self.width == 0
            || self.height == 0
            || self.width > 8192
            || self.height > 8192
            || bytes.is_none_or(|n| n > RAW_FRAME_BYTES || n != self.pixels.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "raw video exceeds its geometry/byte budget",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub struct Display {
    pub source: u32,
    pub logical: InputLayout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VideoEpoch {
    pub layout: u64,
    pub connection: u64,
}
pub struct CapturedVideo {
    pub epoch: VideoEpoch,
    pub display: Display,
    pub frame: RawFrame,
}
impl CapturedVideo {
    /// Pixel location -> compositor/OS input coordinates, including negative origins.
    pub fn logical_point(&self, x: u32, y: u32) -> io::Result<(i32, i32)> {
        self.frame.validate()?;
        if x >= self.frame.width || y >= self.frame.height {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pixel outside captured frame",
            ));
        }
        let logical = self.display.logical;
        let px = i64::from(logical.left)
            + i64::from(x) * i64::from(logical.width) / i64::from(self.frame.width);
        let py = i64::from(logical.top)
            + i64::from(y) * i64::from(logical.height) / i64::from(self.frame.height);
        Ok((
            i32::try_from(px).map_err(io::Error::other)?,
            i32::try_from(py).map_err(io::Error::other)?,
        ))
    }
}
/// Owns only local capture facts. Methods must be nonblocking or bounded and
/// must not call back into the lease. A worker may hold one replaceable frame.
pub trait CaptureDevice: Send + 'static {
    fn check(&mut self) -> io::Result<()>;
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>>;
    fn poll_frame_for(&mut self, source: u32) -> io::Result<Option<RawFrame>> {
        for _ in 0..64 {
            let Some(frame) = self.poll_frame()? else {
                return Ok(None);
            };
            if frame.source == source {
                return Ok(Some(frame));
            }
        }
        Ok(None)
    }
    /// Drop buffered frames before the selected source/epoch is advanced.
    fn discard_pending_frames(&mut self) -> io::Result<()> {
        for _ in 0..64 {
            if self.poll_frame()?.is_none() {
                break;
            }
        }
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()>;
}
struct State<D> {
    device: D,
    displays: BTreeMap<u32, Display>,
    geometry: BTreeMap<u32, (u32, u32)>,
    epoch: VideoEpoch,
    selected_source: u32,
}
#[derive(Clone, Copy)]
enum PollSelection<'a> {
    One(u32),
    Several(&'a BTreeSet<u32>),
}

fn poll_locked<D: CaptureDevice>(
    state: &mut State<D>,
    selection: PollSelection<'_>,
) -> io::Result<Option<CapturedVideo>> {
    state.device.check()?;
    let frame = match selection {
        PollSelection::One(source) => state.device.poll_frame_for(source)?,
        PollSelection::Several(_) => state.device.poll_frame()?,
    };
    let Some(frame) = frame else {
        return Ok(None);
    };
    frame.validate()?;
    let Some(display) = state.displays.get(&frame.source).copied() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "capture produced an unapproved source",
        ));
    };
    match selection {
        PollSelection::One(source) if frame.source != source => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "capture returned a source outside the selected display",
            ));
        }
        PollSelection::Several(sources) if !sources.contains(&frame.source) => {
            return Ok(None);
        }
        _ => {}
    }
    let size = (frame.width, frame.height);
    if state
        .geometry
        .insert(frame.source, size)
        .is_some_and(|old| old != size)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "capture geometry changed",
        ));
    }
    if frame.captured_at > Instant::now() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "capture time is in the future",
        ));
    }
    if frame.captured_at.elapsed() > RAW_FRAME_AGE {
        return Ok(None);
    }
    Ok(Some(CapturedVideo {
        epoch: state.epoch,
        display,
        frame,
    }))
}

struct Cleanup<D>(Arc<Mutex<State<D>>>);
impl<D: CaptureDevice> StopHandler for Cleanup<D> {
    fn check(&mut self) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("capture state poisoned"))?;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.device.check()))
            .unwrap_or_else(|_| Err(io::Error::other("capture fact check panicked")))
    }
    fn stop(&mut self, _: StopReason, _: StopEffects) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("capture state poisoned"))?;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.device.reset()))
            .unwrap_or_else(|_| Err(io::Error::other("capture cleanup panicked")))
    }
}
pub struct VideoController<D: CaptureDevice> {
    lease: LeaseControl,
    state: Arc<Mutex<State<D>>>,
}
impl<D: CaptureDevice> VideoController<D> {
    pub fn attach(
        lease: LeaseControl,
        device: D,
        epoch: VideoEpoch,
        displays: Vec<Display>,
    ) -> Result<Self, RemoteError> {
        let initial_source = displays.first().map(|display| display.source).unwrap_or(0);
        Self::attach_selected(lease, device, epoch, displays, initial_source)
    }
    pub fn attach_selected(
        lease: LeaseControl,
        device: D,
        epoch: VideoEpoch,
        displays: Vec<Display>,
        initial_source: u32,
    ) -> Result<Self, RemoteError> {
        if [epoch.layout, epoch.connection]
            .iter()
            .any(|v| *v == 0 || *v > i64::MAX as u64)
            || displays.is_empty()
            || displays.len() > 64
        {
            return Err(reject_capture(
                device,
                io::Error::new(io::ErrorKind::InvalidInput, "invalid capture epoch/layout").into(),
            ));
        }
        let mut sources = BTreeMap::new();
        for display in displays {
            let l = display.logical;
            if l.width == 0
                || l.height == 0
                || l.width > 32768
                || l.height > 32768
                || l.left.checked_add_unsigned(l.width).is_none()
                || l.top.checked_add_unsigned(l.height).is_none()
                || sources.insert(display.source, display).is_some()
            {
                return Err(reject_capture(
                    device,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid/duplicate capture display",
                    )
                    .into(),
                ));
            }
        }
        if !sources.contains_key(&initial_source) {
            return Err(reject_capture(
                device,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "initial display is not approved",
                )
                .into(),
            ));
        }
        let state = Arc::new(Mutex::new(State {
            device,
            displays: sources,
            geometry: BTreeMap::new(),
            epoch,
            selected_source: initial_source,
        }));
        if let Err(error) = lease.attach_capture(epoch.connection, Box::new(Cleanup(state.clone())))
        {
            // The lease may have stopped between platform preparation and
            // registration. This device never joined its cleanup handlers, so
            // explicitly reset it and preserve a failed reset for the caller.
            let cleanup = state
                .lock()
                .map_err(|_| io::Error::other("capture state poisoned"))
                .and_then(|mut state| reset_device(&mut state.device));
            return Err(cleanup.err().map_or(error, RemoteError::Cleanup));
        }
        Ok(Self { lease, state })
    }
    pub fn poll(&self) -> Result<Option<CapturedVideo>, RemoteError> {
        let result = self.lease.operation(Permission::View, || {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("capture state poisoned"))?;
            let selected_source = state.selected_source;
            // Catch inside the mutex so a platform panic cannot poison cleanup.
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                poll_locked(&mut state, PollSelection::One(selected_source))
            }))
            .unwrap_or_else(|_| Err(io::Error::other("capture operation panicked")))
        });
        if matches!(result, Err(RemoteError::Io(_))) {
            self.lease.stop(StopReason::PlatformChanged)?;
        }
        result
    }

    /// Poll one frame from an explicitly selected set of approved displays.
    /// Unlike `poll`, this consumes the capture device's shared frame queue so
    /// independent monitor streams can be encoded concurrently.
    pub fn poll_sources(&self, sources: &[u32]) -> Result<Option<CapturedVideo>, RemoteError> {
        let selected: BTreeSet<_> = sources.iter().copied().collect();
        if selected.is_empty() || selected.len() != sources.len() || selected.len() > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid selected capture source set",
            )
            .into());
        }
        let result = self.lease.operation(Permission::View, || {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("capture state poisoned"))?;
            if selected
                .iter()
                .any(|source| !state.displays.contains_key(source))
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "selected capture source is not approved",
                ));
            }
            // Catch inside the mutex so a platform panic cannot poison cleanup.
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                poll_locked(&mut state, PollSelection::Several(&selected))
            }))
            .unwrap_or_else(|_| Err(io::Error::other("capture operation panicked")))
        });
        if matches!(result, Err(RemoteError::Io(_))) {
            self.lease.stop(StopReason::PlatformChanged)?;
        }
        result
    }

    /// Atomically discard buffered images and advance to an already registered
    /// source. The caller pauses its sender and releases/switches Input first.
    pub fn select_source(&self, source: u32, epoch: VideoEpoch) -> Result<Display, RemoteError> {
        let result = self.lease.operation(Permission::View, || {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("capture state poisoned"))?;
            let display = *state.displays.get(&source).ok_or_else(|| {
                io::Error::new(io::ErrorKind::PermissionDenied, "unapproved source")
            })?;
            if epoch.connection != state.epoch.connection
                || epoch.layout <= state.epoch.layout
                || epoch.layout > i64::MAX as u64
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stale video epoch",
                ));
            }
            state.device.check()?;
            state.device.discard_pending_frames()?;
            state.selected_source = source;
            state.epoch = epoch;
            state.geometry.remove(&source);
            Ok(display)
        });
        if result.is_err() {
            self.lease.stop(StopReason::Revoked)?;
        }
        result
    }

    pub fn discard_pending_frames(&self) -> Result<(), RemoteError> {
        let result = self.lease.operation(Permission::View, || {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("capture state poisoned"))?;
            state.device.check()?;
            state.device.discard_pending_frames()
        });
        if result.is_err() {
            self.lease.stop(StopReason::Revoked)?;
        }
        result
    }
}
fn reset_device<D: CaptureDevice>(device: &mut D) -> io::Result<()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| device.reset()))
        .unwrap_or_else(|_| Err(io::Error::other("capture cleanup panicked")))
}
fn reject_capture<D: CaptureDevice>(mut device: D, error: RemoteError) -> RemoteError {
    reset_device(&mut device)
        .err()
        .map_or(error, RemoteError::Cleanup)
}
impl<D: CaptureDevice> Drop for VideoController<D> {
    fn drop(&mut self) {
        let _ = self.lease.stop_if_running(StopReason::ExplicitExit);
    }
}
