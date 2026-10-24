//! Windows DXGI capture with a GDI compatibility fallback and terminal OS facts.
#![allow(unsafe_code)]
use nestlink_platform_session::{WindowsSessionObserver, WindowsSessionSnapshot};
use nestlink_remote::{
    input::InputLayout,
    video::{CaptureDevice, Display, RAW_FRAME_BYTES, RawFrame},
};
use std::{
    collections::{BTreeSet, VecDeque},
    io,
    mem::size_of,
    ptr::{null, null_mut},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
#[cfg(test)]
use windows_sys::Win32::{
    Foundation::{HWND, LRESULT, WPARAM},
    System::{
        LibraryLoader::GetModuleHandleW,
        Threading::{GetCurrentProcessId, GetCurrentThreadId},
    },
};
use windows_sys::Win32::{
    Foundation::{LPARAM, RECT},
    Graphics::Gdi::*,
    UI::{HiDpi::*, Shell::GetScaleFactorForMonitor, WindowsAndMessaging::*},
};

const QUEUE_BYTES: usize = 128 * 1024 * 1024;
const STARTUP: Duration = Duration::from_secs(3);
const CLEANUP: Duration = Duration::from_millis(150);
const HEARTBEAT: Duration = Duration::from_millis(250);
const FRAME_INTERVAL: Duration = Duration::from_micros(16_667);

unsafe extern "C" {
    fn nl_dxgi_open(
        monitor: usize,
        width: u32,
        height: u32,
        result: *mut *mut std::ffi::c_void,
    ) -> i32;
    fn nl_dxgi_read(state: *mut std::ffi::c_void, pixels: *mut u8, length: usize) -> i32;
    fn nl_dxgi_close(state: *mut std::ffi::c_void);
}

// Owned by the capture worker only. The source and staging texture never leave
// that thread; authorization and platform facts are checked around every read.
struct DesktopDuplication(*mut std::ffi::c_void);
impl DesktopDuplication {
    fn open(monitor: &Monitor, display: Display) -> io::Result<Self> {
        let mut pointer = null_mut();
        // SAFETY: the approved monitor was enumerated by Windows; the bridge
        // returns one owned state or null, and validates the selected geometry.
        let hr = unsafe {
            nl_dxgi_open(
                monitor.handle,
                display.logical.width,
                display.logical.height,
                &mut pointer,
            )
        };
        if hr < 0 || pointer.is_null() {
            return Err(io::Error::other(format!("DXGI unavailable ({hr:#010x})")));
        }
        Ok(Self(pointer))
    }
    fn read(&mut self, surface: &Surface) -> io::Result<bool> {
        // SAFETY: finish all GDI cursor drawing before the bridge writes the
        // worker-owned DIB. Its validated byte budget is passed explicitly.
        if unsafe { GdiFlush() } == 0 {
            return Err(io::Error::last_os_error());
        }
        let hr = unsafe { nl_dxgi_read(self.0, surface.bits, surface.bytes) };
        match hr {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(io::Error::other(format!("DXGI capture lost ({hr:#010x})"))),
        }
    }
}
impl Drop for DesktopDuplication {
    fn drop(&mut self) {
        // SAFETY: exactly one owner; COM resources are released on their worker.
        unsafe { nl_dxgi_close(self.0) };
    }
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Monitor {
    handle: usize,
    name: Vec<u16>,
    bounds: [i32; 4],
    dpi: [u32; 2],
    scale: i32,
    primary: bool,
}
impl Monitor {
    fn display(&self, source: u32) -> Display {
        Display {
            source,
            logical: InputLayout {
                left: self.bounds[0],
                top: self.bounds[1],
                width: (i64::from(self.bounds[2]) - i64::from(self.bounds[0])) as u32,
                height: (i64::from(self.bounds[3]) - i64::from(self.bounds[1])) as u32,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Context {
    session: WindowsSessionSnapshot,
    monitors: Vec<Monitor>,
}

struct DpiScope(DPI_AWARENESS_CONTEXT);
impl DpiScope {
    fn enter() -> io::Result<Self> {
        // SAFETY: OS-defined context; restored on this same thread by Drop.
        let previous =
            unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        if previous.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(previous))
    }
}
impl Drop for DpiScope {
    fn drop(&mut self) {
        // SAFETY: original thread context returned by the OS.
        unsafe { SetThreadDpiAwarenessContext(self.0) };
    }
}

struct Enumeration {
    monitors: Vec<Monitor>,
    failed: bool,
}
unsafe extern "system" fn enumerate_monitor(
    monitor: HMONITOR,
    _: HDC,
    _: *mut RECT,
    parameter: LPARAM,
) -> i32 {
    // SAFETY: synchronous EnumDisplayMonitors callback borrows the live stack data.
    let output = unsafe { &mut *(parameter as *mut Enumeration) };
    if output.monitors.len() >= 64 {
        output.failed = true;
        return 0;
    }
    let mut info = MONITORINFOEXW::default();
    info.monitorInfo.cbSize = size_of::<MONITORINFOEXW>() as u32;
    let (mut x, mut y, mut scale) = (0, 0, 0);
    // SAFETY: live callback monitor and initialized ABI-sized output structs.
    if unsafe { GetMonitorInfoW(monitor, (&mut info as *mut MONITORINFOEXW).cast()) } == 0
        || unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut x, &mut y) } < 0
        || unsafe { GetScaleFactorForMonitor(monitor, &mut scale) } < 0
        || !(100..=500).contains(&scale)
        || x == 0
        || y == 0
        || x > 960
        || y > 960
    {
        output.failed = true;
        return 0;
    }
    let Some(end) = info.szDevice.iter().position(|c| *c == 0) else {
        output.failed = true;
        return 0;
    };
    let rect = info.monitorInfo.rcMonitor;
    let width = i64::from(rect.right) - i64::from(rect.left);
    let height = i64::from(rect.bottom) - i64::from(rect.top);
    if end == 0 || !(1..=32768).contains(&width) || !(1..=32768).contains(&height) {
        output.failed = true;
        return 0;
    }
    output.monitors.push(Monitor {
        handle: monitor as usize,
        name: info.szDevice[..=end].to_vec(),
        bounds: [rect.left, rect.top, rect.right, rect.bottom],
        dpi: [x, y],
        scale,
        primary: info.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0,
    });
    1
}

fn context() -> io::Result<Context> {
    let _dpi = DpiScope::enter()?;
    let session = WindowsSessionSnapshot::current()?;
    let mut enumeration = Enumeration {
        monitors: Vec::new(),
        failed: false,
    };
    // SAFETY: callback borrows only the synchronous stack enumeration object.
    let result = unsafe {
        EnumDisplayMonitors(
            null_mut(),
            null(),
            Some(enumerate_monitor),
            (&mut enumeration as *mut Enumeration) as LPARAM,
        )
    };
    if result == 0 || enumeration.failed || enumeration.monitors.is_empty() {
        return Err(denied("capture monitor layout unavailable"));
    }
    enumeration.monitors.sort_by(|a, b| a.name.cmp(&b.name));
    if enumeration
        .monitors
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name)
    {
        return Err(denied("capture monitor identity is ambiguous"));
    }
    Ok(Context {
        session,
        monitors: enumeration.monitors,
    })
}

/// An opaque local selection tied to the complete display/session snapshot.
/// Enumerating does not read pixels. Remote messages must not manufacture sources.
#[derive(Clone)]
pub struct WindowsCaptureSource {
    original: Arc<Context>,
    index: usize,
}
impl WindowsCaptureSource {
    pub fn display(&self) -> Display {
        self.original.monitors[self.index].display(self.index as u32 + 1)
    }
    pub fn device_name(&self) -> String {
        let name = &self.original.monitors[self.index].name;
        String::from_utf16_lossy(&name[..name.len() - 1])
    }
    pub fn is_primary(&self) -> bool {
        self.original.monitors[self.index].primary
    }
}

struct State {
    frames: VecDeque<RawFrame>,
    bytes: usize,
    checked: Instant,
    ended: Option<Result<(), io::ErrorKind>>,
    ended_at: Option<Instant>,
}
struct Shared {
    stopped: Arc<AtomicBool>,
    invalidated: Arc<AtomicBool>,
    state: Mutex<State>,
    wake: Condvar,
    #[cfg(test)]
    observer: std::sync::atomic::AtomicUsize,
}
impl Shared {
    fn new() -> Self {
        Self {
            stopped: Arc::new(AtomicBool::new(false)),
            invalidated: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(State {
                frames: VecDeque::new(),
                bytes: 0,
                checked: Instant::now(),
                ended: None,
                ended_at: None,
            }),
            wake: Condvar::new(),
            #[cfg(test)]
            observer: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Ok(mut state) = self.state.lock() {
            state.frames.clear();
            state.bytes = 0;
        }
        self.wake.notify_all();
    }
    fn active(&self) -> bool {
        !self.stopped.load(Ordering::SeqCst) && !self.invalidated.load(Ordering::SeqCst)
    }
    fn check(&self) -> io::Result<()> {
        if !self.active() {
            return Err(denied("Windows capture stopped or platform changed"));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("capture state poisoned"))?;
        if state.ended.is_some() || state.checked.elapsed() > HEARTBEAT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Windows capture worker lost its heartbeat",
            ));
        }
        Ok(())
    }
    fn checked(&self) -> io::Result<()> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("capture state poisoned"))?
            .checked = Instant::now();
        Ok(())
    }
    fn publish(&self, frame: RawFrame) -> io::Result<()> {
        frame.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("capture state poisoned"))?;
        if !self.active() {
            return Err(denied("Windows capture ended while copying"));
        }
        if let Some(index) = state
            .frames
            .iter()
            .position(|old| old.source == frame.source)
            && let Some(old) = state.frames.remove(index)
        {
            state.bytes -= old.pixels.len();
        }
        if state.bytes + frame.pixels.len() > QUEUE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "capture queue exceeds its budget",
            ));
        }
        state.bytes += frame.pixels.len();
        state.frames.push_back(frame);
        Ok(())
    }
    fn finish(&self, result: io::Result<()>) {
        self.stop();
        if let Ok(mut state) = self.state.lock() {
            state
                .ended
                .get_or_insert_with(|| result.map_err(|error| error.kind()));
            state.ended_at.get_or_insert_with(Instant::now);
        }
        self.wake.notify_all();
    }
}

struct Surface {
    memory: HDC,
    bitmap: HBITMAP,
    original: HGDIOBJ,
    bits: *mut u8,
    display: Display,
    bytes: usize,
}
impl Surface {
    fn new(display: Display) -> io::Result<Self> {
        let width = display.logical.width;
        let height = display.logical.height;
        let bytes = frame_bytes(width, height)?;
        // SAFETY: creates a private memory DC; does not read any desktop pixels.
        let memory = unsafe { CreateCompatibleDC(null_mut()) };
        if memory.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut surface = Self {
            memory,
            bitmap: null_mut(),
            original: null_mut(),
            bits: null_mut(),
            display,
            bytes,
        };
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width as i32,
                biHeight: -(height as i32),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: bytes as u32,
                ..BITMAPINFOHEADER::default()
            },
            ..BITMAPINFO::default()
        };
        // SAFETY: initialized top-down 32-bit DIB declaration, no external mapping.
        surface.bitmap = unsafe {
            CreateDIBSection(
                memory,
                &info,
                DIB_RGB_COLORS,
                (&mut surface.bits as *mut *mut u8).cast(),
                null_mut(),
                0,
            )
        };
        if surface.bitmap.is_null() || surface.bits.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: selects an owned bitmap into this private memory DC.
        surface.original = unsafe { SelectObject(memory, surface.bitmap) };
        if surface.original.is_null() || surface.original as isize == -1 {
            surface.original = null_mut();
            return Err(io::Error::last_os_error());
        }
        Ok(surface)
    }
    fn read(&self, captured_at: Instant) -> io::Result<RawFrame> {
        // SAFETY: GDI drawing is complete on the owning worker; flush before CPU access.
        if unsafe { GdiFlush() } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: validated tightly packed DIB allocation owned and not concurrently drawn.
        let mut pixels = unsafe { std::slice::from_raw_parts(self.bits, self.bytes) }.to_vec();
        // BI_RGB's fourth byte is undefined alpha; wire-side BGRA must be opaque.
        for pixel in pixels.chunks_exact_mut(4) {
            pixel[3] = 255;
        }
        Ok(RawFrame {
            source: self.display.source,
            width: self.display.logical.width,
            height: self.display.logical.height,
            captured_at,
            pixels,
        })
    }
}
impl Drop for Surface {
    fn drop(&mut self) {
        // SAFETY: native objects stay on their creating thread and are deselected first.
        unsafe {
            if !self.original.is_null() {
                SelectObject(self.memory, self.original);
            }
            if !self.bitmap.is_null() {
                DeleteObject(self.bitmap);
            }
            DeleteDC(self.memory);
        }
    }
}
fn frame_bytes(width: u32, height: u32) -> io::Result<usize> {
    let bytes = u64::from(width)
        .checked_mul(u64::from(height))
        .and_then(|pixels| pixels.checked_mul(4));
    if width == 0
        || height == 0
        || width > 8192
        || height > 8192
        || bytes.is_none_or(|bytes| bytes > RAW_FRAME_BYTES as u64)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows frame exceeds its geometry/byte budget",
        ));
    }
    usize::try_from(bytes.ok_or_else(|| io::Error::other("Windows frame size overflow"))?)
        .map_err(io::Error::other)
}

struct OwnedIcon(HICON);
impl Drop for OwnedIcon {
    fn drop(&mut self) {
        // SAFETY: this handle was copied/created for this worker, never a shared cursor.
        unsafe { DestroyIcon(self.0) };
    }
}
struct IconBitmaps(ICONINFO);
impl Drop for IconBitmaps {
    fn drop(&mut self) {
        // SAFETY: GetIconInfo gives its caller ownership of these bitmap copies.
        unsafe {
            if !self.0.hbmColor.is_null() {
                DeleteObject(self.0.hbmColor);
            }
            if !self.0.hbmMask.is_null() && self.0.hbmMask != self.0.hbmColor {
                DeleteObject(self.0.hbmMask);
            }
        }
    }
}
fn bitmap_size(bitmap: HBITMAP) -> io::Result<(i32, i32)> {
    if bitmap.is_null() {
        return Err(io::Error::other("cursor bitmap is missing"));
    }
    let mut info = BITMAP::default();
    // SAFETY: live owned bitmap; writable output has the exact public ABI size.
    if unsafe {
        GetObjectW(
            bitmap,
            size_of::<BITMAP>() as i32,
            (&mut info as *mut BITMAP).cast(),
        )
    } != size_of::<BITMAP>() as i32
    {
        return Err(io::Error::last_os_error());
    }
    if info.bmWidth <= 0 || info.bmHeight <= 0 || info.bmWidth > 1024 || info.bmHeight > 2048 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cursor bitmap exceeds its size budget",
        ));
    }
    Ok((info.bmWidth, info.bmHeight))
}
struct CursorImage {
    icon: OwnedIcon,
    width: i32,
    height: i32,
    hotspot: [u32; 2],
    position: [i32; 2],
}
impl CursorImage {
    fn copy(cursor: HICON, position: [i32; 2]) -> io::Result<Self> {
        if cursor.is_null() {
            return Err(io::Error::other("visible cursor handle unavailable"));
        }
        // SAFETY: copies the borrowed OS cursor into a private, owned handle. All
        // subsequent drawing uses this copy even if the foreground app changes it.
        let copied = unsafe { CopyIcon(cursor) };
        if copied.is_null() {
            return Err(io::Error::last_os_error());
        }
        let icon = OwnedIcon(copied);
        let mut bitmaps = IconBitmaps(ICONINFO::default());
        // SAFETY: live private cursor and initialized output. RAII frees both returned
        // bitmap copies on every path, including failed metadata validation.
        if unsafe { GetIconInfo(icon.0, &mut bitmaps.0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mask = bitmap_size(bitmaps.0.hbmMask)?;
        let (width, height) = if bitmaps.0.hbmColor.is_null() {
            if mask.1 % 2 != 0 {
                return Err(io::Error::other("monochrome cursor mask is not paired"));
            }
            (mask.0, mask.1 / 2)
        } else {
            let color = bitmap_size(bitmaps.0.hbmColor)?;
            if color != mask {
                return Err(io::Error::other("cursor mask and color dimensions differ"));
            }
            color
        };
        if height <= 0
            || height > 1024
            || bitmaps.0.fIcon != 0
            || bitmaps.0.xHotspot >= width as u32
            || bitmaps.0.yHotspot >= height as u32
        {
            return Err(io::Error::other("cursor dimensions or hotspot are invalid"));
        }
        Ok(Self {
            icon,
            width,
            height,
            hotspot: [bitmaps.0.xHotspot, bitmaps.0.yHotspot],
            position,
        })
    }
    fn desktop() -> io::Result<Option<Self>> {
        let mut info = CURSORINFO {
            cbSize: size_of::<CURSORINFO>() as u32,
            ..CURSORINFO::default()
        };
        // SAFETY: local, read-only cursor query made only by the authorized monitor worker.
        if unsafe { GetCursorInfo(&mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if !cursor_visible(info.flags)? {
            return Ok(None);
        }
        Self::copy(info.hCursor, [info.ptScreenPos.x, info.ptScreenPos.y]).map(Some)
    }
    fn draw(&self, surface: &Surface) -> io::Result<()> {
        let layout = surface.display.logical;
        // Compute with i64 before clipping: virtual desktops may start below zero,
        // and an out-of-monitor hotspot can still leave visible cursor pixels.
        let x = i64::from(self.position[0]) - i64::from(layout.left) - i64::from(self.hotspot[0]);
        let y = i64::from(self.position[1]) - i64::from(layout.top) - i64::from(self.hotspot[1]);
        if x >= i64::from(layout.width)
            || y >= i64::from(layout.height)
            || x + i64::from(self.width) <= 0
            || y + i64::from(self.height) <= 0
        {
            return Ok(());
        }
        let x = i32::try_from(x).map_err(io::Error::other)?;
        let y = i32::try_from(y).map_err(io::Error::other)?;
        // SAFETY: only our private DIB and owned cursor are used. The memory DC
        // clips negative/edge coordinates; DI_NORMAL preserves alpha and AND/XOR
        // transparency according to Windows' cursor rendering rules.
        if unsafe {
            DrawIconEx(
                surface.memory,
                x,
                y,
                self.icon.0,
                self.width,
                self.height,
                0,
                null_mut(),
                DI_NORMAL | DI_NOMIRROR,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // Keep the copied cursor alive until any batched drawing is complete.
        if unsafe { GdiFlush() } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
fn cursor_visible(flags: CURSORINFO_FLAGS) -> io::Result<bool> {
    if flags & !(CURSOR_SHOWING | CURSOR_SUPPRESSED) != 0 {
        return Err(io::Error::other("unknown cursor visibility state"));
    }
    Ok(flags & CURSOR_SHOWING != 0 && flags & CURSOR_SUPPRESSED == 0)
}

enum Target {
    Monitor(Monitor),
    #[cfg(test)]
    OwnedWindow {
        hwnd: usize,
        thread: u32,
        width: u32,
        height: u32,
    },
}
impl Target {
    fn monitor(&self) -> Option<&Monitor> {
        match self {
            Self::Monitor(monitor) => Some(monitor),
            #[cfg(test)]
            Self::OwnedWindow { .. } => None,
        }
    }
}
struct NativeSource {
    target: Target,
    source: HDC,
    surface: Surface,
    duplication: Option<DesktopDuplication>,
    retry_duplication: Instant,
    #[cfg(test)]
    paint: Option<Surface>,
}
impl NativeSource {
    fn open(target: Target, display: Display) -> io::Result<Self> {
        let surface = Surface::new(display)?;
        let duplication = match &target {
            Target::Monitor(monitor) => match DesktopDuplication::open(monitor, display) {
                Ok(duplication) => {
                    eprintln!("capture_backend=dxgi source={}", display.source);
                    Some(duplication)
                }
                Err(error) => {
                    eprintln!(
                        "capture_backend=gdi source={} fallback={error}",
                        display.source
                    );
                    None
                }
            },
            #[cfg(test)]
            Target::OwnedWindow { .. } => None,
        };
        #[cfg(test)]
        let paint = if matches!(target, Target::OwnedWindow { .. }) {
            Some(Surface::new(display)?)
        } else {
            None
        };
        let source = match &target {
            Target::Monitor(monitor) => {
                // SAFETY: OS-enumerated, terminated monitor device name. Creates DC only.
                let source = unsafe {
                    CreateDCW(
                        windows_sys::w!("DISPLAY"),
                        monitor.name.as_ptr(),
                        null(),
                        null(),
                    )
                };
                if source.is_null() {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: read scalar caps from the just-created display DC. Reject
                // adapter/DC virtualization instead of capturing a different extent.
                if unsafe { GetDeviceCaps(source, HORZRES as i32) } != display.logical.width as i32
                    || unsafe { GetDeviceCaps(source, VERTRES as i32) }
                        != display.logical.height as i32
                {
                    unsafe { DeleteDC(source) };
                    return Err(denied(
                        "Windows display DC dimensions differ from the selected monitor",
                    ));
                }
                source
            }
            #[cfg(test)]
            Target::OwnedWindow { .. } => null_mut(),
        };
        Ok(Self {
            target,
            source,
            surface,
            duplication,
            retry_duplication: Instant::now() + Duration::from_secs(2),
            #[cfg(test)]
            paint,
        })
    }
    fn capture(&mut self) -> io::Result<Option<RawFrame>> {
        let captured_at = Instant::now();
        let d = self.surface.display.logical;
        // The worker validates the original display/session snapshot before
        // each call. Recreate only that approved HMONITOR after access/device
        // loss; retry at a bounded rate while GDI supplies compatibility frames.
        if self.duplication.is_none() && captured_at >= self.retry_duplication {
            self.retry_duplication = captured_at + Duration::from_secs(2);
            if let Some(monitor) = self.target.monitor()
                && let Ok(duplication) = DesktopDuplication::open(monitor, self.surface.display)
            {
                self.duplication = Some(duplication);
                eprintln!(
                    "capture_backend=dxgi source={} recovery=true",
                    self.surface.display.source
                );
            }
        }
        if let Some(duplication) = &mut self.duplication {
            match duplication.read(&self.surface) {
                Ok(false) => return Ok(None),
                Ok(true) => {
                    if let Some(cursor) = CursorImage::desktop()? {
                        cursor.draw(&self.surface)?;
                    }
                    return self.surface.read(captured_at).map(Some);
                }
                Err(error) => {
                    // The outer worker still checks the original session,
                    // monitor and DPI snapshot before delivering any pixels.
                    eprintln!(
                        "capture_backend=gdi source={} fallback={error}",
                        self.surface.display.source
                    );
                    self.duplication = None;
                    self.retry_duplication = captured_at + Duration::from_secs(2);
                }
            }
        }
        let source = match &self.target {
            Target::Monitor(_) => self.source,
            #[cfg(test)]
            Target::OwnedWindow {
                hwnd,
                thread,
                width,
                height,
            } => {
                let window = *hwnd as HWND;
                let mut pid = 0;
                let mut rect = RECT::default();
                // SAFETY: read-only HWND identity and dimensions. Test selects only our process.
                if unsafe { GetWindowThreadProcessId(window, &mut pid) } != *thread
                    || pid != unsafe { GetCurrentProcessId() }
                    || unsafe { GetClientRect(window, &mut rect) } == 0
                    || rect.right != *width as i32
                    || rect.bottom != *height as i32
                {
                    return Err(denied("owned fixture window changed"));
                }
                let paint = self
                    .paint
                    .as_ref()
                    .ok_or_else(|| io::Error::other("owned fixture paint surface absent"))?;
                // SAFETY: our window synchronously paints only into this worker-owned
                // DIB. Keep its DC alive until the callback returns even if rendering
                // stalls; the external controller still has a bounded cleanup wait.
                if unsafe {
                    SendMessageW(
                        window,
                        WM_PRINTCLIENT,
                        paint.memory as usize,
                        PRF_CLIENT as isize,
                    )
                } != 1
                {
                    return Err(io::Error::other("owned fixture paint failed"));
                }
                paint.memory
            }
        };
        // SAFETY: private destination and either the selected display DC or the
        // test's private painted DC. Coordinates are local to that source DC.
        if unsafe {
            BitBlt(
                self.surface.memory,
                0,
                0,
                d.width as i32,
                d.height as i32,
                source,
                0,
                0,
                SRCCOPY | CAPTUREBLT,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // Test windows must never read or draw the user's real cursor. Production
        // monitor capture includes it before the outer worker rechecks OS facts.
        if matches!(self.target, Target::Monitor(_))
            && let Some(cursor) = CursorImage::desktop()?
        {
            cursor.draw(&self.surface)?;
        }
        self.surface.read(captured_at).map(Some)
    }
}
impl Drop for NativeSource {
    fn drop(&mut self) {
        if !self.source.is_null() {
            // SAFETY: this DC was created by CreateDCW and is never shared.
            unsafe { DeleteDC(self.source) };
        }
    }
}

pub struct WindowsCapture {
    shared: Arc<Shared>,
    displays: Vec<Display>,
    worker: Option<thread::JoinHandle<()>>,
    cleanup_deadline: Option<Instant>,
}
impl WindowsCapture {
    /// Read only. UI must obtain a fresh selection after any desktop/layout change.
    pub fn enumerate() -> io::Result<Vec<WindowsCaptureSource>> {
        let original = Arc::new(context()?);
        Ok((0..original.monitors.len())
            .map(|index| WindowsCaptureSource {
                original: original.clone(),
                index,
            })
            .collect())
    }
    /// Starts pixel capture for the locally selected sources. Call only after View
    /// authorization, then immediately attach to VideoController with that lease.
    pub fn open(sources: Vec<WindowsCaptureSource>) -> io::Result<Self> {
        let original = sources
            .first()
            .ok_or_else(|| denied("no display selected"))?
            .original
            .clone();
        let mut ids = BTreeSet::new();
        if sources.len() > 64
            || sources
                .iter()
                .any(|s| *s.original != *original || !ids.insert(s.index))
        {
            return Err(denied("duplicate or mixed Windows display selection"));
        }
        let targets = sources
            .into_iter()
            .map(|s| {
                (
                    Target::Monitor(original.monitors[s.index].clone()),
                    s.display(),
                )
            })
            .collect();
        Self::start(original, targets)
    }
    fn start(original: Arc<Context>, targets: Vec<(Target, Display)>) -> io::Result<Self> {
        let displays: Vec<_> = targets.iter().map(|(_, display)| *display).collect();
        let total = displays.iter().try_fold(0usize, |sum, display| {
            sum.checked_add(frame_bytes(display.logical.width, display.logical.height)?)
                .ok_or_else(|| io::Error::other("Windows capture size overflow"))
        })?;
        if displays.is_empty() || displays.len() > 64 || total > QUEUE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "selected Windows displays exceed aggregate budget",
            ));
        }
        let shared = Arc::new(Shared::new());
        let worker_shared = shared.clone();
        let (ready, readiness) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nestlink-windows-capture".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(worker_shared.clone(), original, targets, ready.clone())
                }))
                .unwrap_or_else(|_| Err(io::Error::other("Windows capture worker panicked")));
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
                    format!("Windows capture did not start: {error}"),
                ))
            }
        }
    }
    pub fn displays(&self) -> &[Display] {
        &self.displays
    }
}
fn run(
    shared: Arc<Shared>,
    original: Arc<Context>,
    targets: Vec<(Target, Display)>,
    ready: mpsc::SyncSender<io::Result<()>>,
) -> io::Result<()> {
    let _dpi = DpiScope::enter()?;
    // Subscribe before comparing facts so changes during initialization are observed.
    let mut observer = WindowsSessionObserver::open(shared.invalidated.clone(), true)?;
    #[cfg(test)]
    shared
        .observer
        .store(observer.notification_window(), Ordering::SeqCst);
    let result = run_observed(shared, original, targets, ready, &observer);
    // Always close on this worker, preserving capture errors first and making
    // observer cleanup errors visible on an otherwise successful stop.
    let cleanup = observer.close();
    result.and(cleanup)
}
fn run_observed(
    shared: Arc<Shared>,
    original: Arc<Context>,
    targets: Vec<(Target, Display)>,
    ready: mpsc::SyncSender<io::Result<()>>,
    observer: &WindowsSessionObserver,
) -> io::Result<()> {
    if context()? != *original {
        return Err(denied("Windows capture selection changed before start"));
    }
    let mut sources = targets
        .into_iter()
        .map(|(target, display)| NativeSource::open(target, display))
        .collect::<io::Result<Vec<_>>>()?;
    observer.pump();
    if !shared.active() || context()? != *original {
        return Err(denied("Windows capture changed during setup"));
    }
    shared.checked()?;
    ready
        .send(Ok(()))
        .map_err(|_| denied("Windows capture caller ended"))?;
    while !shared.stopped.load(Ordering::SeqCst) {
        let iteration = Instant::now();
        for source in &mut sources {
            observer.pump();
            if shared.stopped.load(Ordering::SeqCst) {
                return Ok(());
            }
            if !shared.active() || context()? != *original {
                return Err(denied("Windows desktop, monitor, DPI or session changed"));
            }
            shared.checked()?;
            let frame = source.capture()?;
            observer.pump();
            if shared.stopped.load(Ordering::SeqCst) {
                return Ok(());
            }
            if !shared.active() || context()? != *original {
                return Err(denied("Windows platform changed while capturing"));
            }
            shared.checked()?;
            if let Some(frame) = frame {
                shared.publish(frame)?;
            }
        }
        let state = shared
            .state
            .lock()
            .map_err(|_| io::Error::other("capture state poisoned"))?;
        if shared.stopped.load(Ordering::SeqCst) {
            break;
        }
        let _ = shared
            .wake
            .wait_timeout(state, FRAME_INTERVAL.saturating_sub(iteration.elapsed()))
            .map_err(|_| io::Error::other("capture wait poisoned"))?;
    }
    Ok(())
}
impl CaptureDevice for WindowsCapture {
    fn check(&mut self) -> io::Result<()> {
        let result = self.shared.check();
        if result.is_err() {
            self.shared.stop();
        }
        result
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        self.check()?;
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| io::Error::other("capture state poisoned"))?;
        if !self.shared.active() {
            return Err(denied("Windows capture ended before delivery"));
        }
        let frame = state.frames.pop_front();
        if let Some(frame) = &frame {
            state.bytes -= frame.pixels.len();
        }
        Ok(frame)
    }
    fn reset(&mut self) -> io::Result<()> {
        let deadline = *self
            .cleanup_deadline
            .get_or_insert_with(|| Instant::now() + CLEANUP);
        self.shared.stop();
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| io::Error::other("capture state poisoned"))?;
        while state.ended.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.ended = Some(Err(io::ErrorKind::TimedOut));
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Windows capture worker cleanup timed out",
                ));
            }
            state = self
                .shared
                .wake
                .wait_timeout(state, remaining)
                .map_err(|_| io::Error::other("capture cleanup wait poisoned"))?
                .0;
        }
        let result = state.ended.unwrap_or(Err(io::ErrorKind::Other));
        let result = if result.is_ok() && state.ended_at.is_some_and(|ended| ended > deadline) {
            // The worker may complete after timeout but before this waiter
            // reacquires its mutex. Compare completion time, not wake ordering.
            state.ended = Some(Err(io::ErrorKind::TimedOut));
            Err(io::ErrorKind::TimedOut)
        } else {
            result
        };
        drop(state);
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
            && let Some(worker) = self.worker.take()
        {
            worker
                .join()
                .map_err(|_| io::Error::other("Windows capture worker join failed"))?;
        }
        result.map_err(|kind| io::Error::new(kind, "Windows capture worker failed"))
    }
}
impl Drop for WindowsCapture {
    fn drop(&mut self) {
        let _ = self.reset();
    }
}

#[cfg(test)]
mod tests;

#[path = "windows_host.rs"]
mod host;
pub use host::{WindowsHostCapture, probe_windows_gpu_h264};
