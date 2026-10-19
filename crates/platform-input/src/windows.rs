#![allow(unsafe_code)]
use super::{InputCapabilities, NativeInput, denied};
use crate::keys::{Stroke, windows_stroke};
use nestlink_platform_session::{WindowsSessionMonitor, WindowsSessionSnapshot};
use nestlink_remote::input::{Button, InputAction, InputDevice, InputLayout, PlatformInput};
use std::{
    collections::BTreeSet,
    io,
    mem::size_of,
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{HANDLE, LPARAM, RECT},
    Graphics::Gdi::{EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO},
    System::{StationsAndDesktops::*, Threading::GetCurrentThreadId},
    UI::{HiDpi::*, Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
};
#[derive(Debug, Clone, PartialEq, Eq)]
struct Context {
    desktop: String,
    session: WindowsSessionSnapshot,
    keyboard: usize,
    monitors: Vec<[i32; 7]>,
    bounds: [i32; 4],
}
struct Desktop(HDESK);
impl Drop for Desktop {
    fn drop(&mut self) {
        // SAFETY: OpenInputDesktop transfers one owned handle; no callbacks retain it.
        unsafe {
            CloseDesktop(self.0);
        }
    }
}
struct DpiScope(DPI_AWARENESS_CONTEXT);
impl DpiScope {
    fn enter() -> io::Result<Self> {
        // SAFETY: predefined DPI context is valid; restoration stays on this thread.
        let old =
            unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        if old.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(old))
    }
}
impl Drop for DpiScope {
    fn drop(&mut self) {
        // SAFETY: valid context returned by the thread-local API, restored in the same synchronous scope.
        unsafe {
            SetThreadDpiAwarenessContext(self.0);
        }
    }
}
fn object_name(handle: HANDLE) -> io::Result<String> {
    let mut buffer = [0u16; 128];
    let mut needed = 0;
    // SAFETY: live borrowed OS object handle and correctly sized writable UTF-16 buffer.
    let okay = unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * 2) as u32,
            &mut needed,
        )
    };
    if okay == 0 || needed == 0 || needed as usize > buffer.len() * 2 || needed % 2 != 0 {
        return Err(denied("interactive desktop identity unavailable"));
    }
    let end = buffer
        .iter()
        .position(|n| *n == 0)
        .ok_or_else(|| denied("desktop name not terminated"))?;
    String::from_utf16(&buffer[..end]).map_err(io::Error::other)
}
struct Enumeration {
    monitors: Vec<[i32; 7]>,
    failed: bool,
}
unsafe extern "system" fn monitor_callback(
    monitor: HMONITOR,
    _: HDC,
    _: *mut RECT,
    data: LPARAM,
) -> i32 {
    // SAFETY: EnumDisplayMonitors calls synchronously with the live stack Enumeration pointer.
    let output = unsafe { &mut *(data as *mut Enumeration) };
    if output.monitors.len() >= 64 {
        output.failed = true;
        return 0;
    }
    let mut info = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..MONITORINFO::default()
    };
    let (mut x, mut y) = (0, 0);
    // SAFETY: callback monitor is live; all output structs have declared OS ABI sizes.
    if unsafe { GetMonitorInfoW(monitor, &mut info) } == 0
        || unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut x, &mut y) } < 0
        || x == 0
        || y == 0
        || x > 960
        || y > 960
    {
        output.failed = true;
        return 0;
    }
    output.monitors.push([
        info.rcMonitor.left,
        info.rcMonitor.top,
        info.rcMonitor.right,
        info.rcMonitor.bottom,
        info.dwFlags as i32,
        x as i32,
        y as i32,
    ]);
    1
}
fn context() -> io::Result<Context> {
    let _dpi = DpiScope::enter()?;
    // SAFETY: APIs return borrowed process/thread handles or an owned desktop; no pointer is retained across calls.
    let station = unsafe { GetProcessWindowStation() };
    if station.is_null() || object_name(station)? != "WinSta0" {
        return Err(denied("input requires an interactive user window station"));
    }
    let thread = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
    if thread.is_null() {
        return Err(denied("thread desktop inaccessible"));
    }
    let input = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
    if input.is_null() {
        return Err(denied("input desktop locked or inaccessible"));
    }
    let input = Desktop(input);
    let desktop = object_name(input.0)?;
    if desktop != "Default" || object_name(thread)? != desktop {
        return Err(denied("secure or different desktop is not an input target"));
    }
    let session = WindowsSessionSnapshot::current()?;
    // SAFETY: current foreground HWND is borrowed; the null output process pointer is explicitly supported.
    let foreground = unsafe { GetForegroundWindow() };
    let target_thread = unsafe { GetWindowThreadProcessId(foreground, null_mut()) };
    let keyboard = unsafe { GetKeyboardLayout(target_thread) } as usize;
    if keyboard == 0 {
        return Err(denied("keyboard layout unavailable"));
    }
    let mut output = Enumeration {
        monitors: Vec::new(),
        failed: false,
    };
    // SAFETY: bounded callback writes only into the synchronous live Enumeration object.
    let enumerated = unsafe {
        EnumDisplayMonitors(
            null_mut(),
            null(),
            Some(monitor_callback),
            &mut output as *mut _ as LPARAM,
        )
    };
    if enumerated == 0 || output.failed || output.monitors.is_empty() {
        return Err(denied("monitor layout unavailable"));
    }
    output.monitors.sort();
    // SAFETY: scalar metrics read under the temporary physical-pixel DPI context.
    let bounds = unsafe {
        [
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        ]
    };
    if bounds[2] <= 0 || bounds[3] <= 0 || bounds[2] > 32768 || bounds[3] > 32768 {
        return Err(denied("virtual desktop dimensions out of bounds"));
    }
    Ok(Context {
        desktop,
        session,
        keyboard,
        monitors: output.monitors,
        bounds,
    })
}
fn key(stroke: Stroke, down: bool) -> INPUT {
    let (vk, scan, flags) = match stroke {
        Stroke::Scan(scan, extended) => (
            0,
            scan,
            KEYEVENTF_SCANCODE | if extended { KEYEVENTF_EXTENDEDKEY } else { 0 },
        ),
        Stroke::Virtual(vk) => (vk, 0, 0),
    };
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags | if down { 0 } else { KEYEVENTF_KEYUP },
                ..KEYBDINPUT::default()
            },
        },
    }
}
fn unicode(unit: u16, down: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wScan: unit,
                dwFlags: KEYEVENTF_UNICODE | if down { 0 } else { KEYEVENTF_KEYUP },
                ..KEYBDINPUT::default()
            },
        },
    }
}
fn mouse(button: u8, down: bool) -> io::Result<INPUT> {
    let (flags, data) = match (button, down) {
        (1, true) => (MOUSEEVENTF_LEFTDOWN, 0),
        (1, false) => (MOUSEEVENTF_LEFTUP, 0),
        (2, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
        (2, false) => (MOUSEEVENTF_RIGHTUP, 0),
        (3, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
        (3, false) => (MOUSEEVENTF_MIDDLEUP, 0),
        (4, true) => (MOUSEEVENTF_XDOWN, 1),
        (4, false) => (MOUSEEVENTF_XUP, 1),
        (5, true) => (MOUSEEVENTF_XDOWN, 2),
        (5, false) => (MOUSEEVENTF_XUP, 2),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown pointer button",
            ));
        }
    };
    Ok(INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                mouseData: data,
                dwFlags: flags,
                ..MOUSEINPUT::default()
            },
        },
    })
}
fn position(layout: InputLayout, x: i32, y: i32) -> io::Result<INPUT> {
    let (dx, dy) = (
        i64::from(x) - i64::from(layout.left),
        i64::from(y) - i64::from(layout.top),
    );
    if dx < 0 || dy < 0 || dx >= i64::from(layout.width) || dy >= i64::from(layout.height) {
        return Err(denied("pointer outside physical virtual desktop"));
    }
    let normalize = |offset: i64, size: u32| -> i32 {
        if size <= 1 {
            0
        } else {
            (offset * 65535 / i64::from(size - 1)) as i32
        }
    };
    Ok(INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: normalize(dx, layout.width),
                dy: normalize(dy, layout.height),
                dwFlags: MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE | MOUSEEVENTF_VIRTUALDESK,
                ..MOUSEINPUT::default()
            },
        },
    })
}
fn send(packets: &[INPUT]) -> io::Result<()> {
    if packets.is_empty() || packets.len() > 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native input batch out of bounds",
        ));
    }
    // SAFETY: contiguous initialized INPUT values, exact OS element size and bounded count; SendInput copies synchronously.
    let inserted = unsafe {
        SendInput(
            packets.len() as u32,
            packets.as_ptr(),
            size_of::<INPUT>() as i32,
        )
    };
    if inserted != packets.len() as u32 {
        return Err(denied(
            "OS refused input; desktop or integrity restrictions may apply",
        ));
    }
    Ok(())
}
pub struct WindowsInput {
    original: Context,
    monitor: WindowsSessionMonitor,
    terminal: bool,
    held: BTreeSet<Button>,
    unicode_pending: BTreeSet<u16>,
    cleanup_deadline: Option<Instant>,
    cleanup_result: Option<Result<(), (io::ErrorKind, String)>>,
}
impl WindowsInput {
    pub fn open() -> io::Result<Self> {
        // Subscribe on the monitor worker before reading any input baseline.
        let monitor = WindowsSessionMonitor::open(true)?;
        let original = context()?;
        monitor.check()?;
        if &original.session != monitor.original() {
            return Err(denied("Windows input login changed while subscribing"));
        }
        Ok(Self {
            original,
            monitor,
            terminal: false,
            held: BTreeSet::new(),
            unicode_pending: BTreeSet::new(),
            cleanup_deadline: None,
            cleanup_result: None,
        })
    }
    fn release(&mut self, button: Button) -> io::Result<()> {
        self.release_budget()?;
        if !self.held.contains(&button) {
            return Ok(());
        }
        let packet = match button {
            Button::Key(usage) => key(
                windows_stroke(usage).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Unsupported, "unsupported HID usage")
                })?,
                false,
            ),
            Button::Pointer(b) => mouse(b, false)?,
        };
        // Release belongs only to the original user desktop, never a secure desktop.
        self.release_context()?;
        send(&[packet])?;
        self.held.remove(&button);
        self.release_budget()
    }
    fn release_budget(&self) -> io::Result<()> {
        if self
            .cleanup_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "input cleanup budget exhausted",
            ));
        }
        Ok(())
    }
    fn release_context(&self) -> io::Result<()> {
        // A release may ignore a layout-change latch, but never cross a login,
        // RDP connection replacement, lock or secure desktop boundary.
        if WindowsSessionSnapshot::current()? != self.original.session {
            return Err(denied(
                "original Windows input login unavailable for release",
            ));
        }
        self.release_budget()
    }
    fn text(&mut self, text: &str) -> io::Result<()> {
        if text.is_empty() || text.len() > 16384 || !self.held.is_empty() {
            return Err(denied(
                "text commit requires a bounded message and released remote buttons",
            ));
        }
        // SAFETY: read-only queries of modifier states; never release physical user keys.
        if unsafe {
            [VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN]
                .iter()
                .any(|v| GetAsyncKeyState(i32::from(*v)) < 0)
        } {
            return Err(denied("local modifier is pressed during text commit"));
        }
        let deadline = Instant::now() + Duration::from_millis(100);
        let units: Vec<_> = text.encode_utf16().collect();
        for chunk in units.chunks(32) {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "text injection budget exhausted",
                ));
            }
            self.check()?;
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "text platform check exhausted injection budget",
                ));
            }
            let mut packets = Vec::with_capacity(chunk.len() * 2);
            for unit in chunk {
                self.unicode_pending.insert(*unit);
                packets.extend([unicode(*unit, true), unicode(*unit, false)]);
            }
            send(&packets)?;
            for unit in chunk {
                self.unicode_pending.remove(unit);
            }
        }
        Ok(())
    }
}
impl NativeInput for WindowsInput {
    fn layout(&self) -> InputLayout {
        let b = self.original.bounds;
        InputLayout {
            left: b[0],
            top: b[1],
            width: b[2] as u32,
            height: b[3] as u32,
        }
    }
    fn capabilities(&self) -> InputCapabilities {
        InputCapabilities {
            physical_keys: true,
            pointer_buttons: true,
            text_commit: true,
        }
    }
}
impl InputDevice for WindowsInput {
    fn check(&mut self) -> io::Result<()> {
        let result = (|| {
            if self.terminal {
                return Err(denied("Windows input is terminal"));
            }
            self.monitor.check()?;
            if context()? != self.original {
                return Err(denied(
                    "desktop, login, keyboard layout, monitor or DPI changed",
                ));
            }
            self.monitor.check()
        })();
        if result.is_err() {
            self.terminal = true;
            self.monitor.stop();
        }
        result
    }
    fn begin_reset(&mut self) -> io::Result<()> {
        self.terminal = true;
        self.monitor.stop();
        self.cleanup_deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_millis(150));
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.begin_reset()?;
        if let Some(result) = &self.cleanup_result {
            return result
                .as_ref()
                .copied()
                .map_err(|(kind, message)| io::Error::new(*kind, message.clone()));
        }
        let mut error = None;
        for button in self.held.iter().copied().collect::<Vec<_>>() {
            if let Err(failed) = self.release(button)
                && error.is_none()
            {
                error = Some(failed);
            }
        }
        for unit in self.unicode_pending.iter().copied().collect::<Vec<_>>() {
            let result = self
                .release_budget()
                .and_then(|()| self.release_context())
                .and_then(|()| {
                    send(&[unicode(unit, false)])?;
                    self.unicode_pending.remove(&unit);
                    self.release_budget()
                });
            match result {
                Ok(()) => {
                    self.unicode_pending.remove(&unit);
                }
                Err(failed) => {
                    if error.is_none() {
                        error = Some(failed);
                    }
                }
            }
        }
        if let Err(failed) = self
            .monitor
            .close_until(self.cleanup_deadline.unwrap_or_else(Instant::now))
            && error.is_none()
        {
            error = Some(failed);
        }
        let result = error.map_or(Ok(()), Err);
        self.cleanup_result = Some(
            result
                .as_ref()
                .copied()
                .map_err(|error| (error.kind(), error.to_string())),
        );
        result
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        if let PlatformInput::Release(button) = input {
            return self.release(button);
        }
        self.check()?;
        match input {
            PlatformInput::Action(InputAction::Key { code, down }) => {
                let stroke = windows_stroke(*code).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Unsupported, "unsupported HID usage")
                })?;
                let button = Button::Key(*code);
                if *down {
                    self.held.insert(button);
                } else if !self.held.contains(&button) {
                    return Ok(());
                }
                send(&[key(stroke, *down)])?;
                if !down {
                    self.held.remove(&button);
                }
                Ok(())
            }
            PlatformInput::Action(InputAction::Pointer { button, down, x, y }) => {
                let mut packets = vec![position(self.layout(), *x, *y)?];
                if let Some(button) = button {
                    if *down {
                        self.held.insert(Button::Pointer(*button));
                    } else if !self.held.contains(&Button::Pointer(*button)) {
                        return send(&packets);
                    }
                    packets.push(mouse(*button, *down)?);
                }
                send(&packets)?;
                if let Some(button) = button
                    && !down
                {
                    self.held.remove(&Button::Pointer(*button));
                }
                Ok(())
            }
            PlatformInput::Action(InputAction::Scroll { x, y }) => {
                let packets: Vec<_> = [(*x, MOUSEEVENTF_HWHEEL), (*y, MOUSEEVENTF_WHEEL)]
                    .into_iter()
                    .filter(|(delta, _)| *delta != 0)
                    .map(|(delta, flags)| INPUT {
                        r#type: INPUT_MOUSE,
                        Anonymous: INPUT_0 {
                            mi: MOUSEINPUT {
                                mouseData: delta as u32,
                                dwFlags: flags,
                                ..MOUSEINPUT::default()
                            },
                        },
                    })
                    .collect();
                send(&packets)
            }
            PlatformInput::Action(InputAction::Text(text)) => self.text(text),
            PlatformInput::Release(_) => unreachable!(),
        }
    }
}
impl Drop for WindowsInput {
    fn drop(&mut self) {
        let _ = self.begin_reset();
        let _ = self.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negative_virtual_origin_maps_to_absolute_endpoints_and_extended_keys_keep_their_flags()
    -> io::Result<()> {
        let layout = InputLayout {
            left: -1920,
            top: 0,
            width: 3840,
            height: 1080,
        };
        let first = position(layout, -1920, 0)?;
        let last = position(layout, 1919, 1079)?;
        // SAFETY: these helpers initialize the mouse union for INPUT_MOUSE.
        assert_eq!(
            unsafe { (first.Anonymous.mi.dx, first.Anonymous.mi.dy) },
            (0, 0)
        );
        assert_eq!(
            unsafe { (last.Anonymous.mi.dx, last.Anonymous.mi.dy) },
            (65535, 65535)
        );
        assert!(position(layout, 1920, 0).is_err());
        let right_ctrl = key(Stroke::Scan(0x1d, true), false);
        // SAFETY: key() initializes the keyboard union for INPUT_KEYBOARD.
        assert_eq!(
            unsafe { right_ctrl.Anonymous.ki.dwFlags },
            KEYEVENTF_SCANCODE | KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP
        );
        let units: Vec<_> = "中😀".encode_utf16().collect();
        assert_eq!(units.len(), 3);
        Ok(())
    }
    #[test]
    #[ignore = "requires an actual interactive Windows user desktop; run through platform acceptance"]
    fn actual_interactive_desktop_snapshot_is_bounded_without_injecting_input() -> io::Result<()> {
        let original = context()?;
        assert_eq!(original.desktop, "Default");
        assert_eq!(original.session, WindowsSessionSnapshot::current()?);
        assert!(!original.monitors.is_empty());
        Ok(())
    }
    #[test]
    #[ignore = "requires an interactive Windows desktop; readonly monitor and empty-input reset only"]
    fn actual_input_monitor_stop_is_terminal_and_reset_never_renews_deadline() -> io::Result<()> {
        let mut device = WindowsInput::open()?;
        device.check()?;
        assert!(device.held.is_empty() && device.unicode_pending.is_empty());
        device.monitor.stop();
        assert!(device.check().is_err());
        device.begin_reset()?;
        let deadline = device.cleanup_deadline;
        device.begin_reset()?;
        assert_eq!(deadline, device.cleanup_deadline);
        device.reset()?;
        device.reset()?;
        assert!(device.check().is_err());
        assert_eq!(deadline, device.cleanup_deadline);
        Ok(())
    }
}
