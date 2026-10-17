//! CF_UNICODETEXT only. No OLE objects, delayed rendering or clipboard restore.
#![allow(unsafe_code)]
use crate::{
    Backend, CLIPBOARD_TEXT_BYTES, ClipboardAuthority, ClipboardBinding, ClipboardDevice,
    ClipboardDirection, Context, LocalClipboardApproval, denied, timed_out, validate_text,
};
use nestlink_platform_session::{WindowsSessionMonitor, WindowsSessionSnapshot};
use std::{
    io,
    ptr::{null, null_mut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, GlobalFree, HGLOBAL, HWND, SetLastError},
    System::{DataExchange::*, LibraryLoader::GetModuleHandleW, Memory::*},
    UI::WindowsAndMessaging::*,
};
use zeroize::Zeroizing;

// Documented predefined Win32 clipboard format, independent of OLE.
const UNICODE_TEXT: u32 = 13;
static WORKER_LIVE: AtomicBool = AtomicBool::new(false);
struct WorkerSlot;
impl WorkerSlot {
    fn acquire() -> io::Result<Self> {
        WORKER_LIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "a Windows clipboard worker is still alive",
                )
            })?;
        Ok(Self)
    }
}
impl Drop for WorkerSlot {
    fn drop(&mut self) {
        WORKER_LIVE.store(false, Ordering::SeqCst);
    }
}
pub struct WindowsClipboard;
impl WindowsClipboard {
    /// No clipboard data is accessed until a separately authorized operation.
    pub fn open(
        binding: ClipboardBinding,
        approval: LocalClipboardApproval,
        authority: Arc<dyn ClipboardAuthority>,
    ) -> io::Result<ClipboardDevice> {
        let slot = WorkerSlot::acquire()?;
        ClipboardDevice::open(binding, approval, authority, move |until| {
            Ok(Box::new(Clipboard::open(slot, until)?))
        })
    }
}
struct Window(HWND);
impl Drop for Window {
    fn drop(&mut self) {
        // SAFETY: this worker owns the window and destroys it on its creating thread.
        if !self.0.is_null() {
            unsafe {
                DestroyWindow(self.0);
            }
        }
    }
}
struct Opened(bool);
impl Opened {
    fn open(
        window: HWND,
        context: &Context,
        direction: ClipboardDirection,
        until: Instant,
    ) -> io::Result<Self> {
        loop {
            context.check(direction, until)?;
            // SAFETY: valid worker-owned HWND. OpenClipboard transfers only a thread-local lock.
            if unsafe { OpenClipboard(window) } != 0 {
                return Ok(Self(true));
            }
            if until.saturating_duration_since(Instant::now()) <= Duration::from_millis(3) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Windows clipboard is locked by another application",
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn finish(mut self) -> io::Result<()> {
        // SAFETY: successful OpenClipboard was performed on this worker thread.
        if unsafe { CloseClipboard() } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.0 = false;
        Ok(())
    }
}
impl Drop for Opened {
    fn drop(&mut self) {
        // SAFETY: release only this scope's clipboard lock, never an unrelated open.
        if self.0 {
            unsafe {
                CloseClipboard();
            }
        }
    }
}
struct Global(HGLOBAL);
impl Drop for Global {
    fn drop(&mut self) {
        // SAFETY: an unpublished GMEM_MOVEABLE allocation still belongs to this scope.
        if !self.0.is_null() {
            unsafe {
                GlobalFree(self.0);
            }
        }
    }
}
struct Locked(HGLOBAL);
impl Drop for Locked {
    fn drop(&mut self) {
        // SAFETY: this scope owns one successful GlobalLock; allocation remains live.
        unsafe {
            GlobalUnlock(self.0);
        }
    }
}
fn decode_unicode(units: &[u16]) -> io::Result<Zeroizing<String>> {
    if units.is_empty() || units.len() > CLIPBOARD_TEXT_BYTES + 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows clipboard allocation exceeds the text budget",
        ));
    }
    let end = units.iter().position(|value| *value == 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows Unicode clipboard is not terminated",
        )
    })?;
    let text = Zeroizing::new(String::from_utf16(&units[..end]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows clipboard contains invalid UTF-16",
        )
    })?);
    validate_text(&text)?;
    Ok(text)
}
struct Clipboard {
    window: Window,
    monitor: WindowsSessionMonitor,
    original: WindowsSessionSnapshot,
    _slot: WorkerSlot,
    closed: bool,
}
impl Clipboard {
    fn open(slot: WorkerSlot, until: Instant) -> io::Result<Self> {
        let monitor = WindowsSessionMonitor::open(false)?;
        let original = WindowsSessionSnapshot::current()?;
        if original != *monitor.original() || Instant::now() >= until {
            return Err(denied("Windows clipboard desktop changed during startup"));
        }
        let class: Vec<u16> = "STATIC\0".encode_utf16().collect();
        // SAFETY: built-in class, initialized strings, no callback data, same-thread HWND ownership.
        let window = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                null(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                null_mut(),
                GetModuleHandleW(null()),
                null(),
            )
        };
        if window.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut clipboard = Self {
            window: Window(window),
            monitor,
            original,
            _slot: slot,
            closed: false,
        };
        clipboard.check(until)?;
        Ok(clipboard)
    }
}
fn read_native(
    window: HWND,
    context: &Context,
    until: Instant,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<Option<Zeroizing<String>>> {
    check()?;
    let opened = Opened::open(window, context, ClipboardDirection::Read, until)?;
    context.check(ClipboardDirection::Read, until)?;
    // SAFETY: read-only format availability query while this worker owns OpenClipboard.
    if unsafe { IsClipboardFormatAvailable(UNICODE_TEXT) } == 0 {
        opened.finish()?;
        return Ok(None);
    }
    // SAFETY: format handle is borrowed while the clipboard is locked. Delayed
    // rendering may block; the caller's deadline/terminal flag prevents late delivery.
    let handle = unsafe { GetClipboardData(UNICODE_TEXT) };
    context.check(ClipboardDirection::Read, until)?;
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CF_UNICODETEXT is a documented HGLOBAL, borrowed until CloseClipboard.
    let bytes = unsafe { GlobalSize(handle) };
    if bytes < 2 || bytes % 2 != 0 || bytes > (CLIPBOARD_TEXT_BYTES + 1) * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows clipboard allocation exceeds the Unicode budget",
        ));
    }
    // SAFETY: live validated HGLOBAL, successful lock is paired with Locked's drop.
    let pointer = unsafe { GlobalLock(handle) };
    if pointer.is_null() {
        return Err(io::Error::last_os_error());
    }
    let locked = Locked(handle);
    // SAFETY: GlobalSize was checked before reading; locked memory stays valid and aligned for UTF-16.
    let text =
        decode_unicode(unsafe { std::slice::from_raw_parts(pointer.cast::<u16>(), bytes / 2) })?;
    drop(locked);
    check()?;
    context.check(ClipboardDirection::Read, until)?;
    opened.finish()?;
    Ok(Some(text))
}
fn write_native(
    window: HWND,
    text: &str,
    context: &Context,
    until: Instant,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    validate_text(text)?;
    let mut units = Zeroizing::new(text.encode_utf16().collect::<Vec<_>>());
    units.push(0);
    // SAFETY: exact bounded size; movable Windows clipboard memory is required by SetClipboardData.
    let allocation = unsafe { GlobalAlloc(GMEM_MOVEABLE, units.len() * 2) };
    if allocation.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut allocation = Global(allocation);
    // SAFETY: allocation belongs to this scope and has the exact checked UTF-16 size.
    let pointer = unsafe { GlobalLock(allocation.0) };
    if pointer.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: disjoint source and destination, exact allocated UTF-16 element count.
    unsafe {
        std::ptr::copy_nonoverlapping(units.as_ptr(), pointer.cast::<u16>(), units.len());
    }
    // SAFETY: last-error is thread-local; a zero return with ERROR_SUCCESS is successful final unlock.
    unsafe {
        SetLastError(0);
    }
    let unlocked = unsafe { GlobalUnlock(allocation.0) };
    if unlocked == 0 && unsafe { GetLastError() } != 0 {
        return Err(io::Error::last_os_error());
    }
    check()?;
    let opened = Opened::open(window, context, ClipboardDirection::Write, until)?;
    check()?;
    context.check(ClipboardDirection::Write, until)?;
    // SAFETY: explicit approved write, never called during open/close/revocation.
    // Replacing the clipboard is this operation's intended OS side effect.
    if unsafe { EmptyClipboard() } == 0 {
        return Err(io::Error::last_os_error());
    }
    check()?;
    context.check(ClipboardDirection::Write, until)?;
    // SAFETY: successful call transfers ownership of the unlocked allocation to Windows.
    let published = unsafe { SetClipboardData(UNICODE_TEXT, allocation.0) };
    if published.is_null() {
        return Err(io::Error::last_os_error());
    }
    allocation.0 = null_mut();
    context.check(ClipboardDirection::Write, until)?;
    opened.finish()
}
impl Backend for Clipboard {
    fn check(&mut self, until: Instant) -> io::Result<()> {
        if self.closed || Instant::now() >= until {
            return Err(timed_out(
                "Windows clipboard operation is terminal or expired",
            ));
        }
        self.monitor.check()?;
        if WindowsSessionSnapshot::current()? != self.original {
            return Err(denied(
                "original Windows clipboard desktop is no longer active",
            ));
        }
        Ok(())
    }
    fn read(&mut self, context: &Context, until: Instant) -> io::Result<Option<Zeroizing<String>>> {
        let window = self.window.0;
        read_native(window, context, until, || self.check(until))
    }
    fn write(&mut self, text: &str, context: &Context, until: Instant) -> io::Result<()> {
        let window = self.window.0;
        write_native(window, text, context, until, || self.check(until))
    }
    fn service(&mut self, context: &Context, until: Instant) -> io::Result<()> {
        context.live(until)?;
        let mut message = MSG::default();
        for _ in 0..64 {
            // SAFETY: finite same-thread pump for only this worker's hidden window.
            if unsafe { PeekMessageW(&mut message, self.window.0, 0, 0, PM_REMOVE) } == 0 {
                return Ok(());
            }
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            context.live(until)?;
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows clipboard message budget exceeded",
        ))
    }
    fn close(&mut self, until: Instant) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // No clipboard open, read, clear or restore occurs during cleanup.
        let window_result = if self.window.0.is_null() {
            Ok(())
        } else {
            // SAFETY: owned window destroyed on its original worker thread.
            if unsafe { DestroyWindow(self.window.0) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                self.window.0 = null_mut();
                Ok(())
            }
        };
        let monitor_result = self.monitor.close_until(until);
        window_result.and(monitor_result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::{StationsAndDesktops::*, Threading::GetCurrentThreadId};
    fn fixture_os_error(stage: &str) -> io::Error {
        let error = io::Error::last_os_error();
        io::Error::new(error.kind(), format!("private clipboard {stage}: {error}"))
    }
    struct PrivateDesktop {
        original_station: HWINSTA,
        original_desktop: HDESK,
        station: HWINSTA,
        desktop: HDESK,
    }
    impl PrivateDesktop {
        fn open() -> io::Result<Self> {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos();
            let name = format!("NestLinkClipboardFixture_{}_{nonce}\0", std::process::id())
                .encode_utf16()
                .collect::<Vec<_>>();
            // SAFETY: test runs in a dedicated child process with no other GUI threads.
            let original_station = unsafe { GetProcessWindowStation() };
            let original_desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
            if original_station.is_null() || original_desktop.is_null() {
                return Err(fixture_os_error("read original station/desktop"));
            }
            unsafe {
                SetLastError(0);
            }
            // SAFETY: unique private station name, normal security descriptor, never WinSta0.
            let station = unsafe {
                CreateWindowStationW(
                    name.as_ptr(),
                    0,
                    (WINSTA_ACCESSCLIPBOARD
                        | WINSTA_CREATEDESKTOP
                        | WINSTA_ENUMDESKTOPS
                        | WINSTA_ENUMERATE
                        | WINSTA_READATTRIBUTES
                        | WINSTA_WRITEATTRIBUTES) as u32,
                    null(),
                )
            };
            if station.is_null() {
                return Err(fixture_os_error("CreateWindowStationW"));
            }
            if unsafe { GetLastError() } == 183 {
                unsafe {
                    CloseWindowStation(station);
                }
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "private clipboard fixture station already exists",
                ));
            }
            let mut fixture = Self {
                original_station,
                original_desktop,
                station,
                desktop: null_mut(),
            };
            if unsafe { SetProcessWindowStation(station) } == 0 {
                return Err(fixture_os_error("SetProcessWindowStation"));
            }
            let desktop_name = "fixture\0".encode_utf16().collect::<Vec<_>>();
            // SAFETY: creates a desktop on the new noninteractive station; no SwitchDesktop call exists.
            fixture.desktop = unsafe {
                CreateDesktopW(
                    desktop_name.as_ptr(),
                    null(),
                    null(),
                    0,
                    DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS,
                    null(),
                )
            };
            if fixture.desktop.is_null() {
                return Err(fixture_os_error("CreateDesktopW"));
            }
            if unsafe { SetThreadDesktop(fixture.desktop) } == 0 {
                return Err(fixture_os_error("SetThreadDesktop"));
            }
            Ok(fixture)
        }
        fn release(&mut self) -> io::Result<()> {
            if self.station.is_null() {
                return Ok(());
            }
            // SAFETY: only this isolated child process and its fixture thread
            // are restored; no visible desktop switch is performed.
            if unsafe { SetProcessWindowStation(self.original_station) } == 0
                || unsafe { SetThreadDesktop(self.original_desktop) } == 0
            {
                return Err(fixture_os_error("restore original station/desktop"));
            }
            if !self.desktop.is_null() {
                if unsafe { CloseDesktop(self.desktop) } == 0 {
                    return Err(fixture_os_error("CloseDesktop"));
                }
                self.desktop = null_mut();
            }
            if unsafe { CloseWindowStation(self.station) } == 0 {
                return Err(fixture_os_error("CloseWindowStation"));
            }
            self.station = null_mut();
            Ok(())
        }
        fn close(mut self) -> io::Result<()> {
            self.release()
        }
    }
    impl Drop for PrivateDesktop {
        fn drop(&mut self) {
            let _ = self.release();
        }
    }
    #[test]
    #[ignore = "requires a Windows session allowed to create a private window station; current session returns ERROR_ACCESS_DENIED"]
    fn win32_clipboard_roundtrip_on_a_private_child_window_station() -> io::Result<()> {
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "windows::tests::isolated_win32_fixture_child",
                "--ignored",
                "--test-threads=1",
            ])
            .env("NESTLINK_PRIVATE_CLIPBOARD_CHILD", "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        let until = Instant::now() + Duration::from_secs(10);
        while child.try_wait()?.is_none() {
            if Instant::now() >= until {
                let _ = child.kill();
                let _ = child.wait();
                return Err(timed_out(
                    "private clipboard child exceeded its fixed budget",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output()?;
        let actual_pass = b"test result: ok. 1 passed; 0 failed; 0 ignored";
        if !output.status.success()
            || !output
                .stdout
                .windows(actual_pass.len())
                .any(|text| text == actual_pass)
        {
            return Err(io::Error::other(format!(
                "private Win32 clipboard fixture failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }
    #[test]
    #[ignore = "only launched by the private window-station fixture parent"]
    fn isolated_win32_fixture_child() -> io::Result<()> {
        if std::env::var("NESTLINK_PRIVATE_CLIPBOARD_CHILD").as_deref() != Ok("1") {
            return Err(denied(
                "private clipboard child must be launched by its isolation test",
            ));
        }
        let desktop = PrivateDesktop::open()?;
        assert_ne!(desktop.station, desktop.original_station);
        assert_eq!(unsafe { GetProcessWindowStation() }, desktop.station);
        assert_eq!(
            unsafe { GetThreadDesktop(GetCurrentThreadId()) },
            desktop.desktop
        );
        let class = "STATIC\0".encode_utf16().collect::<Vec<_>>();
        // SAFETY: built-in class on the child's isolated noninteractive desktop.
        let window = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                null(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                null_mut(),
                GetModuleHandleW(null()),
                null(),
            )
        };
        if window.is_null() {
            return Err(fixture_os_error("CreateWindowExW"));
        }
        let mut window = Window(window);
        let (context, _approval) = crate::tests::context()?;
        let until = Instant::now() + Duration::from_secs(1);
        assert!(read_native(window.0, &context, until, || Ok(()))?.is_none());
        write_native(
            window.0,
            "private fixture 中文🙂\ntext",
            &context,
            until,
            || Ok(()),
        )?;
        assert_eq!(
            read_native(window.0, &context, until, || Ok(()))?
                .as_deref()
                .map(String::as_str),
            Some("private fixture 中文🙂\ntext")
        );
        write_native(window.0, "", &context, until, || Ok(()))?;
        assert_eq!(
            read_native(window.0, &context, until, || Ok(()))?
                .as_deref()
                .map(String::as_str),
            Some("")
        );
        // SAFETY: the child owns this hidden fixture HWND and destroys it on
        // its creating thread before restoring/closing its private objects.
        if unsafe { DestroyWindow(window.0) } == 0 {
            return Err(fixture_os_error("DestroyWindow"));
        }
        window.0 = null_mut();
        desktop.close()
    }
    #[test]
    fn strict_utf16_fixture_never_accesses_system_clipboard() -> io::Result<()> {
        let mut text = "中文🙂\nnext".encode_utf16().collect::<Vec<_>>();
        text.push(0);
        assert_eq!(&*decode_unicode(&text)?, "中文🙂\nnext");
        assert!(decode_unicode(&[0xd800, 0]).is_err());
        assert!(decode_unicode(&[65]).is_err());
        assert!(decode_unicode(&vec![65; CLIPBOARD_TEXT_BYTES + 2]).is_err());
        assert_eq!(&*decode_unicode(&[0])?, "");
        Ok(())
    }
    #[test]
    fn real_worker_slot_stays_reserved_until_actual_owner_drops() -> io::Result<()> {
        let first = WorkerSlot::acquire()?;
        assert!(WorkerSlot::acquire().is_err());
        drop(first);
        drop(WorkerSlot::acquire()?);
        Ok(())
    }
}
