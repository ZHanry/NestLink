//! Current interactive Windows session and sticky OS change notifications.
#![allow(unsafe_code)]
use std::{
    cell::Cell,
    io,
    mem::size_of,
    ptr::{null, null_mut},
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{HANDLE, HWND, LPARAM, LRESULT, WPARAM},
    System::{
        LibraryLoader::GetModuleHandleW,
        RemoteDesktop::*,
        StationsAndDesktops::*,
        Threading::{GetCurrentProcessId, GetCurrentThreadId},
    },
    UI::{Accessibility::*, WindowsAndMessaging::*},
};
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
struct ObserverSignal {
    invalidated: Arc<AtomicBool>,
    layout_changes: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsSessionSnapshot {
    id: u32,
    logon: i64,
    connected: i64,
}
struct SessionBuffer(*mut u16);
impl Drop for SessionBuffer {
    fn drop(&mut self) {
        // SAFETY: one successful WTS query transfers one WTSFreeMemory allocation.
        unsafe { WTSFreeMemory(self.0.cast()) };
    }
}
fn session_facts(session: u32) -> io::Result<WindowsSessionSnapshot> {
    let mut pointer = null_mut();
    let mut bytes = 0;
    // SAFETY: local server, current process session, valid allocation/length outputs.
    if unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session,
            WTSSessionInfoEx,
            &mut pointer,
            &mut bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if pointer.is_null() {
        return Err(denied("Windows session facts unavailable"));
    }
    let buffer = SessionBuffer(pointer);
    if bytes as usize != size_of::<WTSINFOEXW>() {
        return Err(denied("Windows session facts have an unexpected size"));
    }
    // SAFETY: exact size checked. Unaligned read avoids assumptions about WTS storage.
    let info = unsafe { buffer.0.cast::<WTSINFOEXW>().read_unaligned() };
    parse_session_facts(session, &info)
}
fn parse_session_facts(session: u32, info: &WTSINFOEXW) -> io::Result<WindowsSessionSnapshot> {
    if info.Level != 1 {
        return Err(denied("Windows session facts have an unknown level"));
    }
    // SAFETY: Level 1 selects the documented WTSInfoExLevel1 union member.
    let facts = unsafe { info.Data.WTSInfoExLevel1 };
    if facts.SessionId != session
        || facts.SessionState != WTSActive
        || facts.SessionFlags != WTS_SESSIONSTATE_UNLOCK as i32
    {
        return Err(denied("Windows user session is locked or disconnected"));
    }
    Ok(WindowsSessionSnapshot {
        id: session,
        logon: facts.LogonTime,
        connected: facts.ConnectTime,
    })
}

struct Desktop(HDESK);
impl Drop for Desktop {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns one OpenInputDesktop reference.
        unsafe { CloseDesktop(self.0) };
    }
}

fn object_name(object: HANDLE) -> io::Result<String> {
    let mut buffer = [0u16; 128];
    let mut size = 0;
    // SAFETY: a borrowed live object, fixed writable buffer and exact byte count.
    let result = unsafe {
        GetUserObjectInformationW(
            object,
            UOI_NAME,
            buffer.as_mut_ptr().cast(),
            size_of_val(&buffer) as u32,
            &mut size,
        )
    };
    if result == 0 || size == 0 || size as usize > size_of_val(&buffer) || size % 2 != 0 {
        return Err(denied("Windows desktop identity unavailable"));
    }
    let end = buffer
        .iter()
        .position(|c| *c == 0)
        .ok_or_else(|| denied("Windows desktop name is not terminated"))?;
    String::from_utf16(&buffer[..end]).map_err(io::Error::other)
}

impl WindowsSessionSnapshot {
    /// Read-only: requires an active, unlocked user on WinSta0\\Default.
    pub fn current() -> io::Result<Self> {
        // SAFETY: read-only process/thread desktop queries. Owned input handle is wrapped.
        let station = unsafe { GetProcessWindowStation() };
        if station.is_null() || object_name(station)? != "WinSta0" {
            return Err(denied("operation requires the interactive window station"));
        }
        let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        let input = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
        if input.is_null() {
            return Err(denied("input desktop is locked or inaccessible"));
        }
        let input = Desktop(input);
        if desktop.is_null()
            || object_name(desktop)? != "Default"
            || object_name(input.0)? != "Default"
        {
            return Err(denied("secure or different desktop cannot be accessed"));
        }
        let mut session = 0;
        // SAFETY: current process id and writable scalar output.
        if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } == 0 || session == 0
        {
            return Err(denied("session zero cannot access user desktops"));
        }
        session_facts(session)
    }
}
thread_local! {
    // Callback runs only on the thread that installed the out-of-context hook.
    static DESKTOP_INVALIDATED: Cell<*const Arc<AtomicBool>> = const { Cell::new(null()) };
}
unsafe extern "system" fn desktop_event(
    _: HWINEVENTHOOK,
    _: u32,
    _: HWND,
    _: i32,
    _: i32,
    _: u32,
    _: u32,
) {
    let _ = DESKTOP_INVALIDATED.try_with(|slot| {
        let pointer = slot.get();
        if !pointer.is_null() {
            // SAFETY: worker Arc outlives hook, removed before this TLS pointer clears.
            unsafe { &*pointer }.store(true, Ordering::SeqCst);
        }
    });
}
unsafe extern "system" fn observer_window(
    hwnd: HWND,
    message: u32,
    w: WPARAM,
    l: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        // SAFETY: WM_NCCREATE provides a live CREATESTRUCTW for this callback.
        let create = unsafe { &*(l as *const CREATESTRUCTW) };
        // SAFETY: own window stores a borrowed AtomicBool pointer, not an OS-owned object.
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize) };
    }
    // SAFETY: only our registered class writes this Arc-owned signal pointer.
    let pointer = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const ObserverSignal;
    if !pointer.is_null() {
        let signal = unsafe { &*pointer };
        let invalidate = matches!(message, WM_CLOSE | WM_DESTROY | WM_NCDESTROY)
            || (signal.layout_changes
                && matches!(message, WM_DISPLAYCHANGE | WM_DPICHANGED | WM_SETTINGCHANGE))
            || (message == WM_WTSSESSION_CHANGE
                && matches!(
                    w as u32,
                    WTS_CONSOLE_DISCONNECT
                        | WTS_REMOTE_DISCONNECT
                        | WTS_SESSION_LOGOFF
                        | WTS_SESSION_LOCK
                ));
        if invalidate {
            signal.invalidated.store(true, Ordering::SeqCst);
            if message == WM_NCDESTROY {
                // The OS is ending this window; remove its borrowed pointer.
                unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
                return unsafe { DefWindowProcW(hwnd, message, w, l) };
            }
            return 0;
        }
    }
    // SAFETY: all unhandled messages are passed back to the OS's default procedure.
    unsafe { DefWindowProcW(hwnd, message, w, l) }
}

pub struct WindowsSessionObserver {
    window: HWND,
    hook: HWINEVENTHOOK,
    registered: bool,
    closed: Option<Result<(), i32>>,
    signal: Arc<ObserverSignal>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl WindowsSessionObserver {
    pub fn open(invalidated: Arc<AtomicBool>, layout_changes: bool) -> io::Result<Self> {
        if DESKTOP_INVALIDATED.with(|slot| !slot.get().is_null()) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "one session observer per worker",
            ));
        }
        let signal = Arc::new(ObserverSignal {
            invalidated,
            layout_changes,
        });
        static CLASS: OnceLock<Result<u16, u32>> = OnceLock::new();
        let class = CLASS.get_or_init(|| {
            let definition = WNDCLASSW {
                lpfnWndProc: Some(observer_window),
                // SAFETY: null selects this process's module, which outlives the class.
                hInstance: unsafe { GetModuleHandleW(null()) },
                lpszClassName: windows_sys::w!("NestLinkSessionObserverV15"),
                ..WNDCLASSW::default()
            };
            // SAFETY: class registration copies this fully initialized definition.
            let atom = unsafe { RegisterClassW(&definition) };
            if atom == 0 {
                Err(io::Error::last_os_error().raw_os_error().unwrap_or(1) as u32)
            } else {
                Ok(atom)
            }
        });
        let atom = class
            .as_ref()
            .map_err(|code| io::Error::from_raw_os_error(*code as i32))?;
        // SAFETY: registered class, borrowed live AtomicBool, hidden top-level window.
        let window = unsafe {
            CreateWindowExW(
                WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
                *atom as usize as *const u16,
                windows_sys::w!("NestLink session observer"),
                WS_POPUP,
                0,
                0,
                0,
                0,
                null_mut(),
                null_mut(),
                GetModuleHandleW(null()),
                Arc::as_ptr(&signal).cast(),
            )
        };
        if window.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut observer = Self {
            window,
            hook: null_mut(),
            registered: false,
            closed: None,
            signal,
            _thread: std::marker::PhantomData,
        };
        // SAFETY: own hidden window, only current session notifications requested.
        if unsafe { WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        observer.registered = true;
        DESKTOP_INVALIDATED
            .with(|slot| slot.set(&observer.signal.invalidated as *const Arc<AtomicBool>));
        // SAFETY: out-of-context callback is delivered on this worker's message loop.
        observer.hook = unsafe {
            SetWinEventHook(
                EVENT_SYSTEM_DESKTOPSWITCH,
                EVENT_SYSTEM_DESKTOPSWITCH,
                null_mut(),
                Some(desktop_event),
                0,
                0,
                WINEVENT_OUTOFCONTEXT,
            )
        };
        if observer.hook.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(observer)
    }
    pub fn pump(&self) {
        let mut message = MSG::default();
        // SAFETY: worker owns this thread's message queue. Pump has a fixed budget.
        for _ in 0..256 {
            if unsafe { PeekMessageW(&mut message, null_mut(), 0, 0, PM_REMOVE) } == 0 {
                break;
            }
            unsafe { DispatchMessageW(&message) };
            if message.message == WM_QUIT {
                self.signal.invalidated.store(true, Ordering::SeqCst);
            }
        }
        // An unbounded thread-message flood must not keep an unseen session event
        // behind a heartbeat that claims the worker is current.
        if unsafe { PeekMessageW(&mut message, null_mut(), 0, 0, PM_NOREMOVE) } != 0 {
            self.signal.invalidated.store(true, Ordering::SeqCst);
        }
    }
}
impl WindowsSessionObserver {
    /// Borrowed notification target; valid only while this worker owns the observer.
    pub fn notification_window(&self) -> usize {
        self.window as usize
    }
    /// Same-worker cleanup, with the first native failure retained on retries.
    pub fn close(&mut self) -> io::Result<()> {
        self.signal.invalidated.store(true, Ordering::SeqCst);
        if let Some(result) = self.closed {
            return result.map_err(io::Error::from_raw_os_error);
        }
        DESKTOP_INVALIDATED.with(|slot| slot.set(null()));
        let mut failure = None;
        let mut record = || {
            failure.get_or_insert(io::Error::last_os_error().raw_os_error().unwrap_or(1));
        };
        // SAFETY: this non-Send observer owns resources on the creating thread.
        unsafe {
            if !self.hook.is_null() && UnhookWinEvent(self.hook) == 0 {
                record();
            }
            self.hook = null_mut();
            if self.registered && WTSUnRegisterSessionNotification(self.window) == 0 {
                record();
            }
            self.registered = false;
            if !self.window.is_null() && DestroyWindow(self.window) == 0 {
                record();
                // Keep the tiny signal alive if a remaining window can call its proc.
                std::mem::forget(self.signal.clone());
            }
            self.window = null_mut();
        }
        let result = failure.map_or(Ok(()), Err);
        self.closed = Some(result);
        result.map_err(io::Error::from_raw_os_error)
    }
}
impl Drop for WindowsSessionObserver {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

const MONITOR_HEARTBEAT: Duration = Duration::from_millis(500);
const MONITOR_CLEANUP: Duration = Duration::from_millis(150);
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
struct MonitorFacts {
    heartbeat: Instant,
    failure: Option<Failure>,
    cleanup: Option<Result<(), Failure>>,
    cleanup_completed_at: Option<Instant>,
}
struct MonitorShared {
    stopped: AtomicBool,
    invalidated: Arc<AtomicBool>,
    facts: Mutex<MonitorFacts>,
    wake: Condvar,
    #[cfg(test)]
    window: std::sync::atomic::AtomicUsize,
}
impl MonitorShared {
    fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            invalidated: Arc::new(AtomicBool::new(false)),
            facts: Mutex::new(MonitorFacts {
                heartbeat: Instant::now(),
                failure: None,
                cleanup: None,
                cleanup_completed_at: None,
            }),
            wake: Condvar::new(),
            #[cfg(test)]
            window: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn check(&self) -> io::Result<()> {
        let facts = self
            .facts
            .lock()
            .map_err(|_| io::Error::other("Windows session monitor state poisoned"))?;
        if let Some(error) = &facts.failure {
            return Err(error.error());
        }
        if self.stopped.load(Ordering::SeqCst) || self.invalidated.load(Ordering::SeqCst) {
            return Err(denied("original Windows session monitor ended"));
        }
        if facts.heartbeat.elapsed() > MONITOR_HEARTBEAT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original Windows session monitor stalled",
            ));
        }
        Ok(())
    }
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.wake.notify_all();
    }
    fn fail(&self, error: io::Error) {
        self.stop();
        if let Ok(mut facts) = self.facts.lock() {
            facts.failure.get_or_insert_with(|| error.into());
        }
        self.wake.notify_all();
    }
    fn heartbeat(&self) -> io::Result<()> {
        self.check()?; // Never renew an already expired or invalidated observation.
        self.facts
            .lock()
            .map_err(|_| io::Error::other("Windows session heartbeat poisoned"))?
            .heartbeat = Instant::now();
        Ok(())
    }
    fn complete(&self, cleanup: io::Result<()>) {
        let completed = Instant::now();
        self.stop();
        if let Ok(mut facts) = self.facts.lock() {
            facts
                .cleanup
                .get_or_insert_with(|| cleanup.map_err(Failure::from));
            facts.cleanup_completed_at.get_or_insert(completed);
        }
        self.wake.notify_all();
    }
}
/// Transferable readonly monitor. The hidden HWND and hook stay on its worker.
/// This owns no input, media, or application authorization.
pub struct WindowsSessionMonitor {
    original: WindowsSessionSnapshot,
    shared: Arc<MonitorShared>,
    worker: Option<thread::JoinHandle<()>>,
    cleanup_until: Option<Instant>,
}
impl WindowsSessionMonitor {
    pub fn open(layout_changes: bool) -> io::Result<Self> {
        let shared = Arc::new(MonitorShared::new());
        let observed = shared.clone();
        let (ready, wait) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nestlink-windows-session".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut observer =
                        WindowsSessionObserver::open(observed.invalidated.clone(), layout_changes)?;
                    #[cfg(test)]
                    observed
                        .window
                        .store(observer.notification_window(), Ordering::SeqCst);
                    let result = (|| -> io::Result<()> {
                        let original = WindowsSessionSnapshot::current()?;
                        observer.pump();
                        observed.heartbeat()?;
                        if WindowsSessionSnapshot::current()? != original {
                            return Err(denied("Windows session changed while subscribing"));
                        }
                        ready
                            .try_send(Ok(original.clone()))
                            .map_err(|_| denied("Windows session caller ended"))?;
                        loop {
                            observer.pump();
                            if observed.stopped.load(Ordering::SeqCst) {
                                break;
                            }
                            observed.check()?;
                            if WindowsSessionSnapshot::current()? != original {
                                return Err(denied("original Windows session changed"));
                            }
                            observer.pump();
                            observed.heartbeat()?;
                            let facts = observed
                                .facts
                                .lock()
                                .map_err(|_| io::Error::other("Windows monitor wait poisoned"))?;
                            let _ = observed
                                .wake
                                .wait_timeout_while(facts, Duration::from_millis(5), |_| {
                                    !observed.stopped.load(Ordering::SeqCst)
                                })
                                .map_err(|_| io::Error::other("Windows monitor wait poisoned"))?;
                        }
                        Ok(())
                    })();
                    let cleanup = observer.close();
                    if let Err(error) = &result {
                        let _ =
                            ready.try_send(Err(io::Error::new(error.kind(), error.to_string())));
                    }
                    if let Err(error) = result {
                        observed.fail(error);
                    }
                    observed.complete(cleanup);
                    Ok::<(), io::Error>(())
                }));
                match outcome {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        let _ =
                            ready.try_send(Err(io::Error::new(error.kind(), error.to_string())));
                        observed.fail(error);
                        observed.complete(Ok(())); // observer setup failed before owning a running monitor
                    }
                    Err(_) => {
                        observed.fail(io::Error::other("Windows session worker panicked"));
                        observed.complete(Err(io::Error::other(
                            "Windows session cleanup could not be proven",
                        )));
                    }
                }
            })?;
        match wait.recv_timeout(Duration::from_secs(2)) {
            Ok(Ok(original)) => {
                let monitor = Self {
                    original,
                    shared,
                    worker: Some(worker),
                    cleanup_until: None,
                };
                monitor.check()?;
                Ok(monitor)
            }
            result => {
                shared.stop();
                if worker.is_finished() {
                    let _ = worker.join();
                }
                match result {
                    Ok(Err(error)) => Err(error),
                    _ => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Windows session monitor startup timed out",
                    )),
                }
            }
        }
    }
    pub fn original(&self) -> &WindowsSessionSnapshot {
        &self.original
    }
    pub fn check(&self) -> io::Result<()> {
        let result = self.shared.check();
        if let Err(error) = &result {
            self.shared
                .fail(io::Error::new(error.kind(), error.to_string()));
        }
        result
    }
    pub fn stop(&self) {
        self.shared.stop();
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.close_until(Instant::now() + MONITOR_CLEANUP)
    }
    /// Respect the caller's earlier cleanup budget; retries never renew it.
    pub fn close_until(&mut self, until: Instant) -> io::Result<()> {
        self.stop();
        let until = *self
            .cleanup_until
            .get_or_insert(until.min(Instant::now() + MONITOR_CLEANUP));
        let facts = self
            .shared
            .facts
            .lock()
            .map_err(|_| io::Error::other("Windows session cleanup poisoned"))?;
        let (mut facts, _) = self
            .shared
            .wake
            .wait_timeout_while(
                facts,
                until.saturating_duration_since(Instant::now()),
                |facts| facts.cleanup.is_none(),
            )
            .map_err(|_| io::Error::other("Windows session cleanup wait poisoned"))?;
        if facts.cleanup.is_none() {
            facts.cleanup = Some(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Windows session cleanup exceeded original deadline",
            )
            .into()));
        }
        if matches!(&facts.cleanup, Some(Ok(())))
            && facts
                .cleanup_completed_at
                .is_some_and(|completed| completed > until)
        {
            facts.cleanup = Some(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Windows session cleanup completed after original deadline",
            )
            .into()));
        }
        let result = match &facts.cleanup {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(error.error()),
            None => Err(io::Error::other("missing Windows session cleanup result")),
        };
        drop(facts);
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
impl Drop for WindowsSessionMonitor {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owned_monitor(shared: Arc<MonitorShared>) -> WindowsSessionMonitor {
        WindowsSessionMonitor {
            original: WindowsSessionSnapshot {
                id: 7,
                logon: 11,
                connected: 22,
            },
            shared,
            worker: None,
            cleanup_until: Some(Instant::now()),
        }
    }
    #[test]
    fn stalled_readonly_monitor_and_cleanup_result_cannot_be_restored() -> io::Result<()> {
        let shared = Arc::new(MonitorShared::new());
        shared
            .facts
            .lock()
            .map_err(|_| io::Error::other("state poisoned"))?
            .heartbeat = Instant::now() - MONITOR_HEARTBEAT * 2;
        let monitor = owned_monitor(shared.clone());
        assert_eq!(
            monitor.check().err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        shared
            .facts
            .lock()
            .map_err(|_| io::Error::other("state poisoned"))?
            .heartbeat = Instant::now();
        assert!(shared.heartbeat().is_err());
        assert!(monitor.check().is_err());
        let clean = Arc::new(MonitorShared::new());
        let mut monitor = owned_monitor(clean.clone());
        assert_eq!(
            monitor.close().err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        clean.complete(Ok(()));
        assert_eq!(
            monitor.close().err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        let raced = Arc::new(MonitorShared::new());
        let earlier = Instant::now() - MONITOR_CLEANUP;
        raced.complete(Ok(()));
        let mut monitor = owned_monitor(raced);
        monitor.cleanup_until = Some(earlier);
        assert_eq!(
            monitor.close().err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        Ok(())
    }
    #[test]
    fn stopped_monitor_keeps_the_first_native_cleanup_failure() -> io::Result<()> {
        let shared = Arc::new(MonitorShared::new());
        shared.complete(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "owned first cleanup failure",
        )));
        shared.complete(Ok(()));
        let mut monitor = owned_monitor(shared);
        let first = monitor
            .close()
            .err()
            .ok_or_else(|| io::Error::other("failure missing"))?;
        assert_eq!(first.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(first.to_string(), "owned first cleanup failure");
        assert_eq!(
            monitor.close().err().map(|error| error.to_string()),
            Some(first.to_string())
        );
        Ok(())
    }
    #[test]
    #[ignore = "requires an interactive Windows desktop; only posts to our own hidden monitor"]
    fn actual_own_window_close_lock_pulse_and_quit_end_original_monitor() -> io::Result<()> {
        for case in ["close", "lock-unlock", "quit"] {
            let mut monitor = WindowsSessionMonitor::open(true)?;
            let window = monitor.shared.window.load(Ordering::SeqCst) as HWND;
            assert!(!window.is_null());
            let post = |message, w| -> io::Result<()> {
                // SAFETY: only the monitor window that this test currently owns.
                if unsafe { PostMessageW(window, message, w, 0) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            };
            match case {
                "close" => post(WM_CLOSE, 0)?,
                "lock-unlock" => {
                    post(WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK as usize)?;
                    post(WM_WTSSESSION_CHANGE, WTS_SESSION_UNLOCK as usize)?;
                }
                "quit" => {
                    // SAFETY: retrieve this owned HWND's creating worker, then
                    // post only to that thread; no OS lock or user input occurs.
                    let thread_id = unsafe { GetWindowThreadProcessId(window, null_mut()) };
                    if thread_id == 0
                        || unsafe { PostThreadMessageW(thread_id, WM_QUIT, 0, 0) } == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                _ => unreachable!(),
            }
            let until = Instant::now() + Duration::from_secs(1);
            while monitor.check().is_ok() && Instant::now() < until {
                thread::sleep(Duration::from_millis(2));
            }
            assert!(monitor.check().is_err(), "original monitor survived {case}");
            monitor.close()?;
            assert_eq!(
                unsafe { IsWindow(window) },
                0,
                "owned monitor window survived cleanup"
            );
            println!(
                "{case}: own hidden monitor terminated and released; no OS lock/input/media effects"
            );
        }
        Ok(())
    }
    #[test]
    fn locked_disconnected_unknown_or_replaced_session_cannot_become_capture_authority()
    -> io::Result<()> {
        let mut facts = WTSINFOEX_LEVEL1_W {
            SessionId: 7,
            SessionState: WTSActive,
            SessionFlags: WTS_SESSIONSTATE_UNLOCK as i32,
            LogonTime: 11,
            ConnectTime: 22,
            ..WTSINFOEX_LEVEL1_W::default()
        };
        let wrap = |level| WTSINFOEXW {
            Level: 1,
            Data: WTSINFOEX_LEVEL_W {
                WTSInfoExLevel1: level,
            },
        };
        let original = parse_session_facts(7, &wrap(facts))?;
        facts.ConnectTime += 1;
        assert_ne!(parse_session_facts(7, &wrap(facts))?, original);
        for state in [WTSDisconnected, WTSIdle, WTSListen, WTSDown, WTSInit] {
            facts.SessionState = state;
            assert!(parse_session_facts(7, &wrap(facts)).is_err());
        }
        facts.SessionState = WTSActive;
        for flags in [
            WTS_SESSIONSTATE_LOCK as i32,
            WTS_SESSIONSTATE_UNKNOWN as i32,
        ] {
            facts.SessionFlags = flags;
            assert!(parse_session_facts(7, &wrap(facts)).is_err());
        }
        facts.SessionFlags = WTS_SESSIONSTATE_UNLOCK as i32;
        assert!(parse_session_facts(8, &wrap(facts)).is_err());
        let mut unknown = wrap(facts);
        unknown.Level = 2;
        assert!(parse_session_facts(7, &unknown).is_err());
        Ok(())
    }
}
