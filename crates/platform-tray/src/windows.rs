//! Synchronous Win32 allocations live on one owned normal-user thread. The
//! HWND callback never borrows the GUI and its Context outlives DestroyWindow.
use super::*;
use std::{
    sync::atomic::{AtomicIsize, AtomicU32},
    thread::{self, JoinHandle},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, HANDLE, HWND, LPARAM, LRESULT, RECT, WAIT_FAILED, WAIT_OBJECT_0, WPARAM,
    },
    Graphics::Gdi::{
        BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS,
        DeleteObject,
    },
    System::LibraryLoader::GetModuleHandleW,
    System::Threading::{CreateEventW, INFINITE, SetEvent},
    UI::{
        Shell::{
            NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
            NOTIFYICONIDENTIFIER, Shell_NotifyIconGetRect, Shell_NotifyIconW,
        },
        WindowsAndMessaging::*,
    },
};
const CALLBACK: u32 = WM_APP + 17;
static CLASS: AtomicU32 = AtomicU32::new(1);
struct StopEvent(AtomicIsize);
impl StopEvent {
    fn create() -> io::Result<Arc<Self>> {
        // SAFETY: an unnamed manual-reset event is process-local and starts nonsignaled.
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Arc::new(Self(AtomicIsize::new(handle as isize))))
    }
    fn signal(&self) {
        let handle = self.0.load(Ordering::Acquire) as HANDLE;
        if !handle.is_null() {
            unsafe {
                SetEvent(handle);
            }
        }
    }
    fn handle(&self) -> HANDLE {
        self.0.load(Ordering::Acquire) as HANDLE
    }
}
impl Drop for StopEvent {
    fn drop(&mut self) {
        let handle = self.0.swap(0, Ordering::AcqRel) as HANDLE;
        if !handle.is_null() {
            unsafe {
                CloseHandle(handle);
            }
        }
    }
}
pub(super) struct Worker {
    window: Arc<AtomicIsize>,
    stop: Arc<StopEvent>,
    thread: Option<JoinHandle<()>>,
}
impl Worker {
    pub fn start(
        icon: Icon,
        labels: Labels,
        sink: Sink,
        available: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let window = Arc::new(AtomicIsize::new(0));
        let shared = window.clone();
        let stop = StopEvent::create()?;
        let thread_stop = stop.clone();
        let (ready, waiting) = std::sync::mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("nestlink-tray".into())
            .spawn(move || {
                let result = run(icon, labels, sink, available, shared, thread_stop, &ready);
                if let Err(error) = result {
                    let _ = ready.try_send(Err(error));
                }
            })?;
        let mut worker = Self {
            window,
            stop,
            thread: Some(thread),
        };
        match waiting.recv_timeout(STARTUP) {
            Ok(Ok(())) => Ok(worker),
            Ok(Err(error)) => {
                worker.stop();
                Err(error)
            }
            Err(_) => {
                worker.stop();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tray startup timed out",
                ))
            }
        }
    }
    pub fn present(&self) -> bool {
        let window = self.window.load(Ordering::Acquire) as HWND;
        if window.is_null() {
            return false;
        }
        let identity = NOTIFYICONIDENTIFIER {
            cbSize: std::mem::size_of::<NOTIFYICONIDENTIFIER>() as u32,
            hWnd: window,
            uID: 1,
            guidItem: unsafe { std::mem::zeroed() },
        };
        let mut rect = RECT::default();
        // SAFETY: a plain identity structure and initialized output; this call
        // consults Shell state and does not dereference our window Context.
        unsafe { Shell_NotifyIconGetRect(&identity, &mut rect) == 0 }
    }
    pub fn stop(&mut self) {
        // The manual-reset event remains alive while either owner references it.
        // No recycled HWND or thread ID can receive a stop intended for us.
        self.stop.signal();
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(thread) = self.thread.take()
        {
            let _ = thread.join();
        }
        // A stuck Shell call is not killed while it holds a callback. The
        // detached thread retains both its event and Context until it returns.
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop();
    }
}
struct NativeIcon(HICON);
impl Drop for NativeIcon {
    fn drop(&mut self) {
        unsafe {
            DestroyIcon(self.0);
        }
    }
}
fn native_icon(icon: Icon) -> io::Result<NativeIcon> {
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: icon.width as i32,
            biHeight: -(icon.height as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut pixels = std::ptr::null_mut();
    // SAFETY: bounded 16..64 geometry; GDI returns a live DIB allocation. Both
    // temporary bitmaps are deleted after CreateIconIndirect copies their data.
    let bitmap = unsafe {
        CreateDIBSection(
            std::ptr::null_mut(),
            &info,
            DIB_RGB_COLORS,
            &mut pixels,
            std::ptr::null_mut(),
            0,
        )
    };
    if bitmap.is_null() {
        return Err(io::Error::last_os_error());
    }
    if pixels.is_null() {
        unsafe {
            DeleteObject(bitmap);
        }
        return Err(io::Error::other("tray DIB has no pixels"));
    }
    let target = unsafe { std::slice::from_raw_parts_mut(pixels.cast::<u8>(), icon.rgba.len()) };
    for (source, target) in icon.rgba.chunks_exact(4).zip(target.chunks_exact_mut(4)) {
        target.copy_from_slice(&[source[2], source[1], source[0], source[3]]);
    }
    let mask = unsafe {
        CreateBitmap(
            icon.width as i32,
            icon.height as i32,
            1,
            1,
            std::ptr::null(),
        )
    };
    if mask.is_null() {
        let error = io::Error::last_os_error();
        unsafe {
            DeleteObject(bitmap);
        }
        return Err(error);
    }
    let info = ICONINFO {
        fIcon: 1,
        hbmMask: mask,
        hbmColor: bitmap,
        ..Default::default()
    };
    let handle = unsafe { CreateIconIndirect(&info) };
    let error = io::Error::last_os_error();
    unsafe {
        DeleteObject(bitmap);
        DeleteObject(mask);
    }
    if handle.is_null() {
        Err(error)
    } else {
        Ok(NativeIcon(handle))
    }
}
struct Context {
    icon: NativeIcon,
    labels: Labels,
    sink: Sink,
    available: Arc<AtomicBool>,
    taskbar: u32,
}
fn notify(window: HWND, icon: HICON, command: u32) -> bool {
    let mut data = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uID: 1,
        uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
        uCallbackMessage: CALLBACK,
        hIcon: icon,
        ..Default::default()
    };
    for (target, source) in data.szTip.iter_mut().zip("NestLink".encode_utf16()) {
        *target = source;
    }
    // SAFETY: all icon/window resources outlive this synchronous Shell call.
    unsafe { Shell_NotifyIconW(command, &data) != 0 }
}
fn run(
    icon: Icon,
    labels: Labels,
    sink: Sink,
    available: Arc<AtomicBool>,
    window: Arc<AtomicIsize>,
    stop: Arc<StopEvent>,
    ready: &SyncSender<io::Result<()>>,
) -> io::Result<()> {
    let name: Vec<u16> = format!(
        "NestLinkV15Tray{}-{}\0",
        std::process::id(),
        CLASS.fetch_add(1, Ordering::Relaxed)
    )
    .encode_utf16()
    .collect();
    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    let class = WNDCLASSW {
        lpfnWndProc: Some(callback),
        hInstance: instance,
        lpszClassName: name.as_ptr(),
        ..Default::default()
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let icon = match native_icon(icon) {
        Ok(icon) => icon,
        Err(error) => {
            unsafe {
                UnregisterClassW(name.as_ptr(), instance);
            }
            return Err(error);
        }
    };
    let taskbar = unsafe {
        RegisterWindowMessageW(
            "TaskbarCreated\0"
                .encode_utf16()
                .collect::<Vec<_>>()
                .as_ptr(),
        )
    };
    let mut context = Box::new(Context {
        icon,
        labels,
        sink,
        available,
        taskbar,
    });
    // SAFETY: Box address is stable until after DestroyWindow; WM_NCCREATE
    // stores only that borrowed pointer. No callback transfers Box ownership.
    let handle = unsafe {
        CreateWindowExW(
            WS_EX_TOOLWINDOW,
            name.as_ptr(),
            name.as_ptr(),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            (&mut *context as *mut Context).cast(),
        )
    };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        unsafe {
            UnregisterClassW(name.as_ptr(), instance);
        }
        return Err(error);
    }
    window.store(handle as isize, Ordering::Release);
    context
        .available
        .store(notify(handle, context.icon.0, NIM_ADD), Ordering::Release);
    unsafe {
        SetTimer(handle, 1, 1000, None);
    }
    if ready.send(Ok(())).is_err() {
        unsafe {
            DestroyWindow(handle);
        }
    } else {
        let mut message = MSG::default();
        let event = stop.handle();
        let mut quit = false;
        loop {
            // SAFETY: `event` is a live manual-reset handle owned by the Worker
            // and this thread; the queue mask wakes the pump for window input.
            let wait = unsafe {
                MsgWaitForMultipleObjectsEx(1, &event, INFINITE, QS_ALLINPUT, MWMO_INPUTAVAILABLE)
            };
            if wait == WAIT_OBJECT_0 {
                break;
            }
            if wait == WAIT_FAILED {
                break;
            }
            if wait == WAIT_OBJECT_0 + 1 {
                while unsafe { PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) }
                    != 0
                {
                    if message.message == WM_QUIT {
                        quit = true;
                        break;
                    }
                    unsafe {
                        TranslateMessage(&message);
                        DispatchMessageW(&message);
                    }
                }
                if quit {
                    break;
                }
            }
        }
        // Stop events and wait failures both converge on worker-owned teardown.
        if unsafe { IsWindow(handle) } != 0 {
            unsafe {
                DestroyWindow(handle);
            }
        }
    }
    context.available.store(false, Ordering::Release);
    window.store(0, Ordering::Release);
    unsafe {
        UnregisterClassW(name.as_ptr(), instance);
    }
    Ok(())
}
unsafe extern "system" fn callback(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        // SAFETY: CreateWindowExW supplied a live CREATESTRUCTW and our stable
        // borrowed Context pointer; it is cleared during WM_NCDESTROY.
        let creation = unsafe { &*(lparam as *const CREATESTRUCTW) };
        unsafe {
            SetWindowLongPtrW(window, GWLP_USERDATA, creation.lpCreateParams as isize);
        }
    }
    let pointer = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *mut Context;
    if !pointer.is_null() {
        // All callback access is shared. Shell and menu APIs can synchronously
        // reenter this procedure, so creating `&mut Context` here would violate
        // Rust's aliasing rules even though the event thread is single-threaded.
        let context = unsafe { &*pointer };
        if message == context.taskbar && context.taskbar != 0 {
            context
                .available
                .store(notify(window, context.icon.0, NIM_ADD), Ordering::Release);
            return 0;
        }
        match message {
            WM_TIMER => {
                if !context.available.load(Ordering::Acquire) {
                    context
                        .available
                        .store(notify(window, context.icon.0, NIM_ADD), Ordering::Release);
                }
                return 0;
            }
            CALLBACK => {
                match lparam as u32 {
                    WM_LBUTTONUP | WM_LBUTTONDBLCLK => context.sink.send(Action::Open),
                    WM_RBUTTONUP => unsafe { menu(window, context) },
                    _ => {}
                }
                return 0;
            }
            WM_CLOSE => {
                unsafe {
                    DestroyWindow(window);
                }
                return 0;
            }
            WM_DESTROY => {
                notify(window, context.icon.0, NIM_DELETE);
                context.available.store(false, Ordering::Release);
                unsafe {
                    PostQuitMessage(0);
                }
                return 0;
            }
            WM_NCDESTROY => unsafe {
                SetWindowLongPtrW(window, GWLP_USERDATA, 0);
            },
            _ => {}
        }
    }
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}
unsafe fn menu(window: HWND, context: &Context) {
    let menu = unsafe { CreatePopupMenu() };
    if menu.is_null() {
        return;
    }
    let open: Vec<u16> = context.labels.open.encode_utf16().chain(Some(0)).collect();
    let exit: Vec<u16> = context.labels.exit.encode_utf16().chain(Some(0)).collect();
    unsafe {
        AppendMenuW(menu, MF_STRING, 1, open.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, 2, exit.as_ptr());
    }
    let mut point = windows_sys::Win32::Foundation::POINT::default();
    if unsafe { GetCursorPos(&mut point) } != 0 {
        unsafe {
            SetForegroundWindow(window);
        }
        let chosen = unsafe {
            TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                point.x,
                point.y,
                0,
                window,
                std::ptr::null(),
            )
        };
        match chosen {
            1 => context.sink.send(Action::Open),
            2 => context.sink.send(Action::Exit),
            _ => {}
        }
        unsafe {
            PostMessageW(window, WM_NULL, 0, 0);
        }
    }
    // SAFETY: menu is worker-local and TrackPopupMenu has returned.
    unsafe {
        DestroyMenu(menu);
    }
}
