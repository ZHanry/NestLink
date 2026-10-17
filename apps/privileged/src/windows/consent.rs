#![allow(unsafe_code)]
use super::{
    installation::hex,
    security::{self, Peer},
};
use crate::{ConsentFacts, wire::CONSENT_BUDGET};
use nestlink_platform_session::WindowsSessionSnapshot;
use std::{
    io,
    ptr::{null, null_mut},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::COLOR_WINDOW,
    System::{
        LibraryLoader::GetModuleHandleW, Pipes::PeekNamedPipe, Threading::WaitForSingleObject,
    },
    UI::{Input::KeyboardAndMouse::SetFocus, WindowsAndMessaging::*},
};

const APPROVE: usize = 1001;
const CANCEL: usize = 1002;
struct State {
    parent: HANDLE,
    pipe: HANDLE,
    started: Instant,
    accepted: bool,
}
unsafe extern "system" fn procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_CREATE {
        // SAFETY: WM_CREATE supplies a live CREATESTRUCTW for this synchronous callback.
        let create = unsafe { &*(lparam as *const CREATESTRUCTW) };
        // SAFETY: confirm() owns this stable Box<State> until all window callbacks end.
        unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, create.lpCreateParams as isize) };
        return 0;
    }
    // SAFETY: only this window sets GWLP_USERDATA, at its WM_CREATE above.
    let raw = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *mut State;
    if !raw.is_null() {
        let state = unsafe { &mut *raw };
        let cancel = match message {
            WM_COMMAND if wparam & 0xffff == APPROVE => {
                state.accepted = true;
                true
            }
            WM_COMMAND if wparam & 0xffff == CANCEL => true,
            WM_CLOSE => true,
            WM_TIMER => {
                // SAFETY: these handles remain owned by the enclosing server while
                // this dialog is live. Peek neither reads nor changes pipe data.
                state.started.elapsed() >= CONSENT_BUDGET
                    || unsafe { WaitForSingleObject(state.parent, 0) } != WAIT_TIMEOUT
                    || unsafe {
                        PeekNamedPipe(
                            state.pipe,
                            null_mut(),
                            0,
                            null_mut(),
                            null_mut(),
                            null_mut(),
                        )
                    } == 0
                    || WindowsSessionSnapshot::current().is_err()
            }
            _ => false,
        };
        if cancel {
            // SAFETY: destroy exactly this thread's owned dialog, never another app.
            unsafe { DestroyWindow(window) };
            return 0;
        }
    }
    if message == WM_DESTROY {
        // SAFETY: timer/window belong to this UI thread; quit only its local loop.
        unsafe {
            KillTimer(window, 1);
            PostQuitMessage(0);
        }
        return 0;
    }
    // SAFETY: forward unhandled documented window messages without retaining pointers.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

/// A bounded elevated local window, with Cancel focused/default. No remote names
/// or text are rendered; only validated IDs, pins and the exact proposed layout.
pub(super) fn confirm(facts: &ConsentFacts, parent: &Peer, pipe: HANDLE) -> io::Result<bool> {
    parent.alive()?;
    WindowsSessionSnapshot::current()?;
    let class = security::text(&format!(
        "NestLink.PrivilegedConsent.{}",
        std::process::id()
    ))?;
    let title = security::text("NestLink — allow elevated input?")?;
    let message = security::text(&format!(
        "Allow this remote session to control normal and elevated windows on your Default desktop?\r\n\r\nDeployment: {}\r\nHost: {}\r\nController: {}\r\nSession: {}\r\nIssuer: {}\r\nHost key: {}\r\nScreen: {}, {} — {} × {}\r\n\r\nCancel is selected. This prompt expires after 30 seconds.",
        facts.deployment_id,
        facts.host_device_id,
        facts.controller_device_id,
        facts.session_id,
        hex(&facts.issuer),
        hex(&facts.host_key_sha256),
        facts.layout.left,
        facts.layout.top,
        facts.layout.width,
        facts.layout.height
    ))?;
    let static_class = security::text("STATIC")?;
    let button_class = security::text("BUTTON")?;
    let approve = security::text("Allow this session")?;
    let cancel = security::text("Cancel")?;
    // SAFETY: null module name returns this process's borrowed module handle.
    let instance = unsafe { GetModuleHandleW(null()) };
    if instance.is_null() {
        return Err(security::denied());
    }
    let definition = WNDCLASSW {
        lpfnWndProc: Some(procedure),
        hInstance: instance,
        lpszClassName: class.as_ptr(),
        hbrBackground: (COLOR_WINDOW + 1) as usize as _,
        ..WNDCLASSW::default()
    };
    // SAFETY: all pointers in the class definition remain live until unregistration.
    if unsafe { RegisterClassW(&definition) } == 0 {
        return Err(security::denied());
    }
    struct Registered {
        class: Vec<u16>,
        instance: HINSTANCE,
    }
    impl Drop for Registered {
        fn drop(&mut self) {
            // SAFETY: only this invocation registered this class; its window is gone.
            unsafe { UnregisterClassW(self.class.as_ptr(), self.instance) };
        }
    }
    let registered = Registered { class, instance };
    let mut state = Box::new(State {
        parent: parent.handle.0,
        pipe,
        started: Instant::now(),
        accepted: false,
    });
    // SAFETY: stable Box context and terminated UTF-16 arguments outlive the modal
    // loop; the window is never exposed as an input-injection target.
    let window = unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
            registered.class.as_ptr(),
            title.as_ptr(),
            WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            760,
            430,
            null_mut(),
            null_mut(),
            instance,
            (&mut *state as *mut State).cast(),
        )
    };
    if window.is_null() {
        return Err(security::denied());
    }
    struct Window(HWND);
    impl Drop for Window {
        fn drop(&mut self) {
            // SAFETY: check and destroy only this invocation's owned HWND if still live.
            unsafe {
                if IsWindow(self.0) != 0 {
                    DestroyWindow(self.0);
                }
            }
        }
    }
    let owned = Window(window);
    // SAFETY: all children belong to the owned window. Button IDs are fixed and
    // only their local click messages may set accepted=true.
    let (label, allow_button, cancel_button) = unsafe {
        (
            CreateWindowExW(
                0,
                static_class.as_ptr(),
                message.as_ptr(),
                WS_CHILD | WS_VISIBLE,
                20,
                16,
                710,
                310,
                window,
                null_mut(),
                instance,
                null(),
            ),
            CreateWindowExW(
                0,
                button_class.as_ptr(),
                approve.as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                380,
                340,
                180,
                34,
                window,
                APPROVE as _,
                instance,
                null(),
            ),
            CreateWindowExW(
                0,
                button_class.as_ptr(),
                cancel.as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
                580,
                340,
                130,
                34,
                window,
                CANCEL as _,
                instance,
                null(),
            ),
        )
    };
    if label.is_null()
        || allow_button.is_null()
        || cancel_button.is_null()
        || unsafe { SetTimer(window, 1, 100, None) } == 0
    {
        return Err(security::denied());
    }
    // SAFETY: show/focus only this invocation's local elevated consent window.
    unsafe {
        ShowWindow(window, SW_SHOW);
        SetForegroundWindow(window);
        SetFocus(cancel_button);
    }
    let mut event = MSG::default();
    loop {
        // SAFETY: live writable MSG; this modal loop belongs to the same thread
        // as the window. The timer bounds human wait and watches owner/pipe loss.
        let result = unsafe { GetMessageW(&mut event, null_mut(), 0, 0) };
        if result == -1 {
            return Err(security::denied());
        }
        if result == 0 {
            break;
        }
        if unsafe { IsDialogMessageW(window, &event) } == 0 {
            unsafe {
                TranslateMessage(&event);
                DispatchMessageW(&event);
            }
        }
    }
    drop(owned);
    parent.alive()?;
    WindowsSessionSnapshot::current()?;
    Ok(state.accepted && state.started.elapsed() < CONSENT_BUDGET)
}
