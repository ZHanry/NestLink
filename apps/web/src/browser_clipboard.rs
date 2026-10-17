//! Text never enters page signals. Receiving remote text and writing the local
//! clipboard are separate user actions, compatible with browser activation rules.
use crate::{
    browser_data::LocalDataConsent,
    browser_rpc::{BrowserRpc, BrowserRpcError},
};
use futures_channel::oneshot;
use gloo_timers::future::TimeoutFuture;
use js_sys::{Function, Promise, Reflect};
use nestlink_protocol::{native_clipboard::Action, webrtc_data::WebRtcDataChannel};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::Clipboard;
use zeroize::Zeroizing;

const CLIPBOARD_API_TIMEOUT_MS: f64 = 30_000.0;
const CLIPBOARD_CONSENT_POLL_MS: u32 = 25;

type WaiterSender = Rc<RefCell<Option<oneshot::Sender<Result<(), BrowserRpcError>>>>>;

/// The clipboard API Promise cannot be aborted. Keep its invocation behind a
/// small port so the isolated verification binary can supply deferred Promises.
pub trait LocalClipboardApi {
    fn read_text(&self) -> Result<Promise, BrowserRpcError>;
    fn write_text(&self, text: &str) -> Result<Promise, BrowserRpcError>;
}

struct NavigatorClipboard;

impl NavigatorClipboard {
    fn method(name: &str) -> Result<(Clipboard, Function), BrowserRpcError> {
        let window = web_sys::window().ok_or(BrowserRpcError::Storage)?;
        let clipboard = Reflect::get(window.navigator().as_ref(), &"clipboard".into())
            .map_err(|_| BrowserRpcError::Storage)?
            .dyn_into::<Clipboard>()
            .map_err(|_| BrowserRpcError::Storage)?;
        let method = Reflect::get(clipboard.as_ref(), &name.into())
            .map_err(|_| BrowserRpcError::Storage)?
            .dyn_into::<Function>()
            .map_err(|_| BrowserRpcError::Storage)?;
        Ok((clipboard, method))
    }
}

impl LocalClipboardApi for NavigatorClipboard {
    fn read_text(&self) -> Result<Promise, BrowserRpcError> {
        // The property/method can be absent or throw before producing a
        // Promise. Catch that synchronous failure as well as its rejection.
        let (clipboard, method) = NavigatorClipboard::method("readText")
            .map_err(|_| BrowserRpcError::ClipboardReadUnavailable)?;
        method
            .call0(clipboard.as_ref())
            .map_err(|_| BrowserRpcError::ClipboardReadUnavailable)?
            .dyn_into::<Promise>()
            .map_err(|_| BrowserRpcError::ClipboardReadUnavailable)
    }

    fn write_text(&self, text: &str) -> Result<Promise, BrowserRpcError> {
        let (clipboard, method) = NavigatorClipboard::method("writeText")
            .map_err(|_| BrowserRpcError::ClipboardWriteUnconfirmed)?;
        method
            .call1(clipboard.as_ref(), &JsValue::from_str(text))
            .map_err(|_| BrowserRpcError::ClipboardWriteUnconfirmed)?
            .dyn_into::<Promise>()
            .map_err(|_| BrowserRpcError::ClipboardWriteUnconfirmed)
    }
}

struct Pending {
    text: Zeroizing<String>,
    expires_ms: f64,
}
struct Owner {
    rpc: BrowserRpc,
    local_clipboard: Rc<dyn LocalClipboardApi>,
    api_timeout_ms: f64,
    pending: RefCell<Option<Pending>>,
    busy: Cell<bool>,
}
#[derive(Clone)]
pub struct BrowserClipboard(Rc<Owner>);
pub type ClipboardWaiter = oneshot::Receiver<Result<(), BrowserRpcError>>;

impl BrowserClipboard {
    pub fn new(rpc: BrowserRpc) -> Self {
        Self::with_local_clipboard(rpc, Rc::new(NavigatorClipboard), CLIPBOARD_API_TIMEOUT_MS)
    }

    #[cfg(feature = "browser-verification")]
    pub fn new_with_local_clipboard_for_verification(
        rpc: BrowserRpc,
        local_clipboard: Rc<dyn LocalClipboardApi>,
        api_timeout_ms: f64,
    ) -> Self {
        Self::with_local_clipboard(rpc, local_clipboard, api_timeout_ms)
    }

    fn with_local_clipboard(
        rpc: BrowserRpc,
        local_clipboard: Rc<dyn LocalClipboardApi>,
        api_timeout_ms: f64,
    ) -> Self {
        Self(Rc::new(Owner {
            rpc,
            local_clipboard,
            api_timeout_ms,
            pending: RefCell::new(None),
            busy: Cell::new(false),
        }))
    }
    pub fn clear(&self) {
        self.0.pending.borrow_mut().take();
    }
    pub fn has_pending(&self) -> bool {
        let live = now().is_ok_and(|at| {
            self.0
                .pending
                .borrow()
                .as_ref()
                .is_some_and(|value| at < value.expires_ms)
        });
        if !live {
            self.clear();
        }
        live
    }
    pub fn has(&self, kind: WebRtcDataChannel) -> bool {
        self.0.rpc.has(kind)
    }
    /// True while an owned browser/RPC operation still holds this clipboard
    /// owner. A timed-out browser Promise remains busy until it actually settles.
    pub fn has_unsettled_operation(&self) -> bool {
        self.0.busy.get()
    }
    fn start(
        &self,
        kind: WebRtcDataChannel,
        consent: &LocalDataConsent,
    ) -> Result<Guard, BrowserRpcError> {
        self.0.rpc.check(kind)?;
        if !consent() {
            return Err(crate::browser_data::BrowserDataError::Denied.into());
        }
        if self.0.busy.replace(true) {
            return Err(BrowserRpcError::Busy);
        }
        Ok(Guard(self.0.clone()))
    }
    /// Fetch only. A subsequent explicit click calls copy_remote while browser
    /// user activation is still live; a delayed network reply never triggers it.
    pub fn receive_remote(
        &self,
        consent: LocalDataConsent,
    ) -> Result<ClipboardWaiter, BrowserRpcError> {
        let guard = self.start(WebRtcDataChannel::ClipboardRead, &consent)?;
        self.clear();
        let owner = self.clone();
        let (sent, waiting) = oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let result = async {
                match owner
                    .0
                    .rpc
                    .clipboard(
                        WebRtcDataChannel::ClipboardRead,
                        Action::Read(true),
                        consent.clone(),
                    )
                    .await?
                {
                    Action::Text(mut value) => {
                        let text = value.text.take().map(Zeroizing::new);
                        if !consent() {
                            return Err(crate::browser_data::BrowserDataError::Denied.into());
                        }
                        if let Some(text) = text {
                            *owner.0.pending.borrow_mut() = Some(Pending {
                                text,
                                expires_ms: now()? + 30_000.0,
                            });
                            Ok(())
                        } else {
                            Err(BrowserRpcError::Refused {
                                code: nestlink_protocol::ClipboardErrorCode::ClipboardUnavailable
                                    as i32,
                                write_effect: 0,
                            })
                        }
                    }
                    Action::Failure(failure) => Err(BrowserRpcError::Refused {
                        code: failure.code,
                        write_effect: failure.write_effect,
                    }),
                    _ => {
                        owner.0.rpc.close();
                        Err(BrowserRpcError::Protocol)
                    }
                }
            }
            .await;
            drop(guard);
            let _ = sent.send(result);
        });
        Ok(waiting)
    }
    /// Call directly inside the click handler, before any await. Once the browser
    /// accepts the local write, cancellation cannot undo that clipboard effect.
    pub fn copy_remote(
        &self,
        consent: LocalDataConsent,
    ) -> Result<ClipboardWaiter, BrowserRpcError> {
        let guard = self.start(WebRtcDataChannel::ClipboardRead, &consent)?;
        if !self.has_pending() {
            return Err(BrowserRpcError::Cancelled);
        }
        let pending = self
            .0
            .pending
            .borrow_mut()
            .take()
            .ok_or(BrowserRpcError::Cancelled)?;
        let deadline_ms = self.deadline_from_now()?;
        let promise = self.0.local_clipboard.write_text(&pending.text)?;
        drop(pending);
        let (sent, waiting) = oneshot::channel();
        let sent = Rc::new(RefCell::new(Some(sent)));
        let api_pending = Rc::new(Cell::new(true));
        let interrupted = Rc::new(Cell::new(None));
        monitor_local_clipboard_api(
            sent.clone(),
            api_pending.clone(),
            interrupted.clone(),
            deadline_ms,
            consent.clone(),
            LocalApiOperation::Write,
        );
        wasm_bindgen_futures::spawn_local(async move {
            let settled = JsFuture::from(promise).await;
            api_pending.set(false);
            let result = if let Some(error) = interrupted.get() {
                Err(error)
            } else {
                match now() {
                    Ok(at) if consent() && at < deadline_ms => settled
                        .map(|_| ())
                        .map_err(|_| BrowserRpcError::ClipboardWriteUnconfirmed),
                    _ => Err(BrowserRpcError::ClipboardWriteUnconfirmed),
                }
            };
            drop(guard);
            finish_waiter(&sent, result);
        });
        Ok(waiting)
    }
    /// Start readText synchronously while the user's click is active. An owned
    /// actor checks current consent again before sending and consumes the exact
    /// result; it never retries a write whose effect is unknown.
    pub fn send_local(
        &self,
        consent: LocalDataConsent,
    ) -> Result<ClipboardWaiter, BrowserRpcError> {
        let guard = self.start(WebRtcDataChannel::ClipboardWrite, &consent)?;
        // Record the deadline before starting readText synchronously in the
        // click stack. A late result is consumed but must never reach the peer.
        let deadline_ms = self.deadline_from_now()?;
        let promise = self.0.local_clipboard.read_text()?;
        let owner = self.clone();
        let (sent, waiting) = oneshot::channel();
        let sent = Rc::new(RefCell::new(Some(sent)));
        let api_pending = Rc::new(Cell::new(true));
        let interrupted = Rc::new(Cell::new(None));
        monitor_local_clipboard_api(
            sent.clone(),
            api_pending.clone(),
            interrupted.clone(),
            deadline_ms,
            consent.clone(),
            LocalApiOperation::Read,
        );
        wasm_bindgen_futures::spawn_local(async move {
            let settled = JsFuture::from(promise).await;
            api_pending.set(false);
            let result = if let Some(error) = interrupted.get() {
                Err(error)
            } else {
                async {
                    if !consent() {
                        return Err(crate::browser_data::BrowserDataError::Denied.into());
                    }
                    if now()? >= deadline_ms {
                        return Err(BrowserRpcError::ClipboardReadTimedOut);
                    }
                    let value = settled.map_err(|_| BrowserRpcError::ClipboardReadUnavailable)?;
                    let text = Zeroizing::new(
                        value
                            .as_string()
                            .ok_or(BrowserRpcError::ClipboardReadUnavailable)?,
                    );
                    nestlink_protocol::clipboard::validate_text(&text)
                        .map_err(|_| BrowserRpcError::Capacity)?;
                    if !consent() {
                        return Err(crate::browser_data::BrowserDataError::Denied.into());
                    }
                    if now()? >= deadline_ms {
                        return Err(BrowserRpcError::ClipboardReadTimedOut);
                    }
                    match owner
                        .0
                        .rpc
                        .clipboard(
                            WebRtcDataChannel::ClipboardWrite,
                            Action::Write(text.to_string()),
                            consent,
                        )
                        .await?
                    {
                        Action::Written(true) => Ok(()),
                        Action::Failure(failure) => Err(BrowserRpcError::Refused {
                            code: failure.code,
                            write_effect: failure.write_effect,
                        }),
                        _ => {
                            owner.0.rpc.close();
                            Err(BrowserRpcError::Protocol)
                        }
                    }
                }
                .await
            };
            drop(guard);
            finish_waiter(&sent, result);
        });
        Ok(waiting)
    }

    fn deadline_from_now(&self) -> Result<f64, BrowserRpcError> {
        let deadline = now()? + self.0.api_timeout_ms;
        if deadline.is_finite() && self.0.api_timeout_ms.is_finite() && self.0.api_timeout_ms > 0.0
        {
            Ok(deadline)
        } else {
            Err(BrowserRpcError::Storage)
        }
    }
}
struct Guard(Rc<Owner>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.busy.set(false);
    }
}
fn now() -> Result<f64, BrowserRpcError> {
    web_sys::window()
        .and_then(|window| window.performance())
        .map(|clock| clock.now())
        .filter(|value| value.is_finite())
        .ok_or(BrowserRpcError::Storage)
}

#[derive(Clone, Copy)]
enum LocalApiOperation {
    Read,
    Write,
}

fn monitor_local_clipboard_api(
    sent: WaiterSender,
    api_pending: Rc<Cell<bool>>,
    interrupted: Rc<Cell<Option<BrowserRpcError>>>,
    deadline_ms: f64,
    consent: LocalDataConsent,
    operation: LocalApiOperation,
) {
    wasm_bindgen_futures::spawn_local(async move {
        while api_pending.get() && sent.borrow().is_some() {
            let detected = if !consent() {
                Some(match operation {
                    LocalApiOperation::Read => crate::browser_data::BrowserDataError::Denied.into(),
                    LocalApiOperation::Write => BrowserRpcError::ClipboardWriteUnconfirmed,
                })
            } else {
                match now() {
                    Ok(at) if at < deadline_ms => None,
                    Ok(_) => Some(match operation {
                        LocalApiOperation::Read => BrowserRpcError::ClipboardReadTimedOut,
                        LocalApiOperation::Write => BrowserRpcError::ClipboardWriteUnconfirmed,
                    }),
                    Err(error) => Some(match operation {
                        LocalApiOperation::Read => error,
                        LocalApiOperation::Write => BrowserRpcError::ClipboardWriteUnconfirmed,
                    }),
                }
            };
            if let Some(error) = detected {
                let terminal_error = record_interruption(&interrupted, error);
                finish_waiter(&sent, Err(terminal_error));
                return;
            }
            let remaining_ms = (deadline_ms - now().unwrap_or(deadline_ms)).max(1.0);
            let delay_ms = remaining_ms.min(CLIPBOARD_CONSENT_POLL_MS as f64).ceil() as u32;
            TimeoutFuture::new(delay_ms.max(1)).await;
        }
    });
}

fn record_interruption(
    interrupted: &Cell<Option<BrowserRpcError>>,
    error: BrowserRpcError,
) -> BrowserRpcError {
    // The first terminal observation remains authoritative after reapproval.
    if interrupted.get().is_none() {
        interrupted.set(Some(error));
    }
    interrupted.get().unwrap_or(error)
}

fn finish_waiter(sent: &WaiterSender, result: Result<(), BrowserRpcError>) {
    if let Some(sent) = sent.borrow_mut().take() {
        let _ = sent.send(result);
    }
}
