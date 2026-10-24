//! Browser-only acceptance hooks compiled solely by the verification binary.
//! The storage, RTC and clipboard paths below are the production modules from
//! this crate; this file only gives Playwright a controlled browser entrypoint.
use crate::{
    browser_clipboard::{BrowserClipboard, ClipboardWaiter, LocalClipboardApi},
    browser_data::{BrowserDataChannels, BrowserDataError, LocalDataApproval, LocalDataConsent},
    browser_identity,
    browser_rpc::{BrowserRpc, BrowserRpcError},
    browser_sdp::rtc_session_description_init,
    browser_storage::PrivateStorage,
};
use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use nestlink_protocol::{
    ClipboardText, NativeClipboard, Path, Permission, PermitClaims, SCHEMA_VERSION,
    native_clipboard::Action as ClipboardAction,
    webrtc_data::{
        WebRtcDataBinding, WebRtcDataChannel, WebRtcDataFragmenter, WebRtcDataReassembler,
    },
};
use std::{cell::Cell, cell::RefCell, rc::Rc};
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use web_sys::{
    Event, MessageEvent, RtcDataChannel, RtcDataChannelState, RtcPeerConnection, RtcSdpType,
    RtcSessionDescriptionInit,
};

thread_local! {
    static HELD_STORAGE: RefCell<Option<PrivateStorage>> = const { RefCell::new(None) };
    static CLIPBOARD_FIXTURE: RefCell<Option<ClipboardFixture>> = const { RefCell::new(None) };
    static CLIPBOARD_LIFECYCLE_FIXTURE: RefCell<Option<ClipboardLifecycleFixture>> = const { RefCell::new(None) };
}

const CLIPBOARD_LIFECYCLE_TIMEOUT_MS: f64 = 250.0;

/// Publish the test-only API on a separate, feature-gated binary. The
/// production `nestlink-web` target never compiles this module or these hooks.
#[wasm_bindgen(start)]
pub fn install_verification_api() -> Result<(), JsValue> {
    let api = Object::new();

    let hold = Closure::<dyn FnMut() -> Promise>::new(|| {
        future_to_promise(async { storage_hold().await.map(JsValue::from_bool) })
    });
    Reflect::set(api.as_ref(), &"storageHold".into(), hold.as_ref())?;
    hold.forget();

    let recover = Closure::<dyn FnMut(u32) -> Promise>::new(|passes| {
        future_to_promise(async move {
            storage_recover_close(passes)
                .await
                .map(|passes| JsValue::from_f64(passes as f64))
        })
    });
    Reflect::set(
        api.as_ref(),
        &"storageRecoverClose".into(),
        recover.as_ref(),
    )?;
    recover.forget();

    let release = Closure::<dyn FnMut() -> Promise>::new(|| {
        future_to_promise(async { storage_release().await.map(JsValue::from_bool) })
    });
    Reflect::set(api.as_ref(), &"storageRelease".into(), release.as_ref())?;
    release.forget();

    let identity_load = Closure::<dyn FnMut(String) -> Promise>::new(|scope: String| {
        future_to_promise(async move {
            let identity = browser_identity::load_or_create(&scope)
                .await
                .map_err(js_error)?;
            let encoded = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                identity.identity.public_key(),
            );
            Ok(JsValue::from_str(&format!(
                "{}:{encoded}",
                identity.device_id
            )))
        })
    });
    Reflect::set(api.as_ref(), &"identityLoad".into(), identity_load.as_ref())?;
    identity_load.forget();

    let fixture_start = Closure::<dyn FnMut() -> Promise>::new(|| {
        future_to_promise(async {
            clipboard_fixture_start().await?;
            Ok(JsValue::UNDEFINED)
        })
    });
    Reflect::set(
        api.as_ref(),
        &"clipboardFixtureStart".into(),
        fixture_start.as_ref(),
    )?;
    fixture_start.forget();

    let lifecycle_start =
        Closure::<dyn FnMut() -> Result<(), JsValue>>::new(clipboard_lifecycle_fixture_start);
    Reflect::set(
        api.as_ref(),
        &"clipboardLifecycleFixtureStart".into(),
        lifecycle_start.as_ref(),
    )?;
    lifecycle_start.forget();

    let lifecycle_read =
        Closure::<dyn FnMut() -> Result<Promise, JsValue>>::new(clipboard_lifecycle_start_read);
    Reflect::set(
        api.as_ref(),
        &"clipboardLifecycleStartRead".into(),
        lifecycle_read.as_ref(),
    )?;
    lifecycle_read.forget();

    let lifecycle_stage =
        Closure::<dyn FnMut() -> Result<Promise, JsValue>>::new(clipboard_lifecycle_stage_remote);
    Reflect::set(
        api.as_ref(),
        &"clipboardLifecycleStageRemote".into(),
        lifecycle_stage.as_ref(),
    )?;
    lifecycle_stage.forget();

    let lifecycle_write =
        Closure::<dyn FnMut() -> Result<Promise, JsValue>>::new(clipboard_lifecycle_start_write);
    Reflect::set(
        api.as_ref(),
        &"clipboardLifecycleStartWrite".into(),
        lifecycle_write.as_ref(),
    )?;
    lifecycle_write.forget();

    let lifecycle_consent =
        Closure::<dyn FnMut(bool) -> Result<(), JsValue>>::new(clipboard_lifecycle_set_consent);
    Reflect::set(
        api.as_ref(),
        &"clipboardLifecycleSetConsent".into(),
        lifecycle_consent.as_ref(),
    )?;
    lifecycle_consent.forget();

    let lifecycle_resolve_read =
        Closure::<dyn FnMut() -> Result<(), JsValue>>::new(clipboard_lifecycle_resolve_read);
    Reflect::set(
        api.as_ref(),
        &"clipboardLifecycleResolveRead".into(),
        lifecycle_resolve_read.as_ref(),
    )?;
    lifecycle_resolve_read.forget();

    let lifecycle_resolve_write =
        Closure::<dyn FnMut() -> Result<(), JsValue>>::new(clipboard_lifecycle_resolve_write);
    Reflect::set(
        api.as_ref(),
        &"clipboardLifecycleResolveWrite".into(),
        lifecycle_resolve_write.as_ref(),
    )?;
    lifecycle_resolve_write.forget();

    let lifecycle_reject_read =
        Closure::<dyn FnMut() -> Result<(), JsValue>>::new(clipboard_lifecycle_reject_read);
    Reflect::set(
        api.as_ref(),
        &"clipboardLifecycleRejectRead".into(),
        lifecycle_reject_read.as_ref(),
    )?;
    lifecycle_reject_read.forget();

    let lifecycle_reject_write =
        Closure::<dyn FnMut() -> Result<(), JsValue>>::new(clipboard_lifecycle_reject_write);
    Reflect::set(
        api.as_ref(),
        &"clipboardLifecycleRejectWrite".into(),
        lifecycle_reject_write.as_ref(),
    )?;
    lifecycle_reject_write.forget();

    let lifecycle_state =
        Closure::<dyn FnMut() -> Result<JsValue, JsValue>>::new(clipboard_lifecycle_state);
    Reflect::set(
        api.as_ref(),
        &"clipboardLifecycleState".into(),
        lifecycle_state.as_ref(),
    )?;
    lifecycle_state.forget();

    let receive = Closure::<dyn FnMut() -> Result<Promise, JsValue>>::new(clipboard_receive_remote);
    Reflect::set(
        api.as_ref(),
        &"clipboardReceiveRemote".into(),
        receive.as_ref(),
    )?;
    receive.forget();

    let copy = Closure::<dyn FnMut() -> Result<Promise, JsValue>>::new(clipboard_copy_remote);
    Reflect::set(api.as_ref(), &"clipboardCopyRemote".into(), copy.as_ref())?;
    copy.forget();

    let send = Closure::<dyn FnMut() -> Result<Promise, JsValue>>::new(clipboard_send_local);
    Reflect::set(api.as_ref(), &"clipboardSendLocal".into(), send.as_ref())?;
    send.forget();

    let pending = Closure::<dyn FnMut() -> bool>::new(clipboard_has_pending);
    Reflect::set(
        api.as_ref(),
        &"clipboardHasPending".into(),
        pending.as_ref(),
    )?;
    pending.forget();

    let last_write = Closure::<dyn FnMut() -> String>::new(clipboard_last_host_write);
    Reflect::set(
        api.as_ref(),
        &"clipboardLastHostWrite".into(),
        last_write.as_ref(),
    )?;
    last_write.forget();

    let bad_sequence =
        Closure::<dyn FnMut() -> Result<(), JsValue>>::new(clipboard_use_bad_reply_sequence);
    Reflect::set(
        api.as_ref(),
        &"clipboardUseBadReplySequence".into(),
        bad_sequence.as_ref(),
    )?;
    bad_sequence.forget();

    let peer_states = Closure::<dyn FnMut() -> Result<Array, JsValue>>::new(clipboard_peer_states);
    Reflect::set(
        api.as_ref(),
        &"clipboardPeerStates".into(),
        peer_states.as_ref(),
    )?;
    peer_states.forget();

    let stop = Closure::<dyn FnMut()>::new(clipboard_stop);
    Reflect::set(api.as_ref(), &"clipboardStop".into(), stop.as_ref())?;
    stop.forget();

    let window = web_sys::window().ok_or_else(|| js_error(BrowserRpcError::Storage))?;
    Reflect::set(
        window.as_ref(),
        &"nestlinkBrowserVerification".into(),
        api.as_ref(),
    )?;
    Ok(())
}

/// Acquire and retain the exact production Web Lock without starting recovery.
/// The returned boolean is false only when another page owns the lock.
#[wasm_bindgen(js_name = storageHold)]
pub async fn storage_hold() -> Result<bool, JsValue> {
    if HELD_STORAGE.with(|storage| storage.borrow().is_some()) {
        return Ok(true);
    }
    match PrivateStorage::open().await {
        Ok(storage) => {
            HELD_STORAGE.with(|held| *held.borrow_mut() = Some(storage));
            Ok(true)
        }
        Err(BrowserRpcError::Busy) => Ok(false),
        Err(error) => Err(js_error(error)),
    }
}

/// Recover through the production OPFS iterator, retrying its bounded passes
/// while preserving the same owner and iterator, then await the real lock end.
#[wasm_bindgen(js_name = storageRecoverClose)]
pub async fn storage_recover_close(maximum_passes: u32) -> Result<u32, JsValue> {
    let mut storage = match HELD_STORAGE.with(|held| held.borrow_mut().take()) {
        Some(storage) => storage,
        None => PrivateStorage::open().await.map_err(js_error)?,
    };
    let maximum_passes = maximum_passes.max(1);
    for pass in 1..=maximum_passes {
        match storage.recover().await {
            Ok(()) => {
                if let Err(error) = storage.close().await {
                    retain_storage(storage);
                    return Err(js_error(error));
                }
                return Ok(pass);
            }
            Err(BrowserRpcError::Capacity) if pass < maximum_passes => {}
            Err(error) => {
                retain_storage(storage);
                return Err(js_error(error));
            }
        }
    }
    retain_storage(storage);
    Err(js_error(BrowserRpcError::Capacity))
}

/// Explicitly release a test lock. Closing the page instead exercises the
/// browser's actual execution-context cleanup path.
#[wasm_bindgen(js_name = storageRelease)]
pub async fn storage_release() -> Result<bool, JsValue> {
    let Some(mut storage) = HELD_STORAGE.with(|held| held.borrow_mut().take()) else {
        return Ok(false);
    };
    storage.close().await.map_err(js_error)?;
    Ok(true)
}

fn retain_storage(storage: PrivateStorage) {
    HELD_STORAGE.with(|held| *held.borrow_mut() = Some(storage));
}

/// Create a same-origin WebRTC pair and run the production BrowserClipboard,
/// BrowserRpc and BrowserDataChannels over real SCTP DataChannels.
#[wasm_bindgen(js_name = clipboardFixtureStart)]
pub async fn clipboard_fixture_start() -> Result<(), JsValue> {
    stop_clipboard_fixture();

    let local = RtcPeerConnection::new().map_err(js_error)?;
    let remote = match RtcPeerConnection::new() {
        Ok(peer) => peer,
        Err(error) => {
            local.close();
            return Err(js_error(error));
        }
    };
    let claims = clipboard_claims();
    let permit_digest = [0x5a; 32];
    let fault_reply_sequence = Rc::new(Cell::new(false));
    let received_write = Rc::new(RefCell::new(String::new()));
    let remote_channels = Rc::new(RefCell::new(Vec::<RtcDataChannel>::new()));
    let host_messages = Rc::new(RefCell::new(Vec::<Closure<dyn FnMut(MessageEvent)>>::new()));

    let callback_claims = claims.clone();
    let callback_fault = fault_reply_sequence.clone();
    let callback_write = received_write.clone();
    let callback_channels = remote_channels.clone();
    let callback_messages = host_messages.clone();
    let on_data_channel = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
        let result = (|| -> Result<(), JsValue> {
            let channel = Reflect::get(event.as_ref(), &"channel".into())?
                .dyn_into::<RtcDataChannel>()
                .map_err(js_error)?;
            let kind = WebRtcDataChannel::from_label(&channel.label()).map_err(js_error)?;
            if !matches!(
                kind,
                WebRtcDataChannel::ClipboardRead | WebRtcDataChannel::ClipboardWrite
            ) {
                return Err(js_error(BrowserRpcError::Protocol));
            }
            let binding = WebRtcDataBinding::for_permit(&callback_claims, permit_digest, kind)
                .map_err(js_error)?;
            let reassembler = Rc::new(RefCell::new(WebRtcDataReassembler::new(binding.clone())));
            let fragmenter = Rc::new(RefCell::new(WebRtcDataFragmenter::new(binding)));
            let request_reassembler = reassembler.clone();
            let response_fragmenter = fragmenter.clone();
            let fault = callback_fault.clone();
            let write = callback_write.clone();
            let host_channel = channel.clone();
            channel.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);
            let on_message =
                Closure::<dyn FnMut(MessageEvent)>::new(move |message: MessageEvent| {
                    let result = (|| -> Result<(), JsValue> {
                        let buffer = message
                            .data()
                            .dyn_into::<js_sys::ArrayBuffer>()
                            .map_err(js_error)?;
                        let wire = Uint8Array::new(&buffer).to_vec();
                        let Some(envelope) = request_reassembler
                            .borrow_mut()
                            .push(&wire)
                            .map_err(js_error)?
                        else {
                            return Ok(());
                        };
                        let mut request = NativeClipboard::decode_validated(&envelope.payload)
                            .map_err(js_error)?;
                        let action = request
                            .action
                            .take()
                            .ok_or_else(|| js_error(BrowserRpcError::Protocol))?;
                        let response_action = match action {
                            ClipboardAction::Read(true)
                                if kind == WebRtcDataChannel::ClipboardRead =>
                            {
                                ClipboardAction::Text(ClipboardText {
                                    text: Some("remote clipboard fixture".into()),
                                })
                            }
                            ClipboardAction::Write(text)
                                if kind == WebRtcDataChannel::ClipboardWrite =>
                            {
                                *write.borrow_mut() = text;
                                ClipboardAction::Written(true)
                            }
                            _ => return Err(js_error(BrowserRpcError::Protocol)),
                        };
                        let mut response = NativeClipboard {
                            schema_version: SCHEMA_VERSION,
                            connection_generation: request.connection_generation,
                            sequence: request.sequence,
                            action: Some(response_action),
                        };
                        if fault.get() {
                            response.sequence = response
                                .sequence
                                .checked_add(1)
                                .ok_or_else(|| js_error(BrowserRpcError::Protocol))?;
                            fault.set(false);
                        }
                        let payload = response.encode_validated().map_err(js_error)?;
                        let (_, fragments) = response_fragmenter
                            .borrow_mut()
                            .fragment(&payload)
                            .map_err(js_error)?;
                        for fragment in fragments {
                            host_channel
                                .send_with_u8_array(&fragment)
                                .map_err(js_error)?;
                        }
                        Ok(())
                    })();
                    if let Err(error) = result {
                        web_sys::console::error_1(&error);
                    }
                });
            channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
            callback_channels.borrow_mut().push(channel);
            callback_messages.borrow_mut().push(on_message);
            Ok(())
        })();
        if let Err(error) = result {
            web_sys::console::error_1(&error);
        }
    });
    Reflect::set(
        remote.as_ref(),
        &"ondatachannel".into(),
        on_data_channel.as_ref(),
    )
    .map_err(js_error)?;

    let authority = Rc::new(|_: WebRtcDataChannel| Ok(()))
        as Rc<dyn Fn(WebRtcDataChannel) -> Result<(), BrowserDataError>>;
    let stop_local = local.clone();
    let stop_remote = remote.clone();
    let channels = match BrowserDataChannels::new(
        &local,
        &claims,
        permit_digest,
        authority,
        Rc::new(move || {
            stop_local.close();
            stop_remote.close();
        }),
    ) {
        Ok(channels) => channels,
        Err(error) => {
            local.close();
            remote.close();
            return Err(js_error(format!("business channel setup: {error:?}")));
        }
    };
    let rpc = match BrowserRpc::new(channels.clone(), claims.connection_generation) {
        Ok(rpc) => rpc,
        Err(error) => {
            channels.close();
            remote.close();
            return Err(js_error(error));
        }
    };
    if let Err(error) = negotiate(&local, &remote).await {
        channels.close();
        remote.close();
        return Err(error);
    }
    if let Err(error) = wait_for_data_channels(&remote_channels).await {
        channels.close();
        remote.close();
        return Err(error);
    }
    let clipboard = BrowserClipboard::new(rpc.clone());
    let controlled_clipboard = Rc::new(ControlledClipboardApi::default());
    let controlled_api: Rc<dyn LocalClipboardApi> = controlled_clipboard.clone();
    let lifecycle_clipboard = BrowserClipboard::new_with_local_clipboard_for_verification(
        rpc.clone(),
        controlled_api,
        CLIPBOARD_LIFECYCLE_TIMEOUT_MS,
    );
    let lifecycle_approval = LocalDataApproval::default();
    lifecycle_approval.approve();
    CLIPBOARD_LIFECYCLE_FIXTURE.with(|fixture| {
        *fixture.borrow_mut() = Some(ClipboardLifecycleFixture {
            clipboard: lifecycle_clipboard,
            local_api: controlled_clipboard,
            approval: lifecycle_approval,
        });
    });
    CLIPBOARD_FIXTURE.with(|fixture| {
        *fixture.borrow_mut() = Some(ClipboardFixture {
            local,
            remote,
            channels,
            rpc,
            clipboard,
            fault_reply_sequence,
            received_write,
            remote_channels,
            host_messages,
            on_data_channel,
        });
    });
    Ok(())
}

/// Start ReadText on the actual production actor. `copy_remote` remains a
/// separate synchronous click path, matching the UI's two-step interaction.
#[wasm_bindgen(js_name = clipboardReceiveRemote)]
pub fn clipboard_receive_remote() -> Result<Promise, JsValue> {
    let clipboard = clipboard_owner()?;
    let waiter = clipboard
        .receive_remote(always_consent())
        .map_err(js_error)?;
    Ok(waiter_promise(waiter))
}

/// Call from a trusted click handler; the browser write API is invoked before
/// this function returns its Promise.
#[wasm_bindgen(js_name = clipboardCopyRemote)]
pub fn clipboard_copy_remote() -> Result<Promise, JsValue> {
    let clipboard = clipboard_owner()?;
    let waiter = clipboard.copy_remote(always_consent()).map_err(js_error)?;
    Ok(waiter_promise(waiter))
}

/// Call from a trusted click handler; clipboard.readText starts synchronously.
#[wasm_bindgen(js_name = clipboardSendLocal)]
pub fn clipboard_send_local() -> Result<Promise, JsValue> {
    let clipboard = clipboard_owner()?;
    let waiter = clipboard.send_local(always_consent()).map_err(js_error)?;
    Ok(waiter_promise(waiter))
}

#[wasm_bindgen(js_name = clipboardHasPending)]
pub fn clipboard_has_pending() -> bool {
    CLIPBOARD_FIXTURE.with(|fixture| {
        fixture
            .borrow()
            .as_ref()
            .is_some_and(|fixture| fixture.clipboard.has_pending())
    })
}

#[wasm_bindgen(js_name = clipboardLastHostWrite)]
pub fn clipboard_last_host_write() -> String {
    CLIPBOARD_FIXTURE.with(|fixture| {
        fixture
            .borrow()
            .as_ref()
            .map_or_else(String::new, |fixture| {
                fixture.received_write.borrow().clone()
            })
    })
}

/// Make the mock peer send one schema-valid but sequence-invalid reply. The
/// production BrowserRpc decoder must close its actual peer owner.
#[wasm_bindgen(js_name = clipboardUseBadReplySequence)]
pub fn clipboard_use_bad_reply_sequence() -> Result<(), JsValue> {
    CLIPBOARD_FIXTURE.with(|fixture| {
        let fixture = fixture.borrow();
        fixture
            .as_ref()
            .ok_or_else(|| js_error(BrowserRpcError::Data(BrowserDataError::Stopped)))?
            .fault_reply_sequence
            .set(true);
        Ok(())
    })
}

#[wasm_bindgen(js_name = clipboardPeerStates)]
pub fn clipboard_peer_states() -> Result<Array, JsValue> {
    CLIPBOARD_FIXTURE.with(|fixture| {
        let fixture = fixture.borrow();
        let fixture = fixture
            .as_ref()
            .ok_or_else(|| js_error(BrowserRpcError::Data(BrowserDataError::Stopped)))?;
        let states = Array::new();
        for peer in [&fixture.local, &fixture.remote] {
            states.push(&Reflect::get(peer.as_ref(), &"connectionState".into()).map_err(js_error)?);
        }
        Ok(states)
    })
}

#[wasm_bindgen(js_name = clipboardStop)]
pub fn clipboard_stop() {
    stop_clipboard_fixture();
}

type HostMessages = Rc<RefCell<Vec<Closure<dyn FnMut(MessageEvent)>>>>;

struct ClipboardFixture {
    local: RtcPeerConnection,
    remote: RtcPeerConnection,
    channels: BrowserDataChannels,
    rpc: BrowserRpc,
    clipboard: BrowserClipboard,
    fault_reply_sequence: Rc<Cell<bool>>,
    received_write: Rc<RefCell<String>>,
    remote_channels: Rc<RefCell<Vec<RtcDataChannel>>>,
    host_messages: HostMessages,
    on_data_channel: Closure<dyn FnMut(Event)>,
}

#[derive(Clone)]
struct ClipboardLifecycleFixture {
    clipboard: BrowserClipboard,
    local_api: Rc<ControlledClipboardApi>,
    approval: LocalDataApproval,
}

#[derive(Default)]
struct ControlledClipboardApi {
    pending_reads: RefCell<Vec<DeferredPromise>>,
    pending_writes: RefCell<Vec<DeferredPromise>>,
    read_calls: Cell<u32>,
    write_calls: Cell<u32>,
}

struct DeferredPromise {
    promise: Promise,
    resolve: Function,
    reject: Function,
}

impl DeferredPromise {
    fn new() -> Result<Self, JsValue> {
        let functions = Rc::new(RefCell::new(None));
        let functions_for_executor = functions.clone();
        let mut executor = move |resolve: Function, reject: Function| {
            *functions_for_executor.borrow_mut() = Some((resolve, reject));
        };
        let promise = Promise::new(&mut executor);
        let (resolve, reject) = functions
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("controlled Promise functions unavailable"))?;
        Ok(Self {
            promise,
            resolve,
            reject,
        })
    }

    fn resolve(self, value: &JsValue) -> Result<(), JsValue> {
        self.resolve.call1(&JsValue::UNDEFINED, value).map(|_| ())
    }

    fn reject(self, value: &JsValue) -> Result<(), JsValue> {
        self.reject.call1(&JsValue::UNDEFINED, value).map(|_| ())
    }
}

impl ControlledClipboardApi {
    fn resolve_read(&self) -> Result<(), JsValue> {
        self.pending_reads
            .borrow_mut()
            .pop()
            .ok_or_else(|| JsValue::from_str("no controlled read Promise is pending"))?
            .resolve(&JsValue::from_str("controlled clipboard input"))
    }

    fn resolve_write(&self) -> Result<(), JsValue> {
        self.pending_writes
            .borrow_mut()
            .pop()
            .ok_or_else(|| JsValue::from_str("no controlled write Promise is pending"))?
            .resolve(&JsValue::UNDEFINED)
    }

    fn reject_read(&self) -> Result<(), JsValue> {
        self.pending_reads
            .borrow_mut()
            .pop()
            .ok_or_else(|| JsValue::from_str("no controlled read Promise is pending"))?
            .reject(&JsValue::from_str("controlled clipboard read rejected"))
    }

    fn reject_write(&self) -> Result<(), JsValue> {
        self.pending_writes
            .borrow_mut()
            .pop()
            .ok_or_else(|| JsValue::from_str("no controlled write Promise is pending"))?
            .reject(&JsValue::from_str("controlled clipboard write rejected"))
    }
}

impl LocalClipboardApi for ControlledClipboardApi {
    fn read_text(&self) -> Result<Promise, BrowserRpcError> {
        let deferred = DeferredPromise::new().map_err(|_| BrowserRpcError::Storage)?;
        let promise = deferred.promise.clone();
        self.pending_reads.borrow_mut().push(deferred);
        self.read_calls.set(self.read_calls.get().saturating_add(1));
        Ok(promise)
    }

    fn write_text(&self, _text: &str) -> Result<Promise, BrowserRpcError> {
        let deferred = DeferredPromise::new().map_err(|_| BrowserRpcError::Storage)?;
        let promise = deferred.promise.clone();
        self.pending_writes.borrow_mut().push(deferred);
        self.write_calls
            .set(self.write_calls.get().saturating_add(1));
        Ok(promise)
    }
}

fn clipboard_lifecycle_fixture() -> Result<ClipboardLifecycleFixture, JsValue> {
    CLIPBOARD_LIFECYCLE_FIXTURE.with(|fixture| {
        fixture
            .borrow()
            .as_ref()
            .cloned()
            .ok_or_else(|| js_error(BrowserRpcError::Data(BrowserDataError::Stopped)))
    })
}

fn clipboard_lifecycle_consent(fixture: &ClipboardLifecycleFixture) -> LocalDataConsent {
    fixture.approval.consent()
}

fn clipboard_lifecycle_fixture_start() -> Result<(), JsValue> {
    let _ = clipboard_lifecycle_fixture()?;
    Ok(())
}

fn clipboard_lifecycle_start_read() -> Result<Promise, JsValue> {
    let fixture = clipboard_lifecycle_fixture()?;
    let waiter = fixture
        .clipboard
        .send_local(clipboard_lifecycle_consent(&fixture))
        .map_err(clipboard_error_js)?;
    Ok(waiter_promise(waiter))
}

fn clipboard_lifecycle_stage_remote() -> Result<Promise, JsValue> {
    let fixture = clipboard_lifecycle_fixture()?;
    let waiter = fixture
        .clipboard
        .receive_remote(clipboard_lifecycle_consent(&fixture))
        .map_err(clipboard_error_js)?;
    Ok(waiter_promise(waiter))
}

fn clipboard_lifecycle_start_write() -> Result<Promise, JsValue> {
    let fixture = clipboard_lifecycle_fixture()?;
    let waiter = fixture
        .clipboard
        .copy_remote(clipboard_lifecycle_consent(&fixture))
        .map_err(clipboard_error_js)?;
    Ok(waiter_promise(waiter))
}

fn clipboard_lifecycle_set_consent(allowed: bool) -> Result<(), JsValue> {
    let fixture = clipboard_lifecycle_fixture()?;
    if allowed {
        fixture.approval.approve();
    } else {
        fixture.approval.revoke();
    }
    Ok(())
}

fn clipboard_lifecycle_resolve_read() -> Result<(), JsValue> {
    clipboard_lifecycle_fixture()?.local_api.resolve_read()
}

fn clipboard_lifecycle_resolve_write() -> Result<(), JsValue> {
    clipboard_lifecycle_fixture()?.local_api.resolve_write()
}

fn clipboard_lifecycle_reject_read() -> Result<(), JsValue> {
    clipboard_lifecycle_fixture()?.local_api.reject_read()
}

fn clipboard_lifecycle_reject_write() -> Result<(), JsValue> {
    clipboard_lifecycle_fixture()?.local_api.reject_write()
}

fn clipboard_lifecycle_state() -> Result<JsValue, JsValue> {
    let fixture = clipboard_lifecycle_fixture()?;
    let state = Object::new();
    let pending = fixture.clipboard.has_unsettled_operation();
    Reflect::set(
        state.as_ref(),
        &"operation_pending".into(),
        &JsValue::from_bool(pending),
    )?;
    Reflect::set(
        state.as_ref(),
        &"replacement_blocked".into(),
        &JsValue::from_bool(pending),
    )?;
    Reflect::set(
        state.as_ref(),
        &"staged_clipboard".into(),
        &JsValue::from_bool(fixture.clipboard.has_pending()),
    )?;
    Reflect::set(
        state.as_ref(),
        &"read_calls".into(),
        &JsValue::from_f64(fixture.local_api.read_calls.get() as f64),
    )?;
    Reflect::set(
        state.as_ref(),
        &"write_calls".into(),
        &JsValue::from_f64(fixture.local_api.write_calls.get() as f64),
    )?;
    Reflect::set(
        state.as_ref(),
        &"api_timeout_ms".into(),
        &JsValue::from_f64(CLIPBOARD_LIFECYCLE_TIMEOUT_MS),
    )?;
    Ok(state.into())
}

fn clipboard_owner() -> Result<BrowserClipboard, JsValue> {
    CLIPBOARD_FIXTURE.with(|fixture| {
        fixture
            .borrow()
            .as_ref()
            .map(|fixture| fixture.clipboard.clone())
            .ok_or_else(|| js_error(BrowserRpcError::Data(BrowserDataError::Stopped)))
    })
}

fn stop_clipboard_fixture() {
    CLIPBOARD_LIFECYCLE_FIXTURE.with(|fixture| {
        fixture.borrow_mut().take();
    });
    let Some(fixture) = CLIPBOARD_FIXTURE.with(|fixture| fixture.borrow_mut().take()) else {
        return;
    };
    fixture.channels.close();
    fixture.rpc.close();
    for channel in fixture.remote_channels.borrow().iter() {
        channel.set_onmessage(None);
        channel.close();
    }
    let _ = Reflect::set(
        fixture.remote.as_ref(),
        &"ondatachannel".into(),
        &JsValue::NULL,
    );
    fixture.local.close();
    fixture.remote.close();
    drop(fixture);
}

fn always_consent() -> LocalDataConsent {
    Rc::new(|| true)
}

fn waiter_promise(waiter: ClipboardWaiter) -> Promise {
    future_to_promise(async move {
        match waiter.await {
            Ok(Ok(())) => Ok(JsValue::UNDEFINED),
            Ok(Err(error)) => Err(clipboard_error_js(error)),
            Err(_) => Err(clipboard_error_js(BrowserRpcError::Cancelled)),
        }
    })
}

fn clipboard_error_js(error: BrowserRpcError) -> JsValue {
    js_sys::Error::new(&error.to_string()).into()
}

fn clipboard_claims() -> PermitClaims {
    let id = |value: u32| format!("{value:08x}-1111-4111-8111-111111111111");
    PermitClaims {
        media_format_version: 0,
        media_formats: Vec::new(),
        media_format_sha256: Vec::new(),
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        session_id: id(2),
        account_id: id(3),
        controller_device_id: id(4),
        host_device_id: id(5),
        resource_id: id(6),
        controller_key_sha256: vec![7; 32],
        host_key_sha256: vec![8; 32],
        capability_sha256: vec![9; 32],
        permissions: vec![
            Permission::ClipboardRead as i32,
            Permission::ClipboardWrite as i32,
        ],
        paths: vec![Path::Direct as i32],
        policy_revision: 1,
        security_epoch: 1,
        connection_generation: 1,
        lease_sequence: 1,
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        ..Default::default()
    }
}

async fn negotiate(local: &RtcPeerConnection, remote: &RtcPeerConnection) -> Result<(), JsValue> {
    let offer = rtc_session_description_init(
        JsFuture::from(local.create_offer())
            .await
            .map_err(js_error)?,
        RtcSdpType::Offer,
    )?;
    JsFuture::from(local.set_local_description(&offer))
        .await
        .map_err(js_error)?;
    wait_for_ice(local).await?;
    let local_offer = local
        .local_description()
        .ok_or_else(|| js_error(BrowserRpcError::Storage))?;
    let remote_offer = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
    remote_offer.set_sdp(&local_offer.sdp());
    JsFuture::from(remote.set_remote_description(&remote_offer))
        .await
        .map_err(js_error)?;

    let answer = rtc_session_description_init(
        JsFuture::from(remote.create_answer())
            .await
            .map_err(js_error)?,
        RtcSdpType::Answer,
    )?;
    JsFuture::from(remote.set_local_description(&answer))
        .await
        .map_err(js_error)?;
    wait_for_ice(remote).await?;
    let local_answer = remote
        .local_description()
        .ok_or_else(|| js_error(BrowserRpcError::Storage))?;
    let remote_answer = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
    remote_answer.set_sdp(&local_answer.sdp());
    JsFuture::from(local.set_remote_description(&remote_answer))
        .await
        .map_err(js_error)?;
    Ok(())
}

async fn wait_for_ice(peer: &RtcPeerConnection) -> Result<(), JsValue> {
    for _ in 0..1_000 {
        if Reflect::get(peer.as_ref(), &"iceGatheringState".into())?
            .as_string()
            .as_deref()
            == Some("complete")
        {
            return Ok(());
        }
        gloo_timers::future::TimeoutFuture::new(5).await;
    }
    Err(js_error(BrowserRpcError::Storage))
}

async fn wait_for_data_channels(
    channels: &Rc<RefCell<Vec<RtcDataChannel>>>,
) -> Result<(), JsValue> {
    for _ in 0..2_000 {
        let ready = {
            let channels = channels.borrow();
            channels.len() == 2
                && channels
                    .iter()
                    .all(|channel| channel.ready_state() == RtcDataChannelState::Open)
        };
        if ready {
            return Ok(());
        }
        gloo_timers::future::TimeoutFuture::new(5).await;
    }
    Err(js_error(BrowserRpcError::Storage))
}

fn js_error(error: impl std::fmt::Debug) -> JsValue {
    js_sys::Error::new(&format!("{error:?}")).into()
}
