//! Independently bounded, ordered business DataChannels on one proved peer.
//! An abandoned UI wait never abandons a half-consumed RPC or replays its write.
use futures_channel::oneshot;
use gloo_timers::future::TimeoutFuture;
use nestlink_protocol::PermitClaims;
use nestlink_protocol::webrtc_data::{
    MAX_WEBRTC_DATA_FRAGMENT_BYTES, WebRtcDataBinding, WebRtcDataChannel, WebRtcDataFragmenter,
    WebRtcDataReassembler,
};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{
    Event, MessageEvent, RtcDataChannel, RtcDataChannelInit, RtcDataChannelState,
    RtcDataChannelType, RtcPeerConnection,
};
use zeroize::Zeroizing;

const FRAGMENT_BYTES: u32 = MAX_WEBRTC_DATA_FRAGMENT_BYTES as u32;
const SEND_QUEUE_BYTES: u32 = FRAGMENT_BYTES * 4;
const RPC_MS: f64 = 30_000.0;
const ASSEMBLY_MS: f64 = 5_000.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserDataError {
    Stopped,
    Denied,
    Busy,
    Expired,
    Protocol,
    Transport,
}

pub type DataAuthority = Rc<dyn Fn(WebRtcDataChannel) -> Result<(), BrowserDataError>>;
pub type LocalDataConsent = Rc<dyn Fn() -> bool>;

struct ApprovalToken {
    _seal: u8,
}

/// A local operation's consent captures the currently issued ticket. Revoking
/// the approval removes that ticket permanently; a later grant creates a new
/// allocation, so stale consent cannot become true again due to counter wrap or
/// pointer reuse while an old operation still owns its captured ticket.
#[derive(Clone, Default)]
pub struct LocalDataApproval(Rc<RefCell<Option<Rc<ApprovalToken>>>>);

impl LocalDataApproval {
    pub fn approve(&self) {
        let mut current = self.0.borrow_mut();
        if current.is_none() {
            *current = Some(Rc::new(ApprovalToken { _seal: 0 }));
        }
    }

    pub fn revoke(&self) {
        self.0.borrow_mut().take();
    }

    /// Return an immutable snapshot of the current approval. If no approval is
    /// active, the returned consent remains denied after future approvals.
    pub fn consent(&self) -> LocalDataConsent {
        let ticket = self.0.borrow().clone();
        let Some(ticket) = ticket else {
            return Rc::new(|| false);
        };
        let current = self.0.clone();
        Rc::new(move || {
            current
                .borrow()
                .as_ref()
                .is_some_and(|active| Rc::ptr_eq(active, &ticket))
        })
    }
}

struct Stream {
    kind: WebRtcDataChannel,
    channel: RtcDataChannel,
    fragmenter: RefCell<WebRtcDataFragmenter>,
    reassembler: RefCell<WebRtcDataReassembler>,
    replies: RefCell<VecDeque<Zeroizing<Vec<u8>>>>,
    assembling_since: Cell<Option<f64>>,
    busy: Cell<bool>,
}
struct Handlers {
    _message: Closure<dyn FnMut(MessageEvent)>,
    _close: Closure<dyn FnMut(Event)>,
    _error: Closure<dyn FnMut(Event)>,
}
struct Owner {
    peer: RtcPeerConnection,
    streams: Vec<Rc<Stream>>,
    _handlers: Vec<Handlers>,
    authority: DataAuthority,
    stop_peer: Rc<dyn Fn()>,
    stopped: Rc<Cell<bool>>,
}
impl Owner {
    fn stop(&self) {
        if !self.stopped.replace(true) {
            (self.stop_peer)();
        }
        for stream in &self.streams {
            stream.replies.borrow_mut().clear();
            stream.channel.set_onmessage(None);
            stream.channel.set_onclose(None);
            stream.channel.set_onerror(None);
            stream.channel.close();
        }
    }
    fn check(&self, stream: &Stream) -> Result<(), BrowserDataError> {
        if self.stopped.get() {
            return Err(BrowserDataError::Stopped);
        }
        (self.authority)(stream.kind)?;
        if stream
            .assembling_since
            .get()
            .is_some_and(|start| now().is_ok_and(|at| at - start >= ASSEMBLY_MS))
        {
            self.stop();
            return Err(BrowserDataError::Expired);
        }
        Ok(())
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone)]
pub struct BrowserDataChannels(Rc<Owner>);
impl BrowserDataChannels {
    /// Create SCTP streams before the offer. The authority closure rejects all
    /// payloads until mutual proof and a verified live path have completed.
    pub fn new(
        peer: &RtcPeerConnection,
        claims: &PermitClaims,
        proved_digest: [u8; 32],
        authority: DataAuthority,
        stop_peer: Rc<dyn Fn()>,
    ) -> Result<Self, BrowserDataError> {
        let stopped = Rc::new(Cell::new(false));
        let mut streams = Vec::new();
        let mut handlers = Vec::new();
        // Validate every binding before allocating a browser channel. A later
        // invalid binding must not leak already-created channels or callbacks.
        let mut bindings = Vec::new();
        for kind in [
            WebRtcDataChannel::FileRead,
            WebRtcDataChannel::FileWrite,
            WebRtcDataChannel::ClipboardRead,
            WebRtcDataChannel::ClipboardWrite,
        ] {
            if claims.permissions.contains(&(kind.permission() as i32)) {
                bindings.push(
                    WebRtcDataBinding::for_permit(claims, proved_digest, kind)
                        .map_err(|_| BrowserDataError::Protocol)?,
                );
            }
        }
        for binding in bindings {
            let kind = binding.channel();
            let options = RtcDataChannelInit::new();
            options.set_ordered(true);
            let channel = peer.create_data_channel_with_data_channel_dict(kind.label(), &options);
            channel.set_binary_type(RtcDataChannelType::Arraybuffer);
            let stream = Rc::new(Stream {
                kind,
                channel: channel.clone(),
                fragmenter: RefCell::new(WebRtcDataFragmenter::new(binding.clone())),
                reassembler: RefCell::new(WebRtcDataReassembler::new(binding)),
                replies: RefCell::new(VecDeque::new()),
                assembling_since: Cell::new(None),
                busy: Cell::new(false),
            });
            let incoming = stream.clone();
            let authorized = authority.clone();
            let failed = stopped.clone();
            let stop = stop_peer.clone();
            let message = Closure::wrap(Box::new(move |event: MessageEvent| {
                let result = (|| {
                    if failed.get() || authorized(incoming.kind).is_err() {
                        return Err(BrowserDataError::Stopped);
                    }
                    if !incoming.busy.get() || !incoming.replies.borrow().is_empty() {
                        return Err(BrowserDataError::Protocol);
                    }
                    let at = now()?;
                    if incoming
                        .assembling_since
                        .get()
                        .is_some_and(|start| at - start >= ASSEMBLY_MS)
                    {
                        return Err(BrowserDataError::Expired);
                    }
                    let buffer = event
                        .data()
                        .dyn_into::<js_sys::ArrayBuffer>()
                        .map_err(|_| BrowserDataError::Protocol)?;
                    if buffer.byte_length() == 0 || buffer.byte_length() > FRAGMENT_BYTES {
                        return Err(BrowserDataError::Protocol);
                    }
                    let browser_wire = js_sys::Uint8Array::new(&buffer);
                    let wire = Zeroizing::new(browser_wire.to_vec());
                    browser_wire.fill(0, 0, browser_wire.length());
                    incoming
                        .assembling_since
                        .set(incoming.assembling_since.get().or(Some(at)));
                    let assembled = incoming
                        .reassembler
                        .borrow_mut()
                        .push(&wire)
                        .map_err(|_| BrowserDataError::Protocol)?;
                    if let Some(assembled) = assembled {
                        incoming.assembling_since.set(None);
                        let mut queue = incoming.replies.borrow_mut();
                        if !queue.is_empty() {
                            return Err(BrowserDataError::Protocol);
                        }
                        queue.push_back(Zeroizing::new(assembled.payload));
                    }
                    Ok(())
                })();
                if result.is_err() && !failed.replace(true) {
                    stop();
                }
            }) as Box<dyn FnMut(MessageEvent)>);
            let failed = stopped.clone();
            let stop = stop_peer.clone();
            let close = Closure::wrap(Box::new(move |_: Event| {
                if !failed.replace(true) {
                    stop();
                }
            }) as Box<dyn FnMut(Event)>);
            let failed = stopped.clone();
            let stop = stop_peer.clone();
            let error = Closure::wrap(Box::new(move |_: Event| {
                if !failed.replace(true) {
                    stop();
                }
            }) as Box<dyn FnMut(Event)>);
            channel.set_onmessage(Some(message.as_ref().unchecked_ref()));
            channel.set_onclose(Some(close.as_ref().unchecked_ref()));
            channel.set_onerror(Some(error.as_ref().unchecked_ref()));
            streams.push(stream);
            handlers.push(Handlers {
                _message: message,
                _close: close,
                _error: error,
            });
        }
        Ok(Self(Rc::new(Owner {
            peer: peer.clone(),
            streams,
            _handlers: handlers,
            authority,
            stop_peer,
            stopped,
        })))
    }
    pub fn has(&self, kind: WebRtcDataChannel) -> bool {
        self.0.streams.iter().any(|stream| stream.kind == kind)
    }
    pub fn check(&self, kind: WebRtcDataChannel) -> Result<(), BrowserDataError> {
        let stream = self
            .0
            .streams
            .iter()
            .find(|stream| stream.kind == kind)
            .ok_or(BrowserDataError::Denied)?;
        self.0.check(stream)
    }
    pub fn check_deadlines(&self) -> Result<(), BrowserDataError> {
        if self.0.stopped.get() {
            return Err(BrowserDataError::Stopped);
        }
        let at = now()?;
        if self.0.streams.iter().any(|stream| {
            stream
                .assembling_since
                .get()
                .is_some_and(|start| at - start >= ASSEMBLY_MS)
        }) {
            self.0.stop();
            return Err(BrowserDataError::Expired);
        }
        Ok(())
    }
    pub fn close(&self) {
        self.0.stop();
    }

    /// The owned actor consumes the exact response even if the awaiting page
    /// disappears. The caller validates/advances its native RPC sequence before
    /// rechecking local delivery consent; no clipboard text enters UI state.
    pub async fn exchange(
        &self,
        kind: WebRtcDataChannel,
        envelope: Zeroizing<Vec<u8>>,
        consent: LocalDataConsent,
    ) -> Result<Zeroizing<Vec<u8>>, BrowserDataError> {
        let stream = self
            .0
            .streams
            .iter()
            .find(|stream| stream.kind == kind)
            .cloned()
            .ok_or(BrowserDataError::Denied)?;
        self.0.check(&stream)?;
        if !consent() {
            return Err(BrowserDataError::Denied);
        }
        if stream.busy.replace(true) {
            return Err(BrowserDataError::Busy);
        }
        let owner = self.clone();
        let guard = BusyGuard(stream.clone());
        let deadline = now()? + RPC_MS;
        let (reply, waiting) = oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let result = owner
                .exchange_owned(&stream, envelope, consent, deadline)
                .await;
            if result
                .as_ref()
                .is_err_and(|error| *error != BrowserDataError::Denied)
            {
                owner.close();
            }
            drop(guard);
            let _ = reply.send(result);
        });
        waiting.await.map_err(|_| BrowserDataError::Stopped)?
    }
    async fn exchange_owned(
        &self,
        stream: &Stream,
        envelope: Zeroizing<Vec<u8>>,
        consent: LocalDataConsent,
        deadline: f64,
    ) -> Result<Zeroizing<Vec<u8>>, BrowserDataError> {
        // Wait for the negotiated SCTP association before reading its limit.
        // No sequence is consumed until local consent and transport are ready.
        loop {
            self.0.check(stream)?;
            if !consent() {
                return Err(BrowserDataError::Denied);
            }
            if now()? >= deadline {
                return Err(BrowserDataError::Expired);
            }
            match stream.channel.ready_state() {
                RtcDataChannelState::Open
                    if stream.channel.buffered_amount() <= SEND_QUEUE_BYTES =>
                {
                    break;
                }
                RtcDataChannelState::Open | RtcDataChannelState::Connecting => {
                    TimeoutFuture::new(5).await
                }
                _ => return Err(BrowserDataError::Stopped),
            }
        }
        let sctp = js_sys::Reflect::get(self.0.peer.as_ref(), &"sctp".into())
            .map_err(|_| BrowserDataError::Transport)?;
        let maximum = js_sys::Reflect::get(&sctp, &"maxMessageSize".into())
            .map_err(|_| BrowserDataError::Transport)?
            .as_f64()
            .ok_or(BrowserDataError::Transport)?;
        if !maximum.is_finite()
            || maximum < 0.0
            || (maximum != 0.0 && maximum < f64::from(FRAGMENT_BYTES))
        {
            return Err(BrowserDataError::Protocol);
        }
        let (_, fragments) = stream
            .fragmenter
            .borrow_mut()
            .fragment(&envelope)
            .map_err(|_| BrowserDataError::Protocol)?;
        let fragments: Vec<_> = fragments.into_iter().map(Zeroizing::new).collect();
        for fragment in fragments {
            loop {
                self.0.check(stream)?;
                if !consent() {
                    // The outer sequence has been consumed; a partial send
                    // cannot be retried or followed by a new RPC on this peer.
                    self.close();
                    return Err(BrowserDataError::Denied);
                }
                if now()? >= deadline {
                    return Err(BrowserDataError::Expired);
                }
                match stream.channel.ready_state() {
                    RtcDataChannelState::Open => {}
                    RtcDataChannelState::Connecting => {
                        TimeoutFuture::new(5).await;
                        continue;
                    }
                    _ => return Err(BrowserDataError::Stopped),
                }
                if stream.channel.buffered_amount() > SEND_QUEUE_BYTES {
                    TimeoutFuture::new(5).await;
                    continue;
                }
                stream
                    .channel
                    .send_with_u8_array(&fragment)
                    .map_err(|_| BrowserDataError::Transport)?;
                break;
            }
        }
        loop {
            self.0.check(stream)?;
            if now()? >= deadline {
                return Err(BrowserDataError::Expired);
            }
            if let Some(reply) = stream.replies.borrow_mut().pop_front() {
                return Ok(reply);
            }
            TimeoutFuture::new(5).await;
        }
    }
}
struct BusyGuard(Rc<Stream>);
impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.busy.set(false);
    }
}
fn now() -> Result<f64, BrowserDataError> {
    web_sys::window()
        .and_then(|window| window.performance())
        .map(|clock| clock.now())
        .filter(|value| value.is_finite())
        .ok_or(BrowserDataError::Transport)
}
