//! Independent opaque WSS relay; the control center's SQLite is never opened here.
use crate::relay_selector::RelaySelector;
use axum::{
    Router,
    body::Bytes,
    extract::{
        ConnectInfo, Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use nestlink_auth::{random_bytes, random_id};
use nestlink_node::control::{
    Error as NodeError, NodeControl, RelayEndpointProof, RelayResourceReservation,
};
use nestlink_protocol::{
    ContractError, ErrorCode, NODE_MESSAGE_BYTES, NodeRole, RelayAllocationClaims, RelayTransport,
    SignedRelayAllocation,
    api::{NodeRelayChallenge, NodeRelayHello, RelayReady},
    decode_bounded, valid_id,
};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, mpsc, watch};

const CHUNK: usize = 65536;
const HELLO: usize = 16384;
enum Output {
    Ready,
    Data(Bytes),
    Stop,
}
struct Slot {
    token: String,
    sender: mpsc::Sender<Output>,
}
type Pair = [Option<Slot>; 2];
#[derive(Default)]
struct Hub {
    pairs: Mutex<HashMap<String, Pair>>,
}
struct Registration {
    hub: Arc<Hub>,
    allocation: String,
    token: String,
}
type SocketParts = (
    futures_util::stream::SplitSink<WebSocket, Message>,
    futures_util::stream::SplitStream<WebSocket>,
);
/// Async cancellation drops the owned carrier and queues before closing the
/// resource guard. A bare resource Drop is insufficient for a release receipt.
struct RelayIo {
    socket: Option<SocketParts>,
    outgoing: Option<mpsc::Receiver<Output>>,
    registration: Option<Registration>,
    guard: RelayResourceReservation,
}
impl Drop for RelayIo {
    fn drop(&mut self) {
        self.registration.take();
        self.outgoing.take();
        self.socket.take();
        self.guard.confirm_io_stopped();
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut pairs) = self.hub.pairs.lock()
            && pairs
                .get(&self.allocation)
                .is_some_and(|p| p.iter().flatten().any(|s| s.token == self.token))
            && let Some(pair) = pairs.remove(&self.allocation)
        {
            for slot in pair.into_iter().flatten() {
                let _ = slot.sender.try_send(Output::Stop);
            }
        }
    }
}
fn failed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "node relay stopped or admission refused",
    )
}
fn queue_error() -> ContractError {
    ContractError::new(ErrorCode::CapacityExceeded, "node relay queue full")
}
async fn forward(
    guard: &RelayResourceReservation,
    peer: mpsc::Sender<Output>,
    bytes: Bytes,
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            let result = guard.admit(bytes.len() as u64, || {
                peer.try_send(Output::Data(bytes.clone()))
                    .map_err(|e| match e {
                        mpsc::error::TrySendError::Full(_) => queue_error(),
                        mpsc::error::TrySendError::Closed(_) => {
                            ContractError::new(ErrorCode::LeaseExpired, "node relay queue closed")
                        }
                    })
            });
            match result {
                Ok(()) => return Ok(()),
                Err(NodeError::Authorization(e)) if e.reason == "node relay queue full" => {
                    // Wait outside the control lock. Dropping this capacity-only
                    // permit changes no accounting; the next attempt rechecks authority.
                    drop(peer.reserve().await.map_err(|_| failed())?);
                }
                Err(_) => return Err(failed()),
            }
        }
    })
    .await
    .map_err(io::Error::other)?
}
impl Hub {
    fn register(
        self: &Arc<Self>,
        allocation: &str,
        controller: bool,
    ) -> io::Result<(Registration, mpsc::Receiver<Output>)> {
        let mut pairs = self.pairs.lock().map_err(|_| failed())?;
        if pairs.len() >= 128 && !pairs.contains_key(allocation) {
            return Err(failed());
        }
        let pair = pairs
            .entry(allocation.into())
            .or_insert_with(|| [None, None]);
        let role = usize::from(!controller);
        if pair[role].is_some() {
            return Err(failed());
        }
        let token = random_id();
        let (sender, receiver) = mpsc::channel(8);
        pair[role] = Some(Slot {
            token: token.clone(),
            sender,
        });
        if pair.iter().all(Option::is_some) {
            for slot in pair.iter().flatten() {
                if slot.sender.try_send(Output::Ready).is_err() {
                    if let Some(pair) = pairs.remove(allocation) {
                        for slot in pair.into_iter().flatten() {
                            let _ = slot.sender.try_send(Output::Stop);
                        }
                    }
                    return Err(failed());
                }
            }
        }
        Ok((
            Registration {
                hub: self.clone(),
                allocation: allocation.into(),
                token,
            },
            receiver,
        ))
    }
    fn destination(&self, registration: &Registration) -> io::Result<mpsc::Sender<Output>> {
        let pairs = self.pairs.lock().map_err(|_| failed())?;
        let pair = pairs.get(&registration.allocation).ok_or_else(failed)?;
        let role = pair
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.token == registration.token))
            .ok_or_else(failed)?;
        Ok(pair[1 - role].as_ref().ok_or_else(failed)?.sender.clone())
    }
}
struct Inner {
    control: Arc<NodeControl>,
    hub: Arc<Hub>,
    selector: Arc<RelaySelector>,
}
/// The caller owns node control and must stop it when this data listener ends.
/// `serve` provides that ownership, including future cancellation.
pub fn router(control: Arc<NodeControl>) -> Router {
    router_with_selector(RelaySelector::new(control))
}
pub fn router_with_selector(selector: Arc<RelaySelector>) -> Router {
    Router::new()
        .route("/api/v3/nodes/{id}/relay/{allocation}", get(upgrade))
        .with_state(Arc::new(Inner {
            control: selector.control(),
            hub: Arc::new(Hub::default()),
            selector,
        }))
}
struct StopOwner(Arc<NodeControl>);
impl Drop for StopOwner {
    fn drop(&mut self) {
        self.0.stop();
    }
}
/// Runs behind the configured node HTTPS/WSS entry point (normally Caddy).
/// Listener stop, loss of node authority and cancellation stop every data socket.
pub async fn serve(
    listener: tokio::net::TcpListener,
    control: Arc<NodeControl>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    serve_with_selector(listener, RelaySelector::new(control), shutdown).await
}
pub async fn serve_with_selector(
    listener: tokio::net::TcpListener,
    selector: Arc<RelaySelector>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let control = selector.control();
    let _owner = StopOwner(control.clone());
    let mut stopped = control.stopped();
    let failed_authority = Arc::new(AtomicBool::new(false));
    let reason = failed_authority.clone();
    axum::serve(
        listener,
        router_with_selector(selector).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
            tokio::select! {biased;_=shutdown=>{},_=wait_node_stopped(&mut stopped)=>{reason.store(true,Ordering::Release);}}
        control.stop();
    })
        .await?;
    if failed_authority.load(Ordering::Acquire) {
        Err(failed())
    } else {
        Ok(())
    }
}
async fn wait_node_stopped(stopped: &mut watch::Receiver<bool>) {
    if !*stopped.borrow() {
        let _ = stopped.changed().await;
    }
}
async fn upgrade(
    State(state): State<Arc<Inner>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((node, allocation)): Path<(String, String)>,
    ws: WebSocketUpgrade,
) -> Result<Response, super::ApiError> {
    let reject = |status, code| super::ApiError(status, code);
    if !valid_id(&node) || !valid_id(&allocation) {
        return Err(reject(StatusCode::BAD_REQUEST, ErrorCode::InvalidMessage));
    }
    let lease = state
        .control
        .authorize(NodeRole::NodeRelay, false)
        .map_err(|_| reject(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::LeaseExpired))?;
    if lease.node_id != node {
        return Err(reject(StatusCode::FORBIDDEN, ErrorCode::IdentityMismatch));
    }
    let capacity = state
        .selector
        .socket(peer.ip())
        .map_err(|_| reject(StatusCode::TOO_MANY_REQUESTS, ErrorCode::CapacityExceeded))?;
    Ok(ws.max_message_size(CHUNK).max_frame_size(CHUNK).write_buffer_size(0).max_write_buffer_size(CHUNK*2)
        .on_upgrade(move|socket|async move { let mut stopped=state.control.stopped();
            tokio::select! {biased;_=wait_node_stopped(&mut stopped)=>{},_=connection(socket,state,node,allocation,capacity)=>{}}
        }).into_response())
}
async fn connection(
    mut socket: WebSocket,
    state: Arc<Inner>,
    node: String,
    allocation: String,
    _capacity: OwnedSemaphorePermit,
) -> io::Result<()> {
    let challenge = random_bytes::<32>();
    let opening = NodeRelayChallenge {
        nonce: URL_SAFE_NO_PAD.encode(challenge),
    };
    let message = serde_json::to_string(&opening).map_err(io::Error::other)?;
    tokio::time::timeout(
        Duration::from_millis(500),
        socket.send(Message::Text(message.into())),
    )
    .await
    .map_err(io::Error::other)?
    .map_err(io::Error::other)?;
    let hello = tokio::time::timeout(Duration::from_secs(3), socket.recv())
        .await
        .map_err(io::Error::other)?
        .ok_or_else(failed)?
        .map_err(io::Error::other)?;
    let Message::Text(hello) = hello else {
        return Err(failed());
    };
    if hello.len() > HELLO {
        return Err(failed());
    }
    let hello: NodeRelayHello = serde_json::from_str(&hello).map_err(io::Error::other)?;
    let ticket = URL_SAFE_NO_PAD
        .decode(hello.allocation)
        .map_err(|_| failed())?;
    let signed: SignedRelayAllocation =
        decode_bounded(&ticket, NODE_MESSAGE_BYTES + 128).map_err(|_| failed())?;
    let unverified: RelayAllocationClaims =
        decode_bounded(&signed.claims, NODE_MESSAGE_BYTES).map_err(|_| failed())?;
    unverified.validate().map_err(|_| failed())?;
    if unverified.allocation_id != allocation || unverified.node_id != node {
        return Err(failed());
    }
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(hello.public_key)
        .map_err(|_| failed())?
        .try_into()
        .map_err(|_| failed())?;
    let signature = URL_SAFE_NO_PAD
        .decode(hello.signature)
        .map_err(|_| failed())?;
    // A just-issued allocation can precede the next authenticated snapshot.
    // Waiting is bounded and conveys no authority until full admission succeeds.
    tokio::time::timeout(Duration::from_millis(700), async {
        loop {
            if state
                .control
                .resource_snapshot()
                .is_ok_and(|s| s.allocations.iter().any(|c| c.allocation_id == allocation))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(io::Error::other)?;
    let candidate = state
        .control
        .prepare_relay_endpoint(
            &ticket,
            RelayEndpointProof {
                device_id: &hello.device_id,
                public_key: &key,
                transport: RelayTransport::WssStream,
                signature: &signature,
            },
            &challenge,
        )
        .map_err(|_| failed())?;
    let selection = state.selector.register(candidate)?;
    let guard = tokio::select! { biased;
        _ = socket.recv() => return Err(failed()),
        result = selection.wait() => result?,
    };
    let mut io = RelayIo {
        socket: Some(socket.split()),
        outgoing: None,
        registration: None,
        guard,
    };
    io.guard.check_live().map_err(|_| failed())?;
    let (registration, outgoing) = state
        .hub
        .register(io.guard.allocation_id(), io.guard.is_controller())?;
    io.registration = Some(registration);
    io.outgoing = Some(outgoing);
    let guard = &io.guard;
    let registration = io.registration.as_ref().ok_or_else(failed)?;
    let outgoing = io.outgoing.as_mut().ok_or_else(failed)?;
    let (sink, source) = io.socket.as_mut().ok_or_else(failed)?;
    let writer = async {
        let ready = tokio::time::timeout(Duration::from_secs(5), outgoing.recv())
            .await
            .map_err(io::Error::other)?
            .ok_or_else(failed)?;
        if !matches!(ready, Output::Ready) {
            return Err(failed());
        }
        let ready = serde_json::to_string(&RelayReady { ready: true }).map_err(io::Error::other)?;
        guard.check_live().map_err(|_| failed())?;
        tokio::time::timeout(
            Duration::from_millis(500),
            sink.send(Message::Text(ready.into())),
        )
        .await
        .map_err(io::Error::other)?
        .map_err(io::Error::other)?;
        while let Some(message) = outgoing.recv().await {
            let Output::Data(data) = message else {
                return Err(failed());
            };
            guard.check_live().map_err(|_| failed())?;
            tokio::time::timeout(Duration::from_millis(500), sink.send(Message::Binary(data)))
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)?;
        }
        Ok::<(), io::Error>(())
    };
    let reader = async {
        while let Some(message) = source.next().await {
            match message.map_err(io::Error::other)? {
                Message::Binary(bytes) if !bytes.is_empty() && bytes.len() <= CHUNK => {
                    let peer = state.hub.destination(registration)?;
                    forward(guard, peer, bytes).await?;
                }
                Message::Close(_) => break,
                _ => return Err(failed()),
            }
        }
        Ok::<(), io::Error>(())
    };
    tokio::select! {biased;_=guard.wait_stopped()=>Err(failed()),result=writer=>result,result=reader=>result}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn a_full_destination_queue_and_stale_registration_cannot_replace_or_close_a_pair()
    -> io::Result<()> {
        let hub = Arc::new(Hub::default());
        let allocation = random_id();
        let (a, mut rx_a) = hub.register(&allocation, true)?;
        assert!(hub.register(&allocation, true).is_err());
        let (b, mut rx_b) = hub.register(&allocation, false)?;
        assert!(matches!(rx_a.recv().await, Some(Output::Ready)));
        assert!(matches!(rx_b.recv().await, Some(Output::Ready)));
        let peer = hub.destination(&a)?;
        for _ in 0..8 {
            peer.try_send(Output::Data(Bytes::from_static(b"test")))
                .map_err(io::Error::other)?;
        }
        assert!(
            peer.try_send(Output::Data(Bytes::from_static(b"full")))
                .is_err()
        );
        let stale = Registration {
            hub: hub.clone(),
            allocation: allocation.clone(),
            token: random_id(),
        };
        drop(stale);
        assert!(hub.destination(&a).is_ok());
        drop(a);
        assert!(hub.destination(&b).is_err());
        Ok(())
    }
}
