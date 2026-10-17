//! Native opaque byte relay. TLS and business channels terminate at endpoints.
use super::*;
use axum::body::Bytes;
use futures_util::{SinkExt, StreamExt};
use nestlink_auth::random_bytes;
use nestlink_protocol::{
    PermitClaims,
    api::{
        RelayAllocationRequest, RelayAllocationResponse, RelayChallenge, RelayHello, RelayReady,
        RelayReservationUsage,
    },
};
use std::{io, time::Duration};

const CHUNK: usize = 65536;
mod hub;
mod reservation;
pub(super) use hub::RelayHub;
use reservation::ReservedConnection;

pub(super) async fn allocate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<RelayAllocationRequest>,
) -> Result<Json<RelayAllocationResponse>, ApiError> {
    let token = access(&headers)?;
    let lifecycle = state.relay_lifecycle.clone();
    let claims = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            s.reserve_node_relay(&lifecycle, &actor, &id, request, now_ms()?)
        })
        .await?;
    let allocation = state
        .signer
        .sign_relay_allocation(&claims)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?;
    Ok(Json(RelayAllocationResponse {
        allocation: URL_SAFE_NO_PAD.encode(allocation.encode_to_vec()),
    }))
}
pub(super) async fn reservations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RelayReservationUsage>, ApiError> {
    let token = access(&headers)?;
    let lifecycle = state.relay_lifecycle.clone();
    state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            let now = now_ms()?;
            lifecycle.check_clock(now)?;
            Ok(Json(s.relay_reservation_usage(&actor, now)?))
        })
        .await
}
enum Output {
    Ready,
    Data(Bytes),
    Stopped,
}
fn failed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "relay closed or capacity exceeded",
    )
}
pub(super) async fn upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let (actor, permit) = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            let permit = s.current_permit(&actor, &resource, now()?)?;
            Ok((actor, permit))
        })
        .await?;
    if !permit
        .paths
        .contains(&(nestlink_protocol::Path::Relay as i32))
    {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::RelayDisabled));
    }
    state.limit(&format!("relay/{}", actor.account_id))?;
    Ok(ws
        .max_message_size(CHUNK)
        .max_frame_size(CHUNK)
        .write_buffer_size(0)
        .max_write_buffer_size(CHUNK * 2)
        .on_upgrade(move |socket| async move {
            let _ = serve(socket, state, actor, id, permit).await;
        })
        .into_response())
}
async fn serve(
    mut socket: WebSocket,
    state: AppState,
    actor: Principal,
    id: String,
    initial: PermitClaims,
) -> io::Result<()> {
    let nonce = random_bytes::<32>();
    let challenge = RelayChallenge {
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        lease_sequence: initial.lease_sequence,
    };
    tokio::time::timeout(
        Duration::from_secs(1),
        socket.send(Message::Text(
            serde_json::to_string(&challenge)
                .map_err(io::Error::other)?
                .into(),
        )),
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
    if hello.len() > 4096 {
        return Err(failed());
    }
    let hello: RelayHello = serde_json::from_str(&hello).map_err(io::Error::other)?;
    let device = hello.device_id.clone();
    let account = actor.clone();
    let resource = id.clone();
    let lifecycle = state.relay_lifecycle.clone();
    let cleanup_store = state.store.clone();
    let cleanup_runtime = tokio::runtime::Handle::current();
    let permit = tokio::time::timeout(
        Duration::from_millis(700),
        state.db(move |s| {
            let (permit, reservation, quota) = s.reserve_combined_relay(
                &lifecycle,
                &account,
                &resource,
                (&hello, &nonce),
                now_ms()?,
            )?;
            // Own cleanup before crossing a cancellable DB response boundary.
            let guard = ReservedConnection::new(cleanup_store, cleanup_runtime, reservation);
            Ok((permit, guard, quota))
        }),
    )
    .await
    .map_err(io::Error::other)?
    .map_err(|_| failed())?;
    let (permit, reserved, quota) = permit;
    if initial != permit {
        return Err(failed());
    }
    let (registration, mut outgoing) = state.relays.register(
        &id,
        &actor.account_id,
        device == permit.controller_device_id,
        quota,
    )?;
    let connection_id = registration.id.clone();
    if registration.quota_revision != reserved.reservation().quota_revision {
        return Err(failed());
    }
    let (mut sink, mut source) = socket.split();
    let writer = async {
        let ready = tokio::time::timeout(Duration::from_secs(5), outgoing.recv())
            .await
            .map_err(io::Error::other)?
            .ok_or_else(failed)?;
        if !matches!(ready, Output::Ready) {
            return Err(failed());
        }
        let ready = serde_json::to_string(&RelayReady { ready: true }).map_err(io::Error::other)?;
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
                Message::Binary(data) => {
                    let peer = state.relays.destination(&id, &connection_id, data.len())?;
                    tokio::time::timeout(Duration::from_millis(500), peer.send(Output::Data(data)))
                        .await
                        .map_err(io::Error::other)?
                        .map_err(|_| failed())?;
                }
                Message::Close(_) => break,
                _ => return Err(failed()),
            }
        }
        Ok::<(), io::Error>(())
    };
    let authorization = check_authorization(&state, &actor, permit, &reserved);
    let mut stopped = registration.stopped.clone();
    let revoked = async {
        if !*stopped.borrow() {
            let _ = stopped.changed().await;
        }
        Err::<(), io::Error>(failed())
    };
    let result = tokio::select! {biased;result=revoked=>result,result=authorization=>result,result=writer=>result,result=reader=>result};
    drop(registration);
    result
}
async fn check_authorization(
    state: &AppState,
    actor: &Principal,
    mut permit: PermitClaims,
    reserved: &ReservedConnection,
) -> io::Result<()> {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut deadline = Instant::now()
        + Duration::from_millis(
            permit
                .expires_at_unix_ms
                .saturating_sub(now_ms().map_err(|_| failed())?),
        );
    loop {
        tokio::select! {_=tick.tick()=>{},_=tokio::time::sleep_until(deadline.into())=>return Err(failed())}
        let account = actor.clone();
        let reservation = reserved.reservation().clone();
        let lifecycle = state.relay_lifecycle.clone();
        let check = state
            .db(move |s| s.renew_combined_relay(&lifecycle, &account, &reservation, now_ms()?));
        let current = tokio::select! {
            result=tokio::time::timeout(Duration::from_millis(700),check)=>result.map_err(io::Error::other)?.map_err(|_|failed())?,
            _=tokio::time::sleep_until(deadline.into())=>return Err(failed()),
        };
        let (current, quota) = current;
        state.relays.synchronize(quota)?;
        if quota.revision != reserved.reservation().quota_revision {
            return Err(failed());
        }
        if current.connection_generation != permit.connection_generation
            || current.controller_key_sha256 != permit.controller_key_sha256
            || current.host_key_sha256 != permit.host_key_sha256
            || !current
                .paths
                .contains(&(nestlink_protocol::Path::Relay as i32))
            || current.lease_sequence < permit.lease_sequence
        {
            return Err(failed());
        }
        // Rechecking an unchanged permit never extends its monotonic deadline.
        if current.lease_sequence > permit.lease_sequence {
            deadline = Instant::now()
                + Duration::from_millis(
                    current
                        .expires_at_unix_ms
                        .saturating_sub(now_ms().map_err(|_| failed())?),
                );
            permit = current;
        }
    }
}
