//! Authenticated, bounded node WSS control. This is not a business-data relay.
use super::*;
use nestlink_protocol::{
    NodeChallenge, NodeLeaseClaims, NodeProof, SignedNodeUsage, SignedNodeUsageAck,
    api::{NodeRegistration, NodeUsagePage, NodeUsageQuery, NodesResponse},
    decode_bounded,
    nodes::{NODE_CHALLENGE_MS, NODE_MESSAGE_BYTES},
};
use std::time::Duration;

pub(super) async fn resources(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(signed): Json<nestlink_protocol::SignedNodeResourceQuery>,
) -> Result<Json<nestlink_protocol::SignedNodeResourceSnapshot>, ApiError> {
    let query: nestlink_protocol::NodeResourceQueryClaims =
        decode_bounded(&signed.claims, NODE_MESSAGE_BYTES)
            .map_err(|_| ApiError(StatusCode::BAD_REQUEST, ErrorCode::InvalidMessage))?;
    if query.node_id != id {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::IdentityMismatch));
    }
    let lifecycle = state.relay_lifecycle.clone();
    let signer = state.signer.clone();
    let c = tokio::time::timeout(
        Duration::from_millis(700),
        state.db(move |s| {
            s.node_resource_snapshot_with_network(&lifecycle, &signed, &signer, now_ms()?)
        }),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::InternalError))??;
    Ok(Json(state.node_signer.sign_resource_snapshot(&c).map_err(
        |_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError),
    )?))
}

pub(super) async fn report(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(signed): Json<SignedNodeUsage>,
) -> Result<Json<SignedNodeUsageAck>, ApiError> {
    let claims: nestlink_protocol::NodeUsageClaims =
        decode_bounded(&signed.claims, NODE_MESSAGE_BYTES)
            .map_err(|_| ApiError(StatusCode::BAD_REQUEST, ErrorCode::InvalidMessage))?;
    if claims.node_id != id {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::IdentityMismatch));
    }
    let ack = tokio::time::timeout(
        Duration::from_millis(700),
        state.db(move |s| s.accept_node_usage(&signed, now_ms()?)),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::InternalError))??;
    Ok(Json(state.node_signer.sign_usage_ack(&ack).map_err(
        |_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError),
    )?))
}
pub(super) async fn usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<NodeUsageQuery>,
) -> Result<Json<NodeUsagePage>, ApiError> {
    let token = access(&headers)?;
    Ok(Json(
        state
            .db(move |s| {
                let p = s.authenticate(&token, now()?)?;
                s.node_usage(&p, &id, query, now_ms()?)
            })
            .await?,
    ))
}

pub(super) async fn close(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(signed): Json<nestlink_protocol::SignedRelayClose>,
) -> Result<Json<nestlink_protocol::SignedRelayCloseAck>, ApiError> {
    let claims: nestlink_protocol::RelayCloseClaims =
        decode_bounded(&signed.claims, nestlink_protocol::RELAY_CLOSE_MESSAGE_BYTES)
            .map_err(|_| ApiError(StatusCode::BAD_REQUEST, ErrorCode::InvalidMessage))?;
    if claims.node_id != id {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::IdentityMismatch));
    }
    let lifecycle = state.relay_lifecycle.clone();
    let ack = tokio::time::timeout(
        Duration::from_millis(700),
        state.db(move |s| s.accept_relay_close(&lifecycle, &signed, now_ms()?)),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::InternalError))??;
    Ok(Json(state.node_signer.sign_relay_close_ack(&ack).map_err(
        |_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError),
    )?))
}

pub(super) async fn nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NodesResponse>, ApiError> {
    let token = access(&headers)?;
    let nodes = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.nodes(&p)
        })
        .await?;
    Ok(Json(NodesResponse { nodes }))
}
pub(super) async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(node): Json<NodeRegistration>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let id = node.id.clone();
    let actor = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.register_node(&p, node)?;
            Ok(p.account_id)
        })
        .await?;
    state.emit("node_registered", Some(id), Some(vec![actor]), json!({}));
    Ok(StatusCode::CREATED)
}
pub(super) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let actor = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.revoke_node(&p, &resource)?;
            Ok(p.account_id)
        })
        .await?;
    state.emit("node_revoked", Some(id), Some(vec![actor]), json!({}));
    Ok(StatusCode::NO_CONTENT)
}
pub(super) async fn upgrade(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    // Connections do not gain any capability until the node proves key possession.
    let slot = state
        .node_connections
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, ErrorCode::CapacityExceeded))?;
    let resource = id.clone();
    let initial = state
        .db(move |s| s.node_challenge(&resource, now_ms()?))
        .await?;
    Ok(ws
        .max_message_size((NODE_MESSAGE_BYTES + 128) as usize)
        .max_frame_size((NODE_MESSAGE_BYTES + 128) as usize)
        .on_upgrade(move |mut socket| async move {
            let _slot = slot;
            let result = serve(&mut socket, state, id, initial).await;
            // Distinguish recoverable overload/restart from terminal authority
            // rejection. An intentional revoke must never look like a proxy
            // disconnect to the reconnecting node.
            let (code, reason) = match result {
                Ok(()) => (1000, "control completed"),
                Err(ApiError(status, _)) if status == StatusCode::TOO_MANY_REQUESTS => {
                    (1013, "control retry later")
                }
                Err(ApiError(status, _)) if status.is_server_error() => {
                    (1012, "control temporarily unavailable")
                }
                Err(_) => (1008, "control authorization ended"),
            };
            let _ = tokio::time::timeout(
                Duration::from_millis(700),
                socket.send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code,
                    reason: reason.into(),
                }))),
            )
            .await;
        }))
}
async fn check(state: &AppState, lease: &NodeLeaseClaims) -> Result<(), ApiError> {
    let claims = lease.clone();
    let current = tokio::time::timeout(
        Duration::from_millis(700),
        state.db(move |s| s.node_lease_current(&claims)),
    )
    .await
    .map_err(|_| ApiError(StatusCode::FORBIDDEN, ErrorCode::PolicyRevoked))??;
    if !current {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::PolicyRevoked));
    }
    Ok(())
}
async fn serve(
    socket: &mut WebSocket,
    state: AppState,
    id: String,
    initial: NodeChallenge,
) -> Result<(), ApiError> {
    let mut challenge = initial;
    let mut current: Option<NodeLeaseClaims> = None;
    let mut deadline = None;
    loop {
        let failed = || ApiError(StatusCode::FORBIDDEN, ErrorCode::AuthRequired);
        tokio::time::timeout(
            Duration::from_millis(700),
            socket.send(Message::Binary(challenge.encode_to_vec().into())),
        )
        .await
        .map_err(|_| failed())?
        .map_err(|_| failed())?;
        let timeout = tokio::time::sleep(Duration::from_millis(NODE_CHALLENGE_MS));
        tokio::pin!(timeout);
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let proof = loop {
            tokio::select! {biased;
                _=&mut timeout=>return Err(failed()),
                _=tick.tick()=>{if let Some(lease)=&current {if deadline.is_some_and(|d|Instant::now()>=d){return Err(failed());}check(&state,lease).await?;}},
                message=socket.recv()=>{
                    let Some(Ok(Message::Binary(bytes)))=message else {return Err(failed());};
                    let proof:NodeProof=decode_bounded(&bytes,NODE_MESSAGE_BYTES).map_err(|_|failed())?;
                    if proof.challenge.as_ref()!=Some(&challenge) {return Err(failed());}
                    if current.as_ref().is_some_and(|c|c.runtime_id!=proof.runtime_id) {return Err(failed());}
                    break proof;
                }
            }
        };
        let request_started = Instant::now();
        let claims = tokio::time::timeout(
            Duration::from_millis(700),
            state.db(move |s| s.issue_node_lease(&proof, now_ms()?)),
        )
        .await
        .map_err(|_| failed())??;
        let signed = state.node_signer.sign(&claims).map_err(|_| failed())?;
        let lease_deadline =
            request_started + Duration::from_millis(nestlink_protocol::NODE_LEASE_MS);
        tokio::time::timeout(
            Duration::from_millis(700),
            socket.send(Message::Binary(signed.encode_to_vec().into())),
        )
        .await
        .map_err(|_| failed())?
        .map_err(|_| failed())?;
        current = Some(claims);
        deadline = Some(lease_deadline);
        let renewal = tokio::time::sleep(Duration::from_millis(
            nestlink_protocol::NODE_REFRESH_MS + 10,
        ));
        tokio::pin!(renewal);
        loop {
            tokio::select! {biased;
                _=tick.tick()=>{if deadline.is_some_and(|d|Instant::now()>=d){return Err(failed());}check(&state,current.as_ref().ok_or_else(failed)?).await?;},
                _=&mut renewal=>break,
                _=socket.recv()=>return Err(failed()),
            }
        }
        let resource = id.clone();
        challenge = state
            .db(move |s| s.node_challenge(&resource, now_ms()?))
            .await?;
    }
}
