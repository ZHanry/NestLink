//! Signed node poll for managed TURN grants and peer bindings.
use super::*;
use nestlink_protocol::{
    NODE_MESSAGE_BYTES, SignedTurnResourceQuery, SignedTurnResourceSnapshot,
    TurnResourceQueryClaims, decode_bounded,
};
use std::time::Duration;

pub(super) async fn resources(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(signed): Json<SignedTurnResourceQuery>,
) -> Result<Json<SignedTurnResourceSnapshot>, ApiError> {
    let query: TurnResourceQueryClaims = decode_bounded(&signed.claims, NODE_MESSAGE_BYTES)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, ErrorCode::InvalidMessage))?;
    query
        .validate()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, ErrorCode::InvalidMessage))?;
    if query.node_id != id {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::IdentityMismatch));
    }
    state.limit_with_budget(&format!("node-turn/{id}"), 1024)?;
    let lifecycle = state.relay_lifecycle.clone();
    let vault = state.vault.clone();
    let snapshot = tokio::time::timeout(
        Duration::from_millis(700),
        state.db(move |store| store.turn_resource_snapshot(&lifecycle, &vault, &signed, now_ms()?)),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::InternalError))??;
    let signed = state
        .node_signer
        .sign_turn_resource_snapshot(&snapshot)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?;
    Ok(Json(signed))
}
