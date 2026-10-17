use super::*;
use nestlink_protocol::api::{
    ReconnectionApproval, ReconnectionOffer, ReconnectionResponse, ReconnectionState,
    ReconnectionSubmission,
};
fn grant(
    state: &AppState,
    receipt: &nestlink_storage::reconnection::ReconnectionReceipt,
) -> Result<String, ApiError> {
    let signed = state
        .signer
        .sign_reconnection(&receipt.previous, &receipt.submission, &receipt.next)
        .map_err(StorageError::from)?;
    Ok(URL_SAFE_NO_PAD.encode(signed.encode_to_vec()))
}
pub(super) async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ReconnectionState>, ApiError> {
    let token = access(&headers)?;
    let (mut body, receipt) = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            s.reconnection_state(&actor, &id, now()?)
        })
        .await?;
    if let Some(receipt) = receipt {
        body.grant = Some(grant(&state, &receipt)?);
    }
    Ok(Json(body))
}
pub(super) async fn offer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReconnectionOffer>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let audience = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            s.offer_reconnection(&actor, &id, body, now()?)?;
            s.remote_event_accounts(&id)
        })
        .await?;
    state.emit(
        "reconnection_changed",
        Some(resource),
        Some(audience),
        json!({}),
    );
    Ok(StatusCode::NO_CONTENT)
}
pub(super) async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReconnectionApproval>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let audience = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            s.approve_reconnection(&actor, &id, body, now()?)?;
            s.remote_event_accounts(&id)
        })
        .await?;
    state.emit(
        "reconnection_changed",
        Some(resource),
        Some(audience),
        json!({}),
    );
    Ok(StatusCode::NO_CONTENT)
}
pub(super) async fn commit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReconnectionSubmission>,
) -> Result<Json<ReconnectionResponse>, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let (receipt, audience) = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            let receipt = s.reconnect_permit(&actor, &id, body, now()?)?;
            Ok((receipt, s.remote_event_accounts(&id)?))
        })
        .await?;
    state.emit(
        "remote_reconnected",
        Some(resource),
        Some(audience),
        json!({"connection_generation":receipt.next.connection_generation}),
    );
    Ok(Json(ReconnectionResponse {
        grant: grant(&state, &receipt)?,
    }))
}
