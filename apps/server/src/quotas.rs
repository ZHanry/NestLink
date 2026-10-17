use crate::{ApiError, AppState, access, now};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use nestlink_protocol::{
    ErrorCode,
    api::{RelayQuota, RelayQuotaUpdate, RelayUsage},
};

pub(crate) async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RelayQuota>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            Ok(Json(s.relay_quota(&actor, now()?)?))
        })
        .await
}
pub(crate) async fn set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(update): Json<RelayQuotaUpdate>,
) -> Result<Json<RelayQuota>, ApiError> {
    let token = access(&headers)?;
    let quota = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            s.set_relay_quota(&actor, update, now()?)
        })
        .await?;
    // If this request is cancelled after DB commit, each existing connection's
    // service-owned authorization future still observes the persistent revision.
    state
        .relays
        .synchronize(quota)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?;
    Ok(Json(quota))
}
pub(crate) async fn usage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RelayUsage>, ApiError> {
    let token = access(&headers)?;
    let quota = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            s.relay_quota(&actor, now()?)
        })
        .await?;
    state
        .relays
        .synchronize(quota)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?;
    Ok(Json(state.relays.usage().map_err(|_| {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError)
    })?))
}
