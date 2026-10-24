//! Explicit versioned authority endpoints. Legacy endpoints keep their old JSON.
use super::*;
use nestlink_protocol::api::{
    MediaAnnouncementSubmission, MediaApprovalSubmission, MediaRemoteRequest,
};
use nestlink_protocol::media_authority::MediaDirection;
fn direction(value: &str) -> Result<MediaDirection, StorageError> {
    match value {
        "encode" => Ok(MediaDirection::Encode),
        "decode" => Ok(MediaDirection::Decode),
        _ => Err(StorageError::Invalid("unknown media direction")),
    }
}
pub(crate) async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, side)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let at = now()?;
            let p = s.authenticate(&token, at)?;
            Ok(Json(serde_json::to_value(s.media_announcement(
                &p,
                &id,
                direction(&side)?,
                at,
            )?)?))
        })
        .await
}
pub(crate) async fn replace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, side)): Path<(String, String)>,
    Json(body): Json<MediaAnnouncementSubmission>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let at = now()?;
            let p = s.authenticate(&token, at)?;
            if body.announcement.device_id != id || body.announcement.direction != direction(&side)?
            {
                return Err(StorageError::Forbidden);
            }
            s.replace_media_announcement(&p, body, at)?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}
pub(crate) async fn request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MediaRemoteRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let token = access(&headers)?;
    let (view, audience) = state
        .db(move |s| {
            let at = now()?;
            let p = s.authenticate(&token, at)?;
            let view = s.create_media_remote(&p, body, at)?;
            let audience = s.remote_event_accounts(&view.id)?;
            Ok((view, audience))
        })
        .await?;
    // Match legacy creation: notify only after storage commits the request and
    // its frozen scope. Hosts use this event to fetch their approval inbox.
    state.emit(
        "approval_requested",
        Some(view.id.clone()),
        Some(audience),
        json!({}),
    );
    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(view).map_err(StorageError::from)?),
    ))
}
pub(crate) async fn scope(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let at = now()?;
            let p = s.authenticate(&token, at)?;
            Ok(Json(serde_json::to_value(
                s.remote_media_scope(&p, &id, at)?,
            )?))
        })
        .await
}
pub(crate) async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<MediaApprovalSubmission>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let audience = state
        .db(move |s| {
            let at = now()?;
            let p = s.authenticate(&token, at)?;
            s.approve_media_remote(&p, &id, body, at)?;
            s.remote_event_accounts(&id)
        })
        .await?;
    // Both approval and rejection refresh controller/host state. Successful
    // approval also wakes the existing host preparation/readiness flow.
    state.emit(
        "approval_changed",
        Some(resource),
        Some(audience),
        json!({}),
    );
    Ok(StatusCode::NO_CONTENT)
}
