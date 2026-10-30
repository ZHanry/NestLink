//! Space operations authenticate accounts and delegate only explicit space roles.
use crate::{ApiError, AppState, access, now_ms};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use nestlink_protocol::spaces::*;

async fn authenticated(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = access(headers)?;
    let check = token.clone();
    let actor = state
        .db(move |s| s.authenticate(&check, now_ms()? / 1000))
        .await?;
    state.limit(&format!("space/{}", actor.session_id))?;
    Ok(token)
}

pub(crate) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SpaceView>>, ApiError> {
    let token = authenticated(&state, &headers).await?;
    Ok(Json(
        state
            .db(move |s| {
                let now = now_ms()?;
                let actor = s.authenticate(&token, now / 1000)?;
                s.spaces(&actor, now)
            })
            .await?,
    ))
}

pub(crate) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SpaceCreateRequest>,
) -> Result<(StatusCode, Json<SpaceView>), ApiError> {
    let token = authenticated(&state, &headers).await?;
    let key = state.network_signer.public_key();
    let view = state
        .db(move |s| {
            let now = now_ms()?;
            let actor = s.authenticate(&token, now / 1000)?;
            s.create_space(&actor, request, key, now)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(view)))
}

pub(crate) async fn details(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(space): Path<String>,
) -> Result<Json<SpaceDetails>, ApiError> {
    let token = authenticated(&state, &headers).await?;
    Ok(Json(
        state
            .db(move |s| {
                let now = now_ms()?;
                let actor = s.authenticate(&token, now / 1000)?;
                s.space_details(&actor, &space, now)
            })
            .await?,
    ))
}

pub(crate) async fn archive(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(space): Path<String>,
    Json(request): Json<SpaceRevisionRequest>,
) -> Result<Json<SpaceView>, ApiError> {
    let token = authenticated(&state, &headers).await?;
    Ok(Json(
        state
            .db(move |s| {
                let now = now_ms()?;
                let actor = s.authenticate(&token, now / 1000)?;
                s.archive_space(&actor, &space, request, now)
            })
            .await?,
    ))
}

pub(crate) async fn update_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, account)): Path<(String, String)>,
    Json(request): Json<SpaceMemberUpdate>,
) -> Result<Json<SpaceView>, ApiError> {
    let token = authenticated(&state, &headers).await?;
    Ok(Json(
        state
            .db(move |s| {
                let now = now_ms()?;
                let actor = s.authenticate(&token, now / 1000)?;
                s.update_space_member(&actor, &space, &account, request, now)
            })
            .await?,
    ))
}

pub(crate) async fn remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, account)): Path<(String, String)>,
    Json(request): Json<SpaceMemberRemoval>,
) -> Result<Json<SpaceView>, ApiError> {
    let token = authenticated(&state, &headers).await?;
    Ok(Json(
        state
            .db(move |s| {
                let now = now_ms()?;
                let actor = s.authenticate(&token, now / 1000)?;
                s.remove_space_member(&actor, &space, &account, request, now)
            })
            .await?,
    ))
}

pub(crate) async fn join_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(space): Path<String>,
    Json(request): Json<SpaceDeviceJoin>,
) -> Result<Json<SpaceView>, ApiError> {
    let token = authenticated(&state, &headers).await?;
    Ok(Json(
        state
            .db(move |s| {
                let now = now_ms()?;
                let actor = s.authenticate(&token, now / 1000)?;
                s.join_space_device(&actor, &space, request, now)
            })
            .await?,
    ))
}

pub(crate) async fn remove_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, installation)): Path<(String, String)>,
    Json(request): Json<SpaceDeviceRemoval>,
) -> Result<Json<SpaceView>, ApiError> {
    let token = authenticated(&state, &headers).await?;
    Ok(Json(
        state
            .db(move |s| {
                let now = now_ms()?;
                let actor = s.authenticate(&token, now / 1000)?;
                s.remove_space_device(&actor, &space, &installation, request, now)
            })
            .await?,
    ))
}

pub(crate) async fn invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(space): Path<String>,
    Json(request): Json<SpaceInvitationRequest>,
) -> Result<(StatusCode, Json<SpaceInvitationIssued>), ApiError> {
    let token = authenticated(&state, &headers).await?;
    let view = state
        .db(move |s| {
            let now = now_ms()?;
            let actor = s.authenticate(&token, now / 1000)?;
            s.invite_to_space(&actor, &space, request, now)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(view)))
}

pub(crate) async fn revoke_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, invitation)): Path<(String, String)>,
    Json(request): Json<SpaceRevisionRequest>,
) -> Result<Json<SpaceView>, ApiError> {
    let token = authenticated(&state, &headers).await?;
    Ok(Json(
        state
            .db(move |s| {
                let now = now_ms()?;
                let actor = s.authenticate(&token, now / 1000)?;
                s.revoke_space_invitation(&actor, &space, &invitation, request, now)
            })
            .await?,
    ))
}

pub(crate) async fn accept_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, invitation)): Path<(String, String)>,
    Json(request): Json<SpaceInvitationAcceptance>,
) -> Result<Json<SpaceView>, ApiError> {
    let token = authenticated(&state, &headers).await?;
    Ok(Json(
        state
            .db(move |s| {
                let now = now_ms()?;
                let actor = s.authenticate(&token, now / 1000)?;
                s.accept_space_invitation(&actor, &space, &invitation, request, now)
            })
            .await?,
    ))
}

pub(crate) async fn audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(space): Path<String>,
) -> Result<Json<Vec<SpaceAuditEntry>>, ApiError> {
    let token = authenticated(&state, &headers).await?;
    Ok(Json(
        state
            .db(move |s| {
                let now = now_ms()?;
                let actor = s.authenticate(&token, now / 1000)?;
                s.space_audit(&actor, &space, now)
            })
            .await?,
    ))
}
