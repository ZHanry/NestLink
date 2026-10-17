//! Authenticated configuration APIs. No service listener is started by these routes.
use crate::{ApiError, AppState, access, now};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use nestlink_protocol::{ErrorCode, api::*};
use serde_json::json;

fn reject_management_hostname(
    state: &AppState,
    definition: &ServiceDefinition,
) -> Result<(), ApiError> {
    if let ServiceIngress::Http { hostname } | ServiceIngress::Https { hostname } =
        &definition.requested_ingress
    {
        let origin = url::Url::parse(state.origin.as_str())
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?;
        if origin.host_str() == Some(hostname.as_str()) {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                ErrorCode::PermissionRequired,
            ));
        }
    }
    Ok(())
}
pub(crate) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ServiceQuery>,
) -> Result<Json<ServicePage>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let now = now()?;
            let actor = s.authenticate(&token, now)?;
            Ok(Json(s.services(&actor, query, now)?))
        })
        .await
}
pub(crate) async fn inspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ServiceView>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let now = now()?;
            let actor = s.authenticate(&token, now)?;
            Ok(Json(s.service(&actor, &id, now)?))
        })
        .await
}
pub(crate) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ServiceCreate>,
) -> Result<(StatusCode, Json<ServiceView>), ApiError> {
    reject_management_hostname(&state, &body.definition)?;
    let token = access(&headers)?;
    let check = token.clone();
    let principal = state.db(move |s| s.authenticate(&check, now()?)).await?;
    state.limit(&format!("services/create/{}", principal.session_id))?;
    let view = state
        .db(move |s| {
            let now = now()?;
            let actor = s.authenticate(&token, now)?;
            s.create_service(&actor, body, now)
        })
        .await?;
    state.emit(
        "service_changed",
        Some(view.id.clone()),
        Some(vec![view.account_id.clone()]),
        json!({"revision":view.revision,"publication":view.publication}),
    );
    Ok((StatusCode::CREATED, Json(view)))
}
pub(crate) async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ServiceUpdate>,
) -> Result<Json<ServiceView>, ApiError> {
    reject_management_hostname(&state, &body.definition)?;
    let token = access(&headers)?;
    let view = state
        .db(move |s| {
            let now = now()?;
            let actor = s.authenticate(&token, now)?;
            s.update_service(&actor, &id, body, now)
        })
        .await?;
    state.emit(
        "service_changed",
        Some(view.id.clone()),
        Some(vec![view.account_id.clone()]),
        json!({"revision":view.revision,"publication":view.publication}),
    );
    Ok(Json(view))
}
pub(crate) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ServiceRevocation>,
) -> Result<Json<ServiceView>, ApiError> {
    let token = access(&headers)?;
    let view = state
        .db(move |s| {
            let now = now()?;
            let actor = s.authenticate(&token, now)?;
            s.revoke_service(&actor, &id, body.expected_revision, now)
        })
        .await?;
    state.emit(
        "service_changed",
        Some(view.id.clone()),
        Some(vec![view.account_id.clone()]),
        json!({"revision":view.revision,"publication":view.publication}),
    );
    Ok(Json(view))
}
pub(crate) async fn challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ServiceApprovalChallengeRequest>,
) -> Result<Json<ServiceApprovalChallenge>, ApiError> {
    let token = access(&headers)?;
    let check = token.clone();
    let principal = state.db(move |s| s.authenticate(&check, now()?)).await?;
    state.limit(&format!("services/challenge/{}", principal.session_id))?;
    state
        .db(move |s| {
            let now = now()?;
            let actor = s.authenticate(&token, now)?;
            Ok(Json(s.service_approval_challenge(
                &actor,
                &id,
                body.expected_revision,
                now,
            )?))
        })
        .await
}
pub(crate) async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ServiceTargetApproval>,
) -> Result<Json<ServiceView>, ApiError> {
    let token = access(&headers)?;
    let view = state
        .db(move |s| {
            let now = now()?;
            let actor = s.authenticate(&token, now)?;
            s.approve_service_target(&actor, &id, body, now)
        })
        .await?;
    state.emit("service_changed",Some(view.id.clone()),Some(vec![view.account_id.clone()]),json!({"revision":view.revision,"approval":"approved_target","publication":view.publication}));
    Ok(Json(view))
}
