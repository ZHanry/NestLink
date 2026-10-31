use crate::{ApiError, AppState, access, now, now_ms};
pub(crate) mod group;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use nestlink_protocol::{
    ErrorCode, SCHEMA_VERSION,
    api::ServicePublicationStatus,
    service_plane::{publication::*, *},
};
use nestlink_storage::{StorageError, services::publication::ServicePublicationIssue};
use serde_json::json;

fn grant(
    state: &AppState,
    issue: ServicePublicationIssue,
) -> Result<ServicePublicationGrant, ApiError> {
    let c = &issue.claims;
    // GET can return a lease issued by the preceding poll. Include its original
    // timestamp in this delegation rather than changing the signed lease.
    let issued = c.issued_at_unix_ms;
    let delegation = ServiceIssuerDelegation {
        schema_version: SCHEMA_VERSION,
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        policy_revision: c.policy_revision,
        service_issuer: state.service_signer.public_key(),
        issued_at_unix_ms: issued,
        expires_at_unix_ms: issued
            .checked_add(SERVICE_DELEGATION_MS)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| ApiError::from(StorageError::Conflict))?,
    };
    Ok(ServicePublicationGrant {
        lease: state.service_signer.sign(c).map_err(StorageError::from)?,
        issuer: state
            .node_signer
            .sign_service_issuer_delegation(&delegation)
            .map_err(StorageError::from)?,
        edge_public_key: issue.edge_public_key,
    })
}
pub(crate) async fn namespace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ServiceEdgeNamespaceView>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let at = now()?;
            let actor = s.authenticate(&token, at)?;
            Ok(Json(s.service_edge_namespace(&actor, &id, at)?))
        })
        .await
}
pub(crate) async fn set_namespace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ServiceEdgeNamespaceUpdate>,
) -> Result<Json<ServiceEdgeNamespaceView>, ApiError> {
    body.config.validate().map_err(StorageError::from)?;
    let management = url::Url::parse(state.origin.as_str())
        .map_err(|_| ApiError::from(StorageError::Conflict))?;
    if management.host_str() != Some(body.config.management_hostname.as_str()) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            ErrorCode::PermissionRequired,
        ));
    }
    let token = access(&headers)?;
    state
        .db(move |s| {
            let at = now()?;
            let actor = s.authenticate(&token, at)?;
            Ok(Json(s.set_service_edge_namespace(&actor, &id, body, at)?))
        })
        .await
}
pub(crate) async fn publish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ServicePublicationRequest>,
) -> Result<Json<ServicePublicationGrant>, ApiError> {
    let token = access(&headers)?;
    let check = token.clone();
    let actor = state.db(move |s| s.authenticate(&check, now()?)).await?;
    state.limit(&format!("services/publish/{}", actor.session_id))?;
    let life = state.service_lifecycle.clone();
    let signer = state.service_signer.clone();
    let issue = state
        .db(move |s| {
            let at = now_ms()?;
            let actor = s.authenticate(&token, at / 1000)?;
            s.publish_service(&life, &actor, &id, body.expected_revision, &signer, at)
        })
        .await?;
    let service_id = issue.claims.service_id.clone();
    let account_id = issue.claims.account_id.clone();
    let revision = issue.claims.service_revision;
    let response = grant(&state, issue)?;
    state.emit(
        "service_changed",
        Some(service_id),
        Some(vec![account_id]),
        json!({"revision":revision,"publication":ServicePublicationStatus::Published}),
    );
    Ok(Json(response))
}
pub(crate) async fn inspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ServicePublicationGrant>, ApiError> {
    let token = access(&headers)?;
    let life = state.service_lifecycle.clone();
    let issue = state
        .db(move |s| {
            let at = now_ms()?;
            let actor = s.authenticate(&token, at / 1000)?;
            s.service_publication(&life, &actor, &id, at)
        })
        .await?;
    Ok(Json(grant(&state, issue)?))
}
pub(crate) async fn stop(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ServicePublicationRequest>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let view = state
        .db(move |s| {
            let at = now()?;
            let actor = s.authenticate(&token, at)?;
            s.stop_service_publication(&actor, &id, body.expected_revision, at)?;
            s.service(&actor, &id, at)
        })
        .await?;
    state.emit(
        "service_changed",
        Some(view.id),
        Some(vec![view.account_id]),
        json!({"revision":view.revision,"publication":view.publication}),
    );
    Ok(StatusCode::NO_CONTENT)
}
pub(crate) async fn resources(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<SignedServiceResourceQuery>,
) -> Result<Json<ServiceResourceGrant>, ApiError> {
    let q: nestlink_protocol::NodeResourceQueryClaims =
        decode_service_message(&body.claims, SERVICE_MESSAGE_BYTES).map_err(StorageError::from)?;
    q.validate().map_err(StorageError::from)?;
    if q.node_id != id {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::IdentityMismatch));
    }
    let life = state.service_lifecycle.clone();
    let signer = state.service_signer.clone();
    let budget = state.clone();
    let snapshot = state
        .db(move |s| {
            s.service_resource_snapshot(&life, &body, &signer, now_ms()?, |node| {
                budget
                    .limit_with_budget(&format!("node-service-resources/{node}"), 1024)
                    .map_err(|_| StorageError::RateLimited)
            })
        })
        .await?;
    let issued = snapshot.issued_at_unix_ms;
    let issuer = state
        .node_signer
        .sign_service_issuer_delegation(&ServiceIssuerDelegation {
            schema_version: SCHEMA_VERSION,
            deployment_id: snapshot.query.deployment_id.clone(),
            security_epoch: snapshot.query.security_epoch,
            policy_revision: snapshot.query.policy_revision,
            service_issuer: snapshot.service_lease_issuer,
            issued_at_unix_ms: issued,
            expires_at_unix_ms: issued
                .checked_add(SERVICE_DELEGATION_MS)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(StorageError::Conflict)?,
        })
        .map_err(StorageError::from)?;
    Ok(Json(ServiceResourceGrant {
        snapshot: state
            .node_signer
            .sign_service_snapshot(&snapshot)
            .map_err(StorageError::from)?,
        issuer,
    }))
}
