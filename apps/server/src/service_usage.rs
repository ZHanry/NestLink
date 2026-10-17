use crate::{ApiError, AppState, access, now, now_ms};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use nestlink_protocol::{
    ErrorCode,
    service_plane::{
        SERVICE_USAGE_BYTES, ServiceQuotaLimitUpdate, ServiceQuotaUsageQuery,
        ServiceUsageReportClaims, SignedServiceUsageReport, SignedServiceUsageRuntimeStop,
        decode_service_message,
    },
};
use nestlink_storage::StorageError;

pub(crate) async fn report(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Json(signed): Json<SignedServiceUsageReport>,
) -> Result<Json<nestlink_protocol::service_plane::SignedServiceUsageReportAck>, ApiError> {
    let claims: ServiceUsageReportClaims =
        decode_service_message(&signed.claims, SERVICE_USAGE_BYTES).map_err(StorageError::from)?;
    if claims.node_id != node_id {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::IdentityMismatch));
    }
    let signer = state.node_signer.clone();
    state
        .db(move |store| {
            Ok(Json(store.accept_service_usage_report(
                &signed,
                &signer,
                now_ms()?,
            )?))
        })
        .await
}

pub(crate) async fn stop(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Json(signed): Json<SignedServiceUsageRuntimeStop>,
) -> Result<StatusCode, ApiError> {
    let claims: nestlink_protocol::service_plane::ServiceUsageRuntimeStopClaims =
        decode_service_message(&signed.claims, SERVICE_USAGE_BYTES).map_err(StorageError::from)?;
    if claims.node_id != node_id {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::IdentityMismatch));
    }
    state
        .db(move |store| store.accept_service_usage_stop(&signed, now_ms()?))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn admin_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ServiceQuotaUsageQuery>,
) -> Result<Json<nestlink_protocol::service_plane::ServiceQuotaUsageView>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |store| {
            let actor = store.authenticate(&token, now()?)?;
            Ok(Json(store.service_quota_usage(&actor, query, now_ms()?)?))
        })
        .await
}

pub(crate) async fn set_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(update): Json<ServiceQuotaLimitUpdate>,
) -> Result<Json<nestlink_protocol::service_plane::ServiceQuotaUsageView>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |store| {
            let actor = store.authenticate(&token, now()?)?;
            Ok(Json(store.set_service_quota_limit(
                &actor,
                update,
                now_ms()?,
            )?))
        })
        .await
}
