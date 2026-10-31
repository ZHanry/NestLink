//! Management admission is independent of public publication and membership.
//! Signed installation reports retain the original shared quota reservation.
use crate::{ApiError, AppState, access, now_ms};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use nestlink_protocol::{
    ErrorCode, SCHEMA_VERSION,
    api::ServiceQuery,
    service_plane::{
        ServiceLeaseClaims, decode_service_message,
        publication::{SERVICE_DELEGATION_MS, ServiceIssuerDelegation},
    },
    services::private::*,
};
use nestlink_storage::StorageError;

fn grant(
    state: &AppState,
    lease: SignedPrivateServiceLease,
    network: PrivateServiceNetworkPath,
) -> Result<PrivateServiceGrant, ApiError> {
    let claims: ServiceLeaseClaims = decode_service_message(
        &lease.service_lease.claims,
        nestlink_protocol::service_plane::SERVICE_MESSAGE_BYTES,
    )
    .map_err(StorageError::from)?;
    let issued = claims.issued_at_unix_ms;
    let delegation = ServiceIssuerDelegation {
        schema_version: SCHEMA_VERSION,
        deployment_id: claims.deployment_id,
        security_epoch: claims.security_epoch,
        policy_revision: claims.policy_revision,
        service_issuer: state.service_signer.public_key(),
        issued_at_unix_ms: issued,
        expires_at_unix_ms: issued
            .checked_add(SERVICE_DELEGATION_MS)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?,
    };
    Ok(PrivateServiceGrant {
        lease,
        network,
        issuer: state
            .node_signer
            .sign_service_issuer_delegation(&delegation)
            .map_err(StorageError::from)?,
    })
}

pub(crate) async fn exposure(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Option<ServiceExposureView>>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |store| {
            let at = now_ms()?;
            let actor = store.authenticate(&token, at / 1000)?;
            Ok(Json(store.service_exposure(&actor, &id, at)?))
        })
        .await
}
pub(crate) async fn set_exposure(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ServiceExposureUpdate>,
) -> Result<Json<ServiceExposureView>, ApiError> {
    let token = access(&headers)?;
    // Changing exposure withdraws existing access; use the reserved revocation lane.
    state
        .db_revocation(move |store| {
            let at = now_ms()?;
            let actor = store.authenticate(&token, at / 1000)?;
            Ok(Json(store.set_service_exposure(&actor, &id, body, at)?))
        })
        .await
}
pub(crate) async fn policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<PrivateServicePolicyView>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |store| {
            let at = now_ms()?;
            let actor = store.authenticate(&token, at / 1000)?;
            Ok(Json(store.private_service_policy(&actor, &id, at)?))
        })
        .await
}
pub(crate) async fn allow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PrivateServiceAclUpdate>,
) -> Result<Json<PrivateServicePolicyView>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |store| {
            let at = now_ms()?;
            let actor = store.authenticate(&token, at / 1000)?;
            Ok(Json(store.grant_private_service(&actor, &id, body, at)?))
        })
        .await
}
pub(crate) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, rule)): Path<(String, String)>,
    Json(body): Json<PrivateServiceAclRevocation>,
) -> Result<Json<PrivateServicePolicyView>, ApiError> {
    let token = access(&headers)?;
    state
        .db_revocation(move |store| {
            let at = now_ms()?;
            let actor = store.authenticate(&token, at / 1000)?;
            Ok(Json(store.revoke_private_service(
                &actor,
                &id,
                &rule,
                body.expected_exposure_revision,
                at,
            )?))
        })
        .await
}
pub(crate) async fn directory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(consumer): Path<String>,
    Query(query): Query<ServiceQuery>,
) -> Result<Json<PrivateServicePage>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |store| {
            let at = now_ms()?;
            let actor = store.authenticate(&token, at / 1000)?;
            Ok(Json(store.private_services(&actor, &consumer, query, at)?))
        })
        .await
}
pub(crate) async fn host(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SignedPrivateServiceHost>,
) -> Result<StatusCode, ApiError> {
    let claims: PrivateServiceHostClaims =
        decode_service_message(&body.claims, PRIVATE_SERVICE_MESSAGE_BYTES)
            .map_err(StorageError::from)?;
    if claims.service_id != id {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::IdentityMismatch));
    }
    let token = access(&headers)?;
    state
        .db(move |store| {
            let at = now_ms()?;
            let actor = store.authenticate(&token, at / 1000)?;
            store.register_private_service_host(&actor, &body, at)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
pub(crate) async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PrivateServiceAccessRequest>,
) -> Result<Json<PrivateServiceGrant>, ApiError> {
    let token = access(&headers)?;
    let check = token.clone();
    let principal = state
        .db(move |store| store.authenticate(&check, now_ms()? / 1000))
        .await?;
    state.limit(&format!("private-service-access/{}", principal.session_id))?;
    let signer = state.service_signer.clone();
    let network_root = state.network_signer.clone();
    let node_signer=state.node_signer.clone();
    let lifecycle=state.relay_lifecycle.clone();
    let result = state
        .db(move |store| {
            let at = now_ms()?;
            let actor = store.authenticate(&token, at / 1000)?;
            let space=store.private_service_access_space(&actor,&id,&body.consumer_device_id,at)?;
            let network_signer =
                store.network_authority_signer(&network_root, &space, at)?;
            store.issue_private_service_grant(&lifecycle,&actor,&id,body,&signer,&network_signer,&node_signer,at)
        })
        .await?;
    Ok(Json(result))
}
pub(crate) async fn host_access(State(state):State<AppState>,headers:HeaderMap,Path((id,runtime)):Path<(String,String)>,Query(query):Query<ServiceQuery>)->Result<Json<PrivateServiceHostAccessPage>,ApiError>{
    let token=access(&headers)?;
    let signer=state.service_signer.clone();let node_signer=state.node_signer.clone();
    state.db(move|store|{let at=now_ms()?;let actor=store.authenticate(&token,at/1000)?;Ok(Json(store.private_service_host_access(&actor,&id,&runtime,query,&signer,&node_signer,at)?))}).await
}
pub(crate) async fn withdraw_host(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SignedPrivateServiceHostWithdrawal>,
) -> Result<StatusCode, ApiError> {
    let claims: PrivateServiceHostClaims =
        decode_service_message(&body.claims, PRIVATE_SERVICE_MESSAGE_BYTES)
            .map_err(StorageError::from)?;
    if claims.service_id != id {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::IdentityMismatch));
    }
    let token = access(&headers)?;
    state
        .db_revocation(move |store| {
            let at = now_ms()?;
            let actor = store.authenticate(&token, at / 1000)?;
            store.withdraw_private_service_host(&actor, &body, at)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
pub(crate) async fn current(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, reservation)): Path<(String, String)>,
) -> Result<Json<PrivateServiceGrant>, ApiError> {
    let token = access(&headers)?;
    let signer = state.service_signer.clone();
    let (lease, network) = state
        .db(move |store| {
            let at = now_ms()?;
            let actor = store.authenticate(&token, at / 1000)?;
            let lease = store.private_service_lease(&actor, &id, &reservation, &signer, at)?;
            let network =
                store.private_service_network_path(&actor, &id, &reservation, &signer, at)?;
            Ok((lease, network))
        })
        .await?;
    Ok(Json(grant(&state, lease, network)?))
}
pub(crate) async fn usage(
    State(state): State<AppState>,
    Json(body): Json<SignedPrivateServiceUsage>,
) -> Result<Json<PrivateServiceUsageAck>, ApiError> {
    state
        .db(move |store| Ok(Json(store.accept_private_service_usage(&body, now_ms()?)?)))
        .await
}
