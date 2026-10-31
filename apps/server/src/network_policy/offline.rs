//! Authenticated production offline review and one-use consume endpoints.
use super::*;
use nestlink_protocol::offline::{OfflineEndpointApproval, management::*};

pub(crate) async fn policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(space): Path<String>,
) -> Result<Json<OfflinePolicyView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Observe).await?;
    Ok(Json(
        state
            .db(move |store| {
                let now = now_ms()?;
                let actor = store.authenticate(&token, now / 1000)?;
                store.offline_policy(&actor, &space, now)
            })
            .await?,
    ))
}
pub(crate) async fn enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(space): Path<String>,
    Json(request): Json<OfflineEnableUpdate>,
) -> Result<Json<OfflinePolicyView>, ApiError> {
    let token = admin_access(&state, &headers).await?;
    Ok(Json(
        state
            .db_revocation(move |store| {
                let now = now_ms()?;
                let actor = store.authenticate(&token, now / 1000)?;
                store.set_offline_enabled(&actor, &space, request, now)
            })
            .await?,
    ))
}
pub(crate) async fn draft(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(space): Path<String>,
    Json(request): Json<OfflinePrivateDraftRequest>,
) -> Result<(StatusCode, Json<OfflineBundleView>), ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Issue).await?;
    let result = state
        .db(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            store.create_offline_private_draft(&actor, &space, request, now)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(result)))
}
pub(crate) async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, id)): Path<(String, String)>,
) -> Result<Json<OfflineBundleView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Observe).await?;
    Ok(Json(
        state
            .db(move |store| {
                let now = now_ms()?;
                let actor = store.authenticate(&token, now / 1000)?;
                store.offline_bundle(&actor, &space, &id, now)
            })
            .await?,
    ))
}
pub(crate) async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, id)): Path<(String, String)>,
    Json(request): Json<OfflineEndpointApproval>,
) -> Result<Json<OfflineBundleView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Issue).await?;
    let signer = state.network_signer.clone();
    Ok(Json(
        state
            .db(move |store| {
                let now = now_ms()?;
                let actor = store.authenticate(&token, now / 1000)?;
                let signer = store.network_authority_signer(&signer, &space, now)?;
                store.approve_offline_bundle(&actor, &signer, &space, &id, request, now)
            })
            .await?,
    ))
}
pub(crate) async fn challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, id, endpoint)): Path<(String, String, u8)>,
) -> Result<Json<OfflineConsumeChallenge>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Issue).await?;
    Ok(Json(
        state
            .db(move |store| {
                let now = now_ms()?;
                let actor = store.authenticate(&token, now / 1000)?;
                store.offline_consume_challenge(&actor, &space, &id, endpoint, now)
            })
            .await?,
    ))
}
pub(crate) async fn consume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, id)): Path<(String, String)>,
    Json(request): Json<OfflineConsumeRequest>,
) -> Result<Json<OfflineBundleView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Issue).await?;
    Ok(Json(
        state
            .db(move |store| {
                let now = now_ms()?;
                let actor = store.authenticate(&token, now / 1000)?;
                store.consume_offline_bundle(&actor, &space, &id, request, now)
            })
            .await?,
    ))
}
pub(crate) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, id)): Path<(String, String)>,
) -> Result<Json<OfflineBundleView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Revoke).await?;
    Ok(Json(
        state
            .db_revocation(move |store| {
                let now = now_ms()?;
                let actor = store.authenticate(&token, now / 1000)?;
                store.revoke_offline_bundle(&actor, &space, &id, now)
            })
            .await?,
    ))
}
