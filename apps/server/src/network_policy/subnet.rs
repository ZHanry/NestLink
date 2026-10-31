//! Manager-approved exact mapping publication. OS/LAN and raw IP business
//! consent remain separate; no endpoint can execute the returned envelope.
use super::*;
use nestlink_protocol::subnet::management::{
    SubnetMappingRequest, SubnetMappingRevoke, SubnetMappingView,
};
use nestlink_storage::network_policy::subnet::SubnetMappingBundle;

pub(super) fn view(bundle: SubnetMappingBundle) -> Result<SubnetMappingView, StorageError> {
    Ok(SubnetMappingView {
        mapping: bundle.mapping,
        route_export: grant_view(bundle.route_export)?,
        gateway: bundle.gateway,
        policy: policy_view(&bundle.policy),
    })
}

pub(crate) async fn bind_installation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, id)): Path<(String, String)>,
    Json(request): Json<nestlink_protocol::subnet::management::SubnetGatewayInstallationRequest>,
) -> Result<Json<PolicyView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Issue).await?;
    let result = state
        .db(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            Ok(policy_view(&store.bind_subnet_gateway_installation(
                &actor, &space, &id, request, now,
            )?))
        })
        .await?;
    Ok(Json(result))
}
pub(crate) async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(space): Path<String>,
    Json(request): Json<SubnetMappingRequest>,
) -> Result<(StatusCode, Json<SubnetMappingView>), ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Issue).await?;
    let signer = state.network_signer.clone();
    let result = state
        .db(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            let signer = store.network_authority_signer(&signer, &space, now)?;
            view(store.issue_subnet_mapping(&actor, &signer, &space, request, now)?)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(result)))
}
pub(crate) async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, id)): Path<(String, String)>,
) -> Result<Json<SubnetMappingView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Observe).await?;
    let result = state
        .db(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            view(store.subnet_mapping(&actor, &space, &id, now)?)
        })
        .await?;
    Ok(Json(result))
}
pub(crate) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, id)): Path<(String, String)>,
    Json(request): Json<SubnetMappingRevoke>,
) -> Result<Json<PolicyView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Revoke).await?;
    let result = state
        .db_revocation(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            Ok(policy_view(&store.revoke_subnet_mapping(
                &actor, &space, &id, request, now,
            )?))
        })
        .await?;
    Ok(Json(result))
}
