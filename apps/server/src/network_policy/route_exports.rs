//! Exact stored prefix publication rights, independent of raw IP admission.
use super::*;
use nestlink_protocol::api::NetworkRouteExportRequest;

pub(crate) async fn issue(
    State(state): State<AppState>, headers: HeaderMap,
    Path((space,node)): Path<(String,String)>, Json(body): Json<NetworkRouteExportRequest>,
) -> Result<(StatusCode,Json<GrantView>),ApiError> {
    let token = member_access(&state,&headers,MemberOperation::Issue).await?;
    let signer = state.network_signer.clone();
    let signed = state.db(move |store| {
        let now = now_ms()?;
        let actor = store.authenticate(&token,now/1000)?;
        let signer = store.network_authority_signer(&signer,&space,now)?;
        store.issue_network_route_export(&actor,&signer,&space,&node,body,now)
    }).await?;
    Ok((StatusCode::CREATED,Json(grant_view(signed)?)))
}

pub(crate) async fn read(
    State(state): State<AppState>, headers: HeaderMap,
    Path((space,grant)): Path<(String,String)>,
) -> Result<Json<GrantView>,ApiError> {
    let token = member_access(&state,&headers,MemberOperation::Observe).await?;
    let signed = state.db(move |store| {
        let now = now_ms()?;
        let actor = store.authenticate(&token,now/1000)?;
        store.network_route_export(&actor,&space,&grant,now)
    }).await?;
    Ok(Json(grant_view(signed)?))
}

pub(crate) async fn revoke(
    State(state): State<AppState>, headers: HeaderMap,
    Path((space,grant)): Path<(String,String)>, Json(body): Json<RevokeGrantRequest>,
) -> Result<Json<PolicyView>,ApiError> {
    let token = member_access(&state,&headers,MemberOperation::Revoke).await?;
    let snapshot = state.db_revocation(move |store| {
        let now = now_ms()?;
        let actor = store.authenticate(&token,now/1000)?;
        store.revoke_network_route_export(&actor,&space,&grant,body.expected_revision,now)
    }).await?;
    Ok(Json(policy_view(&snapshot)))
}
