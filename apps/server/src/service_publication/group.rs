//! Explicit group management. The existing service owner, target approval,
//! publication signer and durable four-scope reservations remain mandatory.
use super::*;
use nestlink_protocol::service_plane::group::*;
use nestlink_storage::services::publication::group::ServiceGroupPublicationIssue;

fn group_grant(state: &AppState, issue: ServiceGroupPublicationIssue) -> Result<ServiceGroupPublicationGrant,ApiError> {
    Ok(ServiceGroupPublicationGrant {group:issue.group,members:issue.members.into_iter().map(|member|grant(state,member)).collect::<Result<_,_>>()?})
}
pub(crate) async fn config(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<ServiceEdgeGroupView>,ApiError> {
    let token = access(&headers)?;
    Ok(Json(state.db(move |store| {
        let at = now_ms()?;
        let actor = store.authenticate(&token,at/1000)?;
        store.service_edge_group(&actor,&id,at)
    }).await?))
}
pub(crate) async fn set_config(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<ServiceEdgeGroupUpdate>) -> Result<Json<ServiceEdgeGroupView>,ApiError> {
    let token = access(&headers)?;
    Ok(Json(state.db(move |store| {
        let at = now_ms()?;
        let actor = store.authenticate(&token,at/1000)?;
        store.set_service_edge_group(&actor,&id,body,at)
    }).await?))
}
pub(crate) async fn revoke_config(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<ServicePublicationRequest>) -> Result<StatusCode,ApiError> {
    let token = access(&headers)?;
    state.db(move |store| {
        let at = now_ms()?;
        let actor = store.authenticate(&token,at/1000)?;
        store.revoke_service_edge_group(&actor,&id,body.expected_revision,at)
    }).await?;
    Ok(StatusCode::NO_CONTENT)
}
pub(crate) async fn publish(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<ServiceGroupPublicationRequest>) -> Result<Json<ServiceGroupPublicationGrant>,ApiError> {
    let token = access(&headers)?;
    let check = token.clone();
    let actor = state.db(move |store|store.authenticate(&check,now()?)).await?;
    state.limit(&format!("services/publish/{}",actor.session_id))?;
    let life = state.service_lifecycle.clone();
    let signer = state.service_signer.clone();
    let issue = state.db(move |store| {
        let at = now_ms()?;
        let actor = store.authenticate(&token,at/1000)?;
        store.publish_service_group(&life,&actor,&id,body,&signer,at)
    }).await?;
    Ok(Json(group_grant(&state,issue)?))
}
pub(crate) async fn inspect(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Result<Json<ServiceGroupPublicationGrant>,ApiError> {
    let token = access(&headers)?;
    let life = state.service_lifecycle.clone();
    let issue = state.db(move |store| {
        let at = now_ms()?;
        let actor = store.authenticate(&token,at/1000)?;
        store.service_group_publication(&life,&actor,&id,at)
    }).await?;
    Ok(Json(group_grant(&state,issue)?))
}
pub(crate) async fn stop(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<ServiceGroupPublicationRequest>) -> Result<StatusCode,ApiError> {
    let token = access(&headers)?;
    state.db(move |store| {
        let at = now_ms()?;
        let actor = store.authenticate(&token,at/1000)?;
        store.stop_service_group_publication(&actor,&id,body,at)
    }).await?;
    Ok(StatusCode::NO_CONTENT)
}
