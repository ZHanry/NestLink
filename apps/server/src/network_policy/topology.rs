//! Signed node observations and account-scoped topology management.
use super::*;
use nestlink_identity::network_topology::{
    SignedTopologyAdvertisement, SignedTopologyPublisher, SignedTopologyReport,
    SignedTopologyUpdate,
};
use nestlink_storage::network_policy::topology::{TopologyPublisherRequest, TopologyQuery};
use std::time::Duration;

pub(crate) async fn issue(
    State(state): State<AppState>, headers: HeaderMap,
    Path((space,node)): Path<(String,String)>, Json(body): Json<TopologyPublisherRequest>,
) -> Result<(StatusCode,Json<SignedTopologyPublisher>),ApiError> {
    let token = member_access(&state,&headers,MemberOperation::Issue).await?;
    let signer = state.network_signer.clone();
    let signed = state.db(move |store| {
        let now = now_ms()?;
        let actor = store.authenticate(&token,now/1000)?;
        let signer = store.network_authority_signer(&signer,&space,now)?;
        store.issue_topology_publisher(&actor,&signer,&space,&node,body,now)
    }).await?;
    Ok((StatusCode::CREATED,Json(signed)))
}

pub(crate) async fn publisher(
    State(state): State<AppState>, headers: HeaderMap,
    Path((space,node)): Path<(String,String)>,
) -> Result<Json<SignedTopologyPublisher>,ApiError> {
    let token = member_access(&state,&headers,MemberOperation::Observe).await?;
    Ok(Json(state.db(move |store| {
        let now = now_ms()?;
        let actor = store.authenticate(&token,now/1000)?;
        store.topology_publisher(&actor,&space,&node,now)
    }).await?))
}

pub(crate) async fn revoke(
    State(state): State<AppState>, headers: HeaderMap,
    Path((space,node)): Path<(String,String)>,
) -> Result<StatusCode,ApiError> {
    let token = member_access(&state,&headers,MemberOperation::Revoke).await?;
    state.db(move |store| {
        let now = now_ms()?;
        let actor = store.authenticate(&token,now/1000)?;
        store.revoke_topology_publisher(&actor,&space,&node,now)
    }).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn report(
    State(state): State<AppState>, Path((space,node)): Path<(String,String)>,
    Json(signed): Json<SignedTopologyReport>,
) -> Result<Json<SignedTopologyAdvertisement>,ApiError> {
    let signer = state.network_signer.clone();
    let advertisement = tokio::time::timeout(Duration::from_millis(700),state.db(move |store| {
        let now = now_ms()?;
        let signer = store.network_authority_signer(&signer,&space,now)?;
        store.accept_topology_report(&signer,&space,&node,&signed,now)
    })).await.map_err(|_|ApiError(StatusCode::SERVICE_UNAVAILABLE,ErrorCode::InternalError))??;
    Ok(Json(advertisement))
}

pub(crate) async fn query(
    State(state): State<AppState>, headers: HeaderMap, Path(space): Path<String>,
    Json(query): Json<TopologyQuery>,
) -> Result<Json<SignedTopologyUpdate>,ApiError> {
    let token = member_access(&state,&headers,MemberOperation::Observe).await?;
    let signer = state.network_signer.clone();
    let update = tokio::time::timeout(Duration::from_millis(700),state.db(move |store| {
        let now = now_ms()?;
        let actor = store.authenticate(&token,now/1000)?;
        let signer = store.network_authority_signer(&signer,&space,now)?;
        store.topology_update(&actor,&signer,&space,query,now)
    })).await.map_err(|_|ApiError(StatusCode::SERVICE_UNAVAILABLE,ErrorCode::InternalError))??;
    Ok(Json(update))
}
