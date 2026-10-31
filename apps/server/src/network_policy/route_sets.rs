//! Atomic candidate reservation/readback only; no route-switching endpoint.
use super::*;
use nestlink_protocol::api::{
    NetworkRemoteRouteSetMemberView, NetworkRemoteRouteSetRequest, NetworkRemoteRouteSetView,
};
use nestlink_storage::network_policy::{
    NetworkRemoteRouteSetBundle, NetworkRemoteRouteSetIssuance,
};

fn view(bundle: NetworkRemoteRouteSetBundle) -> Result<NetworkRemoteRouteSetView, StorageError> {
    let member = |member: nestlink_storage::network_policy::NetworkRemoteRouteSetMemberBundle| -> Result<NetworkRemoteRouteSetMemberView, StorageError> {
        Ok(NetworkRemoteRouteSetMemberView { allocation_id: member.allocation_id, transit: grant_view(member.transit)?, node: member.node, available: member.available })
    };
    let [first, second] = bundle.members;
    Ok(NetworkRemoteRouteSetView {
        set_id: bundle.set_id,
        path: path_view(bundle.path)?,
        members: [member(first)?, member(second)?],
    })
}
pub(crate) async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, request)): Path<(String, String)>,
    Json(body): Json<NetworkRemoteRouteSetRequest>,
) -> Result<(StatusCode, Json<NetworkRemoteRouteSetView>), ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Issue).await?;
    let signer = state.network_signer.clone();
    let lifecycle = state.relay_lifecycle.clone();
    let result = state
        .db(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            let signer = store.network_authority_signer(&signer, &space, now)?;
            view(store.issue_network_remote_route_set(
                &lifecycle,
                &actor,
                &signer,
                NetworkRemoteRouteSetIssuance {
                    space_id: space,
                    request_id: request,
                    request: body,
                },
                now,
            )?)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(result)))
}
pub(crate) async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, set)): Path<(String, String)>,
) -> Result<Json<NetworkRemoteRouteSetView>, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Observe).await?;
    let lifecycle = state.relay_lifecycle.clone();
    let result = state
        .db(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            view(store.network_remote_route_set(&lifecycle, &actor, &space, &set, now)?)
        })
        .await?;
    Ok(Json(result))
}
pub(crate) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((space, set)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let token = member_access(&state, &headers, MemberOperation::Revoke).await?;
    state
        .db_revocation(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            store.revoke_network_remote_route_set(&actor, &space, &set, now)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
