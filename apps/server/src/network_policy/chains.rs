use super::*;
use nestlink_protocol::api::{NetworkRemoteRelayChainRequest, NetworkRemoteRelayChainView};
use nestlink_storage::network_policy::{NetworkRemoteRelayChainBundle, NetworkRemoteRelayChainIssuance};

fn view(bundle: NetworkRemoteRelayChainBundle) -> Result<NetworkRemoteRelayChainView, StorageError> {
    let [first, second] = bundle.transits;
    Ok(NetworkRemoteRelayChainView {
        route_id: bundle.route_id, path: path_view(bundle.path)?,
        transits: [grant_view(first)?, grant_view(second)?],
        nodes: bundle.nodes, topology_digests: bundle.topology_digests,
    })
}
pub(crate) async fn issue(
    State(state): State<AppState>, headers: HeaderMap,
    Path((space, request)): Path<(String,String)>, Json(body): Json<NetworkRemoteRelayChainRequest>,
) -> Result<(StatusCode,Json<NetworkRemoteRelayChainView>),ApiError> {
    let token = member_access(&state,&headers,MemberOperation::Issue).await?;
    let signer = state.network_signer.clone();
    let lifecycle = state.relay_lifecycle.clone();
    let result = state.db(move |s| {
        let now = now_ms()?;
        let actor = s.authenticate(&token,now/1000)?;
        let signer = s.network_authority_signer(&signer,&space,now)?;
        view(s.issue_network_remote_chain(&lifecycle,&actor,&signer,NetworkRemoteRelayChainIssuance {
            space_id:space,request_id:request,request:body,
        },now)?)
    }).await?;
    Ok((StatusCode::CREATED,Json(result)))
}
pub(crate) async fn read(
    State(state): State<AppState>,headers:HeaderMap,Path((space,route)):Path<(String,String)>,
) -> Result<Json<NetworkRemoteRelayChainView>,ApiError> {
    let token = member_access(&state,&headers,MemberOperation::Observe).await?;
    let lifecycle = state.relay_lifecycle.clone();
    let result = state.db(move |s| {
        let now = now_ms()?;
        let actor = s.authenticate(&token,now/1000)?;
        view(s.network_remote_chain(&lifecycle,&actor,&space,&route,now)?)
    }).await?;
    Ok(Json(result))
}
pub(crate) async fn revoke(
    State(state):State<AppState>,headers:HeaderMap,Path((space,route)):Path<(String,String)>,
) -> Result<StatusCode,ApiError> {
    let token = member_access(&state,&headers,MemberOperation::Revoke).await?;
    state.db_revocation(move |s| {
        let now = now_ms()?;
        let actor = s.authenticate(&token,now/1000)?;
        s.revoke_network_remote_chain(&actor,&space,&route,now)
    }).await?;
    Ok(StatusCode::NO_CONTENT)
}
