use super::*;
use nestlink_protocol::api::{
    NodeDiscoveryRequest, NodeDiscoveryResponse, NodeEndpointsUpdate, NodeEndpointsView,
    NodeRelayCandidatesResponse,
};
pub(super) async fn endpoints(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<NodeEndpointsView>, ApiError> {
    let token = access(&headers)?;
    Ok(Json(
        state
            .db(move |s| {
                let actor = s.authenticate(&token, now()?)?;
                s.node_endpoints(&actor, &id, now_ms()?)
            })
            .await?,
    ))
}
pub(super) async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(update): Json<NodeEndpointsUpdate>,
) -> Result<Json<NodeEndpointsView>, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let (actor, endpoints) = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            let result = s.set_node_endpoints(&actor, &id, update, now_ms()?)?;
            Ok((actor.account_id, result))
        })
        .await?;
    state.emit(
        "node_endpoints_updated",
        Some(resource),
        Some(vec![actor]),
        json!({"revision":endpoints.revision}),
    );
    Ok(Json(endpoints))
}
pub(super) async fn discover(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<NodeDiscoveryRequest>,
) -> Result<Json<NodeDiscoveryResponse>, ApiError> {
    let token = access(&headers)?;
    let lifecycle = state.relay_lifecycle.clone();
    let claims = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            s.discover_relay_nodes(&lifecycle, &actor, &id, request, now_ms()?)
        })
        .await?;
    Ok(Json(NodeDiscoveryResponse {
        discovery: signed_discovery(&state, &claims)?,
    }))
}

fn signed_discovery(
    state: &AppState,
    claims: &nestlink_protocol::NodeDiscoveryClaims,
) -> Result<String, ApiError> {
    let signed = state
        .signer
        .sign_node_discovery(claims)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?;
    Ok(URL_SAFE_NO_PAD.encode(signed.encode_to_vec()))
}

pub(super) async fn candidates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<NodeDiscoveryRequest>,
) -> Result<Json<NodeRelayCandidatesResponse>, ApiError> {
    let token = access(&headers)?;
    let lifecycle = state.relay_lifecycle.clone();
    let (claims, attributes) = state
        .db(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            store.discover_relay_candidates(&lifecycle, &actor, &id, request, now)
        })
        .await?;
    Ok(Json(NodeRelayCandidatesResponse {
        discovery: signed_discovery(&state, &claims)?,
        attributes,
    }))
}
