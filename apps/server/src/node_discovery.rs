use super::*;
use nestlink_protocol::api::{
    NodeDiscoveryRequest, NodeDiscoveryResponse, NodeEndpointsUpdate, NodeEndpointsView,
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
    let signed = state
        .signer
        .sign_node_discovery(&claims)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError))?;
    Ok(Json(NodeDiscoveryResponse {
        discovery: URL_SAFE_NO_PAD.encode(signed.encode_to_vec()),
    }))
}
