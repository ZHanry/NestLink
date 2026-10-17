use super::*;
use nestlink_protocol::api::NativeDiscoveryConfig;

pub(super) async fn configuration(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NativeDiscoveryConfig>, ApiError> {
    let token = access(&headers)?;
    let deployment_id = state
        .db(move |store| {
            store.authenticate(&token, now()?)?;
            store.deployment_id()
        })
        .await?;
    Ok(Json(NativeDiscoveryConfig {
        deployment_id,
        stun_servers: state.stun_servers.as_ref().clone(),
    }))
}
