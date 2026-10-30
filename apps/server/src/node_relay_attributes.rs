use super::*;
use nestlink_protocol::api::{NodeRelayAttributesUpdate, NodeRelayAttributesView};

pub(super) async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<NodeRelayAttributesView>, ApiError> {
    let token = access(&headers)?;
    Ok(Json(
        state
            .db(move |store| {
                let now = now_ms()?;
                let actor = store.authenticate(&token, now / 1000)?;
                store.node_relay_attributes(&actor, &id, now)
            })
            .await?,
    ))
}

pub(super) async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(update): Json<NodeRelayAttributesUpdate>,
) -> Result<Json<NodeRelayAttributesView>, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let (actor, view) = state
        .db(move |store| {
            let now = now_ms()?;
            let actor = store.authenticate(&token, now / 1000)?;
            let view = store.set_node_relay_attributes(&actor, &id, update, now)?;
            Ok((actor.account_id, view))
        })
        .await?;
    state.emit(
        "node_relay_attributes_updated",
        Some(resource),
        Some(vec![actor]),
        json!({"revision": view.revision}),
    );
    Ok(Json(view))
}
