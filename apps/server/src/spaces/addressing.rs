//! Account-authenticated directory endpoints; no DNS or traffic admission.
use super::{ApiError, AppState, HeaderMap, Json, Path, State, authenticated, now_ms};
use nestlink_protocol::spaces::addressing::*;

pub(crate) async fn list(
    State(state): State<AppState>, headers: HeaderMap, Path(space): Path<String>,
) -> Result<Json<SpaceAddressDirectory>, ApiError> {
    let token = authenticated(&state,&headers).await?;
    Ok(Json(state.db(move |s| {
        let now = now_ms()?;
        let actor = s.authenticate(&token,now / 1000)?;
        s.space_address_directory(&actor,&space,now)
    }).await?))
}

pub(crate) async fn issue(
    State(state): State<AppState>, headers: HeaderMap, Path(space): Path<String>,
    Json(request): Json<SpaceAddressIssue>,
) -> Result<Json<SpaceAddressDirectory>, ApiError> {
    let token = authenticated(&state,&headers).await?;
    Ok(Json(state.db(move |s| {
        let now = now_ms()?;
        let actor = s.authenticate(&token,now / 1000)?;
        s.issue_space_address(&actor,&space,request,now)
    }).await?))
}

pub(crate) async fn reserve(
    State(state): State<AppState>, headers: HeaderMap, Path((space,installation)): Path<(String,String)>,
    Json(request): Json<SpaceAddressReservation>,
) -> Result<Json<SpaceAddressDirectory>, ApiError> {
    let token = authenticated(&state,&headers).await?;
    Ok(Json(state.db(move |s| {
        let now = now_ms()?;
        let actor = s.authenticate(&token,now / 1000)?;
        s.reserve_space_address(&actor,&space,&installation,request,now)
    }).await?))
}

pub(crate) async fn rename(
    State(state): State<AppState>, headers: HeaderMap, Path((space,installation)): Path<(String,String)>,
    Json(request): Json<SpaceAddressRename>,
) -> Result<Json<SpaceAddressDirectory>, ApiError> {
    let token = authenticated(&state,&headers).await?;
    Ok(Json(state.db(move |s| {
        let now = now_ms()?;
        let actor = s.authenticate(&token,now / 1000)?;
        s.rename_space_address(&actor,&space,&installation,request,now)
    }).await?))
}

pub(crate) async fn revoke(
    State(state): State<AppState>, headers: HeaderMap, Path((space,installation)): Path<(String,String)>,
    Json(request): Json<SpaceAddressRevocation>,
) -> Result<Json<SpaceAddressDirectory>, ApiError> {
    let token = authenticated(&state,&headers).await?;
    Ok(Json(state.db(move |s| {
        let now = now_ms()?;
        let actor = s.authenticate(&token,now / 1000)?;
        s.revoke_space_address(&actor,&space,&installation,request,now)
    }).await?))
}
