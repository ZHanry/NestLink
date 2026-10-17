//! Authenticated deployment configuration and endpoint-scoped TURN credentials.
use super::*;
use nestlink_protocol::{
    SignedTurnCredentials,
    api::{
        TurnBindingState, TurnCredentialRequest, TurnEndpointsUpdate, TurnEndpointsView,
        TurnPeerSubmission,
    },
};
use zeroize::Zeroize;

pub(super) async fn endpoints(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<TurnEndpointsView>, ApiError> {
    let token = access(&headers)?;
    Ok(Json(
        state
            .db(move |s| {
                let p = s.authenticate(&token, now()?)?;
                s.turn_endpoints(&p, &id, now_ms()?)
            })
            .await?,
    ))
}
pub(super) async fn configure(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(update): Json<TurnEndpointsUpdate>,
) -> Result<Json<TurnEndpointsView>, ApiError> {
    let token = access(&headers)?;
    Ok(Json(
        state
            .db(move |s| {
                let p = s.authenticate(&token, now()?)?;
                s.set_turn_endpoints(&p, &id, update, now_ms()?)
            })
            .await?,
    ))
}
pub(super) async fn credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<TurnCredentialRequest>,
) -> Result<Json<SignedTurnCredentials>, ApiError> {
    let token = access(&headers)?;
    let lifecycle = state.relay_lifecycle.clone();
    let vault = state.vault.clone();
    let mut c = state
        .db(move |s| {
            let p = s.authenticate(&token, now()?)?;
            s.turn_credentials(&lifecycle, &vault, &p, &id, &request, now_ms()?)
        })
        .await?;
    let signed = state.signer.sign_turn_credentials(&c);
    c.password.zeroize();
    Ok(Json(signed.map_err(|_| {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError)
    })?))
}
pub(super) async fn peers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<TurnBindingState>, ApiError> {
    let token = access(&headers)?;
    Ok(Json(
        state
            .db(move |s| {
                let p = s.authenticate(&token, now()?)?;
                s.turn_binding_state(&p, &id, now_ms()?)
            })
            .await?,
    ))
}
pub(super) async fn prove_peers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(proof): Json<TurnPeerSubmission>,
) -> Result<Json<TurnBindingState>, ApiError> {
    let token = access(&headers)?;
    Ok(Json(
        state
            .db(move |s| {
                let p = s.authenticate(&token, now()?)?;
                s.submit_turn_peers(&p, &id, &proof, now_ms()?)
            })
            .await?,
    ))
}
