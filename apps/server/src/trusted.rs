use crate::{ApiError, AppState, access, now};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use nestlink_protocol::api::{
    RemoteRequest, RemoteView, TrustRevocation, TrustSubmission, TrustedDevicesResponse,
};
use serde_json::{Value, json};

pub(crate) async fn connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RemoteRequest>,
) -> Result<(StatusCode, Json<RemoteView>), ApiError> {
    let token = access(&headers)?;
    let check = token.clone();
    let principal = state.db(move |s| s.authenticate(&check, now()?)).await?;
    // Unauthenticated token strings must not allocate rate buckets. A token
    // refresh keeps this login-session bucket instead of resetting the quota.
    state.limit(&format!("trusted/{}", principal.session_id))?;
    let (view, audience) = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            let view = s.create_trusted_remote(&actor, body, now()?)?;
            let audience = s.remote_event_accounts(&view.id)?;
            Ok((view, audience))
        })
        .await?;
    state.emit(
        "approval_changed",
        Some(view.id.clone()),
        Some(audience),
        json!({"authorization":"trusted_device"}),
    );
    Ok((StatusCode::CREATED, Json(view)))
}
pub(crate) async fn grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<TrustSubmission>,
) -> Result<Json<Value>, ApiError> {
    let token = access(&headers)?;
    let resource = id.clone();
    let (revision, audience, revoked) = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            let update = s.trust_remote(&actor, &id, body, now()?)?;
            let revoked = update
                .revoked_sessions
                .into_iter()
                .map(|session| Ok((s.remote_event_accounts(&session)?, session)))
                .collect::<Result<Vec<_>, nestlink_storage::StorageError>>()?;
            Ok((update.revision, s.remote_event_accounts(&id)?, revoked))
        })
        .await?;
    for (audience, id) in revoked {
        state.emit(
            "remote_revoked",
            Some(id),
            Some(audience),
            json!({"reason":"device_trust_changed"}),
        );
    }
    state.emit(
        "device_trust_changed",
        Some(resource),
        Some(audience),
        json!({"revision":revision}),
    );
    Ok(Json(json!({"revision":revision})))
}
pub(crate) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<TrustedDevicesResponse>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            Ok(Json(TrustedDevicesResponse {
                devices: s.trusted_devices(&actor, &id, now()?)?,
            }))
        })
        .await
}
pub(crate) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((host, controller)): Path<(String, String)>,
    Json(body): Json<TrustRevocation>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let revoked = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            let ids =
                s.revoke_device_trust(&actor, &host, &controller, body.expected_revision, now()?)?;
            ids.into_iter()
                .map(|id| Ok((s.remote_event_accounts(&id)?, id)))
                .collect::<Result<Vec<_>, nestlink_storage::StorageError>>()
        })
        .await?;
    for (audience, id) in revoked {
        state.emit(
            "remote_revoked",
            Some(id),
            Some(audience),
            json!({"reason":"device_trust_revoked"}),
        );
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_bearers_cannot_fill_the_shared_trusted_access_rate_cache()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = AppState::new(
            nestlink_storage::Store::in_memory(&nestlink_auth::random_id())?,
            nestlink_auth::VaultKey::from_bytes([15; 32]),
            nestlink_identity::PermitSigner::generate(),
            "http://127.0.0.1".into(),
            false,
        )?;
        for case in 0..64 {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {case:043}").parse()?,
            );
            let result = connect(
                State(state.clone()),
                headers,
                Json(RemoteRequest {
                    id: nestlink_auth::random_id(),
                    controller_device_id: nestlink_auth::random_id(),
                    host_device_id: nestlink_auth::random_id(),
                    permissions: vec![nestlink_protocol::Permission::View as i32],
                    path_mode: "direct_only".into(),
                }),
            )
            .await;
            assert!(matches!(result, Err(ApiError(StatusCode::UNAUTHORIZED, _))));
        }
        assert!(
            state
                .rates
                .lock()
                .map_err(|_| "rate cache poisoned")?
                .is_empty(),
            "invalid bearer strings allocated rate records"
        );
        Ok(())
    }
}
