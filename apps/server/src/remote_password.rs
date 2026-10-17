use crate::{ApiError, AppState, access, now};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use nestlink_protocol::api::{
    RemotePasswordRevocation, RemotePasswordSetup, RemotePasswordSubmission, RemotePasswordView,
    RemoteView, RevisionResponse,
};
use nestlink_storage::{StorageError, Store, remote_password::PasswordUpdate};
use serde_json::json;

async fn limited_token(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = access(headers)?;
    let check = token.clone();
    let principal = state.db(move |s| s.authenticate(&check, now()?)).await?;
    state.limit(&format!("remote-password/{}", principal.session_id))?;
    Ok(token)
}
type Revoked = Vec<(Vec<String>, String)>;
fn audiences(store: &Store, update: PasswordUpdate) -> Result<(u64, Revoked), StorageError> {
    let revoked = update
        .revoked_sessions
        .into_iter()
        .map(|id| Ok((store.remote_event_accounts(&id)?, id)))
        .collect::<Result<Vec<_>, StorageError>>()?;
    Ok((update.revision, revoked))
}
fn emit(state: &AppState, revoked: Revoked) {
    for (audience, id) in revoked {
        state.emit(
            "remote_revoked",
            Some(id),
            Some(audience),
            json!({"reason":"remote_password_changed"}),
        );
    }
}
pub(crate) async fn configure(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(host): Path<String>,
    Json(body): Json<RemotePasswordSetup>,
) -> Result<Json<RevisionResponse>, ApiError> {
    let token = limited_token(&state, &headers).await?;
    let check = token.clone();
    let draft = state
        .db(move |s| {
            let actor = s.authenticate(&check, now()?)?;
            s.prepare_remote_password(&actor, &host, body, now()?)
        })
        .await?;
    let replacement = state.cpu(move || draft.derive()).await?;
    let (revision, revoked) = state
        .db(move |s| {
            s.authenticate(&token, now()?)?;
            let update = s.complete_remote_password(replacement, now()?)?;
            audiences(s, update)
        })
        .await?;
    emit(&state, revoked);
    Ok(Json(RevisionResponse { revision }))
}
pub(crate) async fn inspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(host): Path<String>,
) -> Result<Json<RemotePasswordView>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            Ok(Json(s.remote_password(&actor, &host, now()?)?))
        })
        .await
}
pub(crate) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(host): Path<String>,
    Json(body): Json<RemotePasswordRevocation>,
) -> Result<StatusCode, ApiError> {
    let token = access(&headers)?;
    let (_, revoked) = state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            let update = s.revoke_remote_password(&actor, &host, body.expected_revision, now()?)?;
            audiences(s, update)
        })
        .await?;
    emit(&state, revoked);
    Ok(StatusCode::NO_CONTENT)
}
pub(crate) async fn offer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<RemotePasswordView>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            Ok(Json(s.remote_password_offer(&actor, &id, now()?)?))
        })
        .await
}
pub(crate) async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RemotePasswordSubmission>,
) -> Result<Json<RemoteView>, ApiError> {
    let token = limited_token(&state, &headers).await?;
    let check = token.clone();
    let snapshot = state
        .db(move |s| {
            let actor = s.authenticate(&check, now()?)?;
            s.remote_password_snapshot(&actor, &id, body, now()?)
        })
        .await?;
    let verified = state.cpu(move || Ok(snapshot.verify())).await?;
    let (view, audience) = state
        .db(move |s| {
            s.authenticate(&token, now()?)?;
            let view = s.complete_remote_password_access(verified, now()?)?;
            let audience = s.remote_event_accounts(&view.id)?;
            Ok((view, audience))
        })
        .await?;
    state.emit(
        "approval_changed",
        Some(view.id.clone()),
        Some(audience),
        json!({"authorization":"fixed_password"}),
    );
    Ok(Json(view))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;
    use nestlink_auth::{VaultKey, random_id};
    use nestlink_identity::PermitSigner;
    use nestlink_protocol::api::RemotePasswordAttempt;

    #[tokio::test]
    async fn password_http_budget_rejects_unknown_bearers_and_survives_refresh()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = AppState::new(
            Store::in_memory(&random_id())?,
            VaultKey::from_bytes([19; 32]),
            PermitSigner::generate(),
            "http://127.0.0.1".into(),
            false,
        )?;
        let body = || {
            Json(RemotePasswordSubmission {
                attempt: RemotePasswordAttempt {
                    expected_revision: 1,
                    password: "test-only-remote-password".into(),
                },
                signature: String::new(),
            })
        };
        for case in 0..64 {
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, format!("Bearer {case:043}").parse()?);
            assert!(matches!(
                authorize(State(state.clone()), headers, Path(random_id()), body()).await,
                Err(ApiError(StatusCode::UNAUTHORIZED, _))
            ));
        }
        assert!(state.rates.lock().map_err(|_| "poisoned")?.is_empty());
        let mut grant = {
            let mut store = state.store.lock().map_err(|_| "poisoned")?;
            store.bootstrap_admin("admin", "http-limit-test-password")?;
            store.login(
                "admin",
                "http-limit-test-password",
                None,
                now()?,
                &state.vault,
                &state.dummy_hash,
            )?
        };
        for case in 0..31 {
            if case == 15 {
                grant = state.store.lock().map_err(|_| "poisoned")?.refresh_login(
                    grant.refresh_token.expose(),
                    grant.generation,
                    now()?,
                )?;
            }
            let mut headers = HeaderMap::new();
            headers.insert(
                AUTHORIZATION,
                format!("Bearer {}", grant.access_token.expose()).parse()?,
            );
            let outcome = authorize(State(state.clone()), headers, Path(random_id()), body()).await;
            if case < 30 {
                assert!(matches!(outcome, Err(ApiError(StatusCode::FORBIDDEN, _))));
            } else {
                assert!(matches!(
                    outcome,
                    Err(ApiError(StatusCode::TOO_MANY_REQUESTS, _))
                ));
            }
        }
        assert_eq!(state.rates.lock().map_err(|_| "poisoned")?.len(), 1);
        Ok(())
    }
}
