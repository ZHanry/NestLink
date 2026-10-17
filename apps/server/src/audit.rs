use crate::{ApiError, AppState, access, now};
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use nestlink_protocol::api::{AuditPage, AuditQuery, AuditRetention, AuditRetentionUpdate};
use nestlink_storage::StorageError;

pub(crate) async fn query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditPage>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            Ok(Json(s.query_audit(&actor, query, now()?)?))
        })
        .await
}
pub(crate) async fn retention(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AuditRetention>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            Ok(Json(s.audit_retention(&actor, now()?)?))
        })
        .await
}
pub(crate) async fn configure(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(update): Json<AuditRetentionUpdate>,
) -> Result<Json<AuditRetention>, ApiError> {
    let token = access(&headers)?;
    state
        .db(move |s| {
            let actor = s.authenticate(&token, now()?)?;
            Ok(Json(s.set_audit_retention(&actor, update, now()?)?))
        })
        .await
}
impl AppState {
    /// Owned by the control-service lifetime. Capacity exhaustion skips this
    /// tick; integrity/clock/database failures return to the service supervisor.
    pub async fn run_audit_maintenance(&self) -> Result<(), StorageError> {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let permit = match self.work.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(tokio::sync::TryAcquireError::NoPermits) => continue,
                Err(tokio::sync::TryAcquireError::Closed) => {
                    return Err(StorageError::Invalid("audit work budget closed"));
                }
            };
            let store = self.store.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let mut store = store
                    .lock()
                    .map_err(|_| StorageError::Invalid("audit database mutex poisoned"))?;
                store.cleanup_audit(now()?, nestlink_storage::auditing::MAX_CLEANUP_ROWS)
            })
            .await
            .map_err(|_| StorageError::Invalid("audit maintenance worker failed"))??;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn maintenance_surfaces_clock_failure_instead_of_silently_stopping()
    -> Result<(), Box<dyn std::error::Error>> {
        let deployment = nestlink_auth::random_id();
        let store = nestlink_storage::Store::in_memory(&deployment)?;
        let bytes = store.snapshot()?;
        let mut db = rusqlite::Connection::open_in_memory()?;
        db.deserialize_read_exact(rusqlite::MAIN_DB, &bytes[..], bytes.len(), false)?;
        db.execute(
            "UPDATE audit_settings SET last_cleanup_at=?1",
            [now()? + 3600],
        )?;
        let data = db.serialize(rusqlite::MAIN_DB)?;
        let store = nestlink_storage::Store::from_snapshot(&data, &deployment)?;
        let state = AppState::new(
            store,
            nestlink_auth::VaultKey::from_bytes([23; 32]),
            nestlink_identity::PermitSigner::generate(),
            "http://127.0.0.1".into(),
            false,
        )?;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            state.run_audit_maintenance(),
        )
        .await?;
        assert!(matches!(
            result,
            Err(StorageError::Invalid(
                "audit maintenance clock moved backwards"
            ))
        ));
        Ok(())
    }
    #[tokio::test]
    async fn closed_work_budget_returns_permanent_maintenance_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = AppState::new(
            nestlink_storage::Store::in_memory(&nestlink_auth::random_id())?,
            nestlink_auth::VaultKey::from_bytes([24; 32]),
            nestlink_identity::PermitSigner::generate(),
            "http://127.0.0.1".into(),
            false,
        )?;
        state.work.close();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            state.run_audit_maintenance(),
        )
        .await?;
        assert!(matches!(
            result,
            Err(StorageError::Invalid("audit work budget closed"))
        ));
        Ok(())
    }
}
