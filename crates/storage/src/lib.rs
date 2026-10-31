//! A new local SQLite namespace; no legacy migrations or imported credentials.
use nestlink_policy::NetworkPolicy;
use nestlink_protocol::valid_id;
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use std::{path::Path, time::Duration};

pub const APPLICATION_ID: i32 = 1_313_622_833;
pub const SCHEMA_VERSION: i32 = 43;
const MIGRATION: &str = include_str!("../migrations/001_initial.sql");
const CONTROL_MIGRATION: &str = include_str!("../migrations/002_control.sql");
const SCOPES_MIGRATION: &str = include_str!("../migrations/003_policy_scopes.sql");
const SIGNAL_MIGRATION: &str = include_str!("../migrations/004_signaling.sql");
const NODES_MIGRATION: &str = include_str!("../migrations/005_data_nodes.sql");
const TRUST_MIGRATION: &str = include_str!("../migrations/006_device_trust.sql");
const PASSWORD_MIGRATION: &str = include_str!("../migrations/007_remote_password.sql");
const AUDIT_MIGRATION: &str = include_str!("../migrations/008_audit_retention.sql");
const ACTOR_MIGRATION: &str = include_str!("../migrations/009_audit_actor.sql");
const QUOTA_MIGRATION: &str = include_str!("../migrations/010_relay_quotas.sql");
const NODE_USAGE_MIGRATION: &str = include_str!("../migrations/011_node_usage.sql");
const RESERVATION_MIGRATION: &str = include_str!("../migrations/012_relay_reservations.sql");
const NODE_ENDPOINTS_MIGRATION: &str = include_str!("../migrations/013_node_endpoints.sql");
const RECONNECTION_MIGRATION: &str = include_str!("../migrations/014_reconnections.sql");
const RELAY_CLOSE_MIGRATION: &str = include_str!("../migrations/015_relay_close.sql");
const BROWSER_ENDPOINT_MIGRATION: &str =
    include_str!("../migrations/016_browser_endpoint_expiry.sql");
const TURN_MIGRATION: &str = include_str!("../migrations/017_managed_turn.sql");
const SERVICES_MIGRATION: &str = include_str!("../migrations/018_service_registry.sql");
const SERVICE_PUBLICATION_MIGRATION: &str =
    include_str!("../migrations/019_service_publications.sql");
const SERVICE_USAGE_MIGRATION: &str =
    include_str!("../migrations/020_service_usage_accounting.sql");
pub mod accounts;
pub mod auditing;
pub mod browser_readiness;
pub mod control;
pub mod media_authority;
pub mod network_policy;
pub mod node_discovery;
pub mod node_relay_attributes;
pub mod node_resources;
pub mod node_usage;
pub mod nodes;
pub mod quotas;
pub mod reconnection;
pub mod relay_close;
pub mod relay_reservations;
pub mod remote_password;
pub mod scopes;
pub mod services;
pub mod signaling;
pub mod snapshot;
pub mod spaces;
pub mod trusted;
pub mod turn;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("authentication required")]
    Unauthorized,
    #[error("permission required")]
    Forbidden,
    #[error("operation conflicts with current state")]
    Conflict,
    #[error("retry later")]
    RateLimited,
    #[error("authentication operation failed")]
    Auth(#[from] nestlink_auth::AuthError),
    #[error("identity proof invalid")]
    Proof(#[from] nestlink_protocol::ContractError),
    #[error("SQLite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("policy serialization: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(&'static str),
}

pub struct Store {
    connection: Connection,
    internal_software_media_candidate: Option<
        nestlink_protocol::internal_software_media_candidate::InternalSoftwareMediaCandidate,
    >,
    #[cfg(test)]
    media_regression_requests: std::collections::BTreeSet<String>,
}

impl Store {
    pub fn open(path: &Path, deployment_id: &str) -> Result<Self, StorageError> {
        Self::initialize(
            file_connection::open_file(path, OpenFlags::default())?,
            deployment_id,
        )
    }
    /// Existing deployments must never silently recreate a missing database.
    pub fn open_existing(path: &Path, deployment_id: &str) -> Result<Self, StorageError> {
        let connection = file_connection::open_file(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let app: i32 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        if app != APPLICATION_ID {
            return Err(StorageError::Invalid(
                "existing database namespace is missing or foreign",
            ));
        }
        Self::initialize(connection, deployment_id)
    }
    pub fn in_memory(deployment_id: &str) -> Result<Self, StorageError> {
        Self::initialize(Connection::open_in_memory()?, deployment_id)
    }
    fn initialize(mut connection: Connection, deployment_id: &str) -> Result<Self, StorageError> {
        require_id(deployment_id)?;
        let application_id: i32 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i32 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let tables: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        if application_id != APPLICATION_ID && (application_id != 0 || version != 0 || tables != 0)
        {
            return Err(StorageError::Invalid(
                "refusing a foreign or legacy database",
            ));
        }
        if application_id == APPLICATION_ID && !(1..=SCHEMA_VERSION).contains(&version) {
            return Err(StorageError::Invalid(
                "unsupported NestLink database version",
            ));
        }
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        if application_id == 0 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(MIGRATION)?;
            transaction.execute(
                "INSERT INTO deployment VALUES(1, ?1, ?2, 1, ?3)",
                params![
                    deployment_id,
                    fresh_epoch(),
                    serde_json::to_string(&NetworkPolicy::default())?
                ],
            )?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", 1)?;
            transaction.commit()?;
        }
        let actual_id: String =
            connection.query_row("SELECT id FROM deployment WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        if actual_id != deployment_id {
            return Err(StorageError::Invalid(
                "database belongs to a different deployment",
            ));
        }
        if version < 2 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(CONTROL_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 2)?;
            transaction.commit()?;
        }
        if version < 3 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(SCOPES_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 3)?;
            transaction.commit()?;
        }
        if version < 4 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(SIGNAL_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 4)?;
            transaction.commit()?;
        }
        if version < 5 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(NODES_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 5)?;
            transaction.commit()?;
        }
        if version < 6 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(TRUST_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 6)?;
            transaction.commit()?;
        }
        if version < 7 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(PASSWORD_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 7)?;
            transaction.commit()?;
        }
        if version < 8 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(AUDIT_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 8)?;
            transaction.commit()?;
        }
        if version < 9 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(ACTOR_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 9)?;
            transaction.commit()?;
        }
        if version < 10 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(QUOTA_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 10)?;
            transaction.commit()?;
        }
        if version < 11 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(NODE_USAGE_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 11)?;
            transaction.commit()?;
        }
        if version < 12 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(RESERVATION_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 12)?;
            transaction.commit()?;
        }
        if version < 13 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(NODE_ENDPOINTS_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 13)?;
            transaction.commit()?;
        }
        if version < 14 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(RECONNECTION_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 14)?;
            transaction.commit()?;
        }
        if version < 15 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(RELAY_CLOSE_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 15)?;
            transaction.commit()?;
        }
        if version < 16 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(BROWSER_ENDPOINT_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 16)?;
            transaction.commit()?;
        }
        if version < 17 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(TURN_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 17)?;
            transaction.commit()?;
        }
        if version < 18 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(SERVICES_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 18)?;
            transaction.commit()?;
        }
        if version < 19 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(SERVICE_PUBLICATION_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 19)?;
            transaction.commit()?;
        }
        if version < 20 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(SERVICE_USAGE_MIGRATION)?;
            transaction.pragma_update(None, "user_version", 20)?;
            transaction.commit()?;
        }
        if version < 21 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!("../migrations/021_password_only.sql"))?;
            transaction.pragma_update(None, "user_version", 21)?;
            transaction.commit()?;
        }
        if version < 22 {
            let transaction = connection.transaction()?;
            transaction
                .execute_batch(include_str!("../migrations/022_browser_host_readiness.sql"))?;
            transaction.pragma_update(None, "user_version", 22)?;
            transaction.commit()?;
        }
        // Schema 20 has not shipped yet, but local v20 development databases
        // may predate the restore fence added to its migration. Never let
        // those databases reach publication with a missing safety column.
        let has_service_quota_restore_fence: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('service_quota_settings') WHERE name='restore_fenced')",
            [],
            |row| row.get(0),
        )?;
        if !has_service_quota_restore_fence {
            let transaction = connection.transaction()?;
            transaction.execute(
                "ALTER TABLE service_quota_settings ADD COLUMN restore_fenced INTEGER NOT NULL DEFAULT 0 CHECK(restore_fenced IN (0,1))",
                [],
            )?;
            transaction.commit()?;
        }
        if version < 23 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!("../migrations/023_refresh_receipts.sql"))?;
            transaction.pragma_update(None, "user_version", 23)?;
            transaction.commit()?;
        }
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        if version < 24 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!("../migrations/024_setup_features.sql"))?;
            transaction.pragma_update(None, "user_version", 24)?;
            transaction.commit()?;
        }
        if version < 25 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!("../migrations/025_media_authority.sql"))?;
            transaction.pragma_update(None, "user_version", 25)?;
            transaction.commit()?;
        }
        if version < 26 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!("../migrations/026_network_policy.sql"))?;
            transaction.pragma_update(None, "user_version", 26)?;
            transaction.commit()?;
        }
        if version < 27 {
            let transaction = connection.transaction()?;
            transaction
                .execute_batch(include_str!("../migrations/027_network_remote_paths.sql"))?;
            transaction.pragma_update(None, "user_version", 27)?;
            transaction.commit()?;
        }
        if version < 28 {
            let transaction = connection.transaction()?;
            transaction
                .execute_batch(include_str!("../migrations/028_network_remote_relays.sql"))?;
            transaction.pragma_update(None, "user_version", 28)?;
            transaction.commit()?;
        }
        if version < 29 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!("../migrations/029_network_spaces.sql"))?;
            transaction.pragma_update(None, "user_version", 29)?;
            transaction.commit()?;
        }
        if version < 30 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!(
                "../migrations/030_network_authority_lifecycle.sql"
            ))?;
            transaction.pragma_update(None, "user_version", 30)?;
            transaction.commit()?;
        }
        if version < 31 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!(
                "../migrations/031_space_service_publication_acl.sql"
            ))?;
            transaction.pragma_update(None, "user_version", 31)?;
            transaction.commit()?;
        }
        if version < 32 {
            let transaction = connection.transaction()?;
            transaction
                .execute_batch(include_str!("../migrations/032_node_relay_attributes.sql"))?;
            transaction.pragma_update(None, "user_version", 32)?;
            transaction.commit()?;
        }
        if version < 33 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!("../migrations/033_network_topology.sql"))?;
            transaction.pragma_update(None, "user_version", 33)?;
            transaction.commit()?;
        }
        if version < 34 {
            let transaction = connection.transaction()?;
            transaction
                .execute_batch(include_str!("../migrations/034_network_remote_chains.sql"))?;
            transaction.pragma_update(None, "user_version", 34)?;
            transaction.commit()?;
        }
        if version < 35 {
            let transaction = connection.transaction()?;
            transaction
                .execute_batch(include_str!("../migrations/035_network_route_exports.sql"))?;
            transaction.pragma_update(None, "user_version", 35)?;
            transaction.commit()?;
        }
        if version < 36 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!(
                "../migrations/036_network_chain_topology_continuity.sql"
            ))?;
            transaction.pragma_update(None, "user_version", 36)?;
            transaction.commit()?;
        }
        if version < 37 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!(
                "../migrations/037_network_remote_route_sets.sql"
            ))?;
            transaction.pragma_update(None, "user_version", 37)?;
            transaction.commit()?;
        }
        if version < 38 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!("../migrations/038_space_addressing.sql"))?;
            transaction.pragma_update(None, "user_version", 38)?;
            transaction.commit()?;
        }
        if version < 39 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!("../migrations/039_private_services.sql"))?;
            transaction.pragma_update(None, "user_version", 39)?;
            transaction.commit()?;
        }
        if version < 40 {
            // This must be outside a transaction. Renaming the old parent table
            // would rewrite child foreign keys to the temporary table name.
            connection.pragma_update(None, "foreign_keys", "OFF")?;
            let migrated = (|| -> Result<(), StorageError> {
                let transaction = connection.transaction()?;
                transaction.execute_batch(include_str!(
                    "../migrations/040_private_service_host_accounting.sql"
                ))?;
                if transaction
                    .prepare("PRAGMA foreign_key_check")?
                    .exists([])?
                {
                    return Err(StorageError::Invalid(
                        "service migration foreign key failure",
                    ));
                }
                transaction.pragma_update(None, "user_version", 40)?;
                transaction.commit()?;
                Ok(())
            })();
            connection.pragma_update(None, "foreign_keys", "ON")?;
            migrated?;
        }
        if version < 41 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(include_str!(
                "../migrations/041_private_service_network_path.sql"
            ))?;
            transaction.pragma_update(None, "user_version", 41)?;
            transaction.commit()?;
        }
        if version < 42 {
            let transaction = connection.transaction()?;
            transaction
                .execute_batch(include_str!("../migrations/042_private_service_relays.sql"))?;
            transaction.pragma_update(None, "user_version", 42)?;
            transaction.commit()?;
        }
        if version < 43 {
            let transaction = connection.transaction()?;
            transaction
                .execute_batch(include_str!("../migrations/043_network_packet_access.sql"))?;
            transaction.pragma_update(None, "user_version", 43)?;
            transaction.commit()?;
        }
        Ok(Self {
            connection,
            internal_software_media_candidate: None,
            #[cfg(test)]
            media_regression_requests: std::collections::BTreeSet::new(),
        })
    }

    pub fn security_epoch(&self) -> Result<u64, StorageError> {
        Ok(self.connection.query_row(
            "SELECT security_epoch FROM deployment WHERE singleton=1",
            [],
            |r| r.get(0),
        )?)
    }
    pub fn policy(&self) -> Result<(u64, NetworkPolicy), StorageError> {
        let (revision, json): (u64, String) = self.connection.query_row(
            "SELECT policy_revision, policy_json FROM deployment WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let policy: NetworkPolicy = serde_json::from_str(&json)?;
        policy
            .validate()
            .map_err(|_| StorageError::Invalid("stored policy is invalid"))?;
        Ok((revision, policy))
    }
    pub fn apply_policy(
        &mut self,
        expected_revision: u64,
        policy: NetworkPolicy,
    ) -> Result<u64, StorageError> {
        self.apply_policy_with(None, expected_revision, policy)
    }
    pub fn apply_policy_as(
        &mut self,
        actor: &accounts::Principal,
        now: u64,
        expected_revision: u64,
        policy: NetworkPolicy,
    ) -> Result<u64, StorageError> {
        self.apply_policy_with(Some((actor, now)), expected_revision, policy)
    }
    fn apply_policy_with(
        &mut self,
        actor: Option<(&accounts::Principal, u64)>,
        expected_revision: u64,
        policy: NetworkPolicy,
    ) -> Result<u64, StorageError> {
        policy
            .validate()
            .map_err(|_| StorageError::Invalid("illegal network policy combination"))?;
        let revision = expected_revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StorageError::Invalid("policy revision exhausted"))?;
        let transaction = self.connection.unchecked_transaction()?;
        if let Some((principal, now)) = actor {
            self.audit_admin(principal, now)?;
        }
        let updated = transaction.execute("UPDATE deployment SET policy_json=?1, policy_revision=?2 WHERE singleton=1 AND policy_revision=?3",
            params![serde_json::to_string(&policy)?, revision, expected_revision])?;
        if updated != 1 {
            return Err(StorageError::Invalid("policy changed concurrently"));
        }
        network_policy::invalidate_all(&transaction)?;
        // Current leases cannot retain the previous policy revision.
        transaction.execute("UPDATE leases SET revoked=1", [])?;
        transaction.execute("UPDATE sessions SET revoked=1", [])?;
        transaction.execute(
            "UPDATE remote_requests SET status='revoked' WHERE status IN ('pending','approved')",
            [],
        )?;
        audit(
            &transaction,
            "policy_changed",
            "deployment",
            actor.map_or(
                nestlink_protocol::api::AuditActor::LocalOperator,
                |(p, _)| auditing::management(p),
            ),
        )?;
        transaction.commit()?;
        Ok(revision)
    }
    pub fn add_account(&mut self, id: &str, name: &str) -> Result<(), StorageError> {
        require_id(id)?;
        if name.is_empty() || name.len() > 128 {
            return Err(StorageError::Invalid("invalid account name"));
        }
        self.connection.execute(
            "INSERT INTO accounts(id,name) VALUES(?1,?2)",
            params![id, name],
        )?;
        Ok(())
    }
    pub fn add_device(
        &mut self,
        id: &str,
        account_id: &str,
        key_sha256: &[u8; 32],
    ) -> Result<(), StorageError> {
        require_id(id)?;
        require_id(account_id)?;
        let inserted = self.connection.execute("INSERT INTO devices(id,account_id,key_sha256) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM accounts WHERE id=?2 AND disabled=0)", params![id,account_id,key_sha256])?;
        if inserted != 1 {
            return Err(StorageError::Invalid("account unavailable"));
        }
        Ok(())
    }
    pub fn register_credential(
        &mut self,
        id: &str,
        device_id: &str,
        purpose: &str,
        token_sha256: &[u8; 32],
    ) -> Result<(), StorageError> {
        require_id(id)?;
        require_id(device_id)?;
        let changed = self.connection.execute("INSERT INTO credentials(id,device_id,purpose,token_sha256,generation) SELECT ?1,?2,?3,?4,1 WHERE EXISTS(SELECT 1 FROM devices d JOIN accounts a ON a.id=d.account_id WHERE d.id=?2 AND d.revoked=0 AND d.expires_at IS NULL AND a.disabled=0)", params![id,device_id,purpose,token_sha256])?;
        if changed != 1 {
            return Err(StorageError::Invalid("device unavailable"));
        }
        Ok(())
    }
    pub fn rotate_credential(
        &mut self,
        id: &str,
        device_id: &str,
        purpose: &str,
        expected_generation: u64,
        old_token_sha256: &[u8; 32],
        new_token_sha256: &[u8; 32],
    ) -> Result<u64, StorageError> {
        if old_token_sha256 == new_token_sha256 {
            return Err(StorageError::Invalid("refresh must replace token"));
        }
        let next = expected_generation
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StorageError::Invalid("credential generation exhausted"))?;
        let transaction = self.connection.transaction()?;
        let changed = transaction.execute("UPDATE credentials SET token_sha256=?1,generation=?2 WHERE id=?3 AND device_id=?4 AND purpose=?5 AND generation=?6 AND token_sha256=?7 AND revoked=0 AND EXISTS(SELECT 1 FROM devices d JOIN accounts a ON a.id=d.account_id WHERE d.id=?4 AND d.revoked=0 AND d.expires_at IS NULL AND a.disabled=0)",
            params![new_token_sha256,next,id,device_id,purpose,expected_generation,old_token_sha256])?;
        if changed != 1 {
            return Err(StorageError::Invalid(
                "stale, revoked or mismatched credential",
            ));
        }
        let account_id: String = transaction.query_row(
            "SELECT account_id FROM devices WHERE id=?1",
            [device_id],
            |r| r.get(0),
        )?;
        audit(
            &transaction,
            "credential_rotated",
            id,
            nestlink_protocol::api::AuditActor::DeviceCredential {
                account_id,
                device_id: device_id.into(),
            },
        )?;
        transaction.commit()?;
        Ok(next)
    }
    // Session approval is a separate upstream operation; ownership is not approval.
    pub fn register_approved_session(
        &mut self,
        id: &str,
        controller: &str,
        host: &str,
    ) -> Result<(), StorageError> {
        require_id(id)?;
        require_id(controller)?;
        require_id(host)?;
        let changed = self.connection.execute("INSERT INTO sessions(id,controller_device_id,host_device_id,connection_generation) SELECT ?1,?2,?3,1 WHERE (SELECT count(*) FROM devices d JOIN accounts a ON a.id=d.account_id WHERE d.id IN (?2,?3) AND d.revoked=0 AND d.expires_at IS NULL AND a.disabled=0)=2", params![id,controller,host])?;
        if changed != 1 {
            return Err(StorageError::Invalid("session endpoints unavailable"));
        }
        Ok(())
    }
    pub fn add_lease(&mut self, id: &str, session_id: &str) -> Result<(), StorageError> {
        require_id(id)?;
        require_id(session_id)?;
        let changed = self.connection.execute("INSERT INTO leases(id,session_id,security_epoch) SELECT ?1,?2,security_epoch FROM deployment WHERE singleton=1 AND EXISTS(SELECT 1 FROM sessions s JOIN devices c ON c.id=s.controller_device_id JOIN devices h ON h.id=s.host_device_id WHERE s.id=?2 AND s.revoked=0 AND c.expires_at IS NULL AND h.expires_at IS NULL)", params![id,session_id])?;
        if changed != 1 {
            return Err(StorageError::Invalid("session unavailable"));
        }
        Ok(())
    }
    pub fn revoke_device(
        &mut self,
        request_id: &str,
        device_id: &str,
        account_id: &str,
    ) -> Result<(), StorageError> {
        self.revoke_device_with(None, request_id, device_id, account_id)
    }
    pub fn revoke_device_as(
        &mut self,
        actor: &accounts::Principal,
        request_id: &str,
        device_id: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        self.revoke_device_with(Some((actor, now)), request_id, device_id, &actor.account_id)
    }
    fn revoke_device_with(
        &mut self,
        actor: Option<(&accounts::Principal, u64)>,
        request_id: &str,
        device_id: &str,
        account_id: &str,
    ) -> Result<(), StorageError> {
        require_id(request_id)?;
        require_id(device_id)?;
        require_id(account_id)?;
        let transaction = self.connection.unchecked_transaction()?;
        if let Some((principal, now)) = actor {
            self.validate_access(principal, now)?;
        }
        let resource = format!("{account_id}/{device_id}");
        let previous: Option<(String, String)> = transaction
            .query_row(
                "SELECT operation,resource_id FROM idempotency WHERE request_id=?1",
                [request_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((operation, recorded)) = previous {
            if operation == "revoke_device" && recorded == resource {
                return Ok(());
            }
            return Err(StorageError::Invalid(
                "idempotency key belongs to another operation",
            ));
        }
        if transaction.execute(
            "UPDATE devices SET revoked=1 WHERE id=?1 AND account_id=?2",
            params![device_id, account_id],
        )? != 1
        {
            return Err(StorageError::Invalid("device does not belong to account"));
        }
        transaction.execute(
            "UPDATE credentials SET revoked=1 WHERE device_id=?1",
            [device_id],
        )?;
        transaction.execute(
            "UPDATE sessions SET revoked=1 WHERE controller_device_id=?1 OR host_device_id=?1",
            [device_id],
        )?;
        transaction.execute("UPDATE leases SET revoked=1 WHERE session_id IN (SELECT id FROM sessions WHERE controller_device_id=?1 OR host_device_id=?1)", [device_id])?;
        transaction.execute("UPDATE remote_requests SET status='revoked' WHERE controller_device_id=?1 OR host_device_id=?1",[device_id])?;
        transaction.execute(
            "INSERT INTO idempotency VALUES(?1,'revoke_device',?2,1)",
            params![request_id, resource],
        )?;
        audit(
            &transaction,
            "device_revoked",
            device_id,
            actor.map_or(
                nestlink_protocol::api::AuditActor::LocalOperator,
                |(p, _)| auditing::management(p),
            ),
        )?;
        transaction.commit()?;
        Ok(())
    }
    pub fn session_is_active(&self, id: &str) -> Result<bool, StorageError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        self.session_is_active_at(id, now)
    }
    pub fn session_is_active_at(&self, id: &str, now: u64) -> Result<bool, StorageError> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM sessions s JOIN devices c ON c.id=s.controller_device_id JOIN devices h ON h.id=s.host_device_id JOIN accounts ca ON ca.id=c.account_id JOIN accounts ha ON ha.id=h.account_id WHERE s.id=?1 AND s.revoked=0 AND c.revoked=0 AND h.revoked=0 AND ca.disabled=0 AND ha.disabled=0 AND (c.expires_at IS NULL OR c.expires_at>?2) AND (h.expires_at IS NULL OR h.expires_at>?2))", params![id, now], |r| r.get(0))?)
    }
    pub fn lease_is_active(&self, id: &str) -> Result<bool, StorageError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        self.lease_is_active_at(id, now)
    }
    pub fn lease_is_active_at(&self, id: &str, now: u64) -> Result<bool, StorageError> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM leases l JOIN sessions s ON s.id=l.session_id JOIN devices c ON c.id=s.controller_device_id JOIN devices h ON h.id=s.host_device_id JOIN deployment d ON d.singleton=1 WHERE l.id=?1 AND l.revoked=0 AND s.revoked=0 AND l.security_epoch=d.security_epoch AND (c.expires_at IS NULL OR c.expires_at>?2) AND (h.expires_at IS NULL OR h.expires_at>?2))", params![id, now], |r| r.get(0))?)
    }
    // Invoke in the offline restore transaction before listeners can start.
    pub fn invalidate_after_restore(&mut self) -> Result<u64, StorageError> {
        let transaction = self.connection.transaction()?;
        let old: u64 = transaction.query_row(
            "SELECT security_epoch FROM deployment WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let mut next = fresh_epoch();
        while next == old {
            next = fresh_epoch();
        }
        transaction.execute(
            "UPDATE deployment SET security_epoch=?1 WHERE singleton=1",
            [next],
        )?;
        transaction.execute("UPDATE credentials SET revoked=1", [])?;
        transaction.execute("UPDATE trusted_devices SET revoked=1", [])?;
        transaction.execute("UPDATE remote_passwords SET encoded=NULL", [])?;
        transaction.execute("UPDATE management_sessions SET revoked=1", [])?;
        transaction.execute("UPDATE remote_requests SET status='revoked'", [])?;
        transaction.execute("UPDATE enrollment_challenges SET consumed=1", [])?;
        transaction.execute("UPDATE sessions SET revoked=1", [])?;
        transaction.execute("UPDATE leases SET revoked=1", [])?;
        // A restored snapshot may omit later network revocations and epochs.
        // Keep every historical space closed; recovery needs a new space ID.
        transaction.execute("UPDATE network_authorities SET restore_fenced=1", [])?;
        transaction.execute("DELETE FROM idempotency", [])?;
        // A snapshot predates some consumed codes. None may be revived by rollback.
        transaction.execute("DELETE FROM recovery_codes", [])?;
        transaction.execute("DELETE FROM remote_signals", [])?;
        transaction.execute("DELETE FROM reconnection_offers", [])?;
        transaction.execute("DELETE FROM reconnection_receipts", [])?;
        transaction.execute("DELETE FROM used_node_challenges", [])?;
        transaction.execute("DELETE FROM service_approval_challenges", [])?;
        transaction.execute("UPDATE service_target_approvals SET revoked=1", [])?;
        transaction.execute("UPDATE service_publications SET state=1 WHERE state=0", [])?;
        transaction.execute(
            "UPDATE service_publication_settings SET restore_fenced=1",
            [],
        )?;
        transaction.execute(
            "UPDATE service_quota_settings SET restore_fenced=1 WHERE singleton=1",
            [],
        )?;
        transaction.execute("UPDATE data_nodes SET last_issued_at=0,runtime_id=NULL", [])?;
        transaction.execute("UPDATE relay_reservation_settings SET restore_fenced=1", [])?;
        // A restore may roll back a recently consumed TOTP step. Burn the whole
        // current acceptance window so none of those codes can be replayed.
        transaction.execute("UPDATE account_security SET totp_last_step=MAX(COALESCE(totp_last_step,0),unixepoch()/30+1) WHERE totp_ciphertext IS NOT NULL", [])?;
        // Retain the replay floor for enabled TOTP, but discard unfinished enrollments.
        transaction.execute(
            "UPDATE account_security SET totp_pending=NULL,totp_pending_expires=NULL",
            [],
        )?;
        audit(
            &transaction,
            "restore_epoch_rotated",
            "deployment",
            nestlink_protocol::api::AuditActor::LocalOperator,
        )?;
        transaction.commit()?;
        Ok(next)
    }
    pub fn audit_count(&self) -> Result<u64, StorageError> {
        Ok(self
            .connection
            .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))?)
    }
}

fn fresh_epoch() -> u64 {
    loop {
        let epoch = OsRng.next_u64() & i64::MAX as u64;
        if epoch != 0 {
            return epoch;
        }
    }
}
fn require_id(id: &str) -> Result<(), StorageError> {
    if valid_id(id) {
        Ok(())
    } else {
        Err(StorageError::Invalid("invalid identity UUID"))
    }
}
fn audit(
    transaction: &Transaction<'_>,
    event: &str,
    resource: &str,
    actor: nestlink_protocol::api::AuditActor,
) -> Result<(), StorageError> {
    auditing::record(transaction, event, resource, actor)
}

mod file_connection;
