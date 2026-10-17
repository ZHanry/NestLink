//! Durable per-grant highwaters. Every mutation commits with SQLite FULL
//! synchronous durability before the data plane receives an admission result.
use nestlink_identity::{digest, service_plane::VerifiedServiceLease};
use nestlink_protocol::{
    ContractError, ErrorCode,
    service_plane::{
        SERVICE_USAGE_BYTES, ServiceUsageBudgetGrantClaims, ServiceUsageReportAckClaims,
        ServiceUsageReportClaims, ServiceUsageRuntimeStopClaims, SignedServiceUsageBudgetGrant,
        SignedServiceUsageReport, SignedServiceUsageRuntimeStop, decode_service_message,
    },
};
use rusqlite::{Connection, OptionalExtension, params};
use std::{path::Path, sync::Mutex, time::Duration};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("service usage local database failed")]
    Database(#[from] rusqlite::Error),
    #[error("service usage local path is not private")]
    PrivatePath(#[from] std::io::Error),
    #[error("service usage state is missing, corrupt, or inconsistent")]
    Fenced,
}

pub struct ServiceUsageStore {
    connection: Mutex<Connection>,
    // This sentinel drops only after the actual Connection has closed.
    closed_after_connection: std::sync::Arc<()>,
    // Fields drop in declaration order: close SQLite before removing its files.
    #[cfg(test)]
    owned_test_directory: Option<TestDirectory>,
}

/// Observes actual release of every SQLite owner without retaining the store
/// or conferring any accounting or forwarding authority.
#[derive(Clone)]
pub struct ServiceUsageCleanup {
    owner: std::sync::Weak<()>,
}

impl ServiceUsageCleanup {
    pub fn is_finished(&self) -> bool {
        self.owner.strong_count() == 0
    }

    pub async fn wait_finished(&self) {
        while !self.is_finished() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

#[cfg(test)]
struct TestDirectory(std::path::PathBuf);

#[cfg(test)]
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Highwater {
    pub admitted_bytes: u64,
    pub opened_connections: u64,
    pub closed_connections: u64,
}

#[derive(Clone)]
pub struct GrantSnapshot {
    pub grant: SignedServiceUsageBudgetGrant,
    pub claims: ServiceUsageBudgetGrantClaims,
    pub grant_sha256: [u8; 32],
    pub highwater: Highwater,
    pub report_sequence: u64,
    pub report_sha256: [u8; 32],
    pub needs_report: bool,
    pub stop_requested: bool,
    pub drain_confirmed: bool,
    pub pending_report: Option<SignedServiceUsageReport>,
    pub pending_stop: Option<SignedServiceUsageRuntimeStop>,
}

fn fenced() -> Error {
    Error::Fenced
}
fn contract_fenced() -> ContractError {
    ContractError::new(
        ErrorCode::PolicyRevoked,
        "service usage persistence unavailable",
    )
}

impl ServiceUsageStore {
    pub(crate) fn cleanup_owner(store: &std::sync::Arc<Self>) -> ServiceUsageCleanup {
        ServiceUsageCleanup {
            owner: std::sync::Arc::downgrade(&store.closed_after_connection),
        }
    }

    pub fn open(directory: &Path) -> Result<Self, Error> {
        if !directory.is_absolute() {
            return Err(fenced());
        }
        if !directory.exists() {
            let parent = directory.parent().ok_or_else(fenced)?;
            nestlink_platform_security::new_private_directory(directory)?;
            nestlink_platform_security::check_private_directory(parent)?;
        } else {
            nestlink_platform_security::check_private_directory(directory)?;
        }
        let path = directory.join("service-usage.sqlite3");
        if path.exists() {
            let meta = std::fs::symlink_metadata(&path)?;
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err(fenced());
            }
        }
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS service_usage_local_grants(
                grant_id TEXT PRIMARY KEY,
                grant_sha256 BLOB NOT NULL CHECK(length(grant_sha256)=32),
                grant_json TEXT NOT NULL CHECK(json_valid(grant_json) AND length(grant_json)<=32768),
                publication_id TEXT NOT NULL,
                publication_generation INTEGER NOT NULL CHECK(publication_generation>0),
                edge_runtime_id TEXT NOT NULL,
                edge_runtime_generation INTEGER NOT NULL CHECK(edge_runtime_generation>0),
                grant_bytes INTEGER NOT NULL CHECK(grant_bytes BETWEEN 1 AND 9223372036854775807),
                maximum_connections INTEGER NOT NULL CHECK(maximum_connections BETWEEN 1 AND 128),
                admitted_bytes INTEGER NOT NULL DEFAULT 0 CHECK(admitted_bytes BETWEEN 0 AND grant_bytes),
                opened_connections INTEGER NOT NULL DEFAULT 0 CHECK(opened_connections>=0),
                closed_connections INTEGER NOT NULL DEFAULT 0 CHECK(closed_connections>=0 AND closed_connections<=opened_connections),
                report_sequence INTEGER NOT NULL DEFAULT 0 CHECK(report_sequence>=0),
                report_sha256 BLOB NOT NULL CHECK(length(report_sha256)=32),
                stop_requested INTEGER NOT NULL DEFAULT 0 CHECK(stop_requested IN (0,1)),
                drain_confirmed INTEGER NOT NULL DEFAULT 0 CHECK(drain_confirmed IN (0,1)),
                terminal INTEGER NOT NULL DEFAULT 0 CHECK(terminal IN (0,1)),
                stop_json TEXT,
                stop_sha256 BLOB CHECK(stop_sha256 IS NULL OR length(stop_sha256)=32)
            ) STRICT;
            CREATE UNIQUE INDEX IF NOT EXISTS service_usage_local_generation
                ON service_usage_local_grants(publication_id,publication_generation);
            CREATE TABLE IF NOT EXISTS service_usage_local_reports(
                grant_id TEXT NOT NULL REFERENCES service_usage_local_grants(grant_id),
                report_sequence INTEGER NOT NULL CHECK(report_sequence>0),
                report_sha256 BLOB NOT NULL CHECK(length(report_sha256)=32),
                report_json TEXT NOT NULL CHECK(json_valid(report_json) AND length(report_json)<=32768),
                ack_json TEXT CHECK(ack_json IS NULL OR (json_valid(ack_json) AND length(ack_json)<=32768)),
                PRIMARY KEY(grant_id,report_sequence)
            ) STRICT;",
        )?;
        let has_drain_confirmed: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('service_usage_local_grants') WHERE name='drain_confirmed')",
            [],
            |row| row.get(0),
        )?;
        if !has_drain_confirmed {
            connection.execute(
                "ALTER TABLE service_usage_local_grants ADD COLUMN drain_confirmed INTEGER NOT NULL DEFAULT 0 CHECK(drain_confirmed IN (0,1))",
                [],
            )?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
            closed_after_connection: std::sync::Arc::new(()),
            #[cfg(test)]
            owned_test_directory: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Result<Self, Error> {
        let path = std::env::temp_dir().join(format!(
            "nestlink-node-usage-fixture-{}",
            uuid::Uuid::new_v4()
        ));
        nestlink_platform_security::new_private_directory(&path)?;
        let directory = TestDirectory(path);
        let mut store = Self::open(&directory.0)?;
        store.owned_test_directory = Some(directory);
        Ok(store)
    }

    pub fn activate(&self, lease: &VerifiedServiceLease) -> Result<Highwater, Error> {
        let c = lease.claims();
        let signed = &c.usage_grant;
        let grant: ServiceUsageBudgetGrantClaims =
            decode_service_message(&signed.claims, SERVICE_USAGE_BYTES).map_err(|_| fenced())?;
        grant.validate().map_err(|_| fenced())?;
        if grant.edge_runtime_id != c.edge_runtime_id
            || grant.edge_runtime_generation != c.edge_runtime_generation
            || grant.publication_id != c.publication_id
            || grant.publication_generation != c.publication_generation
        {
            return Err(fenced());
        }
        let grant_digest = digest(&signed.claims);
        let grant_json = serde_json::to_string(signed).map_err(|_| fenced())?;
        let mut connection = self.connection.lock().map_err(|_| fenced())?;
        let tx = connection.transaction()?;
        let old: Option<(Vec<u8>,String,String,u64,String,u64)> = tx
            .query_row(
                "SELECT grant_sha256,grant_json,publication_id,publication_generation,edge_runtime_id,edge_runtime_generation FROM service_usage_local_grants WHERE grant_id=?1",
                [&grant.grant_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
            )
            .optional()?;
        if let Some((hash, json, pub_id, pub_generation, runtime, runtime_generation)) = old {
            if hash.as_slice() != grant_digest.as_slice()
                || json != grant_json
                || pub_id != grant.publication_id
                || pub_generation != grant.publication_generation
                || runtime != grant.edge_runtime_id
                || runtime_generation != grant.edge_runtime_generation
            {
                return Err(fenced());
            }
        } else {
            tx.execute(
                "INSERT INTO service_usage_local_grants(grant_id,grant_sha256,grant_json,publication_id,publication_generation,edge_runtime_id,edge_runtime_generation,grant_bytes,maximum_connections,report_sha256) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![grant.grant_id,grant_digest,grant_json,grant.publication_id,grant.publication_generation,grant.edge_runtime_id,grant.edge_runtime_generation,grant.byte_ceiling,c.definition.limits.maximum_connections,[0u8;32].as_slice()],
            )?;
        }
        let result = Self::highwater(&tx, &grant.grant_id)?;
        tx.commit()?;
        Ok(result)
    }

    fn highwater(tx: &rusqlite::Transaction<'_>, grant_id: &str) -> Result<Highwater, Error> {
        Ok(tx.query_row(
            "SELECT admitted_bytes,opened_connections,closed_connections FROM service_usage_local_grants WHERE grant_id=?1 AND terminal=0",
            [grant_id],
            |row| Ok(Highwater { admitted_bytes:row.get(0)?,opened_connections:row.get(1)?,closed_connections:row.get(2)? }),
        )?)
    }

    pub fn counters(&self, grant_id: &str) -> Result<Highwater, Error> {
        let connection = self.connection.lock().map_err(|_| fenced())?;
        Ok(connection.query_row(
            "SELECT admitted_bytes,opened_connections,closed_connections FROM service_usage_local_grants WHERE grant_id=?1 AND terminal=0",
            [grant_id],
            |row| Ok(Highwater { admitted_bytes:row.get(0)?,opened_connections:row.get(1)?,closed_connections:row.get(2)? }),
        )?)
    }

    pub fn reserve(&self, grant_id: &str) -> Result<Highwater, Error> {
        let mut connection = self.connection.lock().map_err(|_| fenced())?;
        let tx = connection.transaction()?;
        let (opened,closed,maximum):(u64,u64,u32)=tx.query_row(
            "SELECT opened_connections,closed_connections,maximum_connections FROM service_usage_local_grants WHERE grant_id=?1 AND terminal=0 AND stop_requested=0",
            [grant_id],
            |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        )?;
        let next = opened
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64 && v.saturating_sub(closed) <= u64::from(maximum))
            .ok_or_else(fenced)?;
        if tx.execute("UPDATE service_usage_local_grants SET opened_connections=?1 WHERE grant_id=?2 AND opened_connections=?3 AND terminal=0 AND stop_requested=0",params![next,grant_id,opened])?!=1{return Err(fenced());}
        let state = Self::highwater(&tx, grant_id)?;
        tx.commit()?;
        Ok(state)
    }

    pub fn close(&self, grant_id: &str) -> Result<Highwater, Error> {
        let mut connection = self.connection.lock().map_err(|_| fenced())?;
        let tx = connection.transaction()?;
        let (opened,closed):(u64,u64)=tx.query_row(
            "SELECT opened_connections,closed_connections FROM service_usage_local_grants WHERE grant_id=?1 AND terminal=0",
            [grant_id],
            |row|Ok((row.get(0)?,row.get(1)?)),
        )?;
        if opened <= closed {
            return Err(fenced());
        }
        if tx.execute("UPDATE service_usage_local_grants SET closed_connections=?1 WHERE grant_id=?2 AND closed_connections=?3 AND terminal=0",params![closed+1,grant_id,closed])?!=1{return Err(fenced());}
        let state = Self::highwater(&tx, grant_id)?;
        tx.commit()?;
        Ok(state)
    }

    pub fn admit(&self, grant_id: &str, bytes: u64) -> Result<Highwater, Error> {
        let mut connection = self.connection.lock().map_err(|_| fenced())?;
        let tx = connection.transaction()?;
        let (current,ceiling):(u64,u64)=tx.query_row("SELECT admitted_bytes,grant_bytes FROM service_usage_local_grants WHERE grant_id=?1 AND terminal=0 AND stop_requested=0",[grant_id],|row|Ok((row.get(0)?,row.get(1)?)))?;
        let next = current
            .checked_add(bytes)
            .filter(|v| *v <= ceiling && *v <= i64::MAX as u64)
            .ok_or_else(fenced)?;
        if tx.execute("UPDATE service_usage_local_grants SET admitted_bytes=?1 WHERE grant_id=?2 AND admitted_bytes=?3 AND terminal=0 AND stop_requested=0",params![next,grant_id,current])?!=1{return Err(fenced());}
        let state = Self::highwater(&tx, grant_id)?;
        tx.commit()?;
        Ok(state)
    }

    pub fn request_stop(&self, grant_id: &str) -> Result<(), Error> {
        let connection = self.connection.lock().map_err(|_| fenced())?;
        if connection.execute("UPDATE service_usage_local_grants SET stop_requested=1 WHERE grant_id=?1 AND terminal=0",[grant_id])?!=1{return Err(fenced());}
        Ok(())
    }

    pub fn confirm_drained(
        &self,
        token: &crate::service_plane::ServiceDrainToken,
    ) -> Result<(), Error> {
        let mut connection = self.connection.lock().map_err(|_| fenced())?;
        let tx = connection.transaction()?;
        type DrainFacts = (Vec<u8>, String, u64, String, u64, u64, u64, bool, bool);
        let row: Option<DrainFacts> = tx
            .query_row(
                "SELECT grant_sha256,publication_id,publication_generation,edge_runtime_id,edge_runtime_generation,opened_connections,closed_connections,stop_requested,drain_confirmed FROM service_usage_local_grants WHERE grant_id=?1 AND terminal=0",
                [&token.grant_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
            )
            .optional()?;
        let (
            hash,
            publication,
            generation,
            runtime,
            runtime_generation,
            opened,
            closed,
            requested,
            confirmed,
        ) = row.ok_or_else(fenced)?;
        if hash.as_slice() != token.grant_sha256.as_slice()
            || publication != token.publication_id
            || generation != token.publication_generation
            || runtime != token.edge_runtime_id
            || runtime_generation != token.edge_runtime_generation
            || opened != closed
            || !requested
        {
            return Err(fenced());
        }
        if !confirmed && tx.execute(
            "UPDATE service_usage_local_grants SET drain_confirmed=1 WHERE grant_id=?1 AND terminal=0 AND stop_requested=1 AND drain_confirmed=0",
            [&token.grant_id],
        )?!=1 { return Err(fenced()); }
        tx.commit()?;
        Ok(())
    }

    pub fn snapshots(&self, runtime_id: &str) -> Result<Vec<GrantSnapshot>, Error> {
        let connection = self.connection.lock().map_err(|_| fenced())?;
        let mut statement = connection.prepare(
            "SELECT grant_id,grant_sha256,grant_json,admitted_bytes,opened_connections,closed_connections,report_sequence,report_sha256,stop_requested,drain_confirmed FROM service_usage_local_grants WHERE edge_runtime_id=?1 AND terminal=0 ORDER BY grant_id",
        )?;
        let rows = statement
            .query_map([runtime_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, bool>(8)?,
                    row.get::<_, bool>(9)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut snapshots = Vec::with_capacity(rows.len());
        for (
            grant_id,
            hash,
            json,
            bytes,
            opened,
            closed,
            sequence,
            report_hash,
            stop_requested,
            drain_confirmed,
        ) in rows
        {
            let grant: SignedServiceUsageBudgetGrant =
                serde_json::from_str(&json).map_err(|_| fenced())?;
            let claims: ServiceUsageBudgetGrantClaims =
                decode_service_message(&grant.claims, SERVICE_USAGE_BYTES).map_err(|_| fenced())?;
            let grant_sha256: [u8; 32] = hash.try_into().map_err(|_| fenced())?;
            let report_sha256: [u8; 32] = report_hash.try_into().map_err(|_| fenced())?;
            if digest(&grant.claims) != grant_sha256 || claims.grant_id != grant_id {
                return Err(fenced());
            }
            let pending_report:Option<String>=connection.query_row(
                "SELECT report_json FROM service_usage_local_reports WHERE grant_id=?1 AND report_sequence=?2 AND ack_json IS NULL",
                params![grant_id,sequence.saturating_add(1)],|row|row.get(0),
            ).optional()?;
            let pending_report = pending_report
                .map(|json| serde_json::from_str(&json).map_err(|_| fenced()))
                .transpose()?;
            let pending_stop_json: Option<String> = connection.query_row(
                "SELECT stop_json FROM service_usage_local_grants WHERE grant_id=?1",
                [&grant_id],
                |row| row.get(0),
            )?;
            let pending_stop = pending_stop_json
                .map(|json| serde_json::from_str(&json).map_err(|_| fenced()))
                .transpose()?;
            let highwater = Highwater {
                admitted_bytes: bytes,
                opened_connections: opened,
                closed_connections: closed,
            };
            let accepted = if sequence == 0 {
                Highwater::default()
            } else {
                let report_json:String=connection.query_row("SELECT report_json FROM service_usage_local_reports WHERE grant_id=?1 AND report_sequence=?2 AND ack_json IS NOT NULL",params![grant_id,sequence],|row|row.get(0))?;
                let report: SignedServiceUsageReport =
                    serde_json::from_str(&report_json).map_err(|_| fenced())?;
                let accepted: ServiceUsageReportClaims =
                    decode_service_message(&report.claims, SERVICE_USAGE_BYTES)
                        .map_err(|_| fenced())?;
                Highwater {
                    admitted_bytes: accepted.admitted_bytes,
                    opened_connections: accepted.opened_connections,
                    closed_connections: accepted.closed_connections,
                }
            };
            snapshots.push(GrantSnapshot {
                grant,
                claims,
                grant_sha256,
                highwater,
                report_sequence: sequence,
                report_sha256,
                needs_report: sequence == 0 || highwater != accepted,
                stop_requested,
                drain_confirmed,
                pending_report,
                pending_stop,
            });
        }
        Ok(snapshots)
    }

    pub fn queue_report(&self, signed: &SignedServiceUsageReport) -> Result<(), Error> {
        let claims: ServiceUsageReportClaims =
            decode_service_message(&signed.claims, SERVICE_USAGE_BYTES).map_err(|_| fenced())?;
        claims.validate().map_err(|_| fenced())?;
        let mut connection = self.connection.lock().map_err(|_| fenced())?;
        let tx = connection.transaction()?;
        let (grant_json,grant_hash,bytes,opened,closed,sequence):(String,Vec<u8>,u64,u64,u64,u64)=tx.query_row(
            "SELECT grant_json,grant_sha256,admitted_bytes,opened_connections,closed_connections,report_sequence FROM service_usage_local_grants WHERE grant_id=?1 AND terminal=0",
            [&claims.grant_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        )?;
        let grant: SignedServiceUsageBudgetGrant =
            serde_json::from_str(&grant_json).map_err(|_| fenced())?;
        let authorized: ServiceUsageBudgetGrantClaims =
            decode_service_message(&grant.claims, SERVICE_USAGE_BYTES).map_err(|_| fenced())?;
        if claims.report_sequence != sequence + 1
            || claims.grant_sha256.as_slice() != grant_hash.as_slice()
            || claims.node_id != authorized.edge_node_id
            || claims.node_runtime_id != authorized.edge_runtime_id
            || claims.node_runtime_generation != authorized.edge_runtime_generation
            || claims.publication_id != authorized.publication_id
            || claims.publication_generation != authorized.publication_generation
            || claims.account_id != authorized.account_id
            || claims.host_device_id != authorized.host_device_id
            || claims.service_id != authorized.service_id
            || claims.admitted_bytes != bytes
            || claims.opened_connections != opened
            || claims.closed_connections != closed
        {
            return Err(fenced());
        }
        let report_hash = digest(&signed.claims);
        let report_json = serde_json::to_string(signed).map_err(|_| fenced())?;
        tx.execute("INSERT INTO service_usage_local_reports(grant_id,report_sequence,report_sha256,report_json) VALUES(?1,?2,?3,?4)",params![claims.grant_id,claims.report_sequence,report_hash,report_json])?;
        tx.commit()?;
        Ok(())
    }

    pub fn acknowledge_report(
        &self,
        ack: &ServiceUsageReportAckClaims,
        signed_ack_json: &str,
    ) -> Result<(), Error> {
        let mut connection = self.connection.lock().map_err(|_| fenced())?;
        let tx = connection.transaction()?;
        let report_hash:Vec<u8>=tx.query_row("SELECT report_sha256 FROM service_usage_local_reports WHERE grant_id=?1 AND report_sequence=?2 AND ack_json IS NULL",params![ack.grant_id,ack.report_sequence],|row|row.get(0))?;
        if report_hash.as_slice() != ack.report_sha256.as_slice() {
            return Err(fenced());
        }
        tx.execute("UPDATE service_usage_local_reports SET ack_json=?1 WHERE grant_id=?2 AND report_sequence=?3 AND ack_json IS NULL",params![signed_ack_json,ack.grant_id,ack.report_sequence])?;
        if tx.execute("UPDATE service_usage_local_grants SET report_sequence=?1,report_sha256=?2 WHERE grant_id=?3 AND report_sequence=?4 AND terminal=0",params![ack.report_sequence,ack.report_sha256.as_slice(),ack.grant_id,ack.report_sequence-1])?!=1{return Err(fenced());}
        tx.commit()?;
        Ok(())
    }

    pub fn queue_stop(&self, signed: &SignedServiceUsageRuntimeStop) -> Result<(), Error> {
        let claims: ServiceUsageRuntimeStopClaims =
            decode_service_message(&signed.claims, SERVICE_USAGE_BYTES).map_err(|_| fenced())?;
        claims.validate().map_err(|_| fenced())?;
        let mut connection = self.connection.lock().map_err(|_| fenced())?;
        let tx = connection.transaction()?;
        let (grant_json,grant_hash,opened,closed,bytes,sequence,report_hash,requested,drained):(String,Vec<u8>,u64,u64,u64,u64,Vec<u8>,bool,bool)=tx.query_row(
            "SELECT grant_json,grant_sha256,opened_connections,closed_connections,admitted_bytes,report_sequence,report_sha256,stop_requested,drain_confirmed FROM service_usage_local_grants WHERE grant_id=?1 AND terminal=0",
            [&claims.grant_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
        )?;
        let grant: SignedServiceUsageBudgetGrant =
            serde_json::from_str(&grant_json).map_err(|_| fenced())?;
        let grant: ServiceUsageBudgetGrantClaims =
            decode_service_message(&grant.claims, SERVICE_USAGE_BYTES).map_err(|_| fenced())?;
        let highwater = Highwater {
            admitted_bytes: bytes,
            opened_connections: opened,
            closed_connections: closed,
        };
        let acknowledged = if sequence == 0 {
            if report_hash.as_slice() != [0u8; 32].as_slice() {
                return Err(fenced());
            }
            Highwater::default()
        } else {
            let report_json: String = tx.query_row(
                "SELECT report_json FROM service_usage_local_reports WHERE grant_id=?1 AND report_sequence=?2 AND ack_json IS NOT NULL",
                params![claims.grant_id, sequence],
                |row| row.get(0),
            )?;
            let report: SignedServiceUsageReport =
                serde_json::from_str(&report_json).map_err(|_| fenced())?;
            let report_claims: ServiceUsageReportClaims =
                decode_service_message(&report.claims, SERVICE_USAGE_BYTES)
                    .map_err(|_| fenced())?;
            if digest(&report.claims).as_slice() != report_hash.as_slice()
                || report_claims.report_sequence != sequence
                || report_claims.grant_id != claims.grant_id
                || report_claims.grant_sha256.as_slice() != grant_hash.as_slice()
            {
                return Err(fenced());
            }
            Highwater {
                admitted_bytes: report_claims.admitted_bytes,
                opened_connections: report_claims.opened_connections,
                closed_connections: report_claims.closed_connections,
            }
        };
        let pending_report: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM service_usage_local_reports WHERE grant_id=?1 AND ack_json IS NULL)",
            [&claims.grant_id],
            |row| row.get(0),
        )?;
        if !requested
            || !drained
            || opened != closed
            || pending_report
            || acknowledged != highwater
            || claims.opened_connections != opened
            || claims.closed_connections != closed
            || claims.admitted_bytes != bytes
            || claims.final_report_sequence != sequence
            || claims.final_report_sha256.as_slice() != report_hash.as_slice()
            || claims.grant_sha256.as_slice() != grant_hash.as_slice()
            || claims.deployment_id != grant.deployment_id
            || claims.security_epoch != grant.security_epoch
            || claims.policy_revision != grant.policy_revision
            || claims.node_id != grant.edge_node_id
            || claims.node_runtime_id != grant.edge_runtime_id
            || claims.node_runtime_generation != grant.edge_runtime_generation
            || claims.publication_id != grant.publication_id
            || claims.publication_generation != grant.publication_generation
        {
            return Err(fenced());
        }
        let json = serde_json::to_string(signed).map_err(|_| fenced())?;
        let hash = digest(&signed.claims);
        if tx.execute("UPDATE service_usage_local_grants SET stop_json=?1,stop_sha256=?2 WHERE grant_id=?3 AND terminal=0 AND stop_json IS NULL",params![json,hash.as_slice(),claims.grant_id])?!=1{return Err(fenced());}
        tx.commit()?;
        Ok(())
    }

    pub fn complete_stop(&self, grant_id: &str, stop_digest: &[u8; 32]) -> Result<(), Error> {
        let connection = self.connection.lock().map_err(|_| fenced())?;
        if connection.execute("UPDATE service_usage_local_grants SET terminal=1 WHERE grant_id=?1 AND terminal=0 AND stop_sha256=?2",params![grant_id,stop_digest.as_slice()])?!=1{return Err(fenced());}
        Ok(())
    }
}

impl From<Error> for ContractError {
    fn from(_: Error) -> Self {
        contract_fenced()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_plane::{
        ServiceDrainToken, ServicePublication,
        test_support::{Fixture, id, wall},
    };
    use nestlink_identity::{digest, nodes::NodePolicySigner};
    use nestlink_protocol::{
        SCHEMA_VERSION,
        api::ServiceIngress,
        service_plane::{
            ServiceUsageReportAckClaims, ServiceUsageReportClaims, ServiceUsageRuntimeStopClaims,
        },
    };
    use std::{
        net::SocketAddr,
        path::PathBuf,
        sync::Arc,
        time::{Duration, Instant},
    };
    use tokio::sync::watch;

    struct PrivateTestDirectory(PathBuf);

    impl PrivateTestDirectory {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let path = std::env::temp_dir()
                .join(format!("nestlink-service-usage-{}", uuid::Uuid::new_v4()));
            nestlink_platform_security::new_private_directory(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for PrivateTestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn terminal_seal_requires_exact_drained_highwater_and_acked_final_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = PrivateTestDirectory::new()?;
        let store = Arc::new(ServiceUsageStore::open(&directory.0.join("state"))?);
        let fixture = Fixture::new(
            ServiceIngress::Tcp { port: 29100 },
            "tcp",
            "127.0.0.1:8080".parse::<SocketAddr>()?,
            5000,
        )?;
        let publication = ServicePublication::new_with_usage_store(
            fixture.verified()?,
            &fixture.context,
            Instant::now(),
            store.clone(),
        )?;
        let handle = publication.handle();
        let (_target_stop, target_stop) = watch::channel(false);
        let flow = handle.reserve_host("127.0.0.1".parse()?, target_stop)?;
        flow.try_charge(19)?;
        publication.revoke();

        let grant_sha256 = digest(&fixture.claims.usage_grant.claims);
        let exact_token = ServiceDrainToken {
            grant_id: id(12),
            grant_sha256,
            publication_id: id(2),
            publication_generation: 1,
            edge_runtime_id: id(10),
            edge_runtime_generation: 1,
        };
        assert!(handle.try_drain_token()?.is_none());
        assert!(store.confirm_drained(&exact_token).is_err());
        let before_close = store.snapshots(&id(10))?;
        assert_eq!(before_close.len(), 1);
        assert!(!before_close[0].drain_confirmed);

        drop(flow);
        let token = tokio::time::timeout(Duration::from_secs(1), handle.wait_drained()).await??;
        let mut wrong_token = ServiceDrainToken {
            grant_id: token.grant_id.clone(),
            grant_sha256: token.grant_sha256,
            publication_id: token.publication_id.clone(),
            publication_generation: token.publication_generation,
            edge_runtime_id: token.edge_runtime_id.clone(),
            edge_runtime_generation: token.edge_runtime_generation,
        };
        wrong_token.grant_sha256[0] ^= 1;
        assert!(store.confirm_drained(&wrong_token).is_err());
        let still_committed = store.snapshots(&id(10))?;
        assert_eq!(still_committed.len(), 1);
        assert!(!still_committed[0].drain_confirmed);

        store.confirm_drained(&token)?;
        let snapshot = store.snapshots(&id(10))?.remove(0);
        assert!(snapshot.drain_confirmed);
        assert_eq!(snapshot.highwater.admitted_bytes, 19);
        assert_eq!(snapshot.highwater.opened_connections, 1);
        assert_eq!(snapshot.highwater.closed_connections, 1);

        let grant = &snapshot.claims;
        let unacked_stop =
            fixture
                .edge
                .sign_service_usage_stop(&ServiceUsageRuntimeStopClaims {
                    schema_version: SCHEMA_VERSION,
                    deployment_id: grant.deployment_id.clone(),
                    security_epoch: grant.security_epoch,
                    policy_revision: grant.policy_revision,
                    node_id: grant.edge_node_id.clone(),
                    node_runtime_id: grant.edge_runtime_id.clone(),
                    node_runtime_generation: grant.edge_runtime_generation,
                    grant_id: grant.grant_id.clone(),
                    grant_sha256: snapshot.grant_sha256,
                    publication_id: grant.publication_id.clone(),
                    publication_generation: grant.publication_generation,
                    final_report_sequence: snapshot.report_sequence,
                    final_report_sha256: snapshot.report_sha256,
                    admitted_bytes: snapshot.highwater.admitted_bytes,
                    opened_connections: snapshot.highwater.opened_connections,
                    closed_connections: snapshot.highwater.closed_connections,
                    stop_nonce: [0x5A; 32],
                    stopped_at_unix_ms: wall()?,
                })?;
        assert!(store.queue_stop(&unacked_stop).is_err());
        assert!(store.snapshots(&id(10))?.remove(0).pending_stop.is_none());

        let report = fixture.edge.sign_service_usage(&ServiceUsageReportClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: grant.deployment_id.clone(),
            security_epoch: grant.security_epoch,
            policy_revision: grant.policy_revision,
            node_id: grant.edge_node_id.clone(),
            node_runtime_id: grant.edge_runtime_id.clone(),
            node_runtime_generation: grant.edge_runtime_generation,
            grant_id: grant.grant_id.clone(),
            grant_sha256: snapshot.grant_sha256,
            publication_id: grant.publication_id.clone(),
            publication_generation: grant.publication_generation,
            account_id: grant.account_id.clone(),
            host_device_id: grant.host_device_id.clone(),
            service_id: grant.service_id.clone(),
            report_sequence: snapshot.report_sequence + 1,
            admitted_bytes: snapshot.highwater.admitted_bytes,
            opened_connections: snapshot.highwater.opened_connections,
            closed_connections: snapshot.highwater.closed_connections,
            sampled_at_unix_ms: wall()?,
        })?;
        store.queue_report(&report)?;
        let pending_report = store
            .snapshots(&id(10))?
            .remove(0)
            .pending_report
            .ok_or("pending report missing")?;
        assert_eq!(pending_report.claims, report.claims);
        assert_eq!(pending_report.signature, report.signature);

        let policy = NodePolicySigner::from_master_seed(&[73; 32])?;
        let report_digest = digest(&report.claims);
        let ack = ServiceUsageReportAckClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: grant.deployment_id.clone(),
            security_epoch: grant.security_epoch,
            node_id: grant.edge_node_id.clone(),
            node_runtime_id: grant.edge_runtime_id.clone(),
            node_runtime_generation: grant.edge_runtime_generation,
            grant_id: grant.grant_id.clone(),
            report_sequence: 1,
            report_sha256: report_digest,
            accepted_at_unix_ms: wall()?,
        };
        let signed_ack = policy.sign_service_usage_ack(&ack)?;
        store.acknowledge_report(&ack, &serde_json::to_string(&signed_ack)?)?;
        let acknowledged = store.snapshots(&id(10))?.remove(0);
        assert!(!acknowledged.needs_report);
        assert_eq!(acknowledged.report_sequence, 1);
        assert_eq!(acknowledged.report_sha256, report_digest);

        let stop = fixture
            .edge
            .sign_service_usage_stop(&ServiceUsageRuntimeStopClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: grant.deployment_id.clone(),
                security_epoch: grant.security_epoch,
                policy_revision: grant.policy_revision,
                node_id: grant.edge_node_id.clone(),
                node_runtime_id: grant.edge_runtime_id.clone(),
                node_runtime_generation: grant.edge_runtime_generation,
                grant_id: grant.grant_id.clone(),
                grant_sha256: acknowledged.grant_sha256,
                publication_id: grant.publication_id.clone(),
                publication_generation: grant.publication_generation,
                final_report_sequence: acknowledged.report_sequence,
                final_report_sha256: acknowledged.report_sha256,
                admitted_bytes: acknowledged.highwater.admitted_bytes,
                opened_connections: acknowledged.highwater.opened_connections,
                closed_connections: acknowledged.highwater.closed_connections,
                stop_nonce: [0xA5; 32],
                stopped_at_unix_ms: wall()?,
            })?;
        store.queue_stop(&stop)?;
        for _ in 0..3 {
            let retry = store
                .snapshots(&id(10))?
                .remove(0)
                .pending_stop
                .ok_or("pending stop missing")?;
            assert_eq!(retry.claims, stop.claims);
            assert_eq!(retry.signature, stop.signature);
        }
        store.complete_stop(&grant.grant_id, &digest(&stop.claims))?;
        assert!(store.snapshots(&id(10))?.is_empty());

        drop(handle);
        drop(publication);
        drop(store);
        Ok(())
    }

    #[tokio::test]
    async fn zero_use_drain_acks_an_initial_zero_report_before_the_terminal_seal()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(ServiceUsageStore::for_test()?);
        let fixture = Fixture::new(
            ServiceIngress::Tcp { port: 29100 },
            "tcp",
            "127.0.0.1:8080".parse::<SocketAddr>()?,
            5000,
        )?;
        let publication = ServicePublication::new_with_usage_store(
            fixture.verified()?,
            &fixture.context,
            Instant::now(),
            store.clone(),
        )?;
        let handle = publication.handle();
        publication.revoke();
        let token = handle
            .try_drain_token()?
            .ok_or("zero-flow publication should be drained immediately")?;
        store.confirm_drained(&token)?;

        let initial = store.snapshots(&id(10))?.remove(0);
        assert_eq!(initial.highwater, Highwater::default());
        assert_eq!(initial.report_sequence, 0);
        assert!(initial.needs_report);
        assert!(initial.drain_confirmed);
        let grant = &initial.claims;
        let report = fixture.edge.sign_service_usage(&ServiceUsageReportClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: grant.deployment_id.clone(),
            security_epoch: grant.security_epoch,
            policy_revision: grant.policy_revision,
            node_id: grant.edge_node_id.clone(),
            node_runtime_id: grant.edge_runtime_id.clone(),
            node_runtime_generation: grant.edge_runtime_generation,
            grant_id: grant.grant_id.clone(),
            grant_sha256: initial.grant_sha256,
            publication_id: grant.publication_id.clone(),
            publication_generation: grant.publication_generation,
            account_id: grant.account_id.clone(),
            host_device_id: grant.host_device_id.clone(),
            service_id: grant.service_id.clone(),
            report_sequence: 1,
            admitted_bytes: 0,
            opened_connections: 0,
            closed_connections: 0,
            sampled_at_unix_ms: wall()?,
        })?;
        store.queue_report(&report)?;
        let pending = store.snapshots(&id(10))?.remove(0);
        assert_eq!(
            pending.pending_report.as_ref().map(|p| &p.claims),
            Some(&report.claims)
        );
        assert_eq!(pending.highwater, Highwater::default());

        let policy = NodePolicySigner::from_master_seed(&[73; 32])?;
        let report_sha256 = digest(&report.claims);
        let ack = ServiceUsageReportAckClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: grant.deployment_id.clone(),
            security_epoch: grant.security_epoch,
            node_id: grant.edge_node_id.clone(),
            node_runtime_id: grant.edge_runtime_id.clone(),
            node_runtime_generation: grant.edge_runtime_generation,
            grant_id: grant.grant_id.clone(),
            report_sequence: 1,
            report_sha256,
            accepted_at_unix_ms: wall()?,
        };
        let signed_ack = policy.sign_service_usage_ack(&ack)?;
        store.acknowledge_report(&ack, &serde_json::to_string(&signed_ack)?)?;
        let acknowledged = store.snapshots(&id(10))?.remove(0);
        assert_eq!(acknowledged.report_sequence, 1);
        assert_eq!(acknowledged.report_sha256, report_sha256);
        assert!(!acknowledged.needs_report);

        let stop = fixture
            .edge
            .sign_service_usage_stop(&ServiceUsageRuntimeStopClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: grant.deployment_id.clone(),
                security_epoch: grant.security_epoch,
                policy_revision: grant.policy_revision,
                node_id: grant.edge_node_id.clone(),
                node_runtime_id: grant.edge_runtime_id.clone(),
                node_runtime_generation: grant.edge_runtime_generation,
                grant_id: grant.grant_id.clone(),
                grant_sha256: acknowledged.grant_sha256,
                publication_id: grant.publication_id.clone(),
                publication_generation: grant.publication_generation,
                final_report_sequence: acknowledged.report_sequence,
                final_report_sha256: acknowledged.report_sha256,
                admitted_bytes: 0,
                opened_connections: 0,
                closed_connections: 0,
                stop_nonce: [0xA6; 32],
                stopped_at_unix_ms: wall()?,
            })?;
        store.queue_stop(&stop)?;
        store.complete_stop(&grant.grant_id, &digest(&stop.claims))?;
        assert!(store.snapshots(&id(10))?.is_empty());
        drop(handle);
        drop(publication);
        drop(store);
        Ok(())
    }
}
