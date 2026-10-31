//! Durable promises. Revocation stops renewal; it never refunds an unexpired
//! listener, connection, rate or byte commitment merely because a row changed.
use super::*;
use nestlink_identity::service_plane::{
    ServiceLeaseSigner, publication_binding, verify_service_query,
};
use nestlink_identity::{
    digest,
    nodes::{
        NodePolicySigner, verify_service_usage_ack, verify_service_usage_report,
        verify_service_usage_stop,
    },
};
use nestlink_protocol::{
    NODE_LEASE_MS, NodeResourceQueryClaims, SCHEMA_VERSION,
    api::AuditActor,
    service_plane::{publication::*, *},
};
use rusqlite::Transaction;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
#[cfg(test)]
mod tests;

const HOLD_MARGIN_MS: u64 = 1000;
const MAX_HISTORY: u64 = 65536;
const GLOBAL_PUBLICATIONS: u64 = 128;
const ACCOUNT_PUBLICATIONS: u64 = 16;
const GLOBAL_CONNECTIONS: u64 = 8192;
const ACCOUNT_CONNECTIONS: u64 = 1024;
const GLOBAL_RATE: u64 = 1024 * 1024 * 1024;
const ACCOUNT_RATE: u64 = 128 * 1024 * 1024;
const GLOBAL_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024;
const ACCOUNT_BYTES: u64 = 4 * 1024 * 1024 * 1024 * 1024;
const DEVICE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const NODE_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;

pub struct ServiceLifecycle {
    runtime_id: String,
    epoch: u64,
    started: Instant,
    wall: u64,
    clock: Mutex<(u64, bool)>,
    fenced: bool,
}
impl ServiceLifecycle {
    fn clock(&self, now_ms: u64) -> Result<(), StorageError> {
        let mut state = self.clock.lock().map_err(|_| StorageError::Conflict)?;
        let elapsed: u64 = self
            .started
            .elapsed()
            .as_millis()
            .try_into()
            .map_err(|_| StorageError::Conflict)?;
        if state.1
            || now_ms < state.0
            || now_ms.saturating_sub(self.wall).abs_diff(elapsed) > HOLD_MARGIN_MS
        {
            state.1 = true;
            return Err(StorageError::Conflict);
        }
        state.0 = now_ms;
        Ok(())
    }
}
pub struct ServicePublicationIssue {
    pub claims: ServiceLeaseClaims,
    pub edge_public_key: [u8; 32],
}
struct Edge {
    key: [u8; 32],
    runtime: String,
    generation: u64,
    lease_end: u64,
    connections: u64,
    rate: u64,
    namespace: ServiceEdgeNamespaceView,
}
struct PublicationVersion {
    id: String,
    generation: u64,
    sequence: u64,
    usage_grant: SignedServiceUsageBudgetGrant,
}
struct PublicationIdentity<'a> {
    id: &'a str,
    generation: u64,
}
fn ingress_key(node: &str, ingress: &ServiceIngress) -> String {
    match ingress {
        ServiceIngress::Tcp { port } => format!("tcp:{node}:{port}"),
        ServiceIngress::Udp { port } => format!("udp:{node}:{port}"),
        ServiceIngress::Http { hostname } | ServiceIngress::Https { hostname } => {
            format!("web:{hostname}")
        }
    }
}
fn bounded_add(a: u64, b: u64) -> Result<u64, StorageError> {
    a.checked_add(b)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(StorageError::Conflict)
}
impl Store {
    pub fn service_lifecycle(&mut self, now_ms: u64) -> Result<ServiceLifecycle, StorageError> {
        if !revision_valid(now_ms) {
            return Err(StorageError::Conflict);
        }
        let tx = self.connection.unchecked_transaction()?;
        let restored: bool = tx.query_row(
            "SELECT restore_fenced FROM service_publication_settings WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let prior: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM service_publications WHERE state<>2)",
            [],
            |r| r.get(0),
        )?;
        let life = ServiceLifecycle {
            runtime_id: random_id(),
            epoch: self.security_epoch()?,
            started: Instant::now(),
            wall: now_ms,
            clock: Mutex::new((now_ms, false)),
            fenced: restored || prior,
        };
        tx.execute("UPDATE service_publications SET state=1 WHERE state=0", [])?;
        tx.execute("UPDATE service_publication_settings SET control_runtime_id=?1,restore_fenced=?2 WHERE singleton=1",params![life.runtime_id,life.fenced])?;
        tx.commit()?;
        Ok(life)
    }
    fn resume_services(&self, life: &ServiceLifecycle, now_ms: u64) -> Result<(), StorageError> {
        life.clock(now_ms)?;
        if life.epoch != self.security_epoch()?
            || life.fenced
                && life.started.elapsed() < Duration::from_millis(SERVICE_LEASE_MS + HOLD_MARGIN_MS)
        {
            return Err(StorageError::RateLimited);
        }
        let (owner,fenced):(Option<String>,bool)=self.connection.query_row("SELECT control_runtime_id,restore_fenced FROM service_publication_settings WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if owner.as_deref() != Some(life.runtime_id.as_str()) {
            return Err(StorageError::Conflict);
        }
        if fenced {
            // Monotonic full-lease fencing also covers snapshots with a future wall clock.
            self.connection.execute("UPDATE service_publications SET state=2,promised_until=?1 WHERE control_runtime_id<>?2",params![now_ms,life.runtime_id])?;
            self.connection.execute(
                "UPDATE service_publication_settings SET restore_fenced=0 WHERE singleton=1",
                [],
            )?;
        }
        self.connection.execute(
            "UPDATE service_publications SET state=2 WHERE state<>2 AND promised_until<=?1",
            [now_ms],
        )?;
        Ok(())
    }
    pub fn service_edge_namespace(
        &self,
        actor: &Principal,
        node: &str,
        now: u64,
    ) -> Result<ServiceEdgeNamespaceView, StorageError> {
        self.audit_admin(actor, now)?;
        self.service_namespace_current(node)
    }
    fn service_namespace_current(
        &self,
        node: &str,
    ) -> Result<ServiceEdgeNamespaceView, StorageError> {
        require_id(node)?;
        let row: Option<(u64, String)> = self
            .connection
            .query_row(
                "SELECT revision,config_json FROM service_edge_namespaces WHERE node_id=?1",
                [node],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (revision, json) = row.ok_or(StorageError::Forbidden)?;
        let config: ServiceEdgeNamespace = serde_json::from_str(&json)?;
        config.validate()?;
        Ok(ServiceEdgeNamespaceView {
            node_id: node.into(),
            revision,
            config,
        })
    }
    pub fn set_service_edge_namespace(
        &mut self,
        actor: &Principal,
        node: &str,
        update: ServiceEdgeNamespaceUpdate,
        now: u64,
    ) -> Result<ServiceEdgeNamespaceView, StorageError> {
        self.audit_admin(actor, now)?;
        require_id(node)?;
        update.config.validate()?;
        let tx = self.connection.unchecked_transaction()?;
        let roles: Option<String> = tx
            .query_row(
                "SELECT roles_json FROM data_nodes WHERE id=?1 AND revoked=0",
                [node],
                |r| r.get(0),
            )
            .optional()?;
        let roles: Vec<i32> = serde_json::from_str(&roles.ok_or(StorageError::Forbidden)?)?;
        if !roles.contains(&(NodeRole::NodeEdge as i32)) {
            return Err(StorageError::Forbidden);
        }
        let revision: u64 = tx.query_row(
            "SELECT COALESCE((SELECT revision FROM service_edge_namespaces WHERE node_id=?1),0)",
            [node],
            |r| r.get(0),
        )?;
        if revision != update.expected_revision {
            return Err(StorageError::Conflict);
        }
        let next = revision
            .checked_add(1)
            .filter(|n| revision_valid(*n))
            .ok_or(StorageError::Conflict)?;
        tx.execute("INSERT INTO service_edge_namespaces(node_id,revision,config_json) VALUES(?1,?2,?3) ON CONFLICT(node_id) DO UPDATE SET revision=excluded.revision,config_json=excluded.config_json",params![node,next,serde_json::to_string(&update.config)?])?;
        tx.execute(
            "UPDATE service_publications SET state=1 WHERE node_id=?1 AND state=0",
            [node],
        )?;
        auditing::record(
            &tx,
            "service_namespace_changed",
            node,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(ServiceEdgeNamespaceView {
            node_id: node.into(),
            revision: next,
            config: update.config,
        })
    }
    fn service_edge_live(&self, node: &str, now_ms: u64) -> Result<Edge, StorageError> {
        type Row = (Vec<u8>, Option<String>, u64, u64, u64, u64, u64, String);
        let row:Option<Row>=self.connection.query_row("SELECT public_key,runtime_id,runtime_generation,last_issued_at,lease_policy_revision,max_connections,bytes_per_second,roles_json FROM data_nodes WHERE id=?1 AND revoked=0",[node],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
        let (key, runtime, generation, last, policy, connections, rate, roles) =
            row.ok_or(StorageError::Forbidden)?;
        let (current, network) = self.policy()?;
        network.may_publish()?;
        let roles: Vec<i32> = serde_json::from_str(&roles)?;
        let lease_end = bounded_add(last, NODE_LEASE_MS)?;
        if !roles.contains(&(NodeRole::NodeEdge as i32))
            || policy != current
            || last == 0
            || now_ms < last
            || now_ms >= lease_end
        {
            return Err(StorageError::Forbidden);
        }
        let key = key.try_into().map_err(|_| StorageError::Conflict)?;
        Ok(Edge {
            key,
            runtime: runtime.ok_or(StorageError::Forbidden)?,
            generation,
            lease_end,
            connections,
            rate,
            namespace: self.service_namespace_current(node)?,
        })
    }
    fn service_publication_facts(
        &self,
        id: &str,
        now_ms: u64,
    ) -> Result<(Record, Approval, Edge), StorageError> {
        let record = self.service_record(id)?;
        let approval = self
            .service_approval_row(id)?
            .ok_or(StorageError::Forbidden)?;
        if !self.service_approval_live(&record, &approval, now_ms / 1000)?
            || now_ms >= approval.expires
        {
            return Err(StorageError::Forbidden);
        }
        // HTTP/HTTPS readiness is owned by the selected edge's private Caddy
        // adapter. Issuing a short lease never claims that ingress is ready.
        if record.definition.allowed_sources.is_empty() {
            return Err(StorageError::Invalid("source ACL is empty"));
        }
        self.space_service_publication_deadline(
            &record.id,
            record.revision,
            &record.account,
            &record.definition,
            now_ms,
        )?;
        let edge = self.service_edge_live(&record.definition.edge_node_id, now_ms)?;
        if !edge
            .namespace
            .config
            .permits(&record.definition.requested_ingress)
        {
            return Err(StorageError::Forbidden);
        }
        Ok((record, approval, edge))
    }
    fn make_service_claims(
        &self,
        record: &Record,
        approval: &Approval,
        edge: &Edge,
        version: PublicationVersion,
        now_ms: u64,
    ) -> Result<ServiceLeaseClaims, StorageError> {
        let PublicationVersion {
            id,
            generation,
            sequence,
            usage_grant,
        } = version;
        let claims = ServiceLeaseClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            policy_revision: self.policy()?.0,
            publication_id: id.clone(),
            publication_generation: generation,
            service_id: record.id.clone(),
            service_revision: record.revision,
            choice_revision: record
                .revision
                .checked_sub(1)
                .filter(|n| revision_valid(*n))
                .ok_or(StorageError::Conflict)?,
            account_id: record.account.clone(),
            creator_login_id: record.login.clone(),
            approving_login_id: approval.login.clone(),
            definition: record.definition.clone(),
            definition_sha256: record.hash,
            host_key_sha256: approval
                .host_hash
                .clone()
                .try_into()
                .map_err(|_| StorageError::Conflict)?,
            target_id: approval.target.clone(),
            target_sha256: approval
                .target_hash
                .clone()
                .try_into()
                .map_err(|_| StorageError::Conflict)?,
            edge_key_sha256: digest(&edge.key),
            edge_service_address: edge.namespace.config.quic_address.clone(),
            edge_runtime_id: edge.runtime.clone(),
            edge_runtime_generation: edge.generation,
            ingress_claim_id: id,
            ingress_claim_revision: edge.namespace.revision,
            usage_grant,
            lease_sequence: sequence,
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: bounded_add(now_ms, SERVICE_LEASE_MS)?
                .min(approval.expires)
                .min(edge.lease_end)
                .min(
                    self.space_service_publication_deadline(
                        &record.id,
                        record.revision,
                        &record.account,
                        &record.definition,
                        now_ms,
                    )?
                    .unwrap_or(u64::MAX),
                ),
        };
        claims.validate()?;
        Ok(claims)
    }
    fn service_capacity(
        &self,
        record: &Record,
        edge: &Edge,
        now_ms: u64,
    ) -> Result<(), StorageError> {
        let limits = &record.definition.limits;
        let sample =
            |sql: &str, account: Option<&str>| -> Result<(u64, u64, u64, u64), StorageError> {
                let row = |r: &rusqlite::Row<'_>| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?));
                Ok(match account {
                    Some(a) => self.connection.query_row(sql, params![now_ms, a], row)?,
                    None => self.connection.query_row(sql, [now_ms], row)?,
                })
            };
        let total = sample(
            "SELECT count(*),COALESCE(sum(maximum_connections),0),COALESCE(sum(bytes_per_second),0),COALESCE(sum(maximum_bytes),0) FROM service_publications WHERE promised_until>?1",
            None,
        )?;
        let account = sample(
            "SELECT count(*),COALESCE(sum(maximum_connections),0),COALESCE(sum(bytes_per_second),0),COALESCE(sum(maximum_bytes),0) FROM service_publications WHERE promised_until>?1 AND account_id=?2",
            Some(&record.account),
        )?;
        let node = sample(
            "SELECT count(*),COALESCE(sum(maximum_connections),0),COALESCE(sum(bytes_per_second),0),COALESCE(sum(maximum_bytes),0) FROM service_publications WHERE promised_until>?1 AND node_id=?2",
            Some(&record.definition.edge_node_id),
        )?;
        for (held, maxima) in [
            (
                total,
                (
                    GLOBAL_PUBLICATIONS,
                    GLOBAL_CONNECTIONS,
                    GLOBAL_RATE,
                    GLOBAL_BYTES,
                ),
            ),
            (
                account,
                (
                    ACCOUNT_PUBLICATIONS,
                    ACCOUNT_CONNECTIONS,
                    ACCOUNT_RATE,
                    ACCOUNT_BYTES,
                ),
            ),
            (
                node,
                (
                    SERVICE_PUBLICATIONS_PER_NODE as u64,
                    edge.connections,
                    edge.rate,
                    u64::MAX,
                ),
            ),
        ] {
            if held.0 >= maxima.0
                || bounded_add(held.1, u64::from(limits.maximum_connections))? > maxima.1
                || bounded_add(held.2, limits.bytes_per_second)? > maxima.2
                || bounded_add(held.3, limits.maximum_bytes)? > maxima.3
            {
                return Err(StorageError::RateLimited);
            }
        }
        let history: u64 =
            self.connection
                .query_row("SELECT count(*) FROM service_publications", [], |r| {
                    r.get(0)
                })?;
        if history >= MAX_HISTORY {
            return Err(StorageError::RateLimited);
        }
        Ok(())
    }

    fn quota_available(
        tx: &Transaction<'_>,
        scope: &str,
        key: &str,
        default_limit: u64,
    ) -> Result<u64, StorageError> {
        require_id(key)?;
        tx.execute(
            "INSERT OR IGNORE INTO service_quota_limits(scope_kind,scope_key,limit_bytes,revision) VALUES(?1,?2,?3,1)",
            params![scope,key,default_limit],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO service_quota_ledgers(scope_kind,scope_key,spent_bytes) VALUES(?1,?2,0)",
            params![scope,key],
        )?;
        let outstanding_column = match scope {
            "account" => "account_id",
            "device" => "host_device_id",
            "node" => "node_id",
            "resource" => "service_id",
            _ => return Err(StorageError::Conflict),
        };
        let (limit, spent, outstanding): (u64, u64, u64) = tx.query_row(
            &format!(
                "SELECT l.limit_bytes,g.spent_bytes,COALESCE((SELECT SUM(grant_bytes-admitted_bytes) FROM service_usage_grants WHERE terminal=0 AND {outstanding_column}=?2),0) FROM service_quota_limits l JOIN service_quota_ledgers g USING(scope_kind,scope_key) WHERE l.scope_kind=?1 AND l.scope_key=?2"
            ),
            params![scope,key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let held = spent
            .checked_add(outstanding)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        Ok(limit.saturating_sub(held))
    }

    fn issue_usage_grant(
        tx: &Transaction<'_>,
        signer: &ServiceLeaseSigner,
        record: &Record,
        approval: &Approval,
        edge: &Edge,
        publication: PublicationIdentity<'_>,
        now_ms: u64,
    ) -> Result<SignedServiceUsageBudgetGrant, StorageError> {
        let PublicationIdentity {
            id: publication_id,
            generation,
        } = publication;
        let requested = super::private::public_reservation_limit(tx, record)?;
        Self::reserve_service_usage(
            tx,
            signer,
            record,
            approval,
            publication_id,
            generation,
            &edge.runtime,
            edge.generation,
            edge.namespace.revision,
            requested,
            now_ms,
        )
    }

    /// One durable reservation primitive for public edge and installation-host
    /// reports. Both paths debit the same four outstanding/spent ledgers.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn reserve_service_usage(
        tx: &Transaction<'_>,
        signer: &ServiceLeaseSigner,
        record: &Record,
        approval: &Approval,
        publication_id: &str,
        generation: u64,
        runtime_id: &str,
        runtime_generation: u64,
        ingress_revision: u64,
        requested: u64,
        now_ms: u64,
    ) -> Result<SignedServiceUsageBudgetGrant, StorageError> {
        let quota_revision: u64 = tx.query_row(
            "SELECT revision FROM service_quota_settings WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let restore_fenced: bool = tx.query_row(
            "SELECT restore_fenced FROM service_quota_settings WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if restore_fenced {
            return Err(StorageError::RateLimited);
        }
        if requested == 0 || requested > record.definition.limits.maximum_bytes {
            return Err(StorageError::RateLimited);
        }
        let capacity = [
            Self::quota_available(tx, "account", &record.account, ACCOUNT_BYTES)?,
            Self::quota_available(
                tx,
                "device",
                &record.definition.host_device_id,
                DEVICE_BYTES,
            )?,
            Self::quota_available(
                tx,
                "node",
                record.definition.accounting_node_id(),
                NODE_BYTES,
            )?,
            Self::quota_available(
                tx,
                "resource",
                &record.id,
                record.definition.limits.maximum_bytes,
            )?,
        ]
        .into_iter()
        .fold(requested, u64::min);
        if capacity == 0 {
            return Err(StorageError::RateLimited);
        }
        let claims = ServiceUsageBudgetGrantClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: tx.query_row(
                "SELECT id FROM deployment WHERE singleton=1",
                [],
                |row| row.get(0),
            )?,
            security_epoch: tx.query_row(
                "SELECT security_epoch FROM deployment WHERE singleton=1",
                [],
                |row| row.get(0),
            )?,
            policy_revision: tx.query_row(
                "SELECT policy_revision FROM deployment WHERE singleton=1",
                [],
                |row| row.get(0),
            )?,
            quota_revision,
            account_id: record.account.clone(),
            host_device_id: record.definition.host_device_id.clone(),
            service_id: record.id.clone(),
            edge_node_id: record.definition.accounting_node_id().into(),
            publication_id: publication_id.into(),
            publication_generation: generation,
            service_revision: record.revision,
            definition_sha256: record.hash,
            target_sha256: approval
                .target_hash
                .clone()
                .try_into()
                .map_err(|_| StorageError::Conflict)?,
            ingress_claim_id: publication_id.into(),
            ingress_claim_revision: ingress_revision,
            edge_runtime_id: runtime_id.into(),
            edge_runtime_generation: runtime_generation,
            grant_id: random_id(),
            grant_sequence: 1,
            byte_ceiling: capacity,
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: approval.expires,
        };
        claims.validate()?;
        let signed = signer.sign_usage_budget_grant(&claims)?;
        let grant_json = serde_json::to_string(&signed)?;
        let grant_sha256 = digest(&signed.claims);
        tx.execute(
            "INSERT INTO service_usage_grants(grant_id,grant_sequence,publication_id,publication_generation,deployment_id,security_epoch,policy_revision,quota_revision,account_id,host_device_id,service_id,node_id,edge_runtime_id,edge_runtime_generation,maximum_connections,bytes_per_second,grant_json,grant_sha256,grant_bytes,report_sha256) VALUES(?1,1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
            params![claims.grant_id,publication_id,generation,claims.deployment_id,claims.security_epoch,claims.policy_revision,quota_revision,claims.account_id,claims.host_device_id,claims.service_id,claims.edge_node_id,claims.edge_runtime_id,claims.edge_runtime_generation,record.definition.limits.maximum_connections,record.definition.limits.bytes_per_second,grant_json,grant_sha256,capacity,[0u8;32].as_slice()],
        )?;
        Ok(signed)
    }
    pub fn publish_service(
        &mut self,
        life: &ServiceLifecycle,
        actor: &Principal,
        id: &str,
        expected_revision: u64,
        signer: &ServiceLeaseSigner,
        now_ms: u64,
    ) -> Result<ServicePublicationIssue, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.resume_services(life, now_ms)?;
        let record = self.service_owner(actor, id, now_ms / 1000)?;
        if record.revision != expected_revision {
            return Err(StorageError::Conflict);
        }
        let (record, approval, edge) = self.service_publication_facts(id, now_ms)?;
        let old:Option<String>=tx.query_row("SELECT claims_json FROM service_publications WHERE service_id=?1 AND state=0 AND control_runtime_id=?2",params![id,life.runtime_id],|r|r.get(0)).optional()?;
        let claims = if let Some(json) = old {
            let old: ServiceLeaseClaims = serde_json::from_str(&json)?;
            if old.expires_at_unix_ms <= now_ms {
                return Err(StorageError::Conflict);
            }
            let next = self.make_service_claims(
                &record,
                &approval,
                &edge,
                PublicationVersion {
                    id: old.publication_id.clone(),
                    generation: old.publication_generation,
                    sequence: next(old.lease_sequence)?,
                    usage_grant: old.usage_grant.clone(),
                },
                now_ms,
            )?;
            if publication_binding(&old)? != publication_binding(&next)? {
                return Err(StorageError::Conflict);
            }
            next
        } else {
            let draining: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM service_publications WHERE service_id=?1 AND state=1)",
                [id],
                |r| r.get(0),
            )?;
            if draining {
                return Err(StorageError::RateLimited);
            }
            self.service_capacity(&record, &edge, now_ms)?;
            let generation: u64 = tx.query_row(
                "SELECT COALESCE(max(generation),0) FROM service_publications WHERE service_id=?1",
                [id],
                |r| r.get(0),
            )?;
            let generation = generation
                .checked_add(1)
                .filter(|n| revision_valid(*n))
                .ok_or(StorageError::Conflict)?;
            let publication_id = random_id();
            let usage_grant = Self::issue_usage_grant(
                &tx,
                signer,
                &record,
                &approval,
                &edge,
                PublicationIdentity {
                    id: &publication_id,
                    generation,
                },
                now_ms,
            )?;
            auditing::record(
                &tx,
                "service_usage_grant_issued",
                id,
                auditing::management(actor),
            )?;
            self.make_service_claims(
                &record,
                &approval,
                &edge,
                PublicationVersion {
                    id: publication_id,
                    generation,
                    sequence: 1,
                    usage_grant,
                },
                now_ms,
            )?
        };
        let promised = bounded_add(claims.expires_at_unix_ms, HOLD_MARGIN_MS)?;
        let limits = &record.definition.limits;
        tx.execute("INSERT INTO service_publications(id,service_id,account_id,node_id,service_revision,generation,control_runtime_id,ingress_key,namespace_revision,claims_json,promised_until,maximum_connections,bytes_per_second,maximum_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) ON CONFLICT(id) DO UPDATE SET claims_json=excluded.claims_json,promised_until=MAX(service_publications.promised_until,excluded.promised_until) WHERE service_publications.state=0 AND service_publications.control_runtime_id=excluded.control_runtime_id",params![claims.publication_id,id,record.account,record.definition.edge_node_id,record.revision,claims.publication_generation,life.runtime_id,ingress_key(&record.definition.edge_node_id,&record.definition.requested_ingress),edge.namespace.revision,serde_json::to_string(&claims)?,promised,limits.maximum_connections,limits.bytes_per_second,limits.maximum_bytes])?;
        auditing::record(
            &tx,
            "service_publication_requested",
            id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(ServicePublicationIssue {
            claims,
            edge_public_key: edge.key,
        })
    }
    pub fn service_publication(
        &self,
        life: &ServiceLifecycle,
        actor: &Principal,
        id: &str,
        now_ms: u64,
    ) -> Result<ServicePublicationIssue, StorageError> {
        self.resume_services(life, now_ms)?;
        self.service_owner(actor, id, now_ms / 1000)?;
        let (record, approval, edge) = self.service_publication_facts(id, now_ms)?;
        let json:Option<String>=self.connection.query_row("SELECT claims_json FROM service_publications WHERE service_id=?1 AND state=0 AND control_runtime_id=?2",params![id,life.runtime_id],|r|r.get(0)).optional()?;
        let claims: ServiceLeaseClaims =
            serde_json::from_str(&json.ok_or(StorageError::Forbidden)?)?;
        let expected = self.make_service_claims(
            &record,
            &approval,
            &edge,
            PublicationVersion {
                id: claims.publication_id.clone(),
                generation: claims.publication_generation,
                sequence: claims.lease_sequence,
                usage_grant: claims.usage_grant.clone(),
            },
            now_ms,
        )?;
        if claims.expires_at_unix_ms <= now_ms
            || publication_binding(&claims)? != publication_binding(&expected)?
        {
            return Err(StorageError::Forbidden);
        }
        Ok(ServicePublicationIssue {
            claims,
            edge_public_key: edge.key,
        })
    }
    /// A renewable database row alone does not prove that its current lease is
    /// still authorized. Reads must apply the same binding checks as renewal,
    /// while retaining the old promise after expiry or invalidation.
    pub(super) fn service_publication_status(
        &self,
        id: &str,
        now_ms: u64,
    ) -> Result<ServicePublicationStatus, StorageError> {
        type Row = (u32, String, bool, u64);
        let row: Option<Row> = self.connection.query_row(
            "SELECT p.state,p.claims_json,COALESCE(p.control_runtime_id=s.control_runtime_id AND s.restore_fenced=0,0),n.last_issued_at FROM service_publications p JOIN service_publication_settings s ON s.singleton=1 JOIN data_nodes n ON n.id=p.node_id WHERE p.service_id=?1 AND p.state IN (0,1) AND p.promised_until>?2",
            params![id, now_ms],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).optional()?;
        let Some((state, json, runtime_current, node_issued)) = row else {
            return Ok(ServicePublicationStatus::NotPublished);
        };
        if state == 1 || !runtime_current {
            return Ok(ServicePublicationStatus::Stopping);
        }
        let claims: ServiceLeaseClaims = serde_json::from_str(&json)?;
        claims.validate()?;
        // Management views accept whole Unix seconds. Account for issuance or
        // heartbeat timestamps later within that same second without accepting
        // a lease or node heartbeat from a subsequent second.
        let at = now_ms.max(claims.issued_at_unix_ms).max(node_issued);
        if at.saturating_sub(now_ms) >= 1000 || claims.expires_at_unix_ms <= at {
            return Ok(ServicePublicationStatus::Stopping);
        }
        let (record, approval, edge) = match self.service_publication_facts(id, at) {
            Ok(facts) => facts,
            Err(
                StorageError::Forbidden | StorageError::Unauthorized | StorageError::Invalid(_),
            ) => {
                return Ok(ServicePublicationStatus::Stopping);
            }
            Err(error) => return Err(error),
        };
        let expected = self.make_service_claims(
            &record,
            &approval,
            &edge,
            PublicationVersion {
                id: claims.publication_id.clone(),
                generation: claims.publication_generation,
                sequence: claims.lease_sequence,
                usage_grant: claims.usage_grant.clone(),
            },
            at,
        )?;
        Ok(
            if publication_binding(&claims)? == publication_binding(&expected)? {
                ServicePublicationStatus::Published
            } else {
                ServicePublicationStatus::Stopping
            },
        )
    }
    pub fn stop_service_publication(
        &mut self,
        actor: &Principal,
        id: &str,
        expected_revision: u64,
        now: u64,
    ) -> Result<(), StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        let record = self.service_owner(actor, id, now)?;
        if record.revision != expected_revision {
            return Err(StorageError::Conflict);
        }
        tx.execute(
            "UPDATE service_publications SET state=1 WHERE service_id=?1 AND state=0",
            [id],
        )?;
        auditing::record(
            &tx,
            "service_publication_stopped",
            id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn service_resource_snapshot(
        &mut self,
        life: &ServiceLifecycle,
        signed: &SignedServiceResourceQuery,
        signer: &ServiceLeaseSigner,
        now_ms: u64,
        charge: impl FnOnce(&str) -> Result<(), StorageError>,
    ) -> Result<ServiceResourceSnapshot, StorageError> {
        let query: NodeResourceQueryClaims =
            decode_service_message(&signed.claims, SERVICE_MESSAGE_BYTES)?;
        query.validate()?;
        let tx = self.connection.unchecked_transaction()?;
        let edge = self.service_edge_live(&query.node_id, now_ms)?;
        let q = verify_service_query(signed, &edge.key)?;
        let sequence: u64 = tx.query_row(
            "SELECT lease_sequence FROM data_nodes WHERE id=?1",
            [&q.node_id],
            |r| r.get(0),
        )?;
        if q.deployment_id != self.deployment_id()?
            || q.security_epoch != self.security_epoch()?
            || q.policy_revision != self.policy()?.0
            || q.runtime_id != edge.runtime
            || q.runtime_generation != edge.generation
            || q.lease_sequence > sequence
            || q.issued_at_unix_ms > now_ms
            || q.expires_at_unix_ms <= now_ms
            || q.expires_at_unix_ms > edge.lease_end
        {
            return Err(StorageError::Forbidden);
        }
        let prior:Option<(String,u64,u64)>=tx.query_row("SELECT runtime_id,runtime_generation,request_sequence FROM service_node_polls WHERE node_id=?1",[&q.node_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if prior.is_some_and(|(runtime, generation, sequence)| {
            runtime == q.runtime_id
                && generation == q.runtime_generation
                && sequence >= q.request_sequence
        }) {
            return Err(StorageError::Conflict);
        }
        // Authentication and replay checks precede charging. No publication
        // rows, signing inputs or renewal promises are inspected until the
        // authenticated node's budget accepts this request. A rejection rolls
        // the transaction back, including consumption of the query sequence.
        charge(&q.node_id)?;
        self.resume_services(life, now_ms)?;
        tx.execute("INSERT INTO service_node_polls(node_id,control_runtime_id,runtime_id,runtime_generation,request_sequence) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(node_id) DO UPDATE SET control_runtime_id=excluded.control_runtime_id,runtime_id=excluded.runtime_id,runtime_generation=excluded.runtime_generation,request_sequence=excluded.request_sequence",params![q.node_id,life.runtime_id,q.runtime_id,q.runtime_generation,q.request_sequence])?;
        let mut statement=tx.prepare("SELECT id,service_id,claims_json FROM service_publications WHERE node_id=?1 AND state=0 AND control_runtime_id=?2 ORDER BY id LIMIT 33")?;
        let rows = statement.query_map(params![q.node_id, life.runtime_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let rows: Vec<_> = rows.collect::<Result<_, _>>()?;
        drop(statement);
        if rows.len() > SERVICE_PUBLICATIONS_PER_NODE {
            return Err(StorageError::RateLimited);
        }
        let mut leases = Vec::new();
        for (id, service, json) in rows {
            let old: ServiceLeaseClaims = serde_json::from_str(&json)?;
            let facts = self.service_publication_facts(&service, now_ms);
            let (record, approval, current) = match facts {
                Ok(f) => f,
                Err(
                    StorageError::Forbidden | StorageError::Unauthorized | StorageError::Invalid(_),
                ) => {
                    tx.execute("UPDATE service_publications SET state=1 WHERE id=?1", [&id])?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let next = self.make_service_claims(
                &record,
                &approval,
                &current,
                PublicationVersion {
                    id: id.clone(),
                    generation: old.publication_generation,
                    sequence: next(old.lease_sequence)?,
                    usage_grant: old.usage_grant.clone(),
                },
                now_ms,
            )?;
            if old.expires_at_unix_ms <= now_ms
                || publication_binding(&old)? != publication_binding(&next)?
            {
                tx.execute("UPDATE service_publications SET state=1 WHERE id=?1", [&id])?;
                continue;
            }
            let signed = signer.sign(&next)?;
            tx.execute("UPDATE service_publications SET claims_json=?1,promised_until=MAX(promised_until,?2) WHERE id=?3 AND state=0",params![serde_json::to_string(&next)?,bounded_add(next.expires_at_unix_ms,HOLD_MARGIN_MS)?,id])?;
            leases.push(signed);
        }
        let snapshot = ServiceResourceSnapshot {
            query: q.clone(),
            query_sha256: digest(&signed.claims),
            service_lease_issuer: signer.public_key(),
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: bounded_add(now_ms, SERVICE_RESOURCE_MS)?
                .min(q.expires_at_unix_ms)
                .min(edge.lease_end),
            leases,
        };
        snapshot.validate()?;
        tx.commit()?;
        Ok(snapshot)
    }

    pub(super) fn add_scope_spend(
        tx: &Transaction<'_>,
        kind: &str,
        key: &str,
        delta: u64,
    ) -> Result<(), StorageError> {
        if delta == 0 {
            return Ok(());
        }
        let changed = tx.execute(
            "UPDATE service_quota_ledgers SET spent_bytes=spent_bytes+?1 WHERE scope_kind=?2 AND scope_key=?3 AND spent_bytes<=9223372036854775807-?1",
            params![delta,kind,key],
        )?;
        if changed != 1 {
            return Err(StorageError::Conflict);
        }
        Ok(())
    }

    pub fn accept_service_usage_report(
        &mut self,
        signed: &SignedServiceUsageReport,
        ack_signer: &NodePolicySigner,
        now_ms: u64,
    ) -> Result<SignedServiceUsageReportAck, StorageError> {
        let untrusted: ServiceUsageReportClaims =
            decode_service_message(&signed.claims, SERVICE_USAGE_BYTES)?;
        untrusted.validate()?;
        if now_ms == 0 || now_ms > i64::MAX as u64 {
            return Err(StorageError::Invalid("invalid service usage clock"));
        }
        let tx = self.connection.transaction()?;
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM private_service_leases WHERE grant_id=?1)",
            [&untrusted.grant_id],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(StorageError::Forbidden);
        }
        type Node = (Vec<u8>, Option<String>, u64, u64, u64);
        let node: Option<Node> = tx
            .query_row(
                "SELECT public_key,runtime_id,runtime_generation,last_issued_at,lease_policy_revision FROM data_nodes WHERE id=?1 AND revoked=0",
                [&untrusted.node_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
            )
            .optional()?;
        let (public_key, current_runtime, current_generation, lease_issued, lease_policy) =
            node.ok_or(StorageError::Forbidden)?;
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| StorageError::Conflict)?;
        let claims = verify_service_usage_report(signed, &public_key)?;
        let (deployment, epoch, policy): (String, u64, u64) = tx.query_row(
            "SELECT id,security_epoch,policy_revision FROM deployment WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if claims.deployment_id != deployment
            || claims.security_epoch != epoch
            || claims.policy_revision != policy
            || lease_policy != policy
            || current_runtime.as_deref() != Some(claims.node_runtime_id.as_str())
            || claims.node_runtime_generation != current_generation
            || now_ms < lease_issued
            || now_ms >= lease_issued.saturating_add(NODE_LEASE_MS)
            || claims.sampled_at_unix_ms < lease_issued
            || claims.sampled_at_unix_ms > now_ms.saturating_add(1000)
        {
            return Err(StorageError::Unauthorized);
        }
        type Grant = (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            u64,
            u64,
            u64,
            Vec<u8>,
            u64,
            u64,
            u64,
            u64,
            u64,
            Vec<u8>,
            Option<String>,
            u64,
            u32,
            u32,
        );
        let grant: Option<Grant> = tx
            .query_row(
                "SELECT deployment_id,account_id,host_device_id,service_id,node_id,publication_id,edge_runtime_id,edge_runtime_generation,publication_generation,security_epoch,grant_sha256,grant_bytes,admitted_bytes,opened_connections,closed_connections,report_sequence,report_sha256,report_ack_json,sampled_at,terminal,maximum_connections FROM service_usage_grants WHERE grant_id=?1",
                [&claims.grant_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?,row.get(15)?,row.get(16)?,row.get(17)?,row.get(18)?,row.get(19)?,row.get(20)?)),
            )
            .optional()?;
        let (
            g_deployment,
            g_account,
            g_device,
            g_service,
            g_node,
            g_publication,
            g_runtime,
            g_runtime_generation,
            g_generation,
            g_epoch,
            g_digest,
            g_bytes,
            g_admitted,
            g_opened,
            g_closed,
            g_sequence,
            g_report_digest,
            g_ack,
            g_sampled,
            terminal,
            g_max_connections,
        ) = grant.ok_or(StorageError::Forbidden)?;
        let report_digest = digest(&signed.claims);
        if g_deployment != deployment
            || g_account != claims.account_id
            || g_device != claims.host_device_id
            || g_service != claims.service_id
            || g_node != claims.node_id
            || g_publication != claims.publication_id
            || g_runtime != claims.node_runtime_id
            || g_runtime_generation != claims.node_runtime_generation
            || g_generation != claims.publication_generation
            || g_epoch != epoch
            || claims.grant_sha256.as_slice() != g_digest.as_slice()
        {
            return Err(StorageError::Unauthorized);
        }
        // A terminal seal closes the report stream. Even an otherwise exact
        // report replay is no longer accepted after that terminal statement.
        if terminal != 0 {
            return Err(StorageError::Conflict);
        }
        if claims.report_sequence == g_sequence {
            let stored: Option<(Vec<u8>, String)> = tx
                .query_row(
                    "SELECT report_sha256,ack_json FROM service_usage_reports WHERE grant_id=?1 AND report_sequence=?2",
                    params![claims.grant_id,claims.report_sequence],
                    |row| Ok((row.get(0)?,row.get(1)?)),
                )
                .optional()?;
            let (stored_digest, ack_json) = stored.ok_or(StorageError::Conflict)?;
            if stored_digest.as_slice() != report_digest.as_slice()
                || g_report_digest.as_slice() != report_digest.as_slice()
                || g_ack.as_deref() != Some(ack_json.as_str())
            {
                return Err(StorageError::Conflict);
            }
            let ack: SignedServiceUsageReportAck = serde_json::from_str(&ack_json)?;
            if verify_service_usage_ack(&ack, &ack_signer.public_key()).is_err() {
                return Err(StorageError::Conflict);
            }
            return Ok(ack);
        }
        if claims.report_sequence != g_sequence.checked_add(1).ok_or(StorageError::Conflict)?
            || claims.admitted_bytes < g_admitted
            || claims.admitted_bytes > g_bytes
            || claims.opened_connections < g_opened
            || claims.closed_connections < g_closed
            || claims.opened_connections - claims.closed_connections > u64::from(g_max_connections)
            || claims.sampled_at_unix_ms < g_sampled
        {
            return Err(StorageError::Conflict);
        }
        let delta = claims.admitted_bytes - g_admitted;
        for (kind, key) in [
            ("account", claims.account_id.as_str()),
            ("device", claims.host_device_id.as_str()),
            ("node", claims.node_id.as_str()),
            ("resource", claims.service_id.as_str()),
        ] {
            Self::add_scope_spend(&tx, kind, key, delta)?;
        }
        let ack_claims = ServiceUsageReportAckClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: deployment,
            security_epoch: epoch,
            node_id: claims.node_id.clone(),
            node_runtime_id: claims.node_runtime_id.clone(),
            node_runtime_generation: claims.node_runtime_generation,
            grant_id: claims.grant_id.clone(),
            report_sequence: claims.report_sequence,
            report_sha256: report_digest,
            accepted_at_unix_ms: now_ms,
        };
        let ack = ack_signer.sign_service_usage_ack(&ack_claims)?;
        let report_json = serde_json::to_string(signed)?;
        let ack_json = serde_json::to_string(&ack)?;
        tx.execute(
            "INSERT INTO service_usage_reports(grant_id,report_sequence,report_sha256,report_json,ack_json) VALUES(?1,?2,?3,?4,?5)",
            params![claims.grant_id,claims.report_sequence,report_digest,report_json,ack_json],
        )?;
        if tx.execute(
            "UPDATE service_usage_grants SET admitted_bytes=?1,opened_connections=?2,closed_connections=?3,report_sequence=?4,report_sha256=?5,sampled_at=?6,report_json=?7,report_ack_json=?8 WHERE grant_id=?9 AND terminal=0 AND report_sequence=?10",
            params![claims.admitted_bytes,claims.opened_connections,claims.closed_connections,claims.report_sequence,report_digest,claims.sampled_at_unix_ms,report_json,ack_json,claims.grant_id,g_sequence],
        )? != 1 {
            return Err(StorageError::Conflict);
        }
        auditing::record(
            &tx,
            "service_usage_report_accepted",
            &claims.grant_id,
            AuditActor::Node {
                node_id: claims.node_id,
                runtime_id: claims.node_runtime_id,
                runtime_generation: claims.node_runtime_generation,
            },
        )?;
        tx.commit()?;
        Ok(ack)
    }

    pub fn accept_service_usage_stop(
        &mut self,
        signed: &SignedServiceUsageRuntimeStop,
        now_ms: u64,
    ) -> Result<(), StorageError> {
        let untrusted: ServiceUsageRuntimeStopClaims =
            decode_service_message(&signed.claims, SERVICE_USAGE_BYTES)?;
        untrusted.validate()?;
        if now_ms == 0 || now_ms > i64::MAX as u64 {
            return Err(StorageError::Invalid("invalid service stop clock"));
        }
        let tx = self.connection.transaction()?;
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM private_service_leases WHERE grant_id=?1)",
            [&untrusted.grant_id],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(StorageError::Forbidden);
        }
        type Node = (Vec<u8>, Option<String>, u64, u64, u64);
        let node: Option<Node> = tx
            .query_row(
                "SELECT public_key,runtime_id,runtime_generation,last_issued_at,lease_policy_revision FROM data_nodes WHERE id=?1 AND revoked=0",
                [&untrusted.node_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
            )
            .optional()?;
        let (public_key, current_runtime, current_generation, lease_issued, lease_policy) =
            node.ok_or(StorageError::Forbidden)?;
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| StorageError::Conflict)?;
        let claims = verify_service_usage_stop(signed, &public_key)?;
        let (deployment, epoch, policy): (String, u64, u64) = tx.query_row(
            "SELECT id,security_epoch,policy_revision FROM deployment WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if claims.deployment_id != deployment
            || claims.security_epoch != epoch
            || claims.policy_revision != policy
            || lease_policy != policy
            || current_runtime.as_deref() != Some(claims.node_runtime_id.as_str())
            || claims.node_runtime_generation != current_generation
            || now_ms < lease_issued
            || now_ms >= lease_issued.saturating_add(NODE_LEASE_MS)
        {
            return Err(StorageError::Unauthorized);
        }
        type Grant = (
            String,
            String,
            String,
            String,
            u64,
            u64,
            u64,
            Vec<u8>,
            u64,
            u64,
            u64,
            u64,
            u64,
            Vec<u8>,
            u32,
            u32,
        );
        let grant: Option<Grant> = tx
            .query_row(
                "SELECT deployment_id,node_id,publication_id,edge_runtime_id,edge_runtime_generation,publication_generation,security_epoch,grant_sha256,grant_bytes,admitted_bytes,opened_connections,closed_connections,report_sequence,report_sha256,terminal,maximum_connections FROM service_usage_grants WHERE grant_id=?1",
                [&claims.grant_id],
                |row| Ok((
                    row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,
                    row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?,row.get(15)?,
                )),
            )
            .optional()?;
        let (
            g_deployment,
            g_node,
            g_publication,
            g_runtime,
            g_runtime_generation,
            g_generation,
            g_epoch,
            g_digest,
            g_bytes,
            g_admitted,
            g_opened,
            g_closed,
            g_sequence,
            g_report_digest,
            terminal,
            g_max_connections,
        ) = grant.ok_or(StorageError::Forbidden)?;
        let stop_digest = digest(&signed.claims);
        if terminal != 0 {
            let old: Option<(Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT stop_nonce,stop_sha256 FROM service_usage_stops WHERE grant_id=?1",
                    [&claims.grant_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if old.is_some_and(|(nonce, hash)| {
                nonce.as_slice() == claims.stop_nonce.as_slice()
                    && hash.as_slice() == stop_digest.as_slice()
            }) {
                return Ok(());
            }
            return Err(StorageError::Conflict);
        }
        if g_deployment != deployment
            || g_epoch != epoch
            || g_node != claims.node_id
            || g_publication != claims.publication_id
            || g_generation != claims.publication_generation
            || g_runtime != claims.node_runtime_id
            || g_runtime_generation != claims.node_runtime_generation
            || g_digest.as_slice() != claims.grant_sha256.as_slice()
            || claims.final_report_sequence != g_sequence
            || claims.final_report_sha256.as_slice() != g_report_digest.as_slice()
            // The terminal statement may release commitment only for the
            // exact highwater whose report has already received an ACK. Any
            // final delta must be reported and acknowledged before sealing.
            // With no traffic, sequence zero and the initial zero highwater
            // remain a valid empty transcript.
            || claims.admitted_bytes != g_admitted
            || claims.admitted_bytes > g_bytes
            || claims.opened_connections != g_opened
            || claims.closed_connections != g_closed
            || claims.opened_connections - claims.closed_connections > u64::from(g_max_connections)
        {
            return Err(StorageError::Conflict);
        }
        // All admitted-byte spend was committed by report ACKs; this durable
        // terminal transaction releases only the unused commitment.
        let stop_json = serde_json::to_string(signed)?;
        if tx.execute("UPDATE service_usage_grants SET admitted_bytes=?1,opened_connections=?2,closed_connections=?3,terminal=1,stop_nonce=?4,stop_sha256=?5,stopped_at=?6 WHERE grant_id=?7 AND terminal=0",params![claims.admitted_bytes,claims.opened_connections,claims.closed_connections,claims.stop_nonce.as_slice(),stop_digest.as_slice(),claims.stopped_at_unix_ms,claims.grant_id])?!=1 { return Err(StorageError::Conflict); }
        tx.execute("INSERT INTO service_usage_stops(grant_id,stop_nonce,stop_sha256,stop_json,acknowledged_at) VALUES(?1,?2,?3,?4,?5)",params![claims.grant_id,claims.stop_nonce.as_slice(),stop_digest.as_slice(),stop_json,now_ms])?;
        auditing::record(
            &tx,
            "service_usage_grant_released",
            &claims.grant_id,
            AuditActor::Node {
                node_id: claims.node_id,
                runtime_id: claims.node_runtime_id,
                runtime_generation: claims.node_runtime_generation,
            },
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(super) fn validate_quota_scope_key(
        tx: &Transaction<'_>,
        scope: ServiceQuotaScope,
        key: &str,
    ) -> Result<(), StorageError> {
        require_id(key)?;
        if scope == ServiceQuotaScope::Node {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM data_nodes WHERE id=?1) OR EXISTS(SELECT 1 FROM services WHERE host_device_id=?1 AND edge_node_id IS NULL)",
                [key], |row| row.get(0),
            )?;
            return if exists {
                Ok(())
            } else {
                Err(StorageError::Forbidden)
            };
        }
        let table = match scope {
            ServiceQuotaScope::Account => "accounts",
            ServiceQuotaScope::Device => "devices",
            ServiceQuotaScope::Node => "data_nodes",
            ServiceQuotaScope::Resource => "services",
        };
        let exists: bool = tx.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id=?1)"),
            [key],
            |row| row.get(0),
        )?;
        if exists {
            Ok(())
        } else {
            Err(StorageError::Forbidden)
        }
    }

    pub(super) fn default_scope_limit(scope: ServiceQuotaScope, resource_limit: u64) -> u64 {
        match scope {
            ServiceQuotaScope::Account => ACCOUNT_BYTES,
            ServiceQuotaScope::Device => DEVICE_BYTES,
            ServiceQuotaScope::Node => NODE_BYTES,
            ServiceQuotaScope::Resource => resource_limit,
        }
    }

    /// A restored database cannot prove that its snapshot includes all usage
    /// already acknowledged after that snapshot. Keep grant issuance closed
    /// until an external accounting reconciliation has been performed.
    pub fn service_quota_restore_fenced(
        &self,
        actor: &Principal,
        now_ms: u64,
    ) -> Result<bool, StorageError> {
        if now_ms == 0 || now_ms > i64::MAX as u64 {
            return Err(StorageError::Invalid("invalid service quota clock"));
        }
        self.audit_admin(actor, now_ms / 1000)?;
        Ok(self.connection.query_row(
            "SELECT restore_fenced FROM service_quota_settings WHERE singleton=1",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn service_quota_usage(
        &mut self,
        actor: &Principal,
        query: ServiceQuotaUsageQuery,
        now_ms: u64,
    ) -> Result<ServiceQuotaUsageView, StorageError> {
        query.validate()?;
        if now_ms == 0 || now_ms > i64::MAX as u64 {
            return Err(StorageError::Invalid("invalid service quota clock"));
        }
        self.audit_admin(actor, now_ms / 1000)?;
        let tx = self.connection.transaction()?;
        Self::validate_quota_scope_key(&tx, query.scope, &query.scope_key)?;
        let resource_limit = if query.scope == ServiceQuotaScope::Resource {
            let json: String = tx.query_row(
                "SELECT definition_json FROM services WHERE id=?1",
                [&query.scope_key],
                |row| row.get(0),
            )?;
            serde_json::from_str::<ServiceDefinition>(&json)?
                .limits
                .maximum_bytes
        } else {
            u64::MAX
        };
        let default_limit = Self::default_scope_limit(query.scope, resource_limit);
        let kind = query.scope.as_str();
        let (limit, revision, spent, outstanding, active): (u64,u64,u64,u64,u64) = tx.query_row(
            "SELECT COALESCE((SELECT limit_bytes FROM service_quota_limits WHERE scope_kind=?1 AND scope_key=?2),?3),COALESCE((SELECT revision FROM service_quota_limits WHERE scope_kind=?1 AND scope_key=?2),0),COALESCE((SELECT spent_bytes FROM service_quota_ledgers WHERE scope_kind=?1 AND scope_key=?2),0),COALESCE((SELECT SUM(grant_bytes-admitted_bytes) FROM service_usage_grants WHERE terminal=0 AND CASE ?1 WHEN 'account' THEN account_id WHEN 'device' THEN host_device_id WHEN 'node' THEN node_id ELSE service_id END=?2),0),COALESCE((SELECT count(*) FROM service_usage_grants WHERE terminal=0 AND CASE ?1 WHEN 'account' THEN account_id WHEN 'device' THEN host_device_id WHEN 'node' THEN node_id ELSE service_id END=?2),0)",
            params![kind,query.scope_key,default_limit],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        )?;
        let latest: Option<(String,u64)> = tx
            .query_row(
                "SELECT edge_runtime_id,edge_runtime_generation FROM service_usage_grants WHERE terminal=0 AND CASE ?1 WHEN 'account' THEN account_id WHEN 'device' THEN host_device_id WHEN 'node' THEN node_id ELSE service_id END=?2 ORDER BY rowid DESC LIMIT 1",
                params![kind,query.scope_key],
                |row| Ok((row.get(0)?,row.get(1)?)),
            )
            .optional()?;
        let reconciliation_required = tx.query_row(
            "SELECT restore_fenced FROM service_quota_settings WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(ServiceQuotaUsageView {
            scope: query.scope,
            scope_key: query.scope_key,
            spent_bytes: spent,
            outstanding_bytes: outstanding,
            limit_bytes: limit,
            limit_revision: revision,
            active_grants: active,
            reconciliation_required,
            latest_runtime_id: latest.as_ref().map(|v| v.0.clone()),
            latest_runtime_generation: latest.map(|v| v.1),
        })
    }

    pub fn set_service_quota_limit(
        &mut self,
        actor: &Principal,
        update: ServiceQuotaLimitUpdate,
        now_ms: u64,
    ) -> Result<ServiceQuotaUsageView, StorageError> {
        update.validate()?;
        if now_ms == 0 || now_ms > i64::MAX as u64 {
            return Err(StorageError::Invalid("invalid service quota clock"));
        }
        self.audit_admin(actor, now_ms / 1000)?;
        let tx = self.connection.transaction()?;
        Self::validate_quota_scope_key(&tx, update.scope, &update.scope_key)?;
        let kind = update.scope.as_str();
        let prior: Option<u64> = tx
            .query_row(
                "SELECT revision FROM service_quota_limits WHERE scope_kind=?1 AND scope_key=?2",
                params![kind, update.scope_key],
                |row| row.get(0),
            )
            .optional()?;
        if prior.unwrap_or(0) != update.expected_revision {
            return Err(StorageError::Conflict);
        }
        let revision = update
            .expected_revision
            .checked_add(1)
            .filter(|value| *value > 0 && *value <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        tx.execute(
            "INSERT INTO service_quota_limits(scope_kind,scope_key,limit_bytes,revision) VALUES(?1,?2,?3,?4) ON CONFLICT(scope_kind,scope_key) DO UPDATE SET limit_bytes=excluded.limit_bytes,revision=excluded.revision",
            params![kind,update.scope_key,update.limit_bytes,revision],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO service_quota_ledgers(scope_kind,scope_key,spent_bytes) VALUES(?1,?2,0)",
            params![kind,update.scope_key],
        )?;
        let quota_revision: Option<u64> = tx.query_row(
            "UPDATE service_quota_settings SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807 RETURNING revision",
            [],
            |row| row.get(0),
        ).optional()?;
        if quota_revision.is_none() {
            return Err(StorageError::Conflict);
        }
        auditing::record(
            &tx,
            "service_quota_limit_changed",
            &format!("{kind}/{}", update.scope_key),
            auditing::management(actor),
        )?;
        tx.commit()?;
        self.service_quota_usage(
            actor,
            ServiceQuotaUsageQuery {
                scope: update.scope,
                scope_key: update.scope_key,
            },
            now_ms,
        )
    }
}
