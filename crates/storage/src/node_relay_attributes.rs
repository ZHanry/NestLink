//! Advisory relay metadata with independent admin CAS; no identity or grant change.
use crate::{StorageError, Store, accounts::Principal, auditing, require_id};
use nestlink_protocol::{
    NodeRole,
    api::{NodeRelayAttributes, NodeRelayAttributesUpdate, NodeRelayAttributesView},
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

fn clock(now_ms: u64) -> Result<u64, StorageError> {
    if now_ms == 0 || now_ms > i64::MAX as u64 {
        return Err(StorageError::Invalid("invalid relay attributes clock"));
    }
    Ok(now_ms / 1000)
}

fn read(connection: &Connection, id: &str) -> Result<NodeRelayAttributesView, StorageError> {
    require_id(id)?;
    let roles: Option<String> = connection.query_row(
        "SELECT roles_json FROM data_nodes WHERE id=?1 AND revoked=0",
        [id], |row| row.get(0),
    ).optional()?;
    let roles = roles.ok_or(StorageError::Forbidden)?;
    if !serde_json::from_str::<Vec<i32>>(&roles)?.contains(&(NodeRole::NodeRelay as i32)) {
        return Err(StorageError::Forbidden);
    }
    let stored = connection.query_row(
        "SELECT revision,region,cost_weight FROM node_relay_attributes WHERE node_id=?1",
        [id], |row| Ok((row.get::<_, u64>(0)?, NodeRelayAttributes {
            region: row.get(1)?, cost_weight: row.get(2)?,
        })),
    ).optional()?;
    let (revision, attributes) = stored.unwrap_or_default();
    attributes.validate()?;
    Ok(NodeRelayAttributesView { node_id: id.into(), revision, attributes })
}

impl Store {
    /// Reuse the authenticated discovery owner. The adjacent local read can
    /// reveal attributes only for identities selected by that exact discovery;
    /// it does not confer deployment-admin metadata access on the consumer.
    pub fn discover_relay_candidates(
        &self, lifecycle: &crate::relay_reservations::RelayLifecycle,
        actor: &Principal, session: &str,
        request: nestlink_protocol::api::NodeDiscoveryRequest, now_ms: u64,
    ) -> Result<(nestlink_protocol::NodeDiscoveryClaims, Vec<NodeRelayAttributesView>), StorageError> {
        let claims = self.discover_relay_nodes(lifecycle, actor, session, request, now_ms)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, clock(now_ms)?)?;
        let attributes = claims.nodes.iter().map(|node| read(&tx, &node.node_id)).collect::<Result<Vec<_>,_>>()?;
        tx.commit()?;
        Ok((claims, attributes))
    }

    pub fn node_relay_attributes(&self, actor: &Principal, id: &str, now_ms: u64) -> Result<NodeRelayAttributesView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, clock(now_ms)?)?;
        let view = read(&tx, id)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn set_node_relay_attributes(&mut self, actor: &Principal, id: &str, update: NodeRelayAttributesUpdate, now_ms: u64) -> Result<NodeRelayAttributesView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, clock(now_ms)?)?;
        let current = read(&tx, id)?;
        if update.expected_revision != current.revision {
            return Err(StorageError::Conflict);
        }
        update.attributes.validate()?;
        let revision = current.revision.checked_add(1).filter(|value| *value <= i64::MAX as u64).ok_or(StorageError::Conflict)?;
        tx.execute(
            "INSERT INTO node_relay_attributes(node_id,revision,region,cost_weight) VALUES(?1,?2,?3,?4)
             ON CONFLICT(node_id) DO UPDATE SET revision=excluded.revision,region=excluded.region,cost_weight=excluded.cost_weight",
            params![id,revision,update.attributes.region,update.attributes.cost_weight],
        )?;
        auditing::record(&tx, "node_relay_attributes_updated", id, auditing::management(actor))?;
        let view = read(&tx, id)?;
        tx.commit()?;
        Ok(view)
    }
}
