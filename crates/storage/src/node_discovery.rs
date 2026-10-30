//! Versioned operator approval and current, endpoint-authenticated relay discovery.
use crate::{
    StorageError, Store, accounts::Principal, auditing, relay_reservations::RelayLifecycle,
    require_id,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{
    digest, node_discovery::discovery_transcript, relay::session_binding, verify_device_action,
};
use nestlink_protocol::{
    DiscoveredRelayNode, NODE_DISCOVERY_COUNT, NODE_DISCOVERY_MS, NODE_LEASE_MS,
    NodeDiscoveryClaims, NodeRole, SCHEMA_VERSION,
    api::{NodeDiscoveryRequest, NodeEndpoints, NodeEndpointsUpdate, NodeEndpointsView},
};
use prost::Message;
use rusqlite::{OptionalExtension, params};
impl Store {
    pub fn node_endpoints(
        &self,
        actor: &Principal,
        id: &str,
        now_ms: u64,
    ) -> Result<NodeEndpointsView, StorageError> {
        self.audit_admin(actor, now_ms / 1000)?;
        require_id(id)?;
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM data_nodes WHERE id=?1 AND revoked=0)",
            [id],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(StorageError::Forbidden);
        }
        let row: Option<(u64, String)> = self
            .connection
            .query_row(
                "SELECT revision,endpoints_json FROM node_endpoints WHERE node_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (revision, endpoints) = match row {
            Some((v, json)) => (v, serde_json::from_str(&json)?),
            None => (0, NodeEndpoints::default()),
        };
        Ok(NodeEndpointsView {
            node_id: id.into(),
            revision,
            endpoints,
        })
    }
    pub fn set_node_endpoints(
        &mut self,
        actor: &Principal,
        id: &str,
        update: NodeEndpointsUpdate,
        now_ms: u64,
    ) -> Result<NodeEndpointsView, StorageError> {
        update.endpoints.validate()?;
        let tx = self.connection.unchecked_transaction()?;
        let old = self.node_endpoints(actor, id, now_ms)?;
        if old.revision != update.expected_revision {
            return Err(StorageError::Conflict);
        }
        let revision = old
            .revision
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        if update.endpoints.quic_uri.is_some() || update.endpoints.wss_origin.is_some() {
            let roles: String =
                tx.query_row("SELECT roles_json FROM data_nodes WHERE id=?1", [id], |r| {
                    r.get(0)
                })?;
            if !serde_json::from_str::<Vec<i32>>(&roles)?.contains(&(NodeRole::NodeRelay as i32)) {
                return Err(StorageError::Forbidden);
            }
        }
        tx.execute("INSERT INTO node_endpoints VALUES(?1,?2,?3) ON CONFLICT(node_id) DO UPDATE SET revision=excluded.revision,endpoints_json=excluded.endpoints_json",params![id,revision,serde_json::to_string(&update.endpoints)?])?;
        auditing::record(
            &tx,
            "node_endpoints_updated",
            id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(NodeEndpointsView {
            node_id: id.into(),
            revision,
            endpoints: update.endpoints,
        })
    }
    /// Discovery reads current facts; it does not issue/renew a permit, node lease
    /// or allocation. A subsequent allocation independently checks capacity.
    pub fn discover_relay_nodes(
        &self,
        lifecycle: &RelayLifecycle,
        actor: &Principal,
        session: &str,
        request: NodeDiscoveryRequest,
        now_ms: u64,
    ) -> Result<NodeDiscoveryClaims, StorageError> {
        require_id(&request.device_id)?;
        self.validate_access(actor, now_ms / 1000)?;
        lifecycle.check_clock(now_ms)?;
        if !lifecycle.ready() {
            return Err(StorageError::RateLimited);
        }
        let tx = self.connection.unchecked_transaction()?;
        let runtime: Option<String> = tx.query_row(
            "SELECT control_runtime_id FROM relay_reservation_settings WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if runtime.as_deref() != Some(&lifecycle.runtime_id) {
            return Err(StorageError::Conflict);
        }
        let permit = self.current_permit(actor, session, now_ms / 1000)?;
        if permit.issued_at_unix_ms > now_ms || permit.expires_at_unix_ms <= now_ms {
            return Err(StorageError::Forbidden);
        }
        let endpoint = self.device_record_at(&request.device_id, now_ms / 1000)?;
        if endpoint.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        if request.device_id == permit.controller_device_id {
            self.check_request_login(session, now_ms / 1000, Some(&actor.session_id))?;
        }
        let nonce: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&request.nonce)
            .map_err(|_| StorageError::Unauthorized)?
            .try_into()
            .map_err(|_| StorageError::Unauthorized)?;
        if URL_SAFE_NO_PAD.encode(nonce) != request.nonce
            || URL_SAFE_NO_PAD.encode(digest(&permit.encode_to_vec())) != request.permit_sha256
        {
            return Err(StorageError::Unauthorized);
        }
        let transcript =
            discovery_transcript(&permit, &actor.account_id, &request.device_id, &nonce)?;
        verify_device_action(
            &transcript,
            &endpoint.public_key,
            &super::control::decode_signature(&request.signature)?,
        )?;
        let expiry = now_ms
            .checked_add(NODE_DISCOVERY_MS)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?
            .min(permit.expires_at_unix_ms);
        let mut c = NodeDiscoveryClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: permit.deployment_id.clone(),
            security_epoch: permit.security_epoch,
            session_id: session.into(),
            account_id: actor.account_id.clone(),
            device_id: request.device_id,
            device_key_sha256: digest(&endpoint.public_key).to_vec(),
            permit_sha256: digest(&permit.encode_to_vec()).to_vec(),
            request_sha256: digest(&transcript.encode_to_vec()).to_vec(),
            nonce: nonce.to_vec(),
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: expiry,
            nodes: vec![],
        };
        let quota = self.relay_quota_current()?;
        let held: u64 = tx.query_row(
            "SELECT (SELECT count(*) FROM all_relay_capacity WHERE promised_until>?1)+(SELECT count(*) FROM turn_grants WHERE promised_until>?1)",
            [now_ms],
            |r| r.get(0),
        )?;
        // This snapshot is advisory availability, never a capacity promise.
        let host = self.device_record_at(&permit.host_device_id, now_ms / 1000)?;
        let mut account_capacity = true;
        for account in [&permit.account_id, &host.account] {
            let held:u64=tx.query_row("SELECT (SELECT COALESCE(sum((controller_account_id=?1)+(host_account_id=?1)),0) FROM all_relay_capacity WHERE promised_until>?2)+(SELECT count(*) FROM turn_grants WHERE account_id=?1 AND promised_until>?2)",params![account,now_ms],|r|r.get(0))?;
            let added = if permit.account_id == host.account {
                2
            } else {
                1
            };
            if held.saturating_add(added) > u64::from(quota.limits.max_account_endpoints) {
                account_capacity = false;
            }
        }
        // A peer joining an already-held reservation needs its node descriptor
        // even when the first endpoint consumed the last free slot. Discovery
        // still promises no capacity; a different UUID must pass fresh admission.
        let mut existing = tx.prepare("SELECT claims_json FROM relay_reservations WHERE kind='node' AND closed=0 AND session_id=?1 AND control_runtime_id=?2 AND security_epoch=?3 AND connection_generation=?4 AND policy_revision=?5 AND quota_revision=?6 AND promised_until>?7 LIMIT 128")?;
        let matching = existing
            .query_map(
                params![
                    session,
                    lifecycle.runtime_id,
                    permit.security_epoch,
                    permit.connection_generation,
                    permit.policy_revision,
                    quota.revision,
                    now_ms
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(existing);
        let binding = session_binding(&permit)?;
        let mut owned = Vec::new();
        for json in matching {
            let allocation: nestlink_protocol::RelayAllocationClaims = serde_json::from_str(&json)?;
            allocation.validate()?;
            if allocation.issued_at_unix_ms <= now_ms
                && allocation.expires_at_unix_ms > now_ms
                && allocation.session_binding_sha256 == binding
            {
                owned.push(allocation);
            }
        }
        let global_capacity = held < u64::from(quota.limits.max_allocations) && account_capacity;
        if global_capacity || !owned.is_empty() {
            let mut query=tx.prepare("SELECT n.id,n.public_key,n.roles_json,n.runtime_id,n.runtime_generation,n.last_issued_at,e.revision,e.endpoints_json,n.max_connections,(SELECT count(*)*2 FROM all_relay_capacity a WHERE a.node_id=n.id AND a.promised_until>?1)+(SELECT count(*) FROM turn_grants t WHERE t.node_id=n.id AND t.promised_until>?1) FROM data_nodes n JOIN node_endpoints e ON e.node_id=n.id JOIN node_runtimes r ON r.node_id=n.id AND r.runtime_id=n.runtime_id AND r.generation=n.runtime_generation WHERE n.revoked=0 AND n.lease_policy_revision=?2 AND r.security_epoch=?3 AND n.last_issued_at<=?1 AND n.last_issued_at>?4 ORDER BY n.id LIMIT 128")?;
            let mut rows = query.query(params![
                now_ms,
                permit.policy_revision,
                permit.security_epoch,
                now_ms.saturating_sub(NODE_LEASE_MS)
            ])?;
            while let Some(row) = rows.next()? {
                let roles: Vec<i32> = serde_json::from_str(&row.get::<_, String>(2)?)?;
                let endpoints: NodeEndpoints = serde_json::from_str(&row.get::<_, String>(7)?)?;
                endpoints.validate()?;
                let id: String = row.get(0)?;
                let runtime: String = row.get(3)?;
                let generation: u64 = row.get(4)?;
                let endpoint_revision: u64 = row.get(6)?;
                let key = digest(&row.get::<_, Vec<u8>>(1)?);
                let own_expiry = owned
                    .iter()
                    .filter(|a| {
                        a.node_id == id
                            && a.runtime_id == runtime
                            && a.runtime_generation == generation
                            && a.node_endpoint_revision == endpoint_revision
                            && a.node_key_sha256 == key
                    })
                    .map(|a| a.expires_at_unix_ms)
                    .max();
                let capacity = global_capacity
                    && row.get::<_, u64>(9)?.saturating_add(2) <= row.get::<_, u64>(8)?;
                if !roles.contains(&(NodeRole::NodeRelay as i32))
                    || (endpoints.quic_uri.is_none() && endpoints.wss_origin.is_none())
                    || (!capacity && own_expiry.is_none())
                {
                    continue;
                }
                c.nodes.push(DiscoveredRelayNode {
                    node_id: id,
                    node_key_sha256: key.to_vec(),
                    runtime_id: runtime,
                    runtime_generation: generation,
                    endpoint_revision,
                    quic_uri: endpoints.quic_uri.unwrap_or_default(),
                    wss_origin: endpoints.wss_origin.unwrap_or_default(),
                    allow_loopback: endpoints.allow_loopback,
                    expires_at_unix_ms: expiry
                        .min(if capacity {
                            expiry
                        } else {
                            own_expiry.ok_or(StorageError::Conflict)?
                        })
                        .min(
                            row.get::<_, u64>(5)?
                                .checked_add(NODE_LEASE_MS)
                                .ok_or(StorageError::Conflict)?,
                        ),
                });
                if c.nodes.len() as u64 == NODE_DISCOVERY_COUNT {
                    break;
                }
            }
        }
        c.validate()?;
        tx.commit()?;
        Ok(c)
    }
}
