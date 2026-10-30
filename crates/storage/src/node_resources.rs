//! Fresh authenticated resource facts; never lease renewal or capacity refund.
use crate::{StorageError, Store, relay_reservations::RelayLifecycle};
use nestlink_identity::{digest, node_resources::verify_resource_query, relay::session_binding};
use nestlink_protocol::{
    NODE_LEASE_MS, NODE_MESSAGE_BYTES, NODE_RESOURCE_ALLOCATIONS, NODE_RESOURCE_TTL_MS,
    NodeResourceQueryClaims, NodeResourceSnapshotClaims, RelayAllocationClaims,
    SignedNodeResourceQuery, decode_bounded,
};
use rusqlite::OptionalExtension;
impl Store {
    pub fn node_resource_snapshot_with_network(
        &mut self,
        lifecycle: &RelayLifecycle,
        signed: &SignedNodeResourceQuery,
        signer: &nestlink_identity::PermitSigner,
        now_ms: u64,
    ) -> Result<NodeResourceSnapshotClaims, StorageError> {
        self.node_resource_snapshot_inner(
            lifecycle,
            signed,
            &signer.public_key(),
            Some(signer),
            now_ms,
        )
    }
    pub fn node_resource_snapshot(
        &mut self,
        lifecycle: &RelayLifecycle,
        signed: &SignedNodeResourceQuery,
        allocation_issuer: &[u8; 32],
        now_ms: u64,
    ) -> Result<NodeResourceSnapshotClaims, StorageError> {
        self.node_resource_snapshot_inner(lifecycle, signed, allocation_issuer, None, now_ms)
    }
    fn node_resource_snapshot_inner(
        &mut self,
        lifecycle: &RelayLifecycle,
        signed: &SignedNodeResourceQuery,
        allocation_issuer: &[u8; 32],
        signer: Option<&nestlink_identity::PermitSigner>,
        now_ms: u64,
    ) -> Result<NodeResourceSnapshotClaims, StorageError> {
        let unverified: NodeResourceQueryClaims =
            decode_bounded(&signed.claims, NODE_MESSAGE_BYTES)?;
        unverified.validate()?;
        let tx = self.connection.unchecked_transaction()?;
        self.resume_relay_reservations(lifecycle, now_ms)?;
        type Row = (Vec<u8>, Option<String>, u64, u64, u64, u64);
        let row:Option<Row>=tx.query_row("SELECT public_key,runtime_id,runtime_generation,lease_policy_revision,lease_sequence,last_issued_at FROM data_nodes WHERE id=?1 AND revoked=0",[&unverified.node_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
        let (key, runtime, generation, policy, sequence, last) =
            row.ok_or(StorageError::Forbidden)?;
        let key: [u8; 32] = key.try_into().map_err(|_| StorageError::Conflict)?;
        let q = verify_resource_query(signed, &key)?;
        let (revision, _) = self.policy()?;
        if q.deployment_id != self.deployment_id()?
            || q.security_epoch != self.security_epoch()?
            || runtime.as_deref() != Some(&q.runtime_id)
            || generation != q.runtime_generation
            || policy != q.policy_revision
            || policy != revision
            || q.lease_sequence > sequence
            || last > now_ms
            || now_ms >= last.saturating_add(NODE_LEASE_MS)
            || q.issued_at_unix_ms > now_ms.saturating_add(1000)
            || q.expires_at_unix_ms <= now_ms
            || q.expires_at_unix_ms > last.saturating_add(NODE_LEASE_MS)
        {
            return Err(StorageError::Forbidden);
        }
        let quota = self.relay_quota_current()?;
        let endpoint_revision: u64 = tx.query_row(
            "SELECT COALESCE((SELECT revision FROM node_endpoints WHERE node_id=?1),0)",
            [&q.node_id],
            |r| r.get(0),
        )?;
        let mut query=tx.prepare("SELECT claims_json FROM relay_reservations WHERE kind='node' AND node_id=?1 AND runtime_id=?2 AND runtime_generation=?3 AND security_epoch=?4 AND quota_revision=?5 AND closed=0 AND promised_until>?6 ORDER BY id")?;
        let rows = query.query_map(
            rusqlite::params![
                q.node_id,
                q.runtime_id,
                q.runtime_generation,
                q.security_epoch,
                quota.revision,
                now_ms
            ],
            |r| r.get::<_, String>(0),
        )?;
        let mut allocations = Vec::new();
        for row in rows {
            let c: RelayAllocationClaims = serde_json::from_str(&row?)?;
            c.validate()?;
            if c.expires_at_unix_ms <= now_ms {
                continue;
            }
            let permit = match self.current_resource_permit(&c.session_id, now_ms) {
                Ok(p) => p,
                Err(StorageError::Forbidden | StorageError::Unauthorized) => continue,
                Err(e) => return Err(e),
            };
            if c.policy_revision != revision
                || c.session_binding_sha256 != session_binding(&permit)?
                || c.node_key_sha256 != digest(&key)
                || c.node_endpoint_revision != endpoint_revision
            {
                continue;
            }
            allocations.push(c);
            if allocations.len() as u64 > NODE_RESOURCE_ALLOCATIONS {
                return Err(StorageError::RateLimited);
            }
        }
        drop(query);
        let network_routes = match signer {
            Some(signer) => self.node_network_resources(&tx, lifecycle, &q, signer, now_ms)?,
            None => Vec::new(),
        };
        let snapshot = NodeResourceSnapshotClaims {
            topology_publications_json: if signer.is_some() {
                let publications = self.node_topology_publications(&q, now_ms)?;
                if publications.is_empty() {
                    Vec::new()
                } else {
                    serde_json::to_vec(&publications)?
                }
            } else {
                Vec::new()
            },
            network_routes,
            query: Some(q.clone()),
            query_sha256: digest(&signed.claims).to_vec(),
            allocation_issuer: allocation_issuer.to_vec(),
            quota_revision: quota.revision,
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: q
                .expires_at_unix_ms
                .min(
                    now_ms
                        .checked_add(NODE_RESOURCE_TTL_MS)
                        .ok_or(StorageError::Conflict)?,
                )
                .min(
                    last.checked_add(NODE_LEASE_MS)
                        .ok_or(StorageError::Conflict)?,
                ),
            allocations,
        };
        snapshot.validate()?;
        tx.commit()?;
        Ok(snapshot)
    }
}
