//! One cumulative record per runtime; retired UUIDs are persistent replay tombstones.
use crate::{StorageError, Store, accounts::Principal, require_id};
use nestlink_identity::{digest, nodes::verify_usage};
use nestlink_protocol::{
    NODE_LEASE_MS, NodeUsageAckClaims, NodeUsageClaims, SCHEMA_VERSION, SignedNodeUsage,
    api::{NodeUsagePage, NodeUsageQuery, NodeUsageView},
    decode_bounded,
    nodes::NODE_MESSAGE_BYTES,
};
use prost::Message;
use rusqlite::{OptionalExtension, params};

impl Store {
    pub fn accept_node_usage(
        &mut self,
        signed: &SignedNodeUsage,
        now_ms: u64,
    ) -> Result<NodeUsageAckClaims, StorageError> {
        let untrusted: NodeUsageClaims = decode_bounded(&signed.claims, NODE_MESSAGE_BYTES)?;
        untrusted.validate()?;
        if now_ms == 0 || now_ms > i64::MAX as u64 {
            return Err(StorageError::Invalid("invalid usage clock"));
        }
        let tx = self.connection.transaction()?;
        type Node = (Vec<u8>, Option<String>, u64, u64, u64, u32, u64, u64);
        let node:Option<Node> = tx.query_row("SELECT public_key,runtime_id,runtime_generation,lease_sequence,last_issued_at,max_connections,bytes_per_second,lease_policy_revision FROM data_nodes WHERE id=?1 AND revoked=0", [&untrusted.node_id], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
        let (key, runtime, generation, lease, last, max, rate, lease_policy) =
            node.ok_or(StorageError::Forbidden)?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| StorageError::Invalid("invalid node key"))?;
        let c = verify_usage(signed, &key)?;
        let (deployment, epoch, policy): (String, u64, u64) = tx.query_row(
            "SELECT id,security_epoch,policy_revision FROM deployment WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if c.deployment_id != deployment
            || c.security_epoch != epoch
            || c.policy_revision != policy
            || lease_policy != policy
            || runtime.as_deref() != Some(c.runtime_id.as_str())
            || c.runtime_generation != generation
            || now_ms < last
            || now_ms >= last.saturating_add(NODE_LEASE_MS)
        {
            return Err(StorageError::Unauthorized);
        }
        type Previous = (
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        );
        let (started,sequence,opened,closed,bytes,sampled,accepted,hash,ack):Previous=tx.query_row("SELECT started_at,report_sequence,opened,closed,admitted_bytes,sampled_at,accepted_at,report_digest,ack_claims FROM node_runtimes WHERE node_id=?1 AND runtime_id=?2 AND generation=?3 AND security_epoch=?4", params![c.node_id,c.runtime_id,generation,epoch], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)))?;
        let report_hash = digest(&signed.claims);
        if c.report_sequence == sequence {
            if now_ms < accepted || hash.as_deref() != Some(report_hash.as_slice()) {
                return Err(StorageError::Conflict);
            }
            let original: NodeUsageAckClaims =
                decode_bounded(&ack.ok_or(StorageError::Conflict)?, NODE_MESSAGE_BYTES)?;
            original.validate()?;
            if original.deployment_id != deployment
                || original.security_epoch != epoch
                || original.node_id != c.node_id
                || original.runtime_id != c.runtime_id
                || original.runtime_generation != generation
                || original.report_sequence != sequence
                || original.report_sha256 != report_hash
                || original.accepted_at_unix_ms != accepted
            {
                return Err(StorageError::Conflict);
            }
            return Ok(original);
        }
        if c.lease_sequence != lease
            || c.report_sequence != sequence.checked_add(1).ok_or(StorageError::Conflict)?
            || c.opened_connections < opened
            || c.closed_connections < closed
            || c.admitted_bytes < bytes
            || c.opened_connections - c.closed_connections > u64::from(max)
            || now_ms < started
            || c.sampled_at_unix_ms < started
            || c.sampled_at_unix_ms < sampled
            || c.sampled_at_unix_ms > now_ms.saturating_add(1000)
            || now_ms < accepted
            || u128::from(c.admitted_bytes)
                > u128::from(rate) * (u128::from(now_ms - started) + 1000) / 1000
        {
            return Err(StorageError::Conflict);
        }
        let ack = NodeUsageAckClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: deployment,
            security_epoch: epoch,
            node_id: c.node_id.clone(),
            runtime_id: c.runtime_id.clone(),
            runtime_generation: generation,
            report_sequence: c.report_sequence,
            report_sha256: report_hash.to_vec(),
            accepted_at_unix_ms: now_ms,
        };
        ack.validate()?;
        tx.execute("UPDATE node_runtimes SET report_sequence=?1,opened=?2,closed=?3,admitted_bytes=?4,sampled_at=?5,accepted_at=?6,report_digest=?7,ack_claims=?8 WHERE node_id=?9 AND runtime_id=?10", params![c.report_sequence,c.opened_connections,c.closed_connections,c.admitted_bytes,c.sampled_at_unix_ms,now_ms,report_hash.as_slice(),ack.encode_to_vec(),c.node_id,c.runtime_id])?;
        tx.commit()?;
        Ok(ack)
    }
    pub fn node_usage(
        &self,
        actor: &Principal,
        id: &str,
        query: NodeUsageQuery,
        now_ms: u64,
    ) -> Result<NodeUsagePage, StorageError> {
        require_id(id)?;
        if now_ms > i64::MAX as u64 {
            return Err(StorageError::Invalid("invalid node usage clock"));
        }
        self.audit_admin(actor, now_ms / 1000)?;
        if query.security_epoch != self.security_epoch()? {
            return Err(StorageError::Unauthorized);
        }
        if query.limit == 0 || query.limit > 100 || query.after_generation > i64::MAX as u64 {
            return Err(StorageError::Invalid("invalid node usage cursor"));
        }
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM data_nodes WHERE id=?1)",
            [id],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(StorageError::Forbidden);
        }
        let mut statement=self.connection.prepare("SELECT r.runtime_id,r.generation,r.security_epoch,r.started_at,r.report_sequence,r.opened,r.closed,r.admitted_bytes,r.sampled_at,r.accepted_at,(n.revoked=0 AND n.runtime_id=r.runtime_id AND n.runtime_generation=r.generation AND r.security_epoch=?3 AND n.lease_policy_revision=d.policy_revision AND n.last_issued_at<=?4 AND n.last_issued_at>?4-10000) FROM node_runtimes r JOIN data_nodes n ON n.id=r.node_id JOIN deployment d ON d.singleton=1 WHERE r.node_id=?1 AND r.generation>?2 ORDER BY r.generation LIMIT ?5")?;
        let mut entries = statement
            .query_map(
                params![
                    id,
                    query.after_generation,
                    query.security_epoch,
                    now_ms,
                    u32::from(query.limit) + 1
                ],
                |r| {
                    Ok(NodeUsageView {
                        runtime_id: r.get(0)?,
                        runtime_generation: r.get(1)?,
                        security_epoch: r.get(2)?,
                        started_at_unix_ms: r.get(3)?,
                        report_sequence: r.get(4)?,
                        opened_connections: r.get(5)?,
                        closed_connections: r.get(6)?,
                        admitted_bytes: r.get(7)?,
                        sampled_at_unix_ms: r.get(8)?,
                        accepted_at_unix_ms: r.get(9)?,
                        current: r.get(10)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let more = entries.len() > usize::from(query.limit);
        entries.truncate(usize::from(query.limit));
        let next_generation = entries
            .last()
            .map_or(query.after_generation, |r| r.runtime_generation);
        Ok(NodeUsagePage {
            node_id: id.into(),
            security_epoch: query.security_epoch,
            entries,
            next_generation,
            more,
        })
    }
}
