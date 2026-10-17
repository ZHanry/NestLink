use crate::{StorageError, Store, accounts::Principal, audit, require_id};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{random_bytes, random_id};
use nestlink_identity::{digest, nodes::verify_proof};
use nestlink_policy::{PublicIngress, ServerForwarding};
use nestlink_protocol::{
    NODE_LEASE_MS, NODE_REFRESH_MS, NodeChallenge, NodeLeaseClaims, NodeProof, SCHEMA_VERSION,
    api::{NodeRegistration, NodeView},
    nodes::{NODE_CHALLENGE_MS, valid_roles},
};
use rusqlite::{OptionalExtension, params};

impl Store {
    pub fn register_node(
        &mut self,
        actor: &Principal,
        node: NodeRegistration,
    ) -> Result<(), StorageError> {
        if !actor.is_admin {
            return Err(StorageError::Forbidden);
        }
        require_id(&node.id)?;
        if node.name.is_empty()
            || node.name.len() > 128
            || node.name.chars().any(char::is_control)
            || !valid_roles(&node.roles)
            || node.max_connections == 0
            || node.max_connections > 100_000
            || node.bytes_per_second == 0
            || node.bytes_per_second > 1024 * 1024 * 1024
        {
            return Err(StorageError::Invalid("invalid node registration"));
        }
        let key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&node.public_key)
            .map_err(|_| StorageError::Invalid("invalid node key"))?
            .try_into()
            .map_err(|_| StorageError::Invalid("invalid node key length"))?;
        if URL_SAFE_NO_PAD.encode(key) != node.public_key {
            return Err(StorageError::Invalid("noncanonical node key"));
        }
        let tx = self.connection.unchecked_transaction()?;
        self.admin_identity(actor)?;
        let count: u64 =
            tx.query_row("SELECT count(*) FROM data_nodes WHERE revoked=0", [], |r| {
                r.get(0)
            })?;
        if count >= 128 {
            return Err(StorageError::RateLimited);
        }
        if tx.query_row("SELECT count(*) FROM data_nodes", [], |r| {
            r.get::<_, u64>(0)
        })? >= 4096
        {
            return Err(StorageError::RateLimited);
        }
        tx.execute("INSERT INTO data_nodes(id,name,public_key,roles_json,max_connections,bytes_per_second) VALUES(?1,?2,?3,?4,?5,?6)",
            params![node.id,node.name,&key,serde_json::to_string(&node.roles)?,node.max_connections,node.bytes_per_second])?;
        audit(
            &tx,
            "node_registered",
            &node.id,
            crate::auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn nodes(&self, actor: &Principal) -> Result<Vec<NodeView>, StorageError> {
        self.admin_identity(actor)?;
        let mut query=self.connection.prepare("SELECT id,name,public_key,roles_json,max_connections,bytes_per_second,revoked,last_issued_at,runtime_id,runtime_generation FROM data_nodes ORDER BY id LIMIT 4096")?;
        let mut result = Vec::new();
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            result.push(NodeView {
                node: NodeRegistration {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    public_key: URL_SAFE_NO_PAD.encode(row.get::<_, Vec<u8>>(2)?),
                    roles: serde_json::from_str(&row.get::<_, String>(3)?)?,
                    max_connections: row.get(4)?,
                    bytes_per_second: row.get(5)?,
                },
                revoked: row.get(6)?,
                last_issued_at_unix_ms: row.get(7)?,
                runtime_id: row.get(8)?,
                runtime_generation: row.get(9)?,
            });
        }
        Ok(result)
    }
    pub fn revoke_node(&mut self, actor: &Principal, id: &str) -> Result<(), StorageError> {
        if !actor.is_admin {
            return Err(StorageError::Forbidden);
        }
        require_id(id)?;
        let tx = self.connection.unchecked_transaction()?;
        self.admin_identity(actor)?;
        if tx.execute(
            "UPDATE data_nodes SET revoked=1 WHERE id=?1 AND revoked=0",
            [id],
        )? != 1
        {
            return Err(StorageError::Conflict);
        }
        audit(&tx, "node_revoked", id, crate::auditing::management(actor))?;
        tx.commit()?;
        Ok(())
    }
    pub fn node_challenge(&self, id: &str, now_ms: u64) -> Result<NodeChallenge, StorageError> {
        require_id(id)?;
        let key: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT public_key FROM data_nodes WHERE id=?1 AND revoked=0",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        let key = key.ok_or(StorageError::Forbidden)?;
        let challenge = NodeChallenge {
            schema_version: SCHEMA_VERSION,
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            node_id: id.into(),
            node_key_sha256: digest(&key).to_vec(),
            request_id: random_id(),
            nonce: random_bytes::<32>().to_vec(),
            expires_at_unix_ms: now_ms
                .checked_add(NODE_CHALLENGE_MS)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(StorageError::Invalid("invalid node clock"))?,
        };
        challenge.validate()?;
        Ok(challenge)
    }
    /// Caller correlates proof to the exact outstanding challenge on its socket.
    pub fn issue_node_lease(
        &mut self,
        proof: &NodeProof,
        now_ms: u64,
    ) -> Result<NodeLeaseClaims, StorageError> {
        let challenge = proof.challenge.as_ref().ok_or(StorageError::Unauthorized)?;
        challenge.validate()?;
        if challenge.deployment_id != self.deployment_id()?
            || challenge.security_epoch != self.security_epoch()?
            || challenge.expires_at_unix_ms <= now_ms
            || challenge.expires_at_unix_ms > now_ms.saturating_add(NODE_CHALLENGE_MS)
        {
            return Err(StorageError::Unauthorized);
        }
        let tx = self.connection.transaction()?;
        type Record = (Vec<u8>, String, u32, u64, u64, u64, Option<String>, u64);
        let record:Option<Record>=tx.query_row("SELECT public_key,roles_json,max_connections,bytes_per_second,lease_sequence,last_issued_at,runtime_id,runtime_generation FROM data_nodes WHERE id=?1 AND revoked=0",[&challenge.node_id],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
        let (key, roles, max_connections, bytes_per_second, sequence, last, runtime, generation) =
            record.ok_or(StorageError::Forbidden)?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| StorageError::Invalid("invalid stored node key"))?;
        verify_proof(proof, &key)?;
        if now_ms < last {
            return Err(StorageError::Unauthorized);
        }
        if runtime.as_deref() == Some(proof.runtime_id.as_str())
            && last != 0
            && now_ms - last < NODE_REFRESH_MS
        {
            return Err(StorageError::RateLimited);
        }
        let generation = if runtime.as_deref() == Some(proof.runtime_id.as_str()) {
            if now_ms >= last.saturating_add(NODE_LEASE_MS) {
                return Err(StorageError::Conflict);
            }
            generation
        } else {
            let seen: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM node_runtimes WHERE node_id=?1 AND runtime_id=?2)",
                params![challenge.node_id, proof.runtime_id],
                |r| r.get(0),
            )?;
            if seen {
                return Err(StorageError::Conflict);
            }
            let count: u64 = tx.query_row(
                "SELECT count(*) FROM node_runtimes WHERE node_id=?1",
                [&challenge.node_id],
                |r| r.get(0),
            )?;
            let total: u64 =
                tx.query_row("SELECT count(*) FROM node_runtimes", [], |r| r.get(0))?;
            if count >= 4096 || total >= 65536 {
                return Err(StorageError::RateLimited);
            }
            let next = generation
                .checked_add(1)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(StorageError::Conflict)?;
            tx.execute("INSERT INTO node_runtimes(node_id,runtime_id,generation,security_epoch,started_at) VALUES(?1,?2,?3,?4,?5)",params![challenge.node_id,proof.runtime_id,next,challenge.security_epoch,now_ms])?;
            next
        };
        let sequence = sequence
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        tx.execute(
            "DELETE FROM used_node_challenges WHERE expires_at<=?1",
            [now_ms],
        )?;
        if tx.query_row("SELECT count(*) FROM used_node_challenges", [], |r| {
            r.get::<_, u64>(0)
        })? >= 4096
        {
            return Err(StorageError::RateLimited);
        }
        let reused: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM used_node_challenges WHERE request_id=?1)",
            [&challenge.request_id],
            |r| r.get(0),
        )?;
        if reused {
            return Err(StorageError::Conflict);
        }
        tx.execute(
            "INSERT INTO used_node_challenges VALUES(?1,?2)",
            params![challenge.request_id, challenge.expires_at_unix_ms],
        )?;
        let (revision, policy_json): (u64, String) = tx.query_row(
            "SELECT policy_revision,policy_json FROM deployment WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let policy: nestlink_policy::NetworkPolicy = serde_json::from_str(&policy_json)?;
        policy.validate()?;
        let allowed = policy.server_forwarding == ServerForwarding::Allow;
        let claims = NodeLeaseClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: challenge.deployment_id.clone(),
            security_epoch: challenge.security_epoch,
            node_id: challenge.node_id.clone(),
            node_key_sha256: challenge.node_key_sha256.clone(),
            request_id: challenge.request_id.clone(),
            nonce: challenge.nonce.clone(),
            roles: serde_json::from_str(&roles)?,
            policy_revision: revision,
            lease_sequence: sequence,
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: now_ms
                .checked_add(NODE_LEASE_MS)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(StorageError::Invalid("invalid node clock"))?,
            server_forwarding_allowed: allowed,
            public_ingress_allowed: allowed && policy.public_ingress == PublicIngress::Enabled,
            max_connections,
            bytes_per_second,
            runtime_id: proof.runtime_id.clone(),
            runtime_generation: generation,
        };
        claims.validate()?;
        tx.execute(
            "UPDATE data_nodes SET lease_sequence=?1,last_issued_at=?2,runtime_id=?4,runtime_generation=?5,lease_policy_revision=?6 WHERE id=?3",
            params![sequence, now_ms, challenge.node_id,proof.runtime_id,generation,revision],
        )?;
        if runtime.as_deref() != Some(proof.runtime_id.as_str()) {
            audit(
                &tx,
                "node_runtime_started",
                &challenge.node_id,
                nestlink_protocol::api::AuditActor::Node {
                    node_id: challenge.node_id.clone(),
                    runtime_id: proof.runtime_id.clone(),
                    runtime_generation: generation,
                },
            )?;
        }
        tx.commit()?;
        Ok(claims)
    }
    pub fn node_lease_current(&self, claims: &NodeLeaseClaims) -> Result<bool, StorageError> {
        claims.validate()?;
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM data_nodes n JOIN deployment d ON d.singleton=1 WHERE n.id=?1 AND n.revoked=0 AND n.lease_sequence=?2 AND d.security_epoch=?3 AND d.policy_revision=?4 AND n.runtime_id=?5 AND n.runtime_generation=?6 AND d.id=?7 AND n.last_issued_at=?8)",
            params![claims.node_id,claims.lease_sequence,claims.security_epoch,claims.policy_revision,claims.runtime_id,claims.runtime_generation,claims.deployment_id,claims.issued_at_unix_ms],|r|r.get(0))?)
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;
    use nestlink_identity::nodes::NodeIdentity;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn fixture() -> Result<(Store, NodeIdentity, String)> {
        let s = Store::in_memory(&random_id())?;
        let key = NodeIdentity::generate();
        let id = random_id();
        s.connection.execute("INSERT INTO data_nodes(id,name,public_key,roles_json,max_connections,bytes_per_second) VALUES(?1,'test',?2,'[1]',2,1024)",params![id,key.public_key().as_slice()])?;
        Ok((s, key, id))
    }
    #[test]
    fn audit_or_generation_exhaustion_rolls_back_runtime_registration_and_challenge_consumption()
    -> Result {
        let (mut s, key, id) = fixture()?;
        let c = s.node_challenge(&id, 1000)?;
        let p = key.prove(&c, &random_id())?;
        s.connection.execute(
            "UPDATE audit_settings SET high_watermark=9223372036854775807",
            [],
        )?;
        assert!(s.issue_node_lease(&p, 1001).is_err());
        assert_eq!(
            s.connection
                .query_row("SELECT count(*) FROM node_runtimes", [], |r| r
                    .get::<_, u64>(0))?,
            0
        );
        assert_eq!(
            s.connection
                .query_row("SELECT count(*) FROM used_node_challenges", [], |r| r
                    .get::<_, u64>(0))?,
            0
        );
        s.connection
            .execute("UPDATE audit_settings SET high_watermark=0", [])?;
        s.connection.execute(
            "UPDATE data_nodes SET runtime_generation=9223372036854775807",
            [],
        )?;
        assert!(s.issue_node_lease(&p, 1001).is_err());
        s.connection
            .execute("UPDATE data_nodes SET runtime_generation=0", [])?;
        assert_eq!(s.issue_node_lease(&p, 1001)?.runtime_generation, 1);
        Ok(())
    }
    #[test]
    fn persistent_tombstone_capacity_fails_closed_without_evicting_old_runtime_ids() -> Result {
        let (mut s, key, id) = fixture()?;
        let tx = s.connection.transaction()?;
        for n in 1..=4096u64 {
            let runtime = format!("{n:08x}-1111-4111-8111-111111111111");
            tx.execute("INSERT INTO node_runtimes(node_id,runtime_id,generation,security_epoch,started_at) VALUES(?1,?2,?3,1,1)",params![id,runtime,n])?;
        }
        tx.execute("UPDATE data_nodes SET runtime_generation=4096", [])?;
        tx.commit()?;
        let c = s.node_challenge(&id, 1000)?;
        assert!(matches!(
            s.issue_node_lease(&key.prove(&c, &random_id())?, 1001),
            Err(StorageError::RateLimited)
        ));
        assert_eq!(
            s.connection
                .query_row("SELECT count(*) FROM node_runtimes", [], |r| r
                    .get::<_, u64>(0))?,
            4096
        );
        assert_eq!(
            s.connection
                .query_row("SELECT lease_sequence FROM data_nodes", [], |r| r
                    .get::<_, u64>(0))?,
            0
        );
        Ok(())
    }
}
