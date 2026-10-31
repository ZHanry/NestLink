//! Durable, endpoint-specific TURN grants and two-party peer activation.
use crate::{
    StorageError, Store, accounts::Principal, auditing, relay_reservations::RelayLifecycle,
    require_id,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, random_bytes, turn_auth_key};
use nestlink_identity::{
    digest,
    turn::{
        credential_request_transcript, verify_turn_peer_binding, verify_turn_peer_signature,
        verify_turn_resource_query,
    },
    verify_device_action,
};
use nestlink_protocol::{
    NODE_LEASE_MS, NODE_MESSAGE_BYTES, NODE_RESOURCE_TTL_MS, NodeRole, Path, SCHEMA_VERSION,
    SignedTurnPeerBinding, SignedTurnResourceQuery, TurnCredentialsClaims, TurnGrantClaims,
    TurnPeerBindingClaims, TurnPurpose, TurnResourceQueryClaims, TurnResourceSnapshotClaims,
    api::{
        TurnBindingState, TurnCredentialRequest, TurnEndpointConfig, TurnEndpointsUpdate,
        TurnEndpointsView, TurnPeerSubmission,
    },
    decode_bounded,
    turn::TURN_BINDING_BYTES,
};
use prost::Message;
use rusqlite::{OptionalExtension, params};
use zeroize::{Zeroize, Zeroizing};

struct Node {
    key: [u8; 32],
    runtime: String,
    generation: u64,
    maximum: u32,
    rate: u64,
    policy: u64,
    lease_sequence: u64,
    last: u64,
}
impl Store {
    fn turn_node(&self, id: &str, now_ms: u64) -> Result<Node, StorageError> {
        type Row = (
            Vec<u8>,
            Option<String>,
            u64,
            u32,
            u64,
            u64,
            u64,
            u64,
            String,
        );
        let row: Option<Row> = self.connection.query_row(
            "SELECT public_key,runtime_id,runtime_generation,max_connections,bytes_per_second,lease_policy_revision,lease_sequence,last_issued_at,roles_json FROM data_nodes WHERE id=?1 AND revoked=0",
            [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)),
        ).optional()?;
        let (key, runtime, generation, maximum, rate, policy, lease_sequence, last, roles) =
            row.ok_or(StorageError::Forbidden)?;
        if !serde_json::from_str::<Vec<i32>>(&roles)?.contains(&(NodeRole::NodeRelay as i32))
            || last > now_ms
            || now_ms >= last.saturating_add(NODE_LEASE_MS)
            || self.policy()?.0 != policy
        {
            return Err(StorageError::Forbidden);
        }
        Ok(Node {
            key: key.try_into().map_err(|_| StorageError::Conflict)?,
            runtime: runtime.ok_or(StorageError::Forbidden)?,
            generation,
            maximum,
            rate,
            policy,
            lease_sequence,
            last,
        })
    }
    fn turn_config(&self, id: &str) -> Result<(u64, TurnEndpointConfig), StorageError> {
        let (revision, json): (u64, String) = self
            .connection
            .query_row(
                "SELECT revision,config_json FROM turn_endpoints WHERE node_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(StorageError::Forbidden)?;
        let config: TurnEndpointConfig = serde_json::from_str(&json)?;
        config.validate()?;
        Ok((revision, config))
    }
    pub fn turn_endpoints(
        &self,
        actor: &Principal,
        id: &str,
        now_ms: u64,
    ) -> Result<TurnEndpointsView, StorageError> {
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
                "SELECT revision,config_json FROM turn_endpoints WHERE node_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (revision, config) = match row {
            Some((v, s)) => (v, serde_json::from_str(&s)?),
            None => (
                0,
                TurnEndpointConfig {
                    realm: "nestlink".into(),
                    endpoints: vec![],
                    allow_loopback: false,
                },
            ),
        };
        Ok(TurnEndpointsView {
            node_id: id.into(),
            revision,
            config,
        })
    }
    pub fn set_turn_endpoints(
        &mut self,
        actor: &Principal,
        id: &str,
        update: TurnEndpointsUpdate,
        now_ms: u64,
    ) -> Result<TurnEndpointsView, StorageError> {
        update.config.validate()?;
        let tx = self.connection.unchecked_transaction()?;
        let old = self.turn_endpoints(actor, id, now_ms)?;
        if old.revision != update.expected_revision {
            return Err(StorageError::Conflict);
        }
        let roles: String =
            tx.query_row("SELECT roles_json FROM data_nodes WHERE id=?1", [id], |r| {
                r.get(0)
            })?;
        if !update.config.endpoints.is_empty()
            && !serde_json::from_str::<Vec<i32>>(&roles)?.contains(&(NodeRole::NodeRelay as i32))
        {
            return Err(StorageError::Forbidden);
        }
        let revision = next(old.revision)?;
        tx.execute("INSERT INTO turn_endpoints VALUES(?1,?2,?3) ON CONFLICT(node_id) DO UPDATE SET revision=excluded.revision,config_json=excluded.config_json",
            params![id,revision,serde_json::to_string(&update.config)?])?;
        auditing::record(
            &tx,
            "turn_endpoints_updated",
            id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(TurnEndpointsView {
            node_id: id.into(),
            revision,
            config: update.config,
        })
    }
    fn turn_grant_metadata(&self, id: &str) -> Result<TurnGrantClaims, StorageError> {
        let json: String = self
            .connection
            .query_row(
                "SELECT claims_json FROM turn_grants WHERE id=?1 AND closed=0",
                [id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StorageError::Forbidden)?;
        let mut claims: TurnGrantClaims = serde_json::from_str(&json)?;
        // A derived authentication key is never stored in JSON. Reconstruct only
        // inside a vault-authorized snapshot; metadata validation uses no key.
        if !claims.auth_key.is_empty() {
            return Err(StorageError::Conflict);
        }
        claims.auth_key = vec![0; 16];
        claims.validate()?;
        claims.auth_key.clear();
        Ok(claims)
    }
    fn turn_password(&self, vault: &VaultKey, id: &str) -> Result<Zeroizing<String>, StorageError> {
        let encrypted: Vec<u8> = self.connection.query_row(
            "SELECT password_cipher FROM turn_grants WHERE id=?1",
            [id],
            |r| r.get(0),
        )?;
        let plain = vault.decrypt_turn(id, &encrypted)?;
        let password = Zeroizing::new(
            std::str::from_utf8(&plain)
                .map_err(|_| StorageError::Conflict)?
                .to_owned(),
        );
        if password.len() != 43 {
            return Err(StorageError::Conflict);
        }
        Ok(password)
    }
    fn reserve_turn_capacity(
        &self,
        actor: &str,
        node: &str,
        maximum: u32,
        now_ms: u64,
    ) -> Result<(), StorageError> {
        let quota = self.relay_quota_current()?;
        let held: u64 = self.connection.query_row(
            "SELECT (SELECT count(*) FROM all_relay_capacity WHERE promised_until>?1)+(SELECT count(*) FROM turn_grants WHERE promised_until>?1)", [now_ms], |r|r.get(0))?;
        let account: u64 = self.connection.query_row(
            "SELECT (SELECT COALESCE(sum((controller_account_id=?1)+(host_account_id=?1)),0) FROM all_relay_capacity WHERE promised_until>?2)+(SELECT count(*) FROM turn_grants WHERE account_id=?1 AND promised_until>?2)",params![actor,now_ms], |r|r.get(0))?;
        let connections: u64 = self.connection.query_row(
            "SELECT (SELECT count(*)*2 FROM all_relay_capacity WHERE node_id=?1 AND promised_until>?2)+(SELECT count(*) FROM turn_grants WHERE node_id=?1 AND promised_until>?2)",params![node,now_ms], |r|r.get(0))?;
        let history: u64 =
            self.connection
                .query_row("SELECT count(*) FROM turn_grants", [], |r| r.get(0))?;
        if held >= u64::from(quota.limits.max_allocations)
            || account >= u64::from(quota.limits.max_account_endpoints)
            || connections >= u64::from(maximum)
            || history >= 65536
        {
            return Err(StorageError::RateLimited);
        }
        Ok(())
    }
    pub fn turn_credentials(
        &mut self,
        lifecycle: &RelayLifecycle,
        vault: &VaultKey,
        actor: &Principal,
        session: &str,
        request: &TurnCredentialRequest,
        now_ms: u64,
    ) -> Result<TurnCredentialsClaims, StorageError> {
        self.validate_access(actor, now_ms / 1000)?;
        let tx = self.connection.unchecked_transaction()?;
        self.resume_relay_reservations(lifecycle, now_ms)?;
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_remote_relays WHERE allocation_id=?1 UNION ALL SELECT 1 FROM network_remote_chains WHERE route_id=?1 UNION ALL SELECT 1 FROM network_remote_route_set_members WHERE allocation_id=?1 UNION ALL SELECT 1 FROM network_remote_route_sets WHERE set_id=?1)",
            [&request.allocation_id],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(StorageError::Conflict);
        }
        let permit = self.current_permit(actor, session, now_ms / 1000)?;
        if permit.issued_at_unix_ms > now_ms
            || permit.expires_at_unix_ms <= now_ms
            || !permit.paths.contains(&(Path::Relay as i32))
        {
            return Err(StorageError::Forbidden);
        }
        // Older browser controllers are server-bounded temporary endpoints;
        // current browser installations are permanent revocable devices. Both
        // remain bounded by the signed session permit, and an expiring device
        // adds its own tighter ceiling.
        let browser_expiry = self.device_expiration_ms(&permit.controller_device_id)?;
        let endpoint = self.device_record_at(&request.device_id, now_ms / 1000)?;
        if endpoint.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        if request.device_id == permit.controller_device_id {
            self.check_request_login(session, now_ms / 1000, Some(&actor.session_id))?;
        }
        let transcript = credential_request_transcript(&permit, &actor.account_id, request)?;
        verify_device_action(
            &transcript,
            &endpoint.public_key,
            &super::control::decode_signature(&request.signature)?,
        )?;
        let controller = self.device_record_at(&permit.controller_device_id, now_ms / 1000)?;
        let host = self.device_record_at(&permit.host_device_id, now_ms / 1000)?;
        let old: Option<(bool, String)> = tx
            .query_row(
                "SELECT closed,claims_json FROM turn_grants WHERE id=?1",
                [&request.allocation_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let old = if let Some((closed, json)) = old {
            if closed {
                return Err(StorageError::Conflict);
            }
            let c: TurnGrantClaims = serde_json::from_str(&json)?;
            if c.session_id != session
                || c.device_id != request.device_id
                || c.network_generation != request.network_generation
                || c.connection_generation != permit.connection_generation
                || c.expires_at_unix_ms <= now_ms
                || c.temporary_identity != permit.controller_device_id
                || c.controller_key_sha256 != permit.controller_key_sha256
                || c.host_key_sha256 != permit.host_key_sha256
                || c.security_epoch != permit.security_epoch
                || c.policy_revision != permit.policy_revision
                || c.lease_sequence > permit.lease_sequence
            {
                return Err(StorageError::Conflict);
            }
            Some(c)
        } else {
            None
        };
        let node_id = if let Some(c) = &old {
            c.node_id.clone()
        } else {
            // Both endpoint allocations use one approved node; an existing peer
            // never lets a request replace the deployment-provided destination.
            let peer: Option<String> = tx.query_row(
                "SELECT node_id FROM turn_grants WHERE session_id=?1 AND device_id<>?2 AND closed=0 AND promised_until>?3 ORDER BY id LIMIT 1",
                params![session,request.device_id,now_ms], |r|r.get(0)).optional()?;
            match peer {
                Some(id) => id,
                None => {
                    let candidates: Vec<String> = tx.prepare("SELECT e.node_id FROM turn_endpoints e JOIN data_nodes n ON n.id=e.node_id WHERE n.revoked=0 ORDER BY e.node_id LIMIT 128")?
                    .query_map([],|r|r.get(0))?.collect::<Result<_,_>>()?;
                    candidates
                        .into_iter()
                        .find(|id| {
                            self.turn_node(id, now_ms).is_ok()
                                && self
                                    .turn_config(id)
                                    .is_ok_and(|(_, c)| !c.endpoints.is_empty())
                                && self
                                    .reserve_turn_capacity(
                                        &actor.account_id,
                                        id,
                                        self.turn_node(id, now_ms).map_or(0, |n| n.maximum),
                                        now_ms,
                                    )
                                    .is_ok()
                        })
                        .ok_or(StorageError::RateLimited)?
                }
            }
        };
        let node = self.turn_node(&node_id, now_ms)?;
        let (endpoint_revision, config) = self.turn_config(&node_id)?;
        let quota = self.relay_quota_current()?;
        if config.endpoints.is_empty() || node.policy != permit.policy_revision {
            return Err(StorageError::Forbidden);
        }
        if let Some(c) = &old {
            if c.runtime_id != node.runtime
                || c.runtime_generation != node.generation
                || c.endpoint_revision != endpoint_revision
                || c.realm != config.realm
                || c.quota_revision != quota.revision
            {
                return Err(StorageError::Conflict);
            }
        } else {
            let current: Option<String> = tx.query_row("SELECT claims_json FROM turn_grants WHERE session_id=?1 AND device_id=?2 AND closed=0 ORDER BY promised_until DESC LIMIT 1",params![session,request.device_id],|r|r.get(0)).optional()?;
            if let Some(json) = current {
                let c: TurnGrantClaims = serde_json::from_str(&json)?;
                if c.connection_generation > permit.connection_generation
                    || (c.connection_generation == permit.connection_generation
                        && c.network_generation >= request.network_generation
                        && c.expires_at_unix_ms > now_ms)
                {
                    return Err(StorageError::Conflict);
                }
            }
            self.reserve_turn_capacity(&actor.account_id, &node_id, node.maximum, now_ms)?;
        }
        let expires = browser_expiry
            .map_or(permit.expires_at_unix_ms, |expiry| {
                permit.expires_at_unix_ms.min(expiry)
            })
            .min(
                node.last
                    .checked_add(NODE_LEASE_MS)
                    .ok_or(StorageError::Conflict)?,
            );
        if expires <= now_ms {
            return Err(StorageError::Forbidden);
        }
        let renew = old.as_ref().is_some_and(|c| {
            c.lease_sequence < permit.lease_sequence || c.expires_at_unix_ms < expires
        });
        let password = if old.is_some() {
            self.turn_password(vault, &request.allocation_id)?
        } else {
            Zeroizing::new(URL_SAFE_NO_PAD.encode(random_bytes::<32>()))
        };
        let mut grant = if let Some(c) = old.as_ref() {
            c.clone()
        } else {
            TurnGrantClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: permit.deployment_id.clone(),
                security_epoch: permit.security_epoch,
                allocation_id: request.allocation_id.clone(),
                session_id: session.into(),
                temporary_identity: permit.controller_device_id.clone(),
                purpose: TurnPurpose::BrowserWebRtc as i32,
                node_id,
                runtime_id: node.runtime,
                runtime_generation: node.generation,
                node_key_sha256: digest(&node.key).to_vec(),
                device_id: request.device_id.clone(),
                controller_device_id: permit.controller_device_id.clone(),
                host_device_id: permit.host_device_id.clone(),
                controller_key_sha256: permit.controller_key_sha256.clone(),
                host_key_sha256: permit.host_key_sha256.clone(),
                controller_public_key: controller.public_key.to_vec(),
                host_public_key: host.public_key.to_vec(),
                session_binding_sha256: nestlink_identity::relay::session_binding(&permit)?
                    .to_vec(),
                network_generation: request.network_generation,
                connection_generation: permit.connection_generation,
                lease_sequence: permit.lease_sequence,
                permit_sha256: digest(&permit.encode_to_vec()).to_vec(),
                policy_revision: permit.policy_revision,
                quota_revision: quota.revision,
                grant_sequence: 1,
                issued_at_unix_ms: now_ms,
                expires_at_unix_ms: expires,
                username: format!("nl:{}", request.allocation_id),
                realm: config.realm.clone(),
                auth_key: vec![],
                bytes_per_second: quota.limits.bytes_per_second.min(node.rate),
                bytes_per_allocation: quota.limits.bytes_per_allocation,
                max_peers: nestlink_protocol::turn::TURN_PEERS as u32,
                endpoint_revision,
            }
        };
        if renew {
            grant.grant_sequence = next(grant.grant_sequence)?;
            grant.lease_sequence = permit.lease_sequence;
            grant.permit_sha256 = digest(&permit.encode_to_vec()).to_vec();
            grant.issued_at_unix_ms = now_ms;
            grant.expires_at_unix_ms = expires;
        }
        grant.auth_key = turn_auth_key(&grant.username, &grant.realm, &password).to_vec();
        grant.validate()?;
        grant.auth_key.zeroize();
        grant.auth_key.clear();
        if old.is_none() {
            tx.execute(
                "UPDATE turn_grants SET closed=1 WHERE session_id=?1 AND device_id=?2 AND closed=0",
                params![session, request.device_id],
            )?;
            tx.execute("INSERT INTO turn_grants(id,session_id,account_id,device_id,node_id,runtime_id,runtime_generation,security_epoch,control_runtime_id,promised_until,claims_json,password_cipher) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![grant.allocation_id,session,actor.account_id,request.device_id,grant.node_id,grant.runtime_id,grant.runtime_generation,grant.security_epoch,lifecycle.runtime_id,
                    expires.checked_add(1000).ok_or(StorageError::Conflict)?,serde_json::to_string(&grant)?,vault.encrypt_turn(&grant.allocation_id,password.as_bytes())?])?;
        } else if renew {
            tx.execute("UPDATE turn_grants SET promised_until=MAX(promised_until,?1),claims_json=?2 WHERE id=?3",params![expires.checked_add(1000).ok_or(StorageError::Conflict)?,serde_json::to_string(&grant)?,grant.allocation_id])?;
        }
        let receipt = TurnCredentialsClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: grant.deployment_id.clone(),
            security_epoch: grant.security_epoch,
            session_id: session.into(),
            allocation_id: grant.allocation_id.clone(),
            device_id: request.device_id.clone(),
            temporary_identity: grant.temporary_identity.clone(),
            purpose: grant.purpose,
            node_id: grant.node_id.clone(),
            runtime_id: grant.runtime_id.clone(),
            runtime_generation: grant.runtime_generation,
            network_generation: grant.network_generation,
            connection_generation: grant.connection_generation,
            lease_sequence: grant.lease_sequence,
            permit_sha256: grant.permit_sha256.clone(),
            request_sha256: digest(&transcript.encode_to_vec()).to_vec(),
            grant_sequence: grant.grant_sequence,
            endpoint_revision: grant.endpoint_revision,
            issued_at_unix_ms: grant.issued_at_unix_ms,
            expires_at_unix_ms: grant.expires_at_unix_ms,
            username: grant.username.clone(),
            realm: grant.realm.clone(),
            password: password.to_string(),
            endpoints: config.endpoints,
            allow_loopback: config.allow_loopback,
        };
        receipt.validate()?;
        if old.is_none() || renew {
            auditing::record(
                &tx,
                if renew {
                    "turn_grant_renewed"
                } else {
                    "turn_grant_reserved"
                },
                &grant.allocation_id,
                auditing::device(actor, &request.device_id),
            )?;
        }
        tx.commit()?;
        Ok(receipt)
    }
    pub fn turn_binding_state(
        &self,
        actor: &Principal,
        session: &str,
        now_ms: u64,
    ) -> Result<TurnBindingState, StorageError> {
        let permit = self.current_permit(actor, session, now_ms / 1000)?;
        let permit_digest = digest(&permit.encode_to_vec());
        let quota_revision = self.relay_quota_current()?.revision;
        let current = |device: &str| -> Result<Option<TurnGrantClaims>, StorageError> {
            let ids: Vec<String> = self.connection.prepare("SELECT id FROM turn_grants WHERE session_id=?1 AND device_id=?2 AND closed=0 AND promised_until>?3 ORDER BY promised_until DESC LIMIT 32")?
                .query_map(params![session,device,now_ms],|r|r.get(0))?.collect::<Result<_,_>>()?;
            for id in ids {
                let c = self.turn_grant_metadata(&id)?;
                if c.device_id != device
                    || c.session_id != session
                    || c.security_epoch != permit.security_epoch
                    || c.connection_generation != permit.connection_generation
                    || c.lease_sequence != permit.lease_sequence
                    || c.permit_sha256 != permit_digest
                    || c.policy_revision != permit.policy_revision
                    || c.quota_revision != quota_revision
                    || c.expires_at_unix_ms <= now_ms
                    || !permit.paths.contains(&(Path::Relay as i32))
                {
                    continue;
                }

                let node = match self.turn_node(&c.node_id, now_ms) {
                    Ok(node) => node,
                    Err(StorageError::Forbidden) => continue,
                    Err(error) => return Err(error),
                };
                let (endpoint_revision, config) = match self.turn_config(&c.node_id) {
                    Ok(config) => config,
                    Err(StorageError::Forbidden) => continue,
                    Err(error) => return Err(error),
                };
                if c.runtime_id != node.runtime
                    || c.runtime_generation != node.generation
                    || c.node_key_sha256 != digest(&node.key)
                    || node.policy != permit.policy_revision
                    || c.endpoint_revision != endpoint_revision
                    || config.endpoints.is_empty()
                    || c.realm != config.realm
                {
                    continue;
                }
                return Ok(Some(c));
            }
            Ok(None)
        };
        let controller = current(&permit.controller_device_id)?;
        let host = current(&permit.host_device_id)?;
        let binding = match (controller.as_ref(), host.as_ref()) {
            (Some(controller), Some(host))
                if controller.node_id == host.node_id
                    && controller.runtime_id == host.runtime_id
                    && controller.runtime_generation == host.runtime_generation
                    && controller.controller_key_sha256 == host.controller_key_sha256
                    && controller.host_key_sha256 == host.host_key_sha256
                    && controller.controller_public_key == host.controller_public_key
                    && controller.host_public_key == host.host_public_key =>
            {
                let stored = self.load_turn_binding(session)?;
                if let Some(signed) = stored {
                    let claims: TurnPeerBindingClaims =
                        decode_bounded(&signed.claims, TURN_BINDING_BYTES)?;
                    let matches_current = claims.matches_grant(controller)
                        && claims.matches_grant(host)
                        && claims.controller_allocation_id == controller.allocation_id
                        && claims.host_allocation_id == host.allocation_id
                        && claims.lease_sequence == permit.lease_sequence
                        && claims.connection_generation == permit.connection_generation
                        && claims.permit_sha256 == permit_digest
                        && claims.expires_at_unix_ms > now_ms
                        && matches!(signed.controller_signature.len(), 0 | 64)
                        && matches!(signed.host_signature.len(), 0 | 64)
                        && (!signed.controller_signature.is_empty()
                            || !signed.host_signature.is_empty());
                    if matches_current {
                        let controller_key: [u8; 32] = controller
                            .controller_public_key
                            .as_slice()
                            .try_into()
                            .map_err(|_| StorageError::Conflict)?;
                        let host_key: [u8; 32] = controller
                            .host_public_key
                            .as_slice()
                            .try_into()
                            .map_err(|_| StorageError::Conflict)?;
                        if !signed.controller_signature.is_empty() {
                            verify_turn_peer_signature(
                                &signed.claims,
                                &controller_key,
                                &signed.controller_signature,
                            )?;
                        }
                        if !signed.host_signature.is_empty() {
                            verify_turn_peer_signature(
                                &signed.claims,
                                &host_key,
                                &signed.host_signature,
                            )?;
                        }
                        Some(signed)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };
        Ok(TurnBindingState {
            controller_allocation_id: controller.as_ref().map(|grant| grant.allocation_id.clone()),
            host_allocation_id: host.as_ref().map(|grant| grant.allocation_id.clone()),
            controller_expires_at_unix_ms: controller.map(|grant| grant.expires_at_unix_ms),
            host_expires_at_unix_ms: host.map(|grant| grant.expires_at_unix_ms),
            binding,
        })
    }
    fn load_turn_binding(
        &self,
        session: &str,
    ) -> Result<Option<SignedTurnPeerBinding>, StorageError> {
        Ok(self.connection.query_row("SELECT claims,controller_signature,host_signature FROM turn_peer_bindings WHERE session_id=?1",[session], |r|Ok(SignedTurnPeerBinding {
            claims:r.get(0)?,controller_signature:r.get::<_,Option<Vec<u8>>>(1)?.unwrap_or_default(),host_signature:r.get::<_,Option<Vec<u8>>>(2)?.unwrap_or_default(),
        })).optional()?)
    }
    pub fn submit_turn_peers(
        &mut self,
        actor: &Principal,
        session: &str,
        submission: &TurnPeerSubmission,
        now_ms: u64,
    ) -> Result<TurnBindingState, StorageError> {
        self.validate_access(actor, now_ms / 1000)?;
        let tx = self.connection.unchecked_transaction()?;
        let permit = self.current_permit(actor, session, now_ms / 1000)?;
        let local = self.device_record_at(&submission.device_id, now_ms / 1000)?;
        if local.account != actor.account_id
            || ![&permit.controller_device_id, &permit.host_device_id]
                .contains(&&submission.device_id)
        {
            return Err(StorageError::Forbidden);
        }
        let binding = verify_turn_peer_signature(
            &submission.claims,
            &local.public_key,
            &submission.signature,
        )?;
        let controller = self.turn_grant_metadata(&binding.controller_allocation_id)?;
        let host = self.turn_grant_metadata(&binding.host_allocation_id)?;
        if !binding.matches_grant(&controller)
            || !binding.matches_grant(&host)
            || controller.node_id != host.node_id
            || binding.session_id != session
            || binding.permit_sha256 != digest(&permit.encode_to_vec())
            || binding.lease_sequence != permit.lease_sequence
            || binding.connection_generation != permit.connection_generation
            || binding.issued_at_unix_ms > now_ms.saturating_add(1000)
            || binding.expires_at_unix_ms <= now_ms
        {
            return Err(StorageError::Forbidden);
        }
        let controller_role = submission.device_id == permit.controller_device_id;
        let old = self.load_turn_binding(session)?;
        let mut signed = if let Some(old) = old {
            if old.claims == submission.claims {
                old
            } else {
                let previous: TurnPeerBindingClaims =
                    decode_bounded(&old.claims, TURN_BINDING_BYTES)?;
                // Rebinding an unchanged, current pair would silently broaden
                // its allowlist. Only a new lease or network allocation can do it.
                if previous.lease_sequence >= binding.lease_sequence
                    && previous.controller_allocation_id == binding.controller_allocation_id
                    && previous.host_allocation_id == binding.host_allocation_id
                    && previous.expires_at_unix_ms > now_ms
                {
                    return Err(StorageError::Conflict);
                }
                SignedTurnPeerBinding {
                    claims: submission.claims.clone(),
                    controller_signature: vec![],
                    host_signature: vec![],
                }
            }
        } else {
            SignedTurnPeerBinding {
                claims: submission.claims.clone(),
                controller_signature: vec![],
                host_signature: vec![],
            }
        };
        if controller_role {
            signed.controller_signature = submission.signature.clone();
        } else {
            signed.host_signature = submission.signature.clone();
        }
        if !signed.controller_signature.is_empty() && !signed.host_signature.is_empty() {
            let c = self.device_record_at(&permit.controller_device_id, now_ms / 1000)?;
            let h = self.device_record_at(&permit.host_device_id, now_ms / 1000)?;
            verify_turn_peer_binding(&signed, &c.public_key, &h.public_key)?;
        }
        tx.execute("INSERT INTO turn_peer_bindings VALUES(?1,?2,?3,?4) ON CONFLICT(session_id) DO UPDATE SET claims=excluded.claims,controller_signature=excluded.controller_signature,host_signature=excluded.host_signature",
            params![session,signed.claims,if signed.controller_signature.is_empty(){None}else{Some(&signed.controller_signature)},if signed.host_signature.is_empty(){None}else{Some(&signed.host_signature)}])?;
        auditing::record(
            &tx,
            "turn_peer_proved",
            session,
            auditing::device(actor, &submission.device_id),
        )?;
        tx.commit()?;
        self.turn_binding_state(actor, session, now_ms)
    }
    pub fn turn_resource_snapshot(
        &mut self,
        lifecycle: &RelayLifecycle,
        vault: &VaultKey,
        signed: &SignedTurnResourceQuery,
        now_ms: u64,
    ) -> Result<TurnResourceSnapshotClaims, StorageError> {
        let unverified: TurnResourceQueryClaims =
            decode_bounded(&signed.claims, NODE_MESSAGE_BYTES)?;
        unverified.validate()?;
        let tx = self.connection.unchecked_transaction()?;
        self.resume_relay_reservations(lifecycle, now_ms)?;
        let node = self.turn_node(&unverified.node_id, now_ms)?;
        let q = verify_turn_resource_query(signed, &node.key)?;
        if q.deployment_id != self.deployment_id()?
            || q.security_epoch != self.security_epoch()?
            || q.runtime_id != node.runtime
            || q.runtime_generation != node.generation
            || q.policy_revision != node.policy
            || q.lease_sequence > node.lease_sequence
            || q.issued_at_unix_ms > now_ms.saturating_add(1000)
            || q.expires_at_unix_ms <= now_ms
            || q.expires_at_unix_ms > node.last.saturating_add(NODE_LEASE_MS)
        {
            return Err(StorageError::Forbidden);
        }
        let old:Option<(String,u64,u64,u64)>=tx.query_row("SELECT runtime_id,runtime_generation,request_sequence,snapshot_sequence FROM turn_snapshot_sequences WHERE node_id=?1",[&q.node_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if old
            .as_ref()
            .is_some_and(|(runtime, generation, request, _)| {
                *runtime == q.runtime_id
                    && *generation == q.runtime_generation
                    && *request >= q.request_sequence
            })
        {
            return Err(StorageError::Conflict);
        }
        let snapshot_sequence = next(old.as_ref().map_or(0, |(_, _, _, sequence)| *sequence))?;
        let quota = self.relay_quota_current()?;
        let endpoint_revision = self
            .turn_config(&q.node_id)
            .ok()
            .map(|(revision, _)| revision);
        let ids:Vec<String>=tx.prepare("SELECT id FROM turn_grants WHERE node_id=?1 AND runtime_id=?2 AND runtime_generation=?3 AND security_epoch=?4 AND control_runtime_id=?5 AND closed=0 AND promised_until>?6 ORDER BY id LIMIT 257")?
            .query_map(params![q.node_id,q.runtime_id,q.runtime_generation,q.security_epoch,lifecycle.runtime_id,now_ms],|r|r.get(0))?.collect::<Result<_,_>>()?;
        let mut grants = vec![];
        let mut peer_bindings = vec![];
        let mut seen = std::collections::HashSet::new();
        for id in ids {
            let mut c = self.turn_grant_metadata(&id)?;
            if c.quota_revision != quota.revision
                || c.policy_revision != q.policy_revision
                || Some(c.endpoint_revision) != endpoint_revision
                || c.expires_at_unix_ms <= now_ms
            {
                continue;
            }
            let permit = match self.current_resource_permit(&c.session_id, now_ms) {
                Ok(p) => p,
                Err(StorageError::Forbidden | StorageError::Unauthorized) => continue,
                Err(e) => return Err(e),
            };
            if c.permit_sha256 != digest(&permit.encode_to_vec())
                || c.lease_sequence != permit.lease_sequence
                || !permit.paths.contains(&(Path::Relay as i32))
            {
                continue;
            }
            if let Some(binding) = self.load_turn_binding(&c.session_id)?
                && binding.controller_signature.len() == 64
                && binding.host_signature.len() == 64
            {
                let controller: [u8; 32] = c
                    .controller_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| StorageError::Conflict)?;
                let host: [u8; 32] = c
                    .host_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| StorageError::Conflict)?;
                let b = verify_turn_peer_binding(&binding, &controller, &host)?;
                let counterpart = if c.device_id == c.controller_device_id {
                    &b.host_allocation_id
                } else {
                    &b.controller_allocation_id
                };
                let pair_live = self.turn_grant_metadata(counterpart).is_ok_and(|other| {
                    b.matches_grant(&other)
                        && other.expires_at_unix_ms > now_ms
                        && other.node_id == c.node_id
                        && other.runtime_id == c.runtime_id
                        && other.runtime_generation == c.runtime_generation
                });
                if b.matches_grant(&c)
                    && pair_live
                    && b.expires_at_unix_ms > now_ms
                    && seen.insert(c.session_id.clone())
                {
                    peer_bindings.push(binding);
                }
            }
            let password = self.turn_password(vault, &id)?;
            c.auth_key = turn_auth_key(&c.username, &c.realm, &password).to_vec();
            c.validate()?;
            grants.push(c);
        }
        let snapshot = TurnResourceSnapshotClaims {
            query: Some(q.clone()),
            query_sha256: digest(&signed.claims).to_vec(),
            snapshot_sequence,
            quota_revision: quota.revision,
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: q
                .expires_at_unix_ms
                .min(
                    now_ms
                        .checked_add(NODE_RESOURCE_TTL_MS)
                        .ok_or(StorageError::Conflict)?,
                )
                .min(node.last.saturating_add(NODE_LEASE_MS)),
            grants,
            peer_bindings,
        };
        snapshot.validate()?;
        tx.execute("INSERT INTO turn_snapshot_sequences VALUES(?1,?2,?3,?4,?5) ON CONFLICT(node_id) DO UPDATE SET runtime_id=excluded.runtime_id,runtime_generation=excluded.runtime_generation,request_sequence=excluded.request_sequence,snapshot_sequence=excluded.snapshot_sequence",params![q.node_id,q.runtime_id,q.runtime_generation,q.request_sequence,snapshot_sequence])?;
        tx.commit()?;
        Ok(snapshot)
    }
}
fn next(sequence: u64) -> Result<u64, StorageError> {
    sequence
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(StorageError::Conflict)
}
