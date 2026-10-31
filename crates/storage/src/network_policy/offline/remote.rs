//! Finite remote approval reuses the existing original remote request, trusted
//! device consent and cumulative online ledger. No service or relay is faked.
use super::*;
use nestlink_protocol::{
    Path, PermitClaims,
    remote_budget::{CAPABILITY, RemoteUsageBudgetClaims},
};

impl Store {
    pub(crate) fn offline_remote_current(
        &self,
        account: &str,
        login: &str,
        claims: &OfflineGrantBundleClaims,
        original: &PermitClaims,
        now: u64,
    ) -> Result<(), StorageError> {
        let OfflineBusiness::RemoteControl {
            resource_id,
            operations,
            capability_digest,
        } = &claims.business
        else {
            return Err(StorageError::Forbidden);
        };
        original.validate()?;
        self.check_request_login(&original.session_id, now / 1000, Some(login))?;
        let live: Option<(String,u64,String)> = self.connection.query_row("SELECT status,connection_generation,last_permit_json FROM remote_requests WHERE id=?1 AND controller_account_id=?2",params![resource_id,account],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let (status, generation, json) = live.ok_or(StorageError::Forbidden)?;
        let current: PermitClaims = serde_json::from_str(&json)?;
        let trust_expiry = self
            .trust_expiration(resource_id, now / 1000)?
            .ok_or(StorageError::Forbidden)?;
        let controller = self.device_record_at(&original.controller_device_id, now / 1000)?;
        let host = self.device_record_at(&original.host_device_id, now / 1000)?;
        let budget_json: String = self.connection.query_row(
            "SELECT claims_json FROM remote_usage_budgets WHERE session_id=?1",
            [resource_id],
            |r| r.get(0),
        )?;
        let budget: RemoteUsageBudgetClaims = serde_json::from_str(&budget_json)?;
        budget.check_permit(original)?;
        budget.check_permit(&current)?;
        if status != "approved"
            || generation != original.connection_generation
            || !self.session_is_active_at(resource_id, now / 1000)?
            || self.policy()?.0 != original.policy_revision
            || self.security_epoch()? != original.security_epoch
            || claims.security_epoch != original.security_epoch
            || claims.deployment_id != original.deployment_id
            || original.session_id != *resource_id
            || original.resource_id != *resource_id
            || original.account_id != account
            || original.controller_device_id != claims.members[0].installation_id
            || original.host_device_id != claims.members[1].installation_id
            || controller.account != claims.members[0].account_id
            || host.account != claims.members[1].account_id
            || controller.public_key != claims.members[0].public_key
            || host.public_key != claims.members[1].public_key
            || digest(&controller.public_key).as_slice() != original.controller_key_sha256
            || digest(&host.public_key).as_slice() != original.host_key_sha256
            || original.capability_sha256.as_slice() != capability_digest
            || current.capability_sha256 != original.capability_sha256
            || !original
                .required_capabilities
                .iter()
                .any(|v| v == CAPABILITY)
            || !original.paths.contains(&(Path::Direct as i32))
            || !current.paths.contains(&(Path::Direct as i32))
            || operations.iter().any(|op| {
                !original.permissions.contains(&(op.permission() as i32))
                    || !current.permissions.contains(&(op.permission() as i32))
            })
            || claims.expires_at_ms > trust_expiry
            || claims.expires_at_ms
                > self
                    .device_expiration_ms(&original.controller_device_id)?
                    .unwrap_or(u64::MAX)
            || claims.expires_at_ms
                > self
                    .device_expiration_ms(&original.host_device_id)?
                    .unwrap_or(u64::MAX)
            || claims.resources.byte_limit > budget.maximum_bytes
            || claims.resources.file_write_limit > budget.maximum_file_write_bytes
            || claims.resources.connection_limit > budget.maximum_connection_attempts
        {
            return Err(StorageError::Forbidden);
        }
        Ok(())
    }
    pub(crate) fn offline_remote_reserve(
        &self,
        tx: &Transaction<'_>,
        claims: &OfflineGrantBundleClaims,
        original: &PermitClaims,
    ) -> Result<(), StorageError> {
        self.reserve_remote_promise(
            tx,
            original,
            claims.resources.byte_limit,
            claims.resources.file_write_limit,
            claims.resources.connection_limit,
        )?;
        tx.execute(
            "INSERT INTO offline_remote_reservations VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                claims.resources.reservation_id,
                claims.bundle_id,
                original.session_id,
                claims.resources.byte_limit,
                claims.resources.file_write_limit,
                claims.resources.connection_limit
            ],
        )?;
        Ok(())
    }
    pub fn create_offline_remote_draft(
        &mut self,
        actor: &Principal,
        space: &str,
        request: OfflineRemoteDraftRequest,
        now: u64,
    ) -> Result<OfflineBundleView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        let policy = settings(&tx, space)?;
        if !policy.enabled || request.expected_policy_revision != snapshot.revision {
            return Err(StorageError::Conflict);
        }
        let count:u64=tx.query_row("SELECT (SELECT count(*) FROM offline_bundles WHERE space_id=?1)+(SELECT count(*) FROM offline_remote_bundles WHERE space_id=?1)",[space],|r|r.get(0))?;
        if count >= MAX_HISTORY {
            return Err(StorageError::RateLimited);
        }
        let original = self.current_permit(actor, &request.session_id, now / 1000)?;
        if original.account_id != actor.account_id
            || request.expected_connection_generation != original.connection_generation
            || request.expected_lease_sequence != original.lease_sequence
        {
            return Err(StorageError::Forbidden);
        }
        let controller = self.device_record_at(&original.controller_device_id, now / 1000)?;
        let host = self.device_record_at(&original.host_device_id, now / 1000)?;
        let source_member = snapshot
            .member(&original.controller_device_id)
            .filter(|m| m.active())
            .ok_or(StorageError::Forbidden)?;
        let host_member = snapshot
            .member(&original.host_device_id)
            .filter(|m| m.active())
            .ok_or(StorageError::Forbidden)?;
        if source_member.public_key() != controller.public_key
            || host_member.public_key() != host.public_key
            || !request.operations.contains(&OfflineRemoteOperation::View)
        {
            return Err(StorageError::Forbidden);
        }
        let claims = OfflineGrantBundleClaims {
            bundle_version: OFFLINE_BUNDLE_VERSION,
            deployment_id: original.deployment_id.clone(),
            space_id: space.into(),
            bundle_id: random_id(),
            policy_epoch: snapshot.policy_epoch,
            security_epoch: original.security_epoch,
            highest_revocation_epoch: policy.highest_revocation_epoch,
            issued_at_ms: now,
            expires_at_ms: request.expires_at_ms,
            members: [
                OfflineMember {
                    installation_id: original.controller_device_id.clone(),
                    account_id: controller.account,
                    public_key: controller.public_key,
                    membership_epoch: source_member.membership_epoch(),
                    process_nonce: request.process_nonces[0],
                },
                OfflineMember {
                    installation_id: original.host_device_id.clone(),
                    account_id: host.account,
                    public_key: host.public_key,
                    membership_epoch: host_member.membership_epoch(),
                    process_nonce: request.process_nonces[1],
                },
            ],
            connection: OfflineConnection {
                connection_id: random_id(),
                path_id: random_id(),
                direct_transports: request.direct_transports,
            },
            business: OfflineBusiness::RemoteControl {
                resource_id: original.resource_id.clone(),
                operations: request.operations,
                capability_digest: original
                    .capability_sha256
                    .as_slice()
                    .try_into()
                    .map_err(|_| StorageError::Conflict)?,
            },
            resources: OfflineResourceReservation {
                reservation_id: random_id(),
                byte_limit: request.maximum_bytes,
                file_write_limit: request.maximum_file_write_bytes,
                connection_limit: request.maximum_connections,
            },
        };
        claims.validate()?;
        self.offline_remote_current(
            &actor.account_id,
            &actor.session_id,
            &claims,
            &original,
            now,
        )?;
        let hash = offline_draft_digest(&snapshot.authority_key, &claims)?;
        tx.execute("INSERT INTO offline_remote_bundles(bundle_id,space_id,requester_account,requester_login,claims_json,draft_digest,authority_key,consume_challenge0,consume_challenge1,original_permit_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![claims.bundle_id,space,actor.account_id,actor.session_id,serde_json::to_string(&claims)?,hash,snapshot.authority_key,random_bytes::<32>(),random_bytes::<32>(),serde_json::to_string(&original)?])?;
        let result = self.offline_current(&tx, &row(&tx, space, &claims.bundle_id)?, now)?;
        auditing::record(
            &tx,
            "offline_remote_draft_created",
            &claims.bundle_id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(result)
    }
}
