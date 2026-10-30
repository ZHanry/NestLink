//! Deployment-admin CAS transitions. Retired keys and revocation never reset.
use super::*;

pub struct NetworkAuthorityChange {
    pub space_id: String,
    pub expected_revision: u64,
    pub expected_policy_epoch: u64,
}

pub struct NetworkAuthorityState {
    pub deployment_id: String,
    pub space_id: String,
    pub public_key: [u8; 32],
    pub revision: u64,
    pub policy_epoch: u64,
    pub signing_generation: u64,
    pub revoked: bool,
    pub observed_at_ms: u64,
}

struct Row {
    deployment_id: String,
    key: Vec<u8>,
    revision: u64,
    policy_epoch: u64,
    generation: u64,
    revoked: bool,
    last: u64,
    fenced: bool,
    same_epoch: bool,
}

fn state(
    connection: &Connection,
    space: &str,
    now_ms: u64,
) -> Result<NetworkAuthorityState, StorageError> {
    require_id(space)?;
    check_clock(now_ms)?;
    let row = connection.query_row(
        "SELECT d.id,a.public_key,a.revision,a.policy_epoch,a.signing_generation,a.authority_revoked,a.last_observed_ms,a.restore_fenced,a.security_epoch=d.security_epoch
         FROM network_authorities a JOIN deployment d ON d.singleton=1 WHERE a.space_id=?1
         AND NOT EXISTS(SELECT 1 FROM network_spaces s WHERE s.space_id=a.space_id AND s.archived=1)",
        [space], |r| Ok(Row {deployment_id:r.get(0)?,key:r.get(1)?,revision:r.get(2)?,policy_epoch:r.get(3)?,generation:r.get(4)?,revoked:r.get(5)?,last:r.get(6)?,fenced:r.get(7)?,same_epoch:r.get(8)?}),
    ).optional()?.ok_or(StorageError::Forbidden)?;
    if row.fenced || !row.same_epoch {
        return Err(StorageError::Forbidden);
    }
    if now_ms < row.last {
        return Err(StorageError::Conflict);
    }
    Ok(NetworkAuthorityState {
        deployment_id: row.deployment_id,
        space_id: space.into(),
        public_key: row
            .key
            .try_into()
            .map_err(|_| StorageError::Invalid("invalid authority key"))?,
        revision: row.revision,
        policy_epoch: row.policy_epoch,
        signing_generation: row.generation,
        revoked: row.revoked,
        observed_at_ms: now_ms,
    })
}

fn current(
    expected: &NetworkAuthorityChange,
    actual: &NetworkAuthorityState,
) -> Result<(), StorageError> {
    if expected.expected_revision != actual.revision
        || expected.expected_policy_epoch != actual.policy_epoch
    {
        return Err(StorageError::Conflict);
    }
    Ok(())
}

pub(super) fn require_unused_key(
    connection: &Connection,
    space: &str,
    key: &[u8; 32],
) -> Result<(), StorageError> {
    let used: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM network_authority_key_history WHERE space_id=?1 AND public_key=?2)",params![space,key.as_slice()],|r|r.get(0))?;
    if used {
        return Err(StorageError::Forbidden);
    }
    Ok(())
}
pub(super) fn retire_key(
    connection: &Connection,
    space: &str,
    key: &[u8],
    now_ms: u64,
) -> Result<(), StorageError> {
    let changed = connection.execute("UPDATE network_authority_key_history SET retired_at_ms=?1 WHERE space_id=?2 AND public_key=?3 AND retired_at_ms IS NULL",params![now_ms,space,key])?;
    if changed != 1 {
        return Err(StorageError::Forbidden);
    }
    Ok(())
}

impl Store {
    /// Readable after permanent revocation so a lost response is recoverable.
    /// This grants no credential issuance or transport authority.
    pub fn network_authority_state(
        &mut self,
        actor: &Principal,
        space: &str,
        now_ms: u64,
    ) -> Result<NetworkAuthorityState, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, checked_seconds(now_ms)?)?;
        let actual = state(&tx, space, now_ms)?;
        observe(&tx, space, now_ms)?;
        tx.commit()?;
        Ok(actual)
    }

    /// Resolve only the current stored generation under the configured root.
    /// Issuance rechecks the returned public key in its own original transaction.
    pub fn network_authority_signer(
        &self,
        root: &NetworkAuthoritySigner,
        space: &str,
        now_ms: u64,
    ) -> Result<NetworkAuthoritySigner, StorageError> {
        let actual = state(&self.connection, space, now_ms)?;
        if actual.revoked {
            return Err(StorageError::Forbidden);
        }
        let signer = root.for_space_generation(space, actual.signing_generation)?;
        if signer.public_key() != actual.public_key {
            return Err(StorageError::Forbidden);
        }
        Ok(signer)
    }

    pub fn rotate_network_authority(
        &mut self,
        actor: &Principal,
        root: &NetworkAuthoritySigner,
        change: NetworkAuthorityChange,
        now_ms: u64,
    ) -> Result<NetworkAuthorityState, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, checked_seconds(now_ms)?)?;
        let actual = state(&tx, &change.space_id, now_ms)?;
        current(&change, &actual)?;
        if actual.revoked
            || root
                .for_space_generation(&change.space_id, actual.signing_generation)?
                .public_key()
                != actual.public_key
        {
            return Err(StorageError::Forbidden);
        }
        let generation = next(actual.signing_generation)?;
        let key = root
            .for_space_generation(&change.space_id, generation)?
            .public_key();
        require_unused_key(&tx, &change.space_id, &key)?;
        retire_key(&tx, &change.space_id, &actual.public_key, now_ms)?;
        tx.execute("UPDATE network_authorities SET public_key=?1,revision=?2,policy_epoch=?3,signing_generation=?4,last_observed_ms=?5 WHERE space_id=?6",
            params![key.as_slice(),next(actual.revision)?,next(actual.policy_epoch)?,generation,now_ms,change.space_id])?;
        tx.execute("INSERT INTO network_authority_key_history(space_id,public_key,signing_generation,activated_policy_epoch,activated_at_ms) VALUES(?1,?2,?3,?4,?5)",params![change.space_id,key.as_slice(),generation,next(actual.policy_epoch)?,now_ms])?;
        audit(
            &tx,
            "network_authority_rotated",
            &change.space_id,
            auditing::management(actor),
        )?;
        let updated = state(&tx, &change.space_id, now_ms)?;
        tx.commit()?;
        Ok(updated)
    }

    pub fn revoke_network_authority(
        &mut self,
        actor: &Principal,
        change: NetworkAuthorityChange,
        now_ms: u64,
    ) -> Result<NetworkAuthorityState, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, checked_seconds(now_ms)?)?;
        let actual = state(&tx, &change.space_id, now_ms)?;
        current(&change, &actual)?;
        if !actual.revoked {
            tx.execute("UPDATE network_authorities SET authority_revoked=1,revision=?1,policy_epoch=?2,last_observed_ms=?3 WHERE space_id=?4",params![next(actual.revision)?,next(actual.policy_epoch)?,now_ms,change.space_id])?;
            retire_key(&tx, &change.space_id, &actual.public_key, now_ms)?;
            audit(
                &tx,
                "network_authority_revoked",
                &change.space_id,
                auditing::management(actor),
            )?;
        } else {
            observe(&tx, &change.space_id, now_ms)?;
        }
        let updated = state(&tx, &change.space_id, now_ms)?;
        tx.commit()?;
        Ok(updated)
    }

    pub fn advance_network_policy_epoch(
        &mut self,
        actor: &Principal,
        change: NetworkAuthorityChange,
        now_ms: u64,
    ) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, checked_seconds(now_ms)?)?;
        let actual = state(&tx, &change.space_id, now_ms)?;
        current(&change, &actual)?;
        let snapshot = read_snapshot(&tx, &change.space_id, now_ms)?;
        advance_policy(&tx, &snapshot, now_ms)?;
        audit(
            &tx,
            "network_policy_epoch_advanced",
            &change.space_id,
            auditing::management(actor),
        )?;
        let updated = read_snapshot(&tx, &change.space_id, now_ms)?;
        tx.commit()?;
        Ok(updated)
    }
}
