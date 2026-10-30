//! Durable network membership authority. Only deployment administrators can
//! mutate this first slice; space-role management and business grants are separate.
//! Signed credentials stay in SQLite and must never appear in audit/log payloads.
use crate::{StorageError, Store, accounts::Principal, audit, auditing, require_id};
use nestlink_identity::{
    digest,
    network::{
        NetworkAuthoritySigner, NetworkVerification, SignedNetworkGrant, VerifiedMembership,
        verify_network_grant,
    },
};
use nestlink_protocol::network::{
    GrantClaims, GrantScope, MembershipClaims, PeerId, SCHEMA_VERSION, SpaceRole,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::collections::{BTreeMap, BTreeSet};
mod remote_paths;
pub use remote_paths::{NetworkRemotePathBundle, NetworkRemotePathIssuance};
mod remote_relays;
pub use remote_relays::{NetworkRemoteRelayBundle, NetworkRemoteRelayIssuance};

pub const MAX_NETWORK_MEMBERS: usize = 4096;
pub const MAX_CURRENT_NETWORK_GRANTS: usize = 65_536;
pub const MAX_MEMBERSHIP_GRANT_MS: u64 = 15 * 60 * 1000;

struct StoredMembershipGrant {
    installation_id: String,
    signed: SignedNetworkGrant,
    digest: Vec<u8>,
}

struct AuthoritySnapshotRow {
    public_key: Vec<u8>,
    deployment_id: String,
    revision: u64,
    policy_epoch: u64,
    last_observed_ms: u64,
    restore_fenced: bool,
    same_security_epoch: bool,
}

pub struct NetworkAuthorityUpdate {
    pub space_id: String,
    pub expected_revision: u64,
    pub public_key: [u8; 32],
}

pub struct NetworkMembershipUpdate {
    pub space_id: String,
    pub installation_id: String,
    pub expected_policy_revision: u64,
    pub expected_membership_epoch: u64,
    pub role: SpaceRole,
}

pub struct NetworkMembershipRevocation {
    pub space_id: String,
    pub installation_id: String,
    pub expected_policy_revision: u64,
    pub expected_membership_epoch: u64,
}

pub struct NetworkGrantRevocation {
    pub space_id: String,
    pub grant_id: String,
    pub expected_revision: u64,
}

pub struct NetworkMembershipRequest {
    pub space_id: String,
    pub installation_id: String,
    pub grant_id: String,
    pub expected_policy_epoch: u64,
    pub expected_membership_epoch: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone)]
pub struct NetworkMemberState {
    installation_id: String,
    public_key: [u8; 32],
    membership_epoch: u64,
    role: SpaceRole,
    active: bool,
}

impl NetworkMemberState {
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
    pub fn membership_epoch(&self) -> u64 {
        self.membership_epoch
    }
    pub fn role(&self) -> SpaceRole {
        self.role
    }
    pub fn active(&self) -> bool {
        self.active
    }
}

/// An atomic bounded read of trusted database state, never a caller-supplied
/// policy. Obtain a fresh snapshot before admission or continued network use;
/// retaining this value does not subscribe the caller to later revocations.
pub struct TrustedNetworkPolicySnapshot {
    authority_key: [u8; 32],
    deployment_id: String,
    space_id: String,
    revision: u64,
    policy_epoch: u64,
    now_ms: u64,
    members: BTreeMap<String, NetworkMemberState>,
    revoked_grant_ids: BTreeSet<String>,
}

impl TrustedNetworkPolicySnapshot {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }
    pub fn member(&self, installation_id: &str) -> Option<&NetworkMemberState> {
        self.members.get(installation_id)
    }
    pub fn verification(&self) -> NetworkVerification<'_> {
        NetworkVerification {
            authority_key: &self.authority_key,
            deployment_id: &self.deployment_id,
            space_id: &self.space_id,
            policy_epoch: self.policy_epoch,
            now_ms: self.now_ms,
            revoked_grant_ids: &self.revoked_grant_ids,
        }
    }
    fn verify_member(
        &self,
        signed: &SignedNetworkGrant,
        installation_id: &str,
    ) -> Result<VerifiedMembership, StorageError> {
        let member = self
            .members
            .get(installation_id)
            .filter(|m| m.active)
            .ok_or(StorageError::Forbidden)?;
        let verified = verify_network_grant(signed, &self.verification())?;
        let bound = VerifiedMembership::from_grant(
            verified,
            &self.verification(),
            installation_id,
            &member.public_key,
            member.membership_epoch,
        )?;
        if bound.claims().role != member.role {
            return Err(StorageError::Forbidden);
        }
        Ok(bound)
    }
}

impl Store {
    /// Pin an independently provisioned network authority. Changes advance both
    /// revision and policy epoch. A restored space cannot be reenabled by this
    /// API: its lost revocation history requires a new space UUID instead.
    pub fn configure_network_authority(
        &mut self,
        actor: &Principal,
        update: NetworkAuthorityUpdate,
        now_ms: u64,
    ) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
        require_id(&update.space_id)?;
        check_clock(now_ms)?;
        if update.public_key == [0; 32] {
            return Err(StorageError::Invalid("empty network authority key"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, now_ms / 1000)?;
        let old: Option<(u64, u64, u64, bool)> = tx.query_row(
            "SELECT revision,policy_epoch,last_observed_ms,restore_fenced FROM network_authorities WHERE space_id=?1",
            [&update.space_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        let (revision, epoch) = if let Some((revision, epoch, last, fenced)) = old {
            if fenced {
                return Err(StorageError::Forbidden);
            }
            if revision != update.expected_revision || now_ms < last {
                return Err(StorageError::Conflict);
            }
            (next(revision)?, next(epoch)?)
        } else {
            if update.expected_revision != 0 {
                return Err(StorageError::Conflict);
            }
            (1, 1)
        };
        tx.execute("INSERT INTO network_authorities(space_id,public_key,revision,policy_epoch,security_epoch,last_observed_ms)
            VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(space_id) DO UPDATE SET public_key=excluded.public_key,revision=excluded.revision,policy_epoch=excluded.policy_epoch,security_epoch=excluded.security_epoch,last_observed_ms=excluded.last_observed_ms",
            params![update.space_id,update.public_key.as_slice(),revision,epoch,self.security_epoch()?,now_ms])?;
        audit(
            &tx,
            "network_authority_changed",
            &update.space_id,
            auditing::management(actor),
        )?;
        let snapshot = read_snapshot(&tx, &update.space_id, now_ms)?;
        tx.commit()?;
        Ok(snapshot)
    }

    /// The installation must already be enrolled and active. Its key is read
    /// from device_details, never accepted from a membership request body.
    /// Every membership change advances the whole space's policy epoch so an
    /// existing VerifiedNetworkPath also rejects an obsolete member epoch.
    pub fn set_network_membership(
        &mut self,
        actor: &Principal,
        update: NetworkMembershipUpdate,
        now_ms: u64,
    ) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
        require_id(&update.installation_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, checked_seconds(now_ms)?)?;
        let snapshot = read_snapshot(&tx, &update.space_id, now_ms)?;
        if snapshot.revision != update.expected_policy_revision {
            return Err(StorageError::Conflict);
        }
        let old = snapshot.members.get(&update.installation_id);
        if old.map_or(0, |m| m.membership_epoch) != update.expected_membership_epoch {
            return Err(StorageError::Conflict);
        }
        if old.is_none() && snapshot.members.len() >= MAX_NETWORK_MEMBERS {
            return Err(StorageError::RateLimited);
        }
        let device = self.device_record_at(&update.installation_id, now_ms / 1000)?;
        let expected_hash: Vec<u8> = tx.query_row(
            "SELECT key_sha256 FROM devices WHERE id=?1",
            [&update.installation_id],
            |r| r.get(0),
        )?;
        if expected_hash != digest(&device.public_key) {
            return Err(StorageError::Forbidden);
        }
        let epoch = next(update.expected_membership_epoch)?;
        tx.execute("INSERT INTO network_memberships(space_id,installation_id,public_key,membership_epoch,role,revoked) VALUES(?1,?2,?3,?4,?5,0)
            ON CONFLICT(space_id,installation_id) DO UPDATE SET public_key=excluded.public_key,membership_epoch=excluded.membership_epoch,role=excluded.role,revoked=0",
            params![update.space_id,update.installation_id,device.public_key.as_slice(),epoch,role_name(update.role)])?;
        advance_policy(&tx, &snapshot, now_ms)?;
        audit(
            &tx,
            "network_membership_changed",
            &update.installation_id,
            auditing::management(actor),
        )?;
        let snapshot = read_snapshot(&tx, &update.space_id, now_ms)?;
        tx.commit()?;
        Ok(snapshot)
    }

    pub fn revoke_network_membership(
        &mut self,
        actor: &Principal,
        update: NetworkMembershipRevocation,
        now_ms: u64,
    ) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
        require_id(&update.installation_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, checked_seconds(now_ms)?)?;
        let snapshot = read_snapshot(&tx, &update.space_id, now_ms)?;
        let member = snapshot
            .members
            .get(&update.installation_id)
            .ok_or(StorageError::Forbidden)?;
        if snapshot.revision != update.expected_policy_revision
            || member.membership_epoch != update.expected_membership_epoch
        {
            return Err(StorageError::Conflict);
        }
        tx.execute("UPDATE network_memberships SET revoked=1,membership_epoch=?1 WHERE space_id=?2 AND installation_id=?3",
            params![next(member.membership_epoch)?,update.space_id,update.installation_id])?;
        advance_policy(&tx, &snapshot, now_ms)?;
        audit(
            &tx,
            "network_membership_revoked",
            &update.installation_id,
            auditing::management(actor),
        )?;
        let snapshot = read_snapshot(&tx, &update.space_id, now_ms)?;
        tx.commit()?;
        Ok(snapshot)
    }

    /// Sign only DB-derived membership facts; this is not an arbitrary claim
    /// signing interface. Nothing is returned until the signed bytes, unique ID
    /// and digest have committed in the same transaction as the audit event.
    pub fn issue_network_membership(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        request: NetworkMembershipRequest,
        now_ms: u64,
    ) -> Result<SignedNetworkGrant, StorageError> {
        require_id(&request.grant_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, checked_seconds(now_ms)?)?;
        let snapshot = read_snapshot(&tx, &request.space_id, now_ms)?;
        remote_paths::grant_id_available(&tx, &request.space_id, &request.grant_id)?;
        let member = snapshot
            .members
            .get(&request.installation_id)
            .filter(|m| m.active)
            .ok_or(StorageError::Forbidden)?;
        if signer.public_key() != snapshot.authority_key {
            return Err(StorageError::Forbidden);
        }
        if request.expected_policy_epoch != snapshot.policy_epoch
            || request.expected_membership_epoch != member.membership_epoch
        {
            return Err(StorageError::Conflict);
        }
        if request.expires_at_ms <= now_ms
            || request.expires_at_ms > i64::MAX as u64
            || request.expires_at_ms - now_ms > MAX_MEMBERSHIP_GRANT_MS
        {
            return Err(StorageError::Invalid(
                "network membership lifetime exceeds its budget",
            ));
        }
        if self
            .device_expiration_ms(&request.installation_id)?
            .is_some_and(|end| request.expires_at_ms > end)
        {
            return Err(StorageError::Forbidden);
        }
        let count: usize = tx.query_row("SELECT count(*) FROM network_grants WHERE space_id=?1 AND policy_epoch=?2 AND expires_at_ms>?3",
            params![request.space_id,snapshot.policy_epoch,now_ms], |r|r.get(0))?;
        if count >= MAX_CURRENT_NETWORK_GRANTS {
            return Err(StorageError::RateLimited);
        }
        let claims = GrantClaims::Membership(MembershipClaims {
            scope: GrantScope {
                schema_version: SCHEMA_VERSION,
                deployment_id: snapshot.deployment_id.clone(),
                space_id: request.space_id.clone(),
                grant_id: request.grant_id.clone(),
                policy_epoch: snapshot.policy_epoch,
                not_before_ms: now_ms,
                expires_at_ms: request.expires_at_ms,
            },
            installation_id: request.installation_id.clone(),
            peer: PeerId::from_public_key(&member.public_key),
            public_key: member.public_key,
            membership_epoch: member.membership_epoch,
            role: member.role,
        });
        let signed = signer.sign(&claims)?;
        let bound = snapshot.verify_member(&signed, &request.installation_id)?;
        tx.execute("INSERT INTO network_grants(space_id,grant_id,kind,installation_id,membership_epoch,policy_epoch,digest,claims,signature,issued_at_ms,expires_at_ms)
            VALUES(?1,?2,'membership',?3,?4,?5,?6,?7,?8,?9,?10)",
            params![request.space_id,request.grant_id,request.installation_id,member.membership_epoch,snapshot.policy_epoch,
                bound.digest().as_slice(),signed.claims,signed.signature,now_ms,request.expires_at_ms])?;
        observe(&tx, &request.space_id, now_ms)?;
        audit(
            &tx,
            "network_membership_issued",
            &request.grant_id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(signed)
    }

    /// Revocation is append-only and idempotent at its current revision. A
    /// grant ID cannot be reused even after expiry, role change or key rotation.
    pub fn revoke_network_grant(
        &mut self,
        actor: &Principal,
        update: NetworkGrantRevocation,
        now_ms: u64,
    ) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
        require_id(&update.grant_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, checked_seconds(now_ms)?)?;
        let snapshot = read_snapshot(&tx, &update.space_id, now_ms)?;
        if snapshot.revision != update.expected_revision {
            return Err(StorageError::Conflict);
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_grants WHERE space_id=?1 AND grant_id=?2)",
            params![update.space_id, update.grant_id],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(StorageError::Forbidden);
        }
        let inserted = tx.execute("INSERT INTO network_grant_revocations(space_id,grant_id,revoked_at_ms) VALUES(?1,?2,?3) ON CONFLICT(space_id,grant_id) DO NOTHING",
            params![update.space_id,update.grant_id,now_ms])?;
        if inserted == 1 {
            tx.execute(
                "UPDATE network_authorities SET revision=?1 WHERE space_id=?2",
                params![next(snapshot.revision)?, update.space_id],
            )?;
            audit(
                &tx,
                "network_grant_revoked",
                &update.grant_id,
                auditing::management(actor),
            )?;
        }
        observe(&tx, &update.space_id, now_ms)?;
        let snapshot = read_snapshot(&tx, &update.space_id, now_ms)?;
        tx.commit()?;
        Ok(snapshot)
    }

    pub fn network_policy_snapshot(
        &mut self,
        space_id: &str,
        now_ms: u64,
    ) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let snapshot = read_snapshot(&tx, space_id, now_ms)?;
        observe(&tx, space_id, now_ms)?;
        tx.commit()?;
        Ok(snapshot)
    }

    /// Recover the exact committed credential after a lost issuance response.
    /// Readback never renews the lifetime or signs a replacement for the ID.
    pub fn network_membership_grant(
        &mut self,
        actor: &Principal,
        space_id: &str,
        grant_id: &str,
        now_ms: u64,
    ) -> Result<SignedNetworkGrant, StorageError> {
        require_id(grant_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_admin(actor, checked_seconds(now_ms)?)?;
        let snapshot = read_snapshot(&tx, space_id, now_ms)?;
        let stored: Option<StoredMembershipGrant> = tx.query_row(
            "SELECT installation_id,claims,signature,digest FROM network_grants WHERE space_id=?1 AND grant_id=?2",
            params![space_id,grant_id], |r|Ok(StoredMembershipGrant {
                installation_id: r.get(0)?,
                signed: SignedNetworkGrant { claims: r.get(1)?, signature: r.get(2)? },
                digest: r.get(3)?,
            }),
        ).optional()?;
        let StoredMembershipGrant {
            installation_id,
            signed,
            digest,
        } = stored.ok_or(StorageError::Forbidden)?;
        let bound = snapshot.verify_member(&signed, &installation_id)?;
        if digest != bound.digest() {
            return Err(StorageError::Forbidden);
        }
        observe(&tx, space_id, now_ms)?;
        tx.commit()?;
        Ok(signed)
    }

    /// Admission reads live membership/device/account state and requires the
    /// exact durable issuer-bound digest, not merely a valid authority signature.
    pub fn verify_network_membership(
        &mut self,
        space_id: &str,
        installation_id: &str,
        signed: &SignedNetworkGrant,
        now_ms: u64,
    ) -> Result<VerifiedMembership, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let snapshot = read_snapshot(&tx, space_id, now_ms)?;
        let bound = snapshot.verify_member(signed, installation_id)?;
        let recorded: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM network_grants WHERE space_id=?1 AND grant_id=?2 AND digest=?3)",
            params![space_id,bound.claims().scope.grant_id,bound.digest().as_slice()], |r|r.get(0))?;
        if !recorded {
            return Err(StorageError::Forbidden);
        }
        observe(&tx, space_id, now_ms)?;
        tx.commit()?;
        Ok(bound)
    }
}

fn read_snapshot(
    connection: &Connection,
    space_id: &str,
    now_ms: u64,
) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
    require_id(space_id)?;
    check_clock(now_ms)?;
    let row: Option<AuthoritySnapshotRow> = connection.query_row(
        "SELECT a.public_key,d.id,a.revision,a.policy_epoch,a.last_observed_ms,a.restore_fenced,a.security_epoch=d.security_epoch FROM network_authorities a JOIN deployment d ON d.singleton=1 WHERE a.space_id=?1",
        [space_id], |r|Ok(AuthoritySnapshotRow {
            public_key: r.get(0)?, deployment_id: r.get(1)?, revision: r.get(2)?, policy_epoch: r.get(3)?,
            last_observed_ms: r.get(4)?, restore_fenced: r.get(5)?, same_security_epoch: r.get(6)?,
        }),
    ).optional()?;
    let AuthoritySnapshotRow {
        public_key: key,
        deployment_id,
        revision,
        policy_epoch,
        last_observed_ms: last,
        restore_fenced: fenced,
        same_security_epoch,
    } = row.ok_or(StorageError::Forbidden)?;
    if fenced || !same_security_epoch {
        return Err(StorageError::Forbidden);
    }
    if now_ms < last {
        return Err(StorageError::Conflict);
    }
    let authority_key = key
        .try_into()
        .map_err(|_| StorageError::Invalid("invalid stored network authority key"))?;
    let mut statement = connection.prepare("SELECT m.installation_id,m.public_key,m.membership_epoch,m.role,
        (m.revoked=0 AND d.revoked=0 AND a.disabled=0 AND (d.expires_at IS NULL OR d.expires_at>?2) AND x.public_key=m.public_key),d.key_sha256
        FROM network_memberships m JOIN devices d ON d.id=m.installation_id JOIN accounts a ON a.id=d.account_id LEFT JOIN device_details x ON x.device_id=d.id
        WHERE m.space_id=?1 ORDER BY m.installation_id LIMIT ?3")?;
    let rows = statement.query_map(
        params![space_id, now_ms / 1000, MAX_NETWORK_MEMBERS + 1],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<bool>>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        },
    )?;
    let mut members = BTreeMap::new();
    for row in rows {
        let (installation_id, key, membership_epoch, role, active, key_sha256) = row?;
        let public_key: [u8; 32] = key
            .try_into()
            .map_err(|_| StorageError::Invalid("invalid stored network member key"))?;
        let active = active.unwrap_or(false) && key_sha256 == digest(&public_key);
        members.insert(
            installation_id.clone(),
            NetworkMemberState {
                installation_id,
                public_key,
                membership_epoch,
                role: parse_role(&role)?,
                active,
            },
        );
        if members.len() > MAX_NETWORK_MEMBERS {
            return Err(StorageError::RateLimited);
        }
    }
    let mut statement = connection.prepare("SELECT g.grant_id,g.installation_id,g.membership_epoch,(r.grant_id IS NOT NULL)
        FROM network_grants g LEFT JOIN network_grant_revocations r ON r.space_id=g.space_id AND r.grant_id=g.grant_id
        WHERE g.space_id=?1 AND g.policy_epoch=?2 AND g.expires_at_ms>?3 ORDER BY g.grant_id LIMIT ?4")?;
    let rows = statement.query_map(
        params![
            space_id,
            policy_epoch,
            now_ms,
            MAX_CURRENT_NETWORK_GRANTS + 1
        ],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, bool>(3)?,
            ))
        },
    )?;
    let mut revoked_grant_ids = BTreeSet::new();
    for (count, row) in rows.enumerate() {
        if count >= MAX_CURRENT_NETWORK_GRANTS {
            return Err(StorageError::RateLimited);
        }
        let (id, installation, epoch, revoked) = row?;
        if revoked
            || members
                .get(&installation)
                .is_none_or(|m| !m.active || m.membership_epoch != epoch)
        {
            revoked_grant_ids.insert(id);
        }
    }
    let mut paths = connection.prepare("SELECT connectivity_grant_id,path_grant_id FROM network_remote_paths WHERE space_id=?1 AND policy_epoch=?2 AND expires_at_ms>?3 AND revoked=1 LIMIT ?4")?;
    for (count, row) in paths
        .query_map(
            params![
                space_id,
                policy_epoch,
                now_ms,
                MAX_CURRENT_NETWORK_GRANTS + 1
            ],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )?
        .enumerate()
    {
        if count >= MAX_CURRENT_NETWORK_GRANTS {
            return Err(StorageError::RateLimited);
        }
        let (connectivity, path) = row?;
        revoked_grant_ids.insert(connectivity);
        revoked_grant_ids.insert(path);
    }
    let mut transits = connection.prepare("SELECT r.transit_grant_id FROM network_remote_relays r JOIN network_remote_paths p ON p.space_id=r.space_id AND p.path_grant_id=r.path_grant_id WHERE r.space_id=?1 AND p.policy_epoch=?2 AND p.expires_at_ms>?3 AND (r.closed=1 OR p.revoked=1) LIMIT ?4")?;
    for (count, id) in transits
        .query_map(
            params![
                space_id,
                policy_epoch,
                now_ms,
                MAX_CURRENT_NETWORK_GRANTS + 1
            ],
            |r| r.get::<_, String>(0),
        )?
        .enumerate()
    {
        if count >= MAX_CURRENT_NETWORK_GRANTS {
            return Err(StorageError::RateLimited);
        }
        revoked_grant_ids.insert(id?);
    }
    Ok(TrustedNetworkPolicySnapshot {
        authority_key,
        deployment_id,
        space_id: space_id.into(),
        revision,
        policy_epoch,
        now_ms,
        members,
        revoked_grant_ids,
    })
}

fn advance_policy(
    tx: &Transaction<'_>,
    snapshot: &TrustedNetworkPolicySnapshot,
    now_ms: u64,
) -> Result<(), StorageError> {
    tx.execute("UPDATE network_authorities SET revision=?1,policy_epoch=?2,last_observed_ms=?3 WHERE space_id=?4",
        params![next(snapshot.revision)?,next(snapshot.policy_epoch)?,now_ms,snapshot.space_id])?;
    Ok(())
}
/// Legacy global/path constraints still apply while the network rewrite rolls
/// out. Invalidate every active space in the originating policy transaction.
/// SQLite STRICT integer columns reject overflow and roll back the operation.
pub(crate) fn invalidate_all(tx: &Transaction<'_>) -> Result<(), StorageError> {
    tx.execute("UPDATE network_authorities SET revision=revision+1,policy_epoch=policy_epoch+1 WHERE restore_fenced=0", [])?;
    Ok(())
}
fn observe(tx: &Transaction<'_>, space_id: &str, now_ms: u64) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE network_authorities SET last_observed_ms=?1 WHERE space_id=?2",
        params![now_ms, space_id],
    )?;
    Ok(())
}
fn next(value: u64) -> Result<u64, StorageError> {
    value
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or(StorageError::Conflict)
}
fn check_clock(now_ms: u64) -> Result<(), StorageError> {
    if now_ms == 0 || now_ms > i64::MAX as u64 {
        return Err(StorageError::Invalid("invalid network authorization clock"));
    }
    Ok(())
}
fn checked_seconds(now_ms: u64) -> Result<u64, StorageError> {
    check_clock(now_ms)?;
    Ok(now_ms / 1000)
}
fn role_name(role: SpaceRole) -> &'static str {
    match role {
        SpaceRole::Owner => "owner",
        SpaceRole::Admin => "admin",
        SpaceRole::Member => "member",
        SpaceRole::Guest => "guest",
    }
}
fn parse_role(value: &str) -> Result<SpaceRole, StorageError> {
    match value {
        "owner" => Ok(SpaceRole::Owner),
        "admin" => Ok(SpaceRole::Admin),
        "member" => Ok(SpaceRole::Member),
        "guest" => Ok(SpaceRole::Guest),
        _ => Err(StorageError::Invalid("invalid stored network member role")),
    }
}
