//! The first path issuance slice is direct remote control with an already
//! approved live SessionPermit. It never creates consent, relay allocation,
//! service authority or raw-IP rights.
use super::*;
use nestlink_identity::network::VerifiedNetworkPath;
use nestlink_protocol::{
    Path,
    api::NetworkRemotePathRequest,
    network::{ConnectivityClaims, PathClaims, PathPolicy, PeerPair, Purpose},
};
use prost::Message;

pub struct NetworkRemotePathIssuance {
    pub space_id: String,
    pub request_id: String,
    pub request: NetworkRemotePathRequest,
}

pub struct NetworkRemotePathBundle {
    pub request_id: String,
    /// Controller then host, independent of canonical peer ordering.
    pub memberships: [SignedNetworkGrant; 2],
    pub connectivity: SignedNetworkGrant,
    pub path: SignedNetworkGrant,
    pub(super) verified: VerifiedNetworkPath,
}
impl NetworkRemotePathBundle {
    pub fn verified(&self) -> &VerifiedNetworkPath {
        &self.verified
    }
}

struct StoredPath {
    request_id: String,
    connectivity_grant_id: String,
    controller_membership_id: String,
    host_membership_id: String,
    business_digest: Vec<u8>,
    connectivity: SignedNetworkGrant,
    path: SignedNetworkGrant,
    policy_epoch: u64,
    expires_at_ms: u64,
    revoked: bool,
}

pub(super) fn current_business(
    store: &Store,
    request_id: &str,
    now_ms: u64,
) -> Result<nestlink_protocol::PermitClaims, StorageError> {
    match store.current_resource_permit(request_id, now_ms) {
        // A previous connection generation can disappear during reconnection.
        // It is no longer authority, rather than a management server failure.
        Err(StorageError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
            Err(StorageError::Forbidden)
        }
        result => result,
    }
}

fn member_credential(
    connection: &Connection,
    snapshot: &TrustedNetworkPolicySnapshot,
    grant_id: &str,
    installation: &str,
) -> Result<(SignedNetworkGrant, VerifiedMembership), StorageError> {
    require_id(grant_id)?;
    let row: Option<StoredMembershipGrant> = connection.query_row(
        "SELECT installation_id,claims,signature,digest FROM network_grants WHERE space_id=?1 AND grant_id=?2",
        params![snapshot.space_id,grant_id], |r|Ok(StoredMembershipGrant {
            installation_id:r.get(0)?,signed:SignedNetworkGrant {claims:r.get(1)?,signature:r.get(2)?},digest:r.get(3)?,
        })).optional()?;
    let row = row.ok_or(StorageError::Forbidden)?;
    if row.installation_id != installation {
        return Err(StorageError::Forbidden);
    }
    let bound = snapshot.verify_member(&row.signed, installation)?;
    if row.digest != bound.digest() {
        return Err(StorageError::Forbidden);
    }
    Ok((row.signed, bound))
}

pub(super) fn grant_id_available(
    connection: &Connection,
    space: &str,
    id: &str,
) -> Result<(), StorageError> {
    require_id(id)?;
    let exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM network_grants WHERE space_id=?1 AND grant_id=?2 UNION ALL SELECT 1 FROM network_remote_paths WHERE space_id=?1 AND (path_grant_id=?2 OR connectivity_grant_id=?2) UNION ALL SELECT 1 FROM network_remote_relays WHERE space_id=?1 AND transit_grant_id=?2 UNION ALL SELECT 1 FROM network_remote_chain_hops WHERE space_id=?1 AND transit_grant_id=?2 UNION ALL SELECT 1 FROM network_remote_route_set_members WHERE space_id=?1 AND transit_grant_id=?2 UNION ALL SELECT 1 FROM network_route_exports WHERE space_id=?1 AND grant_id=?2 UNION ALL SELECT 1 FROM network_topology_publishers WHERE space_id=?1 AND publisher_id=?2)",
        params![space,id], |r|r.get(0))?;
    if exists {
        return Err(StorageError::Conflict);
    }
    Ok(())
}

impl Store {
    /// All claims come from the current consented business session and the
    /// exact stored member credentials. The request cannot choose peers, keys,
    /// purpose, permissions or relays, even when its caller is an administrator.
    pub fn issue_network_remote_path(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        issuance: NetworkRemotePathIssuance,
        now_ms: u64,
    ) -> Result<NetworkRemotePathBundle, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let bundle = self.issue_network_path_in_transaction(
            &tx,
            actor,
            signer,
            issuance,
            PathPolicy {
                allow_direct: true,
                relays: Vec::new(),
                max_hops: 0,
            },
            now_ms,
        )?;
        tx.commit()?;
        Ok(bundle)
    }

    /// One transaction owns both the signed chain and any relay promise. The
    /// policy is selected by trusted storage admission, never a public body.
    pub(super) fn issue_network_path_in_transaction(
        &self,
        tx: &Transaction<'_>,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        issuance: NetworkRemotePathIssuance,
        policy: PathPolicy,
        now_ms: u64,
    ) -> Result<NetworkRemotePathBundle, StorageError> {
        let NetworkRemotePathIssuance {
            space_id,
            request_id,
            request,
        } = issuance;
        self.validate_access(actor, checked_seconds(now_ms)?)?;
        self.remote(actor, &request_id)?;
        let business = current_business(self, &request_id, now_ms)?;
        if (policy.allow_direct && !business.paths.contains(&(Path::Direct as i32)))
            || (!policy.relays.is_empty() && !business.paths.contains(&(Path::Relay as i32)))
        {
            return Err(StorageError::Forbidden);
        }
        let snapshot = read_snapshot(tx, &space_id, now_ms)?;
        if signer.public_key() != snapshot.authority_key {
            return Err(StorageError::Forbidden);
        }
        if request.expected_policy_epoch != snapshot.policy_epoch {
            return Err(StorageError::Conflict);
        }
        if request.path_grant_id == request.connectivity_grant_id {
            return Err(StorageError::Conflict);
        }
        for id in [&request.path_grant_id, &request.connectivity_grant_id] {
            grant_id_available(tx, &space_id, id)?;
        }
        let count: usize = tx.query_row("SELECT count(*) FROM network_remote_paths WHERE space_id=?1 AND policy_epoch=?2 AND expires_at_ms>?3",
            params![space_id,snapshot.policy_epoch,now_ms],|r|r.get(0))?;
        if count >= MAX_CURRENT_NETWORK_GRANTS {
            return Err(StorageError::RateLimited);
        }
        let (controller, controller_bound) = member_credential(
            tx,
            &snapshot,
            &request.controller_membership_grant_id,
            &business.controller_device_id,
        )?;
        let (host, host_bound) = member_credential(
            tx,
            &snapshot,
            &request.host_membership_grant_id,
            &business.host_device_id,
        )?;
        if request.expires_at_unix_ms <= now_ms
            || request.expires_at_unix_ms - now_ms > 60_000
            || request.expires_at_unix_ms > business.expires_at_unix_ms
            || [controller_bound.claims(), host_bound.claims()]
                .iter()
                .any(|m| request.expires_at_unix_ms > m.scope.expires_at_ms)
        {
            return Err(StorageError::Invalid(
                "path lifetime exceeds current business or membership authority",
            ));
        }
        let peers = PeerPair::new(controller_bound.peer(), host_bound.peer())?;
        let membership_digests = if controller_bound.peer() == peers.first {
            [controller_bound.digest(), host_bound.digest()]
        } else {
            [host_bound.digest(), controller_bound.digest()]
        };
        let scope = |id: &str| GrantScope {
            schema_version: SCHEMA_VERSION,
            deployment_id: snapshot.deployment_id.clone(),
            space_id: space_id.clone(),
            grant_id: id.into(),
            policy_epoch: snapshot.policy_epoch,
            not_before_ms: now_ms,
            expires_at_ms: request.expires_at_unix_ms,
        };
        let business_digest = digest(&business.encode_to_vec());
        let connectivity = signer.sign(&GrantClaims::Connectivity(ConnectivityClaims {
            scope: scope(&request.connectivity_grant_id),
            peers,
            purpose: Purpose::RemoteControl,
            membership_digests,
            business_grant_digest: business_digest,
        }))?;
        let verified_connectivity = verify_network_grant(&connectivity, &snapshot.verification())?;
        let path = signer.sign(&GrantClaims::Path(PathClaims {
            scope: scope(&request.path_grant_id),
            peers,
            purpose: Purpose::RemoteControl,
            connectivity_grant_digest: verified_connectivity.digest(),
            policy,
        }))?;
        let verified = VerifiedNetworkPath::from_grants(
            &snapshot.verification(),
            [controller_bound, host_bound],
            verified_connectivity,
            verify_network_grant(&path, &snapshot.verification())?,
            business_digest,
        )?;
        tx.execute("INSERT INTO network_remote_paths(space_id,path_grant_id,connectivity_grant_id,request_id,controller_membership_id,host_membership_id,policy_epoch,business_digest,connectivity_claims,connectivity_signature,path_claims,path_signature,expires_at_ms)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![space_id,request.path_grant_id,request.connectivity_grant_id,request_id,
                request.controller_membership_grant_id,request.host_membership_grant_id,snapshot.policy_epoch,business_digest.as_slice(),
                connectivity.claims,connectivity.signature,path.claims,path.signature,request.expires_at_unix_ms])?;
        observe(tx, &space_id, now_ms)?;
        audit(
            tx,
            "network_remote_path_issued",
            &request.path_grant_id,
            auditing::management(actor),
        )?;
        Ok(NetworkRemotePathBundle {
            request_id,
            memberships: [controller, host],
            connectivity,
            path,
            verified,
        })
    }

    /// Reopening the database or retrying a lost response returns the identical
    /// signed bytes. Current business renewal/revocation and membership changes
    /// invalidate admission; readback never re-signs or extends the old chain.
    pub fn network_remote_path(
        &mut self,
        actor: &Principal,
        space: &str,
        path_id: &str,
        now_ms: u64,
    ) -> Result<NetworkRemotePathBundle, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let bundle = self.network_path_in_transaction(&tx, actor, space, path_id, false, now_ms)?;
        tx.commit()?;
        Ok(bundle)
    }

    pub(super) fn network_path_in_transaction(
        &self,
        tx: &Transaction<'_>,
        actor: &Principal,
        space: &str,
        path_id: &str,
        relay: bool,
        now_ms: u64,
    ) -> Result<NetworkRemotePathBundle, StorageError> {
        self.network_path_current_in_transaction(tx, Some(actor), space, path_id, relay, now_ms)
    }

    pub(super) fn network_path_current_in_transaction(
        &self,
        tx: &Transaction<'_>,
        actor: Option<&Principal>,
        space: &str,
        path_id: &str,
        relay: bool,
        now_ms: u64,
    ) -> Result<NetworkRemotePathBundle, StorageError> {
        self.network_path_current_with_hops(tx, actor, space, path_id, u8::from(relay), now_ms)
    }

    pub(super) fn network_path_current_with_hops(
        &self,
        tx: &Transaction<'_>,
        actor: Option<&Principal>,
        space: &str,
        path_id: &str,
        relay_hops: u8,
        now_ms: u64,
    ) -> Result<NetworkRemotePathBundle, StorageError> {
        self.network_path_current_with_shape(
            tx,
            actor,
            space,
            path_id,
            (relay_hops, usize::from(relay_hops)),
            now_ms,
        )
    }

    pub(super) fn network_route_set_path_current(
        &self,
        tx: &Transaction<'_>,
        actor: Option<&Principal>,
        space: &str,
        path_id: &str,
        now_ms: u64,
    ) -> Result<NetworkRemotePathBundle, StorageError> {
        self.network_path_current_with_shape(tx, actor, space, path_id, (1, 2), now_ms)
    }

    fn network_path_current_with_shape(
        &self,
        tx: &Transaction<'_>,
        actor: Option<&Principal>,
        space: &str,
        path_id: &str,
        shape: (u8, usize),
        now_ms: u64,
    ) -> Result<NetworkRemotePathBundle, StorageError> {
        self.network_path_current_with_business(tx, actor, space, path_id, shape, now_ms, None)
    }
    /// Only the dual-signed reconnection receipt may validate its exact previous
    /// generation. Current membership, policy, expiry and revocation still apply.
    pub(super) fn network_route_set_recovery_path(&self, tx: &Transaction<'_>, space: &str,
        path_id: &str, now_ms: u64, previous: &nestlink_protocol::PermitClaims,
    ) -> Result<NetworkRemotePathBundle, StorageError> {
        self.network_path_current_with_business(tx, None, space, path_id, (1,2), now_ms, Some(previous))
    }
    #[allow(clippy::too_many_arguments)]
    fn network_path_current_with_business(&self, tx: &Transaction<'_>, actor: Option<&Principal>,
        space: &str, path_id: &str, shape: (u8,usize), now_ms: u64,
        previous: Option<&nestlink_protocol::PermitClaims>,
    ) -> Result<NetworkRemotePathBundle, StorageError> {
        let (relay_hops, relay_count) = shape;
        require_id(path_id)?;
        if let Some(actor) = actor {
            self.validate_access(actor, checked_seconds(now_ms)?)?;
        }
        let snapshot = read_snapshot(tx, space, now_ms)?;
        let row: Option<StoredPath> = tx.query_row("SELECT request_id,controller_membership_id,host_membership_id,business_digest,connectivity_claims,connectivity_signature,path_claims,path_signature,revoked,connectivity_grant_id,policy_epoch,expires_at_ms FROM network_remote_paths WHERE space_id=?1 AND path_grant_id=?2",
            params![space,path_id], |r|Ok(StoredPath {request_id:r.get(0)?,controller_membership_id:r.get(1)?,host_membership_id:r.get(2)?,business_digest:r.get(3)?,
                connectivity:SignedNetworkGrant {claims:r.get(4)?,signature:r.get(5)?},path:SignedNetworkGrant {claims:r.get(6)?,signature:r.get(7)?},revoked:r.get(8)?,
                connectivity_grant_id:r.get(9)?,policy_epoch:r.get(10)?,expires_at_ms:r.get(11)?})).optional()?;
        let row = row
            .filter(|r| {
                !r.revoked && r.policy_epoch == snapshot.policy_epoch && r.expires_at_ms > now_ms
            })
            .ok_or(StorageError::Forbidden)?;
        if let Some(actor) = actor {
            self.remote(actor, &row.request_id)?;
        }
        let business = match previous {
            Some(previous) if previous.session_id == row.request_id => previous.clone(),
            Some(_) => return Err(StorageError::Forbidden),
            None => current_business(self, &row.request_id, now_ms)?,
        };
        let business_digest = digest(&business.encode_to_vec());
        if row.business_digest != business_digest
            || !business.paths.contains(
                &(if relay_hops > 0 {
                    Path::Relay
                } else {
                    Path::Direct
                } as i32),
            )
        {
            return Err(StorageError::Forbidden);
        }
        let (controller, controller_bound) = member_credential(
            tx,
            &snapshot,
            &row.controller_membership_id,
            &business.controller_device_id,
        )?;
        let (host, host_bound) = member_credential(
            tx,
            &snapshot,
            &row.host_membership_id,
            &business.host_device_id,
        )?;
        let path = verify_network_grant(&row.path, &snapshot.verification())?;
        let connectivity = verify_network_grant(&row.connectivity, &snapshot.verification())?;
        if path.claims().scope().grant_id != path_id
            || connectivity.claims().scope().grant_id != row.connectivity_grant_id
            || [path.claims().scope(), connectivity.claims().scope()]
                .iter()
                .any(|scope| {
                    scope.policy_epoch != row.policy_epoch
                        || scope.expires_at_ms != row.expires_at_ms
                })
        {
            return Err(StorageError::Forbidden);
        }
        let verified = VerifiedNetworkPath::from_grants(
            &snapshot.verification(),
            [controller_bound, host_bound],
            connectivity,
            path,
            business_digest,
        )?;
        let policy = &verified.claims().policy;
        if verified.purpose() != Purpose::RemoteControl
            || if relay_hops > 0 {
                relay_hops > 2
                    || policy.allow_direct
                    || policy.relays.len() != relay_count
                    || policy.max_hops != relay_hops
            } else {
                !policy.allow_direct || !policy.relays.is_empty() || policy.max_hops != 0
            }
        {
            return Err(StorageError::Forbidden);
        }
        observe(tx, space, now_ms)?;
        Ok(NetworkRemotePathBundle {
            request_id: row.request_id,
            memberships: [controller, host],
            connectivity: row.connectivity,
            path: row.path,
            verified,
        })
    }

    pub fn revoke_network_remote_path(
        &mut self,
        actor: &Principal,
        space: &str,
        path_id: &str,
        now_ms: u64,
    ) -> Result<(), StorageError> {
        require_id(path_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now_ms)?)?;
        read_snapshot(&tx, space, now_ms)?;
        let request_id: Option<String> = tx.query_row("SELECT request_id FROM network_remote_paths WHERE space_id=?1 AND path_grant_id=?2",
            params![space,path_id],|r|r.get(0)).optional()?;
        self.remote(actor, &request_id.ok_or(StorageError::Forbidden)?)?;
        if tx.execute("UPDATE network_remote_paths SET revoked=1 WHERE space_id=?1 AND path_grant_id=?2 AND revoked=0",params![space,path_id])? == 1 {
            audit(&tx,"network_remote_path_revoked",path_id,auditing::management(actor))?;
        }
        observe(&tx, space, now_ms)?;
        tx.commit()?;
        Ok(())
    }
}
