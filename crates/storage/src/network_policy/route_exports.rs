//! Stored publication authority, independent of membership and IP access.
//! Managers delegate exact prefixes; the node must separately opt to report
//! them. No method here creates routes, enables forwarding or grants IP access.
use super::*;
use nestlink_identity::network::VerifiedNetworkGrant;
pub use nestlink_protocol::api::NetworkRouteExportRequest as RouteExportRequest;
use nestlink_protocol::network::{IpPrefix, MAX_PREFIXES, RouteExportClaims};

pub const MAX_ROUTE_EXPORT_MS: u64 = 15 * 60 * 1000;
pub const MAX_CURRENT_ROUTE_EXPORTS: usize = 4096;
pub const MAX_ROUTE_EXPORT_HISTORY: usize = 65_536;

struct Stored {
    grant_id: String,
    node_id: String,
    public_key: Vec<u8>,
    digest: Vec<u8>,
    signed: SignedNetworkGrant,
    revoked: bool,
}
fn stored(connection: &Connection, space: &str, id: &str) -> Result<Stored, StorageError> {
    require_id(id)?;
    connection.query_row(
        "SELECT node_id,public_key,digest,claims,signature,revoked FROM network_route_exports WHERE space_id=?1 AND grant_id=?2",
        params![space,id], |r| Ok(Stored {
            grant_id:id.into(),
            node_id:r.get(0)?, public_key:r.get(1)?, digest:r.get(2)?,
            signed: SignedNetworkGrant {claims:r.get(3)?,signature:r.get(4)?}, revoked:r.get(5)?,
        }),
    ).optional()?.ok_or(StorageError::Forbidden)
}
fn verified(
    store: &Store,
    snapshot: &TrustedNetworkPolicySnapshot,
    expected_node: &str,
    row: &Stored,
) -> Result<VerifiedNetworkGrant, StorageError> {
    if row.revoked || row.node_id != expected_node {
        return Err(StorageError::Forbidden);
    }
    let key = topology::node_key(store, expected_node, snapshot.now_ms)?;
    if row.public_key.as_slice() != key.as_slice() {
        return Err(StorageError::Forbidden);
    }
    let grant = verify_network_grant(&row.signed, &snapshot.verification())?;
    let GrantClaims::RouteExport(export) = grant.claims() else {
        return Err(StorageError::Forbidden);
    };
    if export.scope.grant_id != row.grant_id
        || export.gateway != PeerId::from_public_key(&key)
        || row.digest.as_slice() != grant.digest().as_slice()
    {
        return Err(StorageError::Forbidden);
    }
    Ok(grant)
}

pub(super) fn for_ids(
    store: &Store,
    snapshot: &TrustedNetworkPolicySnapshot,
    node_id: &str,
    ids: &[String],
) -> Result<Vec<VerifiedNetworkGrant>, StorageError> {
    if ids.len() > MAX_PREFIXES || ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(StorageError::Invalid(
            "invalid topology export reference count",
        ));
    }
    let mut grants = Vec::new();
    for id in ids {
        grants.push(verified(
            store,
            snapshot,
            node_id,
            &stored(&store.connection, &snapshot.space_id, id)?,
        )?);
    }
    grants.sort_by_key(VerifiedNetworkGrant::digest);
    Ok(grants)
}

/// Every consumer uses the exact durable referenced bytes, never proofs
/// supplied by a report. All reads share the caller's SQLite transaction.
pub(super) fn for_publisher(
    store: &Store,
    snapshot: &TrustedNetworkPolicySnapshot,
    publisher: &nestlink_protocol::network_topology::TopologyPublisherClaims,
) -> Result<Vec<VerifiedNetworkGrant>, StorageError> {
    let mut statement = store.connection.prepare(
        "SELECT grant_id FROM network_topology_publisher_exports WHERE space_id=?1 AND publisher_id=?2 ORDER BY grant_id LIMIT ?3",
    )?;
    let ids = statement
        .query_map(
            params![
                snapshot.space_id,
                publisher.scope.grant_id,
                MAX_PREFIXES + 1
            ],
            |r| r.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let grants = for_ids(store, snapshot, &publisher.node_id, &ids)?;
    if grants
        .iter()
        .map(VerifiedNetworkGrant::digest)
        .collect::<Vec<_>>()
        != publisher.route_export_digests
    {
        return Err(StorageError::Forbidden);
    }
    Ok(grants)
}

pub(super) fn prefixes(grants: &[VerifiedNetworkGrant]) -> Result<Vec<IpPrefix>, StorageError> {
    let mut prefixes = Vec::new();
    for grant in grants {
        let GrantClaims::RouteExport(export) = grant.claims() else {
            return Err(StorageError::Forbidden);
        };
        prefixes.extend(export.prefixes.iter().copied());
    }
    prefixes.sort_by_key(|prefix| (prefix.network, prefix.prefix_len));
    prefixes.dedup();
    if prefixes.len() > MAX_PREFIXES {
        return Err(StorageError::Invalid(
            "publisher export prefix union exceeds its budget",
        ));
    }
    Ok(prefixes)
}

/// Dynamic node revocation, identity replacement, policy and lease changes
/// must invalidate cached publication proofs as well as fresh Store readback.
pub(super) fn collect_revocations(
    connection: &Connection,
    space: &str,
    epoch: u64,
    now: u64,
    revoked: &mut BTreeSet<String>,
) -> Result<(), StorageError> {
    let mut statement = connection.prepare(
        "SELECT e.grant_id, (e.revoked=1 OR n.id IS NULL OR n.revoked=1 OR n.public_key!=e.public_key
          OR n.last_issued_at>?3 OR ?3-n.last_issued_at>=?4 OR n.lease_policy_revision!=d.policy_revision
          OR NOT EXISTS(SELECT 1 FROM json_each(n.roles_json) WHERE value=1)
          OR NOT EXISTS(SELECT 1 FROM node_runtimes r WHERE r.node_id=n.id AND r.runtime_id=n.runtime_id AND r.generation=n.runtime_generation AND r.security_epoch=d.security_epoch))
         FROM network_route_exports e LEFT JOIN data_nodes n ON n.id=e.node_id JOIN deployment d ON d.singleton=1
         WHERE e.space_id=?1 AND e.policy_epoch=?2 AND e.expires_at_ms>?3 ORDER BY e.grant_id LIMIT ?5",
    )?;
    for (count, row) in statement
        .query_map(
            params![
                space,
                epoch,
                now,
                nestlink_protocol::NODE_LEASE_MS,
                MAX_ROUTE_EXPORT_HISTORY + 1
            ],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
        )?
        .enumerate()
    {
        if count >= MAX_ROUTE_EXPORT_HISTORY {
            return Err(StorageError::RateLimited);
        }
        let (id, invalid) = row?;
        if invalid {
            revoked.insert(id);
        }
    }
    Ok(())
}

impl Store {
    pub fn issue_network_route_export(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        space: &str,
        node_id: &str,
        mut request: RouteExportRequest,
        now: u64,
    ) -> Result<SignedNetworkGrant, StorageError> {
        require_id(&request.grant_id)?;
        if request.expires_at_ms <= now
            || request.expires_at_ms > i64::MAX as u64
            || request.expires_at_ms - now > MAX_ROUTE_EXPORT_MS
        {
            return Err(StorageError::Invalid(
                "route export lifetime exceeds its budget",
            ));
        }
        request
            .prefixes
            .sort_by_key(|prefix| (prefix.network, prefix.prefix_len));
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        topology::access(self, actor, space, true, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        if request.expected_revision != snapshot.revision
            || request.expected_policy_epoch != snapshot.policy_epoch
        {
            return Err(StorageError::Conflict);
        }
        if signer.public_key() != snapshot.authority_key {
            return Err(StorageError::Forbidden);
        }
        remote_paths::grant_id_available(&tx, space, &request.grant_id)?;
        let history: usize = tx.query_row(
            "SELECT count(*) FROM network_route_exports WHERE space_id=?1",
            [space],
            |r| r.get(0),
        )?;
        let current: usize = tx.query_row("SELECT count(*) FROM network_route_exports WHERE space_id=?1 AND policy_epoch=?2 AND expires_at_ms>?3 AND revoked=0",params![space,snapshot.policy_epoch,now],|r|r.get(0))?;
        if history >= MAX_ROUTE_EXPORT_HISTORY || current >= MAX_CURRENT_ROUTE_EXPORTS {
            return Err(StorageError::RateLimited);
        }
        let key = topology::node_key(self, node_id, now)?;
        let claims = GrantClaims::RouteExport(RouteExportClaims {
            scope: GrantScope {
                schema_version: SCHEMA_VERSION,
                deployment_id: snapshot.deployment_id.clone(),
                space_id: space.into(),
                grant_id: request.grant_id.clone(),
                policy_epoch: snapshot.policy_epoch,
                not_before_ms: now,
                expires_at_ms: request.expires_at_ms,
            },
            gateway: PeerId::from_public_key(&key),
            prefixes: request.prefixes,
        });
        let signed = signer.sign(&claims)?;
        let bound = verify_network_grant(&signed, &snapshot.verification())?;
        tx.execute("INSERT INTO network_route_exports(space_id,grant_id,node_id,public_key,policy_epoch,digest,claims,signature,issued_at_ms,expires_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![space,request.grant_id,node_id,key.as_slice(),snapshot.policy_epoch,bound.digest().as_slice(),signed.claims,signed.signature,now,request.expires_at_ms])?;
        tx.execute(
            "UPDATE network_authorities SET revision=?1 WHERE space_id=?2",
            params![next(snapshot.revision)?, space],
        )?;
        observe(&tx, space, now)?;
        audit(
            &tx,
            "network_route_export_issued",
            &request.grant_id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(signed)
    }

    /// Recover only the original committed bytes; readback never signs or
    /// renews an ID, including after an ambiguous issuance response.
    pub fn network_route_export(
        &mut self,
        actor: &Principal,
        space: &str,
        grant_id: &str,
        now: u64,
    ) -> Result<SignedNetworkGrant, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        topology::access(self, actor, space, false, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        let row = stored(&tx, space, grant_id)?;
        verified(self, &snapshot, &row.node_id, &row)?;
        observe(&tx, space, now)?;
        tx.commit()?;
        Ok(row.signed)
    }

    pub fn revoke_network_route_export(
        &mut self,
        actor: &Principal,
        space: &str,
        grant_id: &str,
        expected_revision: u64,
        now: u64,
    ) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        topology::access(self, actor, space, true, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        if snapshot.revision != expected_revision {
            return Err(StorageError::Conflict);
        }
        stored(&tx, space, grant_id)?;
        let changed = tx.execute("UPDATE network_route_exports SET revoked=1 WHERE space_id=?1 AND grant_id=?2 AND revoked=0",params![space,grant_id])?;
        if changed == 1 {
            let mut statement = tx.prepare("SELECT p.node_id,p.publisher_id FROM network_topology_publishers p JOIN network_topology_publisher_exports e ON e.space_id=p.space_id AND e.publisher_id=p.publisher_id WHERE e.space_id=?1 AND e.grant_id=?2 AND p.revoked=0 LIMIT ?3")?;
            let affected = statement
                .query_map(
                    params![
                        space,
                        grant_id,
                        nestlink_protocol::network_topology::MAX_ADVERTISEMENTS + 1
                    ],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            if affected.len() > nestlink_protocol::network_topology::MAX_ADVERTISEMENTS {
                return Err(StorageError::RateLimited);
            }
            for (node, publisher) in affected {
                tx.execute("UPDATE network_topology_publishers SET revoked=1 WHERE space_id=?1 AND publisher_id=?2",params![space,publisher])?;
                topology::withdraw(&tx, space, &node, now)?;
            }
            tx.execute(
                "UPDATE network_authorities SET revision=?1 WHERE space_id=?2",
                params![next(snapshot.revision)?, space],
            )?;
            audit(
                &tx,
                "network_route_export_revoked",
                grant_id,
                auditing::management(actor),
            )?;
        }
        observe(&tx, space, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        tx.commit()?;
        Ok(snapshot)
    }
}
