//! Durable, space-scoped topology publications. Reports are observations, not
//! forwarding or business grants. SQLite owns sequence and withdrawal history.
use super::*;
use nestlink_identity::network_topology::{
    SignedTopologyAdvertisement, SignedTopologyPublisher, SignedTopologyReport,
    SignedTopologyUpdate, verify_topology_publisher, verify_topology_report,
};
pub use nestlink_protocol::api::{
    NetworkTopologyPublisherRequest as TopologyPublisherRequest,
    NetworkTopologyQuery as TopologyQuery,
};
use nestlink_protocol::{
    NODE_LEASE_MS, NodeRole,
    network_topology::{
        BootIncarnation, MAX_ADVERTISEMENTS, MAX_DELTA, MAX_NEIGHBORS, TopologyAdvertisement,
        TopologyChange, TopologyDeltaEntry, TopologyPublisherClaims, TopologyReport, TopologySync,
        TopologyUpdate, TopologyWithdrawal,
    },
};

const MAX_PUBLISHER_HISTORY: u64 = 65_536;
const MAX_PUBLISHER_MS: u64 = 15 * 60 * 1000;
const MIN_REPORT_INTERVAL_MS: u64 = 100;
const RETAINED_CHANGES: u64 = 4096;

struct Node {
    key: [u8; 32],
    incarnation: BootIncarnation,
    endpoint_revision: u64,
    lease_end: u64,
}

/// Read registered identity, an accepted control incarnation, and the current
/// endpoint revision in the caller's transaction. A global relay role alone
/// still does not authorize publication into any space.
fn node(store: &Store, id: &str, now: u64) -> Result<Node, StorageError> {
    require_id(id)?;
    type Row = (Vec<u8>, String, u64, u64, u64, String, u64);
    let row: Option<Row> = store.connection.query_row(
        "SELECT n.public_key,n.runtime_id,n.runtime_generation,n.last_issued_at,n.lease_policy_revision,n.roles_json,e.revision
         FROM data_nodes n JOIN node_endpoints e ON e.node_id=n.id
         JOIN node_runtimes r ON r.node_id=n.id AND r.runtime_id=n.runtime_id AND r.generation=n.runtime_generation
         JOIN deployment d ON d.singleton=1 AND r.security_epoch=d.security_epoch
         WHERE n.id=?1 AND n.revoked=0",
        [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)),
    ).optional()?;
    let (key, runtime_id, runtime_generation, last, policy, roles, endpoint_revision) =
        row.ok_or(StorageError::Forbidden)?;
    let lease_end = last
        .checked_add(NODE_LEASE_MS)
        .ok_or(StorageError::Conflict)?;
    if last > now
        || now >= lease_end
        || policy != store.policy()?.0
        || !serde_json::from_str::<Vec<i32>>(&roles)?.contains(&(NodeRole::NodeRelay as i32))
    {
        return Err(StorageError::Forbidden);
    }
    Ok(Node {
        key: key.try_into().map_err(|_| StorageError::Forbidden)?,
        incarnation: BootIncarnation {
            runtime_generation,
            runtime_id,
        },
        endpoint_revision,
        lease_end,
    })
}

fn access(
    store: &Store,
    actor: &Principal,
    space: &str,
    manage: bool,
    now: u64,
) -> Result<(), StorageError> {
    store.validate_access(actor, checked_seconds(now)?)?;
    let product: bool = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM network_spaces WHERE space_id=?1)",
        [space],
        |r| r.get(0),
    )?;
    if product {
        let permitted: bool = store.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_space_members WHERE space_id=?1 AND account_id=?2 AND revoked=0 AND (?3=0 OR role IN ('owner','admin')))",
            params![space,actor.account_id,manage], |r|r.get(0),
        )?;
        if !permitted {
            return Err(StorageError::Forbidden);
        }
    } else {
        store.audit_admin(actor, now / 1000)?;
    }
    Ok(())
}

fn publisher(
    connection: &Connection,
    space: &str,
    id: &str,
) -> Result<SignedTopologyPublisher, StorageError> {
    connection.query_row(
        "SELECT claims,signature FROM network_topology_publishers WHERE space_id=?1 AND publisher_id=?2 AND revoked=0",
        params![space,id], |r|Ok(SignedTopologyPublisher {claims:r.get(0)?,signature:r.get(1)?}),
    ).optional()?.ok_or(StorageError::Forbidden)
}

fn check_neighbors(
    store: &Store,
    snapshot: &TrustedNetworkPolicySnapshot,
    report: &TopologyReport,
    now: u64,
) -> Result<(), StorageError> {
    let current = node(store, &report.node_id, now)?;
    let mut statement = store.connection.prepare("SELECT p.node_id,n.public_key,p.claims,p.signature FROM network_topology_publishers p JOIN data_nodes n ON n.id=p.node_id WHERE p.space_id=?1 AND p.revoked=0 AND p.policy_epoch=?2 AND p.expires_at_ms>?3 ORDER BY p.node_id LIMIT ?4")?;
    let rows = statement.query_map(
        params![
            report.space_id,
            report.policy_epoch,
            now,
            MAX_ADVERTISEMENTS + 1
        ],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        },
    )?;
    let mut publishers = BTreeMap::new();
    for (count, row) in rows.enumerate() {
        if count >= MAX_ADVERTISEMENTS {
            return Err(StorageError::RateLimited);
        }
        let (id, key, claims, signature) = row?;
        publishers.insert(
            PeerId(digest(&key)),
            (id, SignedTopologyPublisher { claims, signature }),
        );
    }
    for neighbor in &report.neighbors {
        if neighbor.local != PeerId::from_public_key(&current.key)
            || neighbor.local_endpoint_revision != current.endpoint_revision
        {
            return Err(StorageError::Forbidden);
        }
        if !neighbor.up {
            continue;
        }
        let (id, signed) = publishers
            .get(&neighbor.remote)
            .ok_or(StorageError::Forbidden)?;
        let remote = node(store, id, now)?;
        verify_topology_publisher(
            signed,
            &snapshot.verification(),
            id,
            &remote.key,
            &remote.incarnation,
            &[],
        )?;
        if neighbor.remote_endpoint_revision != remote.endpoint_revision {
            return Err(StorageError::Forbidden);
        }
    }
    Ok(())
}

/// Revalidate the exact durable head and publisher in the caller's reservation
/// transaction. A supplied digest cannot resurrect a withdrawn or replaced head.
pub(super) fn current_advertisement(
    store: &Store,
    snapshot: &TrustedNetworkPolicySnapshot,
    node_id: &str,
    expected: &[u8; 32],
    now: u64,
) -> Result<nestlink_identity::network_topology::VerifiedTopologyAdvertisement, StorageError> {
    let current = node(store, node_id, now)?;
    let row: Option<(String, Vec<u8>, Vec<u8>)> = store.connection.query_row(
        "SELECT publisher_id,advertisement,advertisement_signature FROM network_topology_heads WHERE space_id=?1 AND node_id=?2 AND withdrawn=0 AND expires_at_ms>?3",
        params![snapshot.space_id,node_id,now], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).optional()?;
    let (publisher_id, claims, signature) = row.ok_or(StorageError::Forbidden)?;
    let publisher = verify_topology_publisher(
        &publisher(&store.connection, &snapshot.space_id, &publisher_id)?,
        &snapshot.verification(), node_id, &current.key, &current.incarnation, &[],
    )?;
    let verified = nestlink_identity::network_topology::verify_topology_advertisement(
        &SignedTopologyAdvertisement { claims, signature }, &publisher,
        &snapshot.verification(), &current.incarnation, 0,
    )?;
    if verified.digest() != *expected {
        return Err(StorageError::Conflict);
    }
    check_neighbors(store, snapshot, &verified.claims().report, now)?;
    Ok(verified)
}

impl Store {
    /// Space managers grant only an explicit registered node and neighbor set.
    /// Prefix export is deliberately closed until its stored RouteExport chain
    /// is supplied; a report can never create that right by naming a prefix.
    pub fn issue_topology_publisher(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        space: &str,
        node_id: &str,
        request: TopologyPublisherRequest,
        now: u64,
    ) -> Result<SignedTopologyPublisher, StorageError> {
        require_id(&request.publisher_id)?;
        if request.allowed_node_ids.len() > MAX_NEIGHBORS
            || request.allowed_node_ids.iter().any(|id| id == node_id)
            || request
                .allowed_node_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != request.allowed_node_ids.len()
            || request.expires_at_ms <= now
            || request.expires_at_ms
                > now
                    .checked_add(MAX_PUBLISHER_MS)
                    .ok_or(StorageError::Conflict)?
        {
            return Err(StorageError::Invalid("invalid topology publisher request"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        access(self, actor, space, true, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        if request.expected_policy_epoch != snapshot.policy_epoch
            || signer.public_key() != snapshot.authority_key
        {
            return Err(StorageError::Conflict);
        }
        if tx.query_row(
            "SELECT count(*) FROM network_topology_publishers WHERE space_id=?1",
            [space],
            |r| r.get::<_, u64>(0),
        )? >= MAX_PUBLISHER_HISTORY
        {
            return Err(StorageError::RateLimited);
        }
        let current = node(self, node_id, now)?;
        let mut allowed_neighbors = Vec::new();
        for id in &request.allowed_node_ids {
            allowed_neighbors.push(PeerId::from_public_key(&node(self, id, now)?.key));
        }
        allowed_neighbors.sort();
        let claims = TopologyPublisherClaims {
            scope: GrantScope {
                schema_version: 1,
                deployment_id: snapshot.deployment_id.clone(),
                space_id: space.into(),
                grant_id: request.publisher_id.clone(),
                policy_epoch: snapshot.policy_epoch,
                not_before_ms: now,
                expires_at_ms: request.expires_at_ms,
            },
            node_id: node_id.into(),
            public_key: current.key,
            peer: PeerId::from_public_key(&current.key),
            incarnation: current.incarnation,
            allowed_neighbors,
            route_export_digests: Vec::new(),
            allowed_prefixes: Vec::new(),
        };
        let signed = signer.sign_topology_publisher(&claims)?;
        tx.execute("UPDATE network_topology_publishers SET revoked=1 WHERE space_id=?1 AND node_id=?2 AND revoked=0",params![space,node_id])?;
        withdraw(&tx, space, node_id, now)?;
        tx.execute("INSERT INTO network_topology_publishers(space_id,publisher_id,node_id,runtime_id,runtime_generation,policy_epoch,claims,signature,expires_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![space,request.publisher_id,node_id,claims.incarnation.runtime_id,claims.incarnation.runtime_generation,claims.scope.policy_epoch,signed.claims,signed.signature,claims.scope.expires_at_ms])?;
        observe(&tx, space, now)?;
        audit(
            &tx,
            "network_topology_publisher_issued",
            node_id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(signed)
    }

    pub fn topology_publisher(
        &mut self,
        actor: &Principal,
        space: &str,
        node_id: &str,
        now: u64,
    ) -> Result<SignedTopologyPublisher, StorageError> {
        access(self, actor, space, false, now)?;
        let snapshot = read_snapshot(&self.connection, space, now)?;
        let current = node(self, node_id, now)?;
        let id: String = self.connection.query_row("SELECT publisher_id FROM network_topology_publishers WHERE space_id=?1 AND node_id=?2 AND revoked=0 AND policy_epoch=?3 AND expires_at_ms>?4",params![space,node_id,snapshot.policy_epoch,now],|r|r.get(0)).optional()?.ok_or(StorageError::Forbidden)?;
        let signed = publisher(&self.connection, space, &id)?;
        let claims = TopologyPublisherClaims::decode_canonical(&signed.claims)?;
        if claims.incarnation != current.incarnation {
            return Err(StorageError::Forbidden);
        }
        Ok(signed)
    }

    pub fn revoke_topology_publisher(
        &mut self,
        actor: &Principal,
        space: &str,
        node_id: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        access(self, actor, space, true, now)?;
        read_snapshot(&tx, space, now)?;
        if tx.execute("UPDATE network_topology_publishers SET revoked=1 WHERE space_id=?1 AND node_id=?2 AND revoked=0",params![space,node_id])? != 1 { return Err(StorageError::Conflict); }
        withdraw(&tx, space, node_id, now)?;
        observe(&tx, space, now)?;
        audit(
            &tx,
            "network_topology_publisher_revoked",
            node_id,
            auditing::management(actor),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Authentication is the registered node's signature plus the current,
    /// explicit space publisher. No management bearer token is accepted here.
    pub fn accept_topology_report(
        &mut self,
        signer: &NetworkAuthoritySigner,
        space: &str,
        node_id: &str,
        signed: &SignedTopologyReport,
        now: u64,
    ) -> Result<SignedTopologyAdvertisement, StorageError> {
        let report = TopologyReport::decode_canonical(&signed.claims)?;
        if report.node_id != node_id || report.space_id != space || !report.prefixes.is_empty() {
            return Err(StorageError::Forbidden);
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        if signer.public_key() != snapshot.authority_key {
            return Err(StorageError::Forbidden);
        }
        let current = node(self, node_id, now)?;
        let id: String = tx.query_row("SELECT publisher_id FROM network_topology_publishers WHERE space_id=?1 AND node_id=?2 AND revoked=0",params![space,node_id],|r|r.get(0)).optional()?.ok_or(StorageError::Forbidden)?;
        let publisher_signed = publisher(&tx, space, &id)?;
        let context = snapshot.verification();
        let verified_publisher = verify_topology_publisher(
            &publisher_signed,
            &context,
            node_id,
            &current.key,
            &current.incarnation,
            &[],
        )?;
        // Authenticate the report before reading other publishers or verifying
        // their signatures. An unauthenticated request cannot trigger a graph
        // scan. The durable head below adds the sequence fence to this proof.
        let verified = verify_topology_report(
            signed,
            &verified_publisher,
            &context,
            &current.incarnation,
            0,
        )?;
        check_neighbors(self, &snapshot, &report, now)?;
        type Head = (
            String,
            u64,
            u64,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            u64,
            bool,
            u64,
        );
        let old: Option<Head> = tx.query_row("SELECT runtime_id,runtime_generation,sequence,report_claims,report_signature,advertisement,advertisement_signature,accepted_at_ms,withdrawn,expires_at_ms FROM network_topology_heads WHERE space_id=?1 AND node_id=?2",params![space,node_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?))).optional()?;
        if let Some((
            runtime,
            generation,
            sequence,
            claims,
            signature,
            advertisement,
            ad_signature,
            accepted,
            withdrawn,
            expires,
        )) = old
        {
            if runtime == current.incarnation.runtime_id
                && generation == current.incarnation.runtime_generation
            {
                if report.sequence == sequence
                    && signed.claims == claims
                    && signed.signature == signature
                    && !withdrawn
                    && now < expires
                {
                    // Re-authenticate at the current time before returning the
                    // original envelope. An exact retry never renews its TTL.
                    let result = SignedTopologyAdvertisement {
                        claims: advertisement,
                        signature: ad_signature,
                    };
                    tx.commit()?;
                    return Ok(result);
                }
                if report.sequence <= sequence {
                    return Err(StorageError::Proof(nestlink_protocol::ContractError::new(
                        nestlink_protocol::ErrorCode::ReplayRejected,
                        "topology report sequence did not advance",
                    )));
                }
            }
            if now < accepted || now - accepted < MIN_REPORT_INTERVAL_MS {
                return Err(StorageError::RateLimited);
            }
        }
        let advertisement =
            signer.sign_topology_advertisement(&verified, now, current.lease_end)?;
        let ad = nestlink_protocol::network_topology::TopologyAdvertisement::decode_canonical(
            &advertisement.claims,
        )?;
        tx.execute("INSERT INTO network_topology_heads(space_id,node_id,runtime_id,runtime_generation,sequence,publisher_id,report_digest,report_claims,report_signature,advertisement,advertisement_signature,expires_at_ms,accepted_at_ms,withdrawn) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,0)
            ON CONFLICT(space_id,node_id) DO UPDATE SET runtime_id=excluded.runtime_id,runtime_generation=excluded.runtime_generation,sequence=excluded.sequence,publisher_id=excluded.publisher_id,report_digest=excluded.report_digest,report_claims=excluded.report_claims,report_signature=excluded.report_signature,advertisement=excluded.advertisement,advertisement_signature=excluded.advertisement_signature,expires_at_ms=excluded.expires_at_ms,accepted_at_ms=excluded.accepted_at_ms,withdrawn=0",
            params![space,node_id,report.incarnation.runtime_id,report.incarnation.runtime_generation,report.sequence,id,verified.digest().as_slice(),signed.claims,signed.signature,advertisement.claims,advertisement.signature,ad.expires_at_ms,now])?;
        record_upsert(&tx, space, &advertisement, now)?;
        observe(&tx, space, now)?;
        tx.commit()?;
        Ok(advertisement)
    }

    /// A full response replaces the consumer's graph atomically; a delta
    /// applies only to its exact cursor. Missing entries in a delta are never
    /// withdrawals. Old cursors fail closed and require a fresh full query.
    pub fn topology_update(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        space: &str,
        query: TopologyQuery,
        now: u64,
    ) -> Result<SignedTopologyUpdate, StorageError> {
        if query.nonce == [0; 32] || query.after_cursor.is_some_and(|c| c > i64::MAX as u64) {
            return Err(StorageError::Invalid("invalid topology query"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        access(self, actor, space, false, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        if signer.public_key() != snapshot.authority_key {
            return Err(StorageError::Forbidden);
        }
        ensure_cursor(&tx, space, now)?;
        let mut statement = tx.prepare("SELECT node_id,advertisement,advertisement_signature,publisher_id,expires_at_ms FROM network_topology_heads WHERE space_id=?1 AND withdrawn=0 ORDER BY node_id LIMIT ?2")?;
        type Row = (String, Vec<u8>, Vec<u8>, String, u64);
        let rows = statement
            .query_map(params![space, MAX_ADVERTISEMENTS + 1], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<Vec<Row>, _>>()?;
        drop(statement);
        if rows.len() > MAX_ADVERTISEMENTS {
            return Err(StorageError::RateLimited);
        }
        let mut advertisements = Vec::new();
        for (node_id, claims, signature, publisher_id, expires) in rows {
            let ad = TopologyAdvertisement::decode_canonical(&claims)?;
            let live = (|| -> Result<(), StorageError> {
                if now >= expires {
                    return Err(StorageError::Forbidden);
                }
                let current = node(self, &node_id, now)?;
                let signed_publisher = publisher(&tx, space, &publisher_id)?;
                let verified = verify_topology_publisher(
                    &signed_publisher,
                    &snapshot.verification(),
                    &node_id,
                    &current.key,
                    &current.incarnation,
                    &[],
                )?;
                if verified.digest() != ad.report.publisher_digest
                    || current.incarnation != ad.report.incarnation
                    || ad.report.policy_epoch != snapshot.policy_epoch
                {
                    return Err(StorageError::Forbidden);
                }
                check_neighbors(self, &snapshot, &ad.report, now)?;
                Ok(())
            })();
            match live {
                Ok(()) => advertisements.push(SignedTopologyAdvertisement { claims, signature }),
                Err(StorageError::Forbidden | StorageError::Unauthorized) => {
                    withdraw(&tx, space, &node_id, now)?;
                }
                Err(StorageError::Proof(_)) => {
                    withdraw(&tx, space, &node_id, now)?;
                }
                Err(error) => return Err(error),
            }
        }
        let (cursor, retained): (u64, u64) = tx.query_row(
            "SELECT cursor,retained_after FROM network_topology_cursors WHERE space_id=?1",
            [space],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let sync = if let Some(after_cursor) = query.after_cursor {
            if after_cursor < retained || after_cursor > cursor {
                return Err(StorageError::Conflict);
            }
            let mut statement = tx.prepare("SELECT cursor,change_json FROM network_topology_changes WHERE space_id=?1 AND cursor>?2 ORDER BY cursor LIMIT ?3")?;
            let rows = statement
                .query_map(params![space, after_cursor, MAX_DELTA + 1], |r| {
                    Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let has_more = rows.len() > MAX_DELTA;
            let changes = rows
                .into_iter()
                .take(MAX_DELTA)
                .map(|(cursor, json)| {
                    Ok(TopologyDeltaEntry {
                        cursor,
                        change: serde_json::from_str(&json)?,
                    })
                })
                .collect::<Result<Vec<_>, StorageError>>()?;
            let cursor = changes.last().map_or(after_cursor, |change| change.cursor);
            TopologySync::Delta {
                after_cursor,
                cursor,
                has_more,
                changes,
            }
        } else {
            TopologySync::Full {
                cursor,
                advertisements,
            }
        };
        let update = signer.sign_topology_update(&TopologyUpdate {
            schema_version: 1,
            deployment_id: snapshot.deployment_id.clone(),
            space_id: space.into(),
            policy_epoch: snapshot.policy_epoch,
            query_nonce: query.nonce,
            issued_at_ms: now,
            expires_at_ms: now
                .checked_add(nestlink_protocol::NODE_RESOURCE_TTL_MS)
                .ok_or(StorageError::Conflict)?,
            sync,
        })?;
        observe(&tx, space, now)?;
        tx.execute(
            "UPDATE network_topology_cursors SET last_observed_ms=?1 WHERE space_id=?2",
            params![now, space],
        )?;
        tx.commit()?;
        Ok(update)
    }
}

fn ensure_cursor(tx: &Transaction<'_>, space: &str, now: u64) -> Result<(), StorageError> {
    let epoch: u64 = tx.query_row(
        "SELECT policy_epoch FROM network_authorities WHERE space_id=?1",
        [space],
        |r| r.get(0),
    )?;
    tx.execute("INSERT INTO network_topology_cursors(space_id,policy_epoch,last_observed_ms) VALUES(?1,?2,?3) ON CONFLICT(space_id) DO NOTHING",params![space,epoch,now])?;
    let (previous, last): (u64, u64) = tx.query_row(
        "SELECT policy_epoch,last_observed_ms FROM network_topology_cursors WHERE space_id=?1",
        [space],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if now < last {
        return Err(StorageError::Conflict);
    }
    if previous != epoch {
        // A delta cannot transplant old-epoch grants into a new policy. Keep
        // the global cursor and node sequence fences while requiring a full
        // snapshot from consumers behind this epoch boundary.
        tx.execute(
            "DELETE FROM network_topology_changes WHERE space_id=?1",
            [space],
        )?;
        tx.execute("UPDATE network_topology_cursors SET policy_epoch=?1,retained_after=cursor,last_observed_ms=?2 WHERE space_id=?3",params![epoch,now,space])?;
    }
    Ok(())
}

fn record(
    tx: &Transaction<'_>,
    space: &str,
    change: TopologyChange,
    now: u64,
) -> Result<(), StorageError> {
    ensure_cursor(tx, space, now)?;
    tx.execute(
        "UPDATE network_topology_cursors SET cursor=cursor+1,last_observed_ms=?1 WHERE space_id=?2",
        params![now, space],
    )?;
    let cursor: u64 = tx.query_row(
        "SELECT cursor FROM network_topology_cursors WHERE space_id=?1",
        [space],
        |r| r.get(0),
    )?;
    tx.execute(
        "INSERT INTO network_topology_changes(space_id,cursor,change_json) VALUES(?1,?2,?3)",
        params![space, cursor, serde_json::to_string(&change)?],
    )?;
    let retained = cursor.saturating_sub(RETAINED_CHANGES);
    tx.execute(
        "DELETE FROM network_topology_changes WHERE space_id=?1 AND cursor<=?2",
        params![space, retained],
    )?;
    tx.execute("UPDATE network_topology_cursors SET retained_after=max(retained_after,?1) WHERE space_id=?2",params![retained,space])?;
    Ok(())
}

fn record_upsert(
    tx: &Transaction<'_>,
    space: &str,
    ad: &SignedTopologyAdvertisement,
    now: u64,
) -> Result<(), StorageError> {
    record(tx, space, TopologyChange::Upsert(ad.clone()), now)
}

fn withdraw(
    tx: &Transaction<'_>,
    space: &str,
    node_id: &str,
    now: u64,
) -> Result<(), StorageError> {
    let report: Option<Vec<u8>> = tx.query_row("SELECT report_claims FROM network_topology_heads WHERE space_id=?1 AND node_id=?2 AND withdrawn=0",params![space,node_id],|r|r.get(0)).optional()?;
    let Some(report) = report else {
        return Ok(());
    };
    let report = TopologyReport::decode_canonical(&report)?;
    record(
        tx,
        space,
        TopologyChange::Withdraw(TopologyWithdrawal {
            node_id: report.node_id,
            peer: report.peer,
            publisher_digest: report.publisher_digest,
            incarnation: report.incarnation,
            sequence: report.sequence,
        }),
        now,
    )?;
    tx.execute(
        "UPDATE network_topology_heads SET withdrawn=1 WHERE space_id=?1 AND node_id=?2",
        params![space, node_id],
    )?;
    Ok(())
}
