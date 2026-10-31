//! Durable manager-approved mapping authority. This creates no OS resource or
//! NetworkAccess and never renews an original mapping on readback/restart.
use super::*;
use ipnet::IpNet;
use nestlink_identity::subnet::{SubnetGatewayState, verify_subnet_mapping};
use nestlink_protocol::{
    network::IpPrefix,
    subnet::{
        MAX_SUBNET_MAPPING_MS, MAX_SUBNET_MAPPINGS, SUBNET_MAPPING_VERSION, SignedSubnetMapping,
        SubnetMappingClaims,
        management::{
            SubnetGatewayInstallationRequest, SubnetGatewayView, SubnetMappingReference,
            SubnetMappingRequest, SubnetMappingRevoke,
        },
    },
};

pub const MAX_SUBNET_MAPPING_HISTORY: usize = 65_536;
pub struct SubnetMappingBundle {
    pub mapping: SignedSubnetMapping,
    pub route_export: SignedNetworkGrant,
    pub gateway: SubnetGatewayView,
    pub policy: TrustedNetworkPolicySnapshot,
}
struct Stored {
    signed: SignedSubnetMapping,
    export_id: String,
    node_id: String,
    key: Vec<u8>,
    runtime_id: String,
    runtime_generation: u64,
    revision: u64,
    digest: Vec<u8>,
    revoked: bool,
}
fn stored(connection: &Connection, space: &str, id: &str) -> Result<Stored, StorageError> {
    require_id(id)?;
    connection.query_row("SELECT claims,signature,export_grant_id,node_id,public_key,runtime_id,runtime_generation,mapping_revision,digest,revoked FROM network_subnet_mappings WHERE space_id=?1 AND grant_id=?2",
        params![space,id], |row| Ok(Stored { signed: SignedSubnetMapping { claims: row.get(0)?, signature: row.get(1)? },
            export_id: row.get(2)?, node_id: row.get(3)?, key: row.get(4)?, runtime_id: row.get(5)?,
            runtime_generation: row.get(6)?, revision: row.get(7)?, digest: row.get(8)?, revoked: row.get(9)? }))
        .optional()?.ok_or(StorageError::Forbidden)
}
fn gateway(
    store: &Store,
    node: &str,
    revision: u64,
    now: u64,
) -> Result<SubnetGatewayView, StorageError> {
    let (public_key, incarnation, lease_expires_at_ms) =
        topology::current_node_authority(store, node, now)?;
    Ok(SubnetGatewayView {
        node_id: node.into(),
        public_key,
        incarnation,
        mapping_revision: revision,
        lease_expires_at_ms,
    })
}
fn state(view: &SubnetGatewayView) -> SubnetGatewayState<'_> {
    SubnetGatewayState {
        node_id: &view.node_id,
        public_key: &view.public_key,
        incarnation: &view.incarnation,
        mapping_revision: view.mapping_revision,
        lease_expires_at_ms: view.lease_expires_at_ms,
    }
}
fn prefix(value: IpPrefix) -> Result<IpNet, StorageError> {
    value.validate()?;
    IpNet::new(value.network, value.prefix_len).map_err(|_| StorageError::Forbidden)
}
fn overlaps(a: IpNet, b: IpNet) -> bool {
    a.contains(&b.addr()) || b.contains(&a.addr())
}
fn namespace(
    connection: &Connection,
    space: &str,
    claims: &SubnetMappingClaims,
    now: u64,
) -> Result<(), StorageError> {
    // A revoked/old-epoch mapping can still own kernel NAT/route resources until
    // its original finite deadline. Never let another request adopt that name.
    let mut statement = connection.prepare("SELECT claims FROM network_subnet_mappings WHERE space_id=?1 AND expires_at_ms>?2 ORDER BY grant_id LIMIT ?3")?;
    let rows = statement.query_map(params![space, now, MAX_SUBNET_MAPPINGS + 1], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    let alias = prefix(claims.alias)?;
    let original = prefix(claims.original)?;
    for (index, bytes) in rows.enumerate() {
        if index + 1 >= MAX_SUBNET_MAPPINGS {
            return Err(StorageError::RateLimited);
        }
        let other = SubnetMappingClaims::decode_canonical(&bytes?)?;
        if overlaps(alias, prefix(other.alias)?)
            || overlaps(alias, prefix(other.original)?)
            || overlaps(prefix(other.alias)?, original)
            || (claims.gateway == other.gateway && overlaps(original, prefix(other.original)?))
        {
            return Err(StorageError::Conflict);
        }
    }
    Ok(())
}
fn bundle(
    store: &Store,
    snapshot: TrustedNetworkPolicySnapshot,
    id: &str,
    row: Stored,
) -> Result<SubnetMappingBundle, StorageError> {
    if row.revoked {
        return Err(StorageError::Forbidden);
    }
    let claims = SubnetMappingClaims::decode_canonical(&row.signed.claims)?;
    if claims.scope.grant_id != id
        || claims.gateway_node_id != row.node_id
        || claims.gateway_public_key.as_slice() != row.key.as_slice()
        || claims.gateway_incarnation.runtime_id != row.runtime_id
        || claims.gateway_incarnation.runtime_generation != row.runtime_generation
        || claims.mapping_revision != row.revision
    {
        return Err(StorageError::Forbidden);
    }
    let exports = route_exports::for_ids(store, &snapshot, &row.node_id, &[row.export_id])?;
    let export = exports.into_iter().next().ok_or(StorageError::Forbidden)?;
    let gateway = gateway(store, &row.node_id, row.revision, snapshot.now_ms)?;
    let verified = verify_subnet_mapping(
        &row.signed,
        &snapshot.verification(),
        export.clone(),
        &state(&gateway),
    )?;
    if verified.digest().as_slice() != row.digest.as_slice() {
        return Err(StorageError::Forbidden);
    }
    // Recover the exact original stored envelope, not newly signed claims.
    let signed_export = store.connection.query_row(
        "SELECT claims,signature FROM network_route_exports WHERE space_id=?1 AND grant_id=?2",
        params![snapshot.space_id, export.claims().scope().grant_id],
        |row| {
            Ok(SignedNetworkGrant {
                claims: row.get(0)?,
                signature: row.get(1)?,
            })
        },
    )?;
    Ok(SubnetMappingBundle {
        mapping: row.signed,
        route_export: signed_export,
        gateway,
        policy: snapshot,
    })
}

pub(super) fn referenced(
    store: &Store,
    space: &str,
    reference: &SubnetMappingReference,
    now: u64,
) -> Result<SubnetMappingBundle, StorageError> {
    let snapshot = read_snapshot(&store.connection, space, now)?;
    let row = stored(&store.connection, space, &reference.mapping_id)?;
    if row.revision != reference.expected_mapping_revision
        || row.digest.as_slice() != reference.mapping_digest.as_slice()
    {
        return Err(StorageError::Forbidden);
    }
    bundle(store, snapshot, &reference.mapping_id, row)
}
impl Store {
    pub fn bind_subnet_gateway_installation(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        request: SubnetGatewayInstallationRequest,
        now: u64,
    ) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        topology::access(self, actor, space, false, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        if snapshot.revision != request.expected_revision {
            return Err(StorageError::Conflict);
        }
        if request.mapping.mapping_id != id {
            return Err(StorageError::Forbidden);
        }
        let mapping = referenced(self, space, &request.mapping, now)?;
        let (_, member) = remote_paths::member_credential(
            &tx,
            &snapshot,
            &request.membership_grant_id,
            &request.installation_id,
        )?;
        let owned: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM devices d JOIN device_details x ON x.device_id=d.id WHERE d.id=?1 AND d.account_id=?2 AND d.revoked=0 AND x.public_key=?3)",
            params![request.installation_id,actor.account_id,member.claims().public_key.as_slice()], |row| row.get(0))?;
        // Device registration already required the enrollment challenge PoP.
        // `referenced` independently verifies the accepted node lease PoP,
        // current boot and manager-signed mapping. Only the owning account's
        // explicit request may join these separate authorities.
        if !owned
            || member.claims().public_key != mapping.gateway.public_key
            || member.peer() != PeerId::from_public_key(&mapping.gateway.public_key)
        {
            return Err(StorageError::Forbidden);
        }
        let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM network_subnet_installations WHERE space_id=?1 AND mapping_id=?2)", params![space,id], |row| row.get(0))?;
        if exists {
            return Err(StorageError::Conflict);
        }
        tx.execute("INSERT INTO network_subnet_installations(space_id,mapping_id,installation_id,membership_grant_id,public_key,membership_digest,mapping_digest,mapping_revision,approved_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![space,id,request.installation_id,request.membership_grant_id,mapping.gateway.public_key.as_slice(),member.digest().as_slice(),request.mapping.mapping_digest.as_slice(),request.mapping.expected_mapping_revision,now])?;
        tx.execute(
            "UPDATE network_authorities SET revision=?1 WHERE space_id=?2",
            params![next(snapshot.revision)?, space],
        )?;
        observe(&tx, space, now)?;
        audit(
            &tx,
            "network_subnet_installation_approved",
            id,
            auditing::management(actor),
        )?;
        let result = read_snapshot(&tx, space, now)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn issue_subnet_mapping(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        space: &str,
        request: SubnetMappingRequest,
        now: u64,
    ) -> Result<SubnetMappingBundle, StorageError> {
        require_id(&request.grant_id)?;
        require_id(&request.gateway_node_id)?;
        require_id(&request.route_export_grant_id)?;
        if request.mapping_version != SUBNET_MAPPING_VERSION
            || request.expires_at_ms <= now
            || request.expires_at_ms > i64::MAX as u64
            || request.expires_at_ms - now > MAX_SUBNET_MAPPING_MS
        {
            return Err(StorageError::Invalid(
                "invalid subnet mapping version or lifetime",
            ));
        }
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
            "SELECT count(*) FROM network_subnet_mappings WHERE space_id=?1",
            [space],
            |row| row.get(0),
        )?;
        if history >= MAX_SUBNET_MAPPING_HISTORY {
            return Err(StorageError::RateLimited);
        }
        let gateway = gateway(self, &request.gateway_node_id, 1, now)?;
        if gateway.incarnation != request.expected_gateway_incarnation {
            return Err(StorageError::Conflict);
        }
        let exports = route_exports::for_ids(
            self,
            &snapshot,
            &request.gateway_node_id,
            std::slice::from_ref(&request.route_export_grant_id),
        )?;
        let export = exports.into_iter().next().ok_or(StorageError::Forbidden)?;
        let expires_at_ms = request
            .expires_at_ms
            .min(export.claims().scope().expires_at_ms)
            .min(gateway.lease_expires_at_ms);
        if expires_at_ms <= now {
            return Err(StorageError::Forbidden);
        }
        let claims = SubnetMappingClaims {
            mapping_version: SUBNET_MAPPING_VERSION,
            scope: GrantScope {
                schema_version: SCHEMA_VERSION,
                deployment_id: snapshot.deployment_id.clone(),
                space_id: space.into(),
                grant_id: request.grant_id.clone(),
                policy_epoch: snapshot.policy_epoch,
                not_before_ms: now,
                expires_at_ms,
            },
            gateway_node_id: gateway.node_id.clone(),
            gateway_public_key: gateway.public_key,
            gateway: PeerId::from_public_key(&gateway.public_key),
            gateway_incarnation: gateway.incarnation.clone(),
            original: request.original,
            alias: request.alias,
            route_export_digest: export.digest(),
            mapping_revision: 1,
        };
        let signed = signer.sign_subnet_mapping(&claims)?;
        let verified =
            verify_subnet_mapping(&signed, &snapshot.verification(), export, &state(&gateway))?;
        namespace(&tx, space, &claims, now)?;
        tx.execute("INSERT INTO network_subnet_mappings(space_id,grant_id,node_id,export_grant_id,public_key,runtime_id,runtime_generation,policy_epoch,mapping_revision,digest,claims,signature,issued_at_ms,expires_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,?9,?10,?11,?12,?13)",
            params![space,request.grant_id,gateway.node_id,request.route_export_grant_id,gateway.public_key.as_slice(),gateway.incarnation.runtime_id,gateway.incarnation.runtime_generation,
                snapshot.policy_epoch,verified.digest().as_slice(),signed.claims,signed.signature,now,expires_at_ms])?;
        tx.execute(
            "UPDATE network_authorities SET revision=?1 WHERE space_id=?2",
            params![next(snapshot.revision)?, space],
        )?;
        observe(&tx, space, now)?;
        audit(
            &tx,
            "network_subnet_mapping_issued",
            &request.grant_id,
            auditing::management(actor),
        )?;
        let snapshot = read_snapshot(&tx, space, now)?;
        let result = bundle(
            self,
            snapshot,
            &request.grant_id,
            stored(&tx, space, &request.grant_id)?,
        )?;
        tx.commit()?;
        Ok(result)
    }
    pub fn subnet_mapping(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        now: u64,
    ) -> Result<SubnetMappingBundle, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        topology::access(self, actor, space, false, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        let row = stored(&tx, space, id)?;
        let revision = snapshot.revision;
        let result = bundle(self, snapshot, id, row);
        if result.is_err() {
            // An observed terminal deadline/boot/export failure cannot be
            // undone by a later clock rollback or restored node availability.
            // Preserve the signed bytes and namespace, only close this ID.
            let changed = tx.execute("UPDATE network_subnet_mappings SET revoked=1,mapping_revision=mapping_revision+1 WHERE space_id=?1 AND grant_id=?2 AND revoked=0", params![space,id])?;
            if changed == 1 {
                tx.execute(
                    "UPDATE network_authorities SET revision=?1 WHERE space_id=?2",
                    params![next(revision)?, space],
                )?;
                audit(
                    &tx,
                    "network_subnet_mapping_invalidated",
                    id,
                    auditing::management(actor),
                )?;
            }
        }
        observe(&tx, space, now)?;
        tx.commit()?;
        result
    }
    pub fn revoke_subnet_mapping(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        request: SubnetMappingRevoke,
        now: u64,
    ) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        topology::access(self, actor, space, true, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        if snapshot.revision != request.expected_revision {
            return Err(StorageError::Conflict);
        }
        let row = stored(&tx, space, id)?;
        if !row.revoked {
            if row.revision != request.expected_mapping_revision {
                return Err(StorageError::Conflict);
            }
            tx.execute("UPDATE network_subnet_mappings SET revoked=1,mapping_revision=?1 WHERE space_id=?2 AND grant_id=?3 AND revoked=0", params![next(row.revision)?,space,id])?;
            tx.execute(
                "UPDATE network_authorities SET revision=?1 WHERE space_id=?2",
                params![next(snapshot.revision)?, space],
            )?;
            audit(
                &tx,
                "network_subnet_mapping_revoked",
                id,
                auditing::management(actor),
            )?;
        }
        observe(&tx, space, now)?;
        let result = read_snapshot(&tx, space, now)?;
        tx.commit()?;
        Ok(result)
    }
}

pub(super) fn collect_revocations(
    connection: &Connection,
    space: &str,
    epoch: u64,
    now: u64,
    revoked: &mut BTreeSet<String>,
) -> Result<(), StorageError> {
    let mut statement = connection.prepare("SELECT m.grant_id,m.export_grant_id,(m.revoked=1 OR n.id IS NULL OR n.revoked=1 OR n.public_key!=m.public_key
        OR n.runtime_id!=m.runtime_id OR n.runtime_generation!=m.runtime_generation OR n.last_issued_at>?3 OR ?3-n.last_issued_at>=?4
        OR n.lease_policy_revision!=d.policy_revision OR NOT EXISTS(SELECT 1 FROM json_each(n.roles_json) WHERE value=1)
        OR NOT EXISTS(SELECT 1 FROM node_runtimes r WHERE r.node_id=n.id AND r.runtime_id=m.runtime_id AND r.generation=m.runtime_generation AND r.security_epoch=d.security_epoch))
        FROM network_subnet_mappings m LEFT JOIN data_nodes n ON n.id=m.node_id JOIN deployment d ON d.singleton=1
        WHERE m.space_id=?1 AND m.policy_epoch=?2 AND m.expires_at_ms>?3 ORDER BY m.grant_id LIMIT ?5")?;
    for (index, row) in statement
        .query_map(
            params![
                space,
                epoch,
                now,
                nestlink_protocol::NODE_LEASE_MS,
                MAX_SUBNET_MAPPING_HISTORY + 1
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )?
        .enumerate()
    {
        if index >= MAX_SUBNET_MAPPING_HISTORY {
            return Err(StorageError::RateLimited);
        }
        let (id, export, invalid) = row?;
        if invalid || revoked.contains(&export) {
            revoked.insert(id);
        }
    }
    Ok(())
}
