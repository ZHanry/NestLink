//! Durable client-key delegation of original NetworkAccess. The original
//! destination-account approval, memberships, mapping, one-use owner, finite
//! lifetime and packet budget remain mandatory; no portal-wide authority.
use super::*;
use nestlink_identity::wireguard::{WireGuardPortalState, verify_wireguard_client_binding};
use nestlink_protocol::{
    network::IpPrefix,
    subnet::SubnetMappingClaims,
    wireguard::{management::*, *},
};
use std::net::IpAddr;

const MAX_HISTORY: usize = 65_536;
pub struct WireGuardClientBindingBundle {
    pub binding: SignedWireGuardClientBinding,
    pub packet_access: network_access::NetworkAccessBundle,
    pub policy: TrustedNetworkPolicySnapshot,
    pub total_byte_ceiling: u64,
    pub committed_bytes: u64,
}
struct Stored {
    binding: SignedWireGuardClientBinding,
    client: String,
    revision: u64,
    account: String,
    installation: String,
    node: String,
    access: String,
    ceiling: u64,
    committed: u64,
    digest: Vec<u8>,
    revoked: bool,
}
fn stored(connection: &Connection, space: &str, id: &str) -> Result<Stored, StorageError> {
    require_id(id)?;
    connection.query_row("SELECT b.claims,b.signature,b.client_id,b.client_revision,c.account_id,c.installation_id,c.portal_node_id,c.total_byte_ceiling,c.committed_bytes,b.digest,(b.revoked=1 OR c.revoked=1 OR b.client_revision!=c.revision),b.access_grant_id FROM network_wireguard_bindings b JOIN network_wireguard_clients c ON c.space_id=b.space_id AND c.client_id=b.client_id WHERE b.space_id=?1 AND b.grant_id=?2",params![space,id],|r|Ok(Stored{
        binding:SignedWireGuardClientBinding{claims:r.get(0)?,signature:r.get(1)?},client:r.get(2)?,revision:r.get(3)?,account:r.get(4)?,installation:r.get(5)?,node:r.get(6)?,ceiling:r.get(7)?,committed:r.get(8)?,digest:r.get(9)?,revoked:r.get(10)?,access:r.get(11)?
    })).optional()?.ok_or(StorageError::Forbidden)
}
fn original(
    store: &Store,
    tx: &Transaction<'_>,
    actor: &Principal,
    snapshot: &TrustedNetworkPolicySnapshot,
    claims: &WireGuardClientBindingClaims,
    now: u64,
) -> Result<network_access::NetworkAccessBundle, StorageError> {
    let bundle =
        store.current_packet_access(tx, actor, &snapshot.space_id, &claims.access_grant_id, now)?;
    let source = bundle
        .address_directory
        .addresses
        .first()
        .ok_or(StorageError::Forbidden)?;
    if source.account_id != claims.account_id
        || source.installation_id != claims.installation_id
        || source.account_id != actor.account_id
    {
        return Err(StorageError::Forbidden);
    }
    let membership = snapshot.verify_member(&bundle.memberships[0], &claims.installation_id)?;
    if membership.claims().public_key != claims.portal_public_key {
        return Err(StorageError::Forbidden);
    }
    // The external client cannot borrow the portal installation's host address.
    // Its /32 must already have the exact separately approved source mapping.
    let prefix = IpPrefix {
        network: IpAddr::V4(claims.client_address),
        prefix_len: 32,
    };
    let mut source_mapping = false;
    for mapping in &bundle.subnet_mappings {
        let mapping = SubnetMappingClaims::decode_canonical(&mapping.mapping.claims)?;
        if mapping.gateway_node_id == claims.portal_node_id
            && mapping.gateway_public_key == claims.portal_public_key
            && mapping.gateway_incarnation == claims.portal_incarnation
            && mapping.alias == prefix
            && mapping.original == prefix
        {
            source_mapping = true;
        }
    }
    if !source_mapping {
        return Err(StorageError::Forbidden);
    }
    Ok(bundle)
}
fn bundle(
    store: &Store,
    tx: &Transaction<'_>,
    actor: &Principal,
    snapshot: TrustedNetworkPolicySnapshot,
    row: Stored,
    now: u64,
) -> Result<WireGuardClientBindingBundle, StorageError> {
    if row.revoked || actor.account_id != row.account {
        return Err(StorageError::Forbidden);
    }
    let claims = WireGuardClientBindingClaims::decode_canonical(&row.binding.claims)?;
    if claims.client_id != row.client
        || claims.client_revision != row.revision
        || claims.account_id != row.account
        || claims.installation_id != row.installation
        || claims.portal_node_id != row.node
        || claims.access_grant_id != row.access
    {
        return Err(StorageError::Forbidden);
    }
    let packet = original(store, tx, actor, &snapshot, &claims, now)?;
    let (key, incarnation, lease_end) =
        topology::current_node_authority(store, &claims.portal_node_id, now)?;
    let verified = verify_wireguard_client_binding(
        &row.binding,
        &snapshot.verification(),
        verify_network_grant(&packet.access, &snapshot.verification())?,
        &WireGuardPortalState {
            node_id: &claims.portal_node_id,
            public_key: &key,
            incarnation: &incarnation,
            lease_expires_at_ms: lease_end,
            client_revision: row.revision,
        },
    )?;
    if verified.digest().as_slice() != row.digest {
        return Err(StorageError::Forbidden);
    }
    Ok(WireGuardClientBindingBundle {
        binding: row.binding,
        packet_access: packet,
        policy: snapshot,
        total_byte_ceiling: row.ceiling,
        committed_bytes: row.committed,
    })
}
impl Store {
    pub fn issue_wireguard_client_binding(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        space: &str,
        request: WireGuardClientBindingRequest,
        now: u64,
    ) -> Result<WireGuardClientBindingBundle, StorageError> {
        for id in [
            &request.grant_id,
            &request.client_id,
            &request.installation_id,
            &request.portal_node_id,
            &request.access_grant_id,
        ] {
            require_id(id)?;
        }
        if request.binding_version != WIREGUARD_BINDING_VERSION
            || request.total_byte_ceiling == 0
            || request.total_byte_ceiling > i64::MAX as u64
            || request.expires_at_ms <= now
        {
            return Err(StorageError::Invalid(
                "invalid WireGuard client version, ceiling or lifetime",
            ));
        }
        // First use the public observation owner: a known terminal original
        // graph must be durably closed, even if this wrapper cannot be issued.
        self.network_access(actor, space, &request.access_grant_id, now)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        topology::access(self, actor, space, false, now)?;
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
        let packet =
            self.current_packet_access(&tx, actor, space, &request.access_grant_id, now)?;
        let access = verify_network_grant(&packet.access, &snapshot.verification())?;
        let GrantClaims::NetworkAccess(access_claims) = access.claims() else {
            return Err(StorageError::Forbidden);
        };
        let (key, incarnation, lease_end) =
            topology::current_node_authority(self, &request.portal_node_id, now)?;
        if incarnation != request.expected_portal_incarnation {
            return Err(StorageError::Conflict);
        }
        let revision = next(request.expected_client_revision)?;
        let claims = WireGuardClientBindingClaims {
            binding_version: WIREGUARD_BINDING_VERSION,
            scope: GrantScope {
                schema_version: SCHEMA_VERSION,
                deployment_id: snapshot.deployment_id.clone(),
                space_id: space.into(),
                grant_id: request.grant_id.clone(),
                policy_epoch: snapshot.policy_epoch,
                not_before_ms: now,
                expires_at_ms: request.expires_at_ms.min(access_claims.scope.expires_at_ms),
            },
            client_id: request.client_id.clone(),
            client_revision: revision,
            account_id: actor.account_id.clone(),
            installation_id: request.installation_id.clone(),
            client_public_key: request.client_public_key,
            client_address: request.client_address,
            portal_node_id: request.portal_node_id.clone(),
            portal_public_key: key,
            portal_incarnation: incarnation.clone(),
            access_grant_id: request.access_grant_id.clone(),
            access_digest: access.digest(),
            committed_bytes: access_claims.byte_limit,
        };
        let signed = signer.sign_wireguard_client_binding(&claims)?;
        original(self, &tx, actor, &snapshot, &claims, now)?;
        let verified = verify_wireguard_client_binding(
            &signed,
            &snapshot.verification(),
            access,
            &WireGuardPortalState {
                node_id: &request.portal_node_id,
                public_key: &key,
                incarnation: &incarnation,
                lease_expires_at_ms: lease_end,
                client_revision: revision,
            },
        )?;
        let history: usize = tx.query_row(
            "SELECT count(*) FROM network_wireguard_bindings WHERE space_id=?1",
            [space],
            |r| r.get(0),
        )?;
        let active:usize=tx.query_row("SELECT count(*) FROM network_wireguard_bindings WHERE space_id=?1 AND expires_at_ms>?2",params![space,now],|r|r.get(0))?;
        if history >= MAX_HISTORY || active >= MAX_WIREGUARD_CLIENTS {
            return Err(StorageError::RateLimited);
        }
        let collision:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM network_wireguard_bindings WHERE expires_at_ms>?1 AND (public_key=?2 OR client_address=?3) UNION ALL SELECT 1 FROM network_space_addresses WHERE ipv4=?3 AND revoked=0)",params![now,request.client_public_key.as_slice(),request.client_address.to_string()],|r|r.get(0))?;
        if collision {
            return Err(StorageError::Conflict);
        }
        type Prior = (String, String, String, u64, u64, u64, bool);
        let prior:Option<Prior>=tx.query_row("SELECT account_id,installation_id,portal_node_id,revision,total_byte_ceiling,committed_bytes,revoked FROM network_wireguard_clients WHERE space_id=?1 AND client_id=?2",params![space,request.client_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
        let committed =
            if let Some((account, installation, node, old, ceiling, committed, revoked)) = prior {
                if revoked
                    || account != actor.account_id
                    || installation != request.installation_id
                    || node != request.portal_node_id
                {
                    return Err(StorageError::Forbidden);
                }
                if old != request.expected_client_revision || ceiling != request.total_byte_ceiling
                {
                    return Err(StorageError::Conflict);
                }
                committed
                    .checked_add(claims.committed_bytes)
                    .ok_or(StorageError::RateLimited)?
            } else {
                if request.expected_client_revision != 0 {
                    return Err(StorageError::Conflict);
                }
                claims.committed_bytes
            };
        if committed > request.total_byte_ceiling {
            return Err(StorageError::RateLimited);
        }
        tx.execute("INSERT INTO network_wireguard_clients(space_id,client_id,account_id,installation_id,portal_node_id,revision,total_byte_ceiling,committed_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(space_id,client_id) DO UPDATE SET revision=excluded.revision,committed_bytes=excluded.committed_bytes",params![space,request.client_id,actor.account_id,request.installation_id,request.portal_node_id,revision,request.total_byte_ceiling,committed])?;
        tx.execute(
            "UPDATE network_wireguard_bindings SET revoked=1 WHERE space_id=?1 AND client_id=?2",
            params![space, request.client_id],
        )?;
        tx.execute("UPDATE network_packet_access SET revoked=1 WHERE space_id=?1 AND access_grant_id IN(SELECT access_grant_id FROM network_wireguard_bindings WHERE space_id=?1 AND client_id=?2)",params![space,request.client_id])?;
        tx.execute("INSERT INTO network_wireguard_bindings(space_id,grant_id,client_id,client_revision,access_grant_id,public_key,client_address,claims,signature,digest,expires_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![space,request.grant_id,request.client_id,revision,request.access_grant_id,request.client_public_key.as_slice(),request.client_address.to_string(),signed.claims,signed.signature,verified.digest().as_slice(),claims.scope.expires_at_ms])?;
        tx.execute(
            "UPDATE network_authorities SET revision=?1 WHERE space_id=?2",
            params![next(snapshot.revision)?, space],
        )?;
        observe(&tx, space, now)?;
        audit(
            &tx,
            "wireguard_client_binding_issued",
            &request.grant_id,
            auditing::management(actor),
        )?;
        let result = bundle(
            self,
            &tx,
            actor,
            read_snapshot(&tx, space, now)?,
            stored(&tx, space, &request.grant_id)?,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }
    pub fn wireguard_client_binding(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        now: u64,
    ) -> Result<WireGuardClientBindingBundle, StorageError> {
        self.validate_access(actor, checked_seconds(now)?)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        topology::access(self, actor, space, false, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        let row = stored(&tx, space, id)?;
        if row.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        let access = row.access.clone();
        let revision = snapshot.revision;
        let result = bundle(self, &tx, actor, snapshot, row, now);
        if result.is_err() {
            // Once this authenticated owner observes an invalid binding it
            // cannot reappear after clock rollback or a portal restart.
            if tx.execute("UPDATE network_wireguard_bindings SET revoked=1 WHERE space_id=?1 AND grant_id=?2 AND revoked=0",params![space,id])?==1 {
                tx.execute("UPDATE network_packet_access SET revoked=1 WHERE space_id=?1 AND access_grant_id=?2",params![space,access])?;
                tx.execute("UPDATE network_authorities SET revision=?1 WHERE space_id=?2",params![next(revision)?,space])?;
                audit(&tx,"wireguard_client_binding_invalidated",id,auditing::management(actor))?;
            }
        }
        observe(&tx, space, now)?;
        tx.commit()?;
        result
    }
    pub fn revoke_wireguard_client(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        request: WireGuardClientRevoke,
        now: u64,
    ) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        topology::access(self, actor, space, false, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        if snapshot.revision != request.expected_revision {
            return Err(StorageError::Conflict);
        }
        let row = stored(&tx, space, id)?;
        if row.account != actor.account_id || row.revoked {
            return Err(StorageError::Forbidden);
        }
        if row.revision != request.expected_client_revision {
            return Err(StorageError::Conflict);
        }
        tx.execute(
            "UPDATE network_wireguard_clients SET revoked=1 WHERE space_id=?1 AND client_id=?2",
            params![space, row.client],
        )?;
        tx.execute(
            "UPDATE network_wireguard_bindings SET revoked=1 WHERE space_id=?1 AND client_id=?2",
            params![space, row.client],
        )?;
        tx.execute("UPDATE network_packet_access SET revoked=1 WHERE space_id=?1 AND access_grant_id IN(SELECT access_grant_id FROM network_wireguard_bindings WHERE space_id=?1 AND client_id=?2)",params![space,row.client])?;
        tx.execute(
            "UPDATE network_authorities SET revision=?1 WHERE space_id=?2",
            params![next(snapshot.revision)?, space],
        )?;
        observe(&tx, space, now)?;
        audit(
            &tx,
            "wireguard_client_revoked",
            id,
            auditing::management(actor),
        )?;
        let result = read_snapshot(&tx, space, now)?;
        tx.commit()?;
        Ok(result)
    }
}
pub(super) fn collect_revocations(
    connection: &Connection,
    space: &str,
    now: u64,
    revoked: &mut BTreeSet<String>,
) -> Result<(), StorageError> {
    let mut statement=connection.prepare("SELECT b.grant_id,b.access_grant_id,p.connectivity_grant_id,p.path_grant_id,(b.revoked=1 OR c.revoked=1 OR b.client_revision!=c.revision OR b.expires_at_ms<=?2) FROM network_wireguard_bindings b JOIN network_wireguard_clients c ON c.space_id=b.space_id AND c.client_id=b.client_id JOIN network_packet_access p ON p.space_id=b.space_id AND p.access_grant_id=b.access_grant_id WHERE b.space_id=?1 LIMIT ?3")?;
    for (index, row) in statement
        .query_map(params![space, now, MAX_HISTORY + 1], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, bool>(4)?,
            ))
        })?
        .enumerate()
    {
        if index >= MAX_HISTORY {
            return Err(StorageError::RateLimited);
        }
        let (id, access, connectivity, path, closed) = row?;
        if closed || revoked.contains(&access) {
            revoked.extend([id, access, connectivity, path]);
        }
    }
    Ok(())
}
