//! Exact host raw-IP authority, explicitly issued by the destination's account.
//! All graphs use the existing network grant domains and original memberships.
//! A management credential never opts a local OS into packet injection.
use super::*;
use nestlink_identity::network::{VerifiedMembership, VerifiedNetworkPath};
use nestlink_protocol::{
    network::{
        ConnectivityClaims, IpPrefix, NetworkAccessClaims, PathClaims, PathPolicy, PeerPair,
        Purpose,
    },
    network_access::{NetworkAccessRequest, NetworkAccessStart},
    spaces::addressing::{SpaceAddressDirectory, SpaceAddressView},
};
use std::net::IpAddr;
mod subnet;

pub const MAX_PACKET_ACCESS_MS: u64 = 60_000;
pub const MAX_CURRENT_PACKET_ACCESS: usize = 1024;
pub const MAX_PACKET_ACCESS_HISTORY: usize = 65_536;

pub struct NetworkAccessBundle {
    pub memberships: [SignedNetworkGrant; 2],
    pub access: SignedNetworkGrant,
    pub connectivity: SignedNetworkGrant,
    pub path: SignedNetworkGrant,
    pub address_directory: SpaceAddressDirectory,
    pub subnet_mappings: Vec<super::subnet::SubnetMappingBundle>,
}

struct Stored {
    request: NetworkAccessRequest,
    addresses: [SpaceAddressView; 2],
    access: SignedNetworkGrant,
    connectivity: SignedNetworkGrant,
    path: SignedNetworkGrant,
    digest: Vec<u8>,
    issued: u64,
    revoked: bool,
    subnet_binding_count: usize,
}

fn stored(connection: &Connection, space: &str, id: &str) -> Result<Stored, StorageError> {
    require_id(id)?;
    type Row = (
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        u64,
        bool,
        String,
        String,
        String,
        usize,
    );
    let row: Option<Row> = connection.query_row(
        "SELECT request_json,addresses_json,access_claims,access_signature,connectivity_claims,connectivity_signature,path_claims,path_signature,digest,issued_at_ms,revoked,connectivity_grant_id,path_grant_id,source_installation_id,subnet_binding_count FROM network_packet_access WHERE space_id=?1 AND access_grant_id=?2",
        params![space,id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?)),
    ).optional()?;
    let (
        request,
        addresses,
        ac,
        asig,
        cc,
        cs,
        pc,
        ps,
        digest,
        issued,
        revoked,
        connectivity_id,
        path_id,
        source_id,
        subnet_binding_count,
    ) = row.ok_or(StorageError::Forbidden)?;
    let request: NetworkAccessRequest = serde_json::from_str(&request)?;
    if request.access_grant_id != id
        || request.connectivity_grant_id != connectivity_id
        || request.path_grant_id != path_id
        || request.source_installation_id != source_id
    {
        return Err(StorageError::Forbidden);
    }
    Ok(Stored {
        request,
        addresses: serde_json::from_str(&addresses)?,
        access: SignedNetworkGrant {
            claims: ac,
            signature: asig,
        },
        connectivity: SignedNetworkGrant {
            claims: cc,
            signature: cs,
        },
        path: SignedNetworkGrant {
            claims: pc,
            signature: ps,
        },
        digest,
        issued,
        revoked,
        subnet_binding_count,
    })
}

fn host_prefixes(requested: &[IpPrefix], address: &SpaceAddressView) -> Result<(), StorageError> {
    let ipv4: std::net::Ipv4Addr = address.ipv4.parse().map_err(|_| StorageError::Forbidden)?;
    let ipv6: std::net::Ipv6Addr = address.ipv6.parse().map_err(|_| StorageError::Forbidden)?;
    if requested.is_empty() || requested.len() > 2 {
        return Err(StorageError::Invalid(
            "packet access requires exact host prefixes",
        ));
    }
    for prefix in requested {
        prefix.validate()?;
        if !matches!((prefix.network,prefix.prefix_len), (IpAddr::V4(ip),32) if ip==ipv4)
            && !matches!((prefix.network,prefix.prefix_len), (IpAddr::V6(ip),128) if ip==ipv6)
        {
            return Err(StorageError::Forbidden);
        }
    }
    if requested.len() == 2 && requested[0] == requested[1] {
        return Err(StorageError::Invalid("duplicate packet access host prefix"));
    }
    Ok(())
}

fn same_assignment(previous: &SpaceAddressView, current: &SpaceAddressView) -> bool {
    previous.installation_id == current.installation_id
        && previous.account_id == current.account_id
        && previous.public_key == current.public_key
        && previous.account_member_epoch == current.account_member_epoch
        && previous.membership_epoch == current.membership_epoch
        && previous.address_epoch == current.address_epoch
        && previous.ipv4 == current.ipv4
        && previous.ipv6 == current.ipv6
        && current.active
        && !current.revoked
        && !current.reserved
}

fn claims(
    snapshot: &TrustedNetworkPolicySnapshot,
    request: &NetworkAccessRequest,
    members: &[VerifiedMembership; 2],
    issued: u64,
) -> Result<GrantClaims, StorageError> {
    let scope = GrantScope {
        schema_version: SCHEMA_VERSION,
        deployment_id: snapshot.deployment_id.clone(),
        space_id: snapshot.space_id.clone(),
        grant_id: request.access_grant_id.clone(),
        policy_epoch: snapshot.policy_epoch,
        not_before_ms: issued,
        expires_at_ms: request.expires_at_unix_ms,
    };
    Ok(GrantClaims::NetworkAccess(NetworkAccessClaims {
        scope,
        source: members[0].peer(),
        destination: members[1].peer(),
        source_prefixes: request.source_prefixes.clone(),
        destination_prefixes: request.destination_prefixes.clone(),
        rules: request.rules.clone(),
        byte_limit: request.byte_limit,
    }))
}

fn member_pair(
    connection: &Connection,
    snapshot: &TrustedNetworkPolicySnapshot,
    request: &NetworkAccessRequest,
) -> Result<([SignedNetworkGrant; 2], [VerifiedMembership; 2]), StorageError> {
    let (source, source_bound) = remote_paths::member_credential(
        connection,
        snapshot,
        &request.source_membership_grant_id,
        &request.source_installation_id,
    )?;
    let (destination, destination_bound) = remote_paths::member_credential(
        connection,
        snapshot,
        &request.destination_membership_grant_id,
        &request.destination_installation_id,
    )?;
    Ok(([source, destination], [source_bound, destination_bound]))
}

fn check_addresses(
    request: &NetworkAccessRequest,
    directory: &SpaceAddressDirectory,
) -> Result<(), StorageError> {
    if directory.addresses.len() != 2 {
        return Err(StorageError::Forbidden);
    }
    for (address, installation, epoch) in [
        (
            &directory.addresses[0],
            &request.source_installation_id,
            request.expected_source_address_epoch,
        ),
        (
            &directory.addresses[1],
            &request.destination_installation_id,
            request.expected_destination_address_epoch,
        ),
    ] {
        if address.installation_id != *installation
            || address.address_epoch != epoch
            || !address.active
            || address.revoked
            || address.reserved
        {
            return Err(StorageError::Forbidden);
        }
    }
    Ok(())
}

fn endpoint_account(
    actor: &Principal,
    directory: &SpaceAddressDirectory,
) -> Result<(), StorageError> {
    if !directory
        .addresses
        .iter()
        .any(|address| address.account_id == actor.account_id)
    {
        return Err(StorageError::Forbidden);
    }
    Ok(())
}

impl Store {
    fn packet_direct_allowed(
        &self,
        actor: &Principal,
        directory: &SpaceAddressDirectory,
    ) -> Result<(), StorageError> {
        use nestlink_policy::PeerPathMode;
        if !self
            .policy()?
            .1
            .paths()?
            .contains(nestlink_protocol::Path::Direct)
            || self.path_limit("login_session", &actor.session_id)? == PeerPathMode::RelayOnly
        {
            return Err(StorageError::Forbidden);
        }
        for address in &directory.addresses {
            let mode: String = self.connection.query_row(
                "SELECT path_mode FROM device_details WHERE device_id=?1",
                [&address.installation_id],
                |r| r.get(0),
            )?;
            if crate::control::parse_mode(&mode)? == PeerPathMode::RelayOnly
                || self.path_limit("account", &address.account_id)? == PeerPathMode::RelayOnly
                || self.path_limit("device", &address.installation_id)? == PeerPathMode::RelayOnly
                || self.path_limit("resource", &address.installation_id)? == PeerPathMode::RelayOnly
            {
                return Err(StorageError::Forbidden);
            }
        }
        Ok(())
    }

    pub fn issue_network_access(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        space: &str,
        request: NetworkAccessRequest,
        now: u64,
    ) -> Result<NetworkAccessBundle, StorageError> {
        self.issue_packet_access(actor, signer, space, request, [None, None], now)
    }

    pub fn issue_subnet_network_access(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        space: &str,
        request: nestlink_protocol::subnet::management::SubnetNetworkAccessRequest,
        now: u64,
    ) -> Result<NetworkAccessBundle, StorageError> {
        if request.source_mapping.is_none() && request.destination_mapping.is_none() {
            return Err(StorageError::Invalid(
                "subnet packet access needs an explicitly approved mapping",
            ));
        }
        self.issue_packet_access(
            actor,
            signer,
            space,
            request.packet,
            [request.source_mapping, request.destination_mapping],
            now,
        )
    }

    fn issue_packet_access(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        space: &str,
        mut request: NetworkAccessRequest,
        references: [Option<nestlink_protocol::subnet::management::SubnetMappingReference>; 2],
        now: u64,
    ) -> Result<NetworkAccessBundle, StorageError> {
        self.validate_access(actor, checked_seconds(now)?)?;
        if request.expires_at_unix_ms <= now
            || request.expires_at_unix_ms > i64::MAX as u64
            || request.expires_at_unix_ms - now > MAX_PACKET_ACCESS_MS
            || request.byte_limit > i64::MAX as u64
        {
            return Err(StorageError::Invalid(
                "packet access lifetime or quota exceeds its budget",
            ));
        }
        let ids = [
            &request.access_grant_id,
            &request.connectivity_grant_id,
            &request.path_grant_id,
        ];
        if ids.iter().collect::<BTreeSet<_>>().len() != 3
            || request.source_installation_id == request.destination_installation_id
        {
            return Err(StorageError::Invalid(
                "packet access requires distinct grants and devices",
            ));
        }
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
        for id in ids {
            remote_paths::grant_id_available(&tx, space, id)?;
        }
        let directory = self.space_packet_address_pair(
            &tx,
            actor,
            space,
            &[
                request.source_installation_id.clone(),
                request.destination_installation_id.clone(),
            ],
            now,
        )?;
        if directory.revision != request.expected_directory_revision {
            return Err(StorageError::Conflict);
        }
        check_addresses(&request, &directory)?;
        self.packet_direct_allowed(actor, &directory)?;
        // An owner/admin of the space cannot approve another account's host.
        // This explicit destination-account request still needs independent
        // local OS opt-in to the exact access digest at runtime.
        if directory.addresses[1].account_id != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        let (memberships, members) = member_pair(&tx, &snapshot, &request)?;
        let subnet_mappings = subnet::select(self, &snapshot, &request, &members, references, now)?;
        subnet::check_prefixes(&request, &directory, &subnet_mappings)?;
        request.expires_at_unix_ms = request
            .expires_at_unix_ms
            .min(members[0].claims().scope.expires_at_ms)
            .min(members[1].claims().scope.expires_at_ms);
        for mapping in &subnet_mappings {
            let claims = nestlink_protocol::subnet::SubnetMappingClaims::decode_canonical(
                &mapping.bundle.mapping.claims,
            )?;
            request.expires_at_unix_ms = request
                .expires_at_unix_ms
                .min(claims.scope.expires_at_ms)
                .min(mapping.bundle.gateway.lease_expires_at_ms);
        }
        if request.expires_at_unix_ms <= now {
            return Err(StorageError::Forbidden);
        }
        let history: usize = tx.query_row(
            "SELECT count(*) FROM network_packet_access WHERE space_id=?1",
            [space],
            |r| r.get(0),
        )?;
        let active: usize = tx.query_row("SELECT count(*) FROM network_packet_access WHERE space_id=?1 AND policy_epoch=?2 AND expires_at_ms>?3 AND revoked=0",params![space,snapshot.policy_epoch,now],|r|r.get(0))?;
        if history >= MAX_PACKET_ACCESS_HISTORY || active >= MAX_CURRENT_PACKET_ACCESS {
            return Err(StorageError::RateLimited);
        }
        let access = signer.sign(&claims(&snapshot, &request, &members, now)?)?;
        let access_bound = verify_network_grant(&access, &snapshot.verification())?;
        let peers = PeerPair::new(members[0].peer(), members[1].peer())?;
        let digests = if peers.first == members[0].peer() {
            [members[0].digest(), members[1].digest()]
        } else {
            [members[1].digest(), members[0].digest()]
        };
        let scope = |id: &str| GrantScope {
            schema_version: SCHEMA_VERSION,
            deployment_id: snapshot.deployment_id.clone(),
            space_id: space.into(),
            grant_id: id.into(),
            policy_epoch: snapshot.policy_epoch,
            not_before_ms: now,
            expires_at_ms: request.expires_at_unix_ms,
        };
        let connectivity = signer.sign(&GrantClaims::Connectivity(ConnectivityClaims {
            scope: scope(&request.connectivity_grant_id),
            peers,
            purpose: Purpose::NetworkPacket,
            membership_digests: digests,
            business_grant_digest: access_bound.digest(),
        }))?;
        let connection = verify_network_grant(&connectivity, &snapshot.verification())?;
        let path = signer.sign(&GrantClaims::Path(PathClaims {
            scope: scope(&request.path_grant_id),
            peers,
            purpose: Purpose::NetworkPacket,
            connectivity_grant_digest: connection.digest(),
            policy: PathPolicy {
                allow_direct: true,
                relays: Vec::new(),
                max_hops: 0,
            },
        }))?;
        VerifiedNetworkPath::from_grants(
            &snapshot.verification(),
            members,
            connection,
            verify_network_grant(&path, &snapshot.verification())?,
            access_bound.digest(),
        )?;
        let request_json = serde_json::to_string(&request)?;
        let addresses_json = serde_json::to_string(&directory.addresses)?;
        tx.execute("INSERT INTO network_packet_access(space_id,access_grant_id,connectivity_grant_id,path_grant_id,source_installation_id,destination_installation_id,source_membership_id,destination_membership_id,policy_epoch,digest,request_json,addresses_json,access_claims,access_signature,connectivity_claims,connectivity_signature,path_claims,path_signature,issued_at_ms,expires_at_ms,subnet_binding_count) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
            params![space,request.access_grant_id,request.connectivity_grant_id,request.path_grant_id,request.source_installation_id,request.destination_installation_id,
                request.source_membership_grant_id,request.destination_membership_grant_id,snapshot.policy_epoch,access_bound.digest().as_slice(),request_json,addresses_json,
                access.claims,access.signature,connectivity.claims,connectivity.signature,path.claims,path.signature,now,request.expires_at_unix_ms,subnet_mappings.len()])?;
        subnet::insert(
            &tx,
            space,
            &request,
            access_bound.digest(),
            &subnet_mappings,
        )?;
        tx.execute(
            "UPDATE network_authorities SET revision=?1 WHERE space_id=?2",
            params![next(snapshot.revision)?, space],
        )?;
        observe(&tx, space, now)?;
        crate::spaces::event(
            &tx,
            actor,
            space,
            "network_packet_access_issued",
            &request.access_grant_id,
            now,
        )?;
        let address_directory = self.space_packet_address_pair(
            &tx,
            actor,
            space,
            &[
                request.source_installation_id,
                request.destination_installation_id,
            ],
            now,
        )?;
        tx.commit()?;
        Ok(NetworkAccessBundle {
            memberships,
            access,
            connectivity,
            path,
            address_directory,
            subnet_mappings: subnet_mappings
                .into_iter()
                .map(|mapping| mapping.bundle)
                .collect(),
        })
    }

    /// The graph retains its original signed bytes. This rechecks both current
    /// identities and address assignments and refreshes only their observation.
    pub fn network_access(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        now: u64,
    ) -> Result<NetworkAccessBundle, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.packet_observation_access(&tx, actor, space, id, now)?;
        let bundle = self.current_packet_access(&tx, actor, space, id, now);
        if bundle.is_err() {
            close_failed_observation(&tx, actor, space, id, now)?;
        }
        observe(&tx, space, now)?;
        tx.commit()?;
        bundle
    }

    fn packet_observation_access(
        &self,
        tx: &Transaction<'_>,
        actor: &Principal,
        space: &str,
        id: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        topology::access(self, actor, space, false, now)?;
        let row = stored(tx, space, id)?;
        if !row
            .addresses
            .iter()
            .any(|address| address.account_id == actor.account_id)
        {
            return Err(StorageError::Forbidden);
        }
        // Refuse rollback before any terminal mutation can advance revisions.
        read_snapshot(tx, space, now)?;
        Ok(())
    }

    fn current_packet_access(
        &self,
        tx: &Transaction<'_>,
        actor: &Principal,
        space: &str,
        id: &str,
        now: u64,
    ) -> Result<NetworkAccessBundle, StorageError> {
        self.validate_access(actor, checked_seconds(now)?)?;
        let snapshot = read_snapshot(tx, space, now)?;
        let row = stored(tx, space, id)?;
        if row.revoked {
            return Err(StorageError::Forbidden);
        }
        let request = &row.request;
        let address_directory = self.space_packet_address_pair(
            tx,
            actor,
            space,
            &[
                request.source_installation_id.clone(),
                request.destination_installation_id.clone(),
            ],
            now,
        )?;
        endpoint_account(actor, &address_directory)?;
        check_addresses(request, &address_directory)?;
        self.packet_direct_allowed(actor, &address_directory)?;
        if !row
            .addresses
            .iter()
            .zip(&address_directory.addresses)
            .all(|(previous, current)| same_assignment(previous, current))
        {
            return Err(StorageError::Forbidden);
        }
        let (memberships, members) = member_pair(tx, &snapshot, request)?;
        let subnet_mappings = subnet::current(self, &snapshot, &row, &members, now)?;
        subnet::check_prefixes(request, &address_directory, &subnet_mappings)?;
        let access = verify_network_grant(&row.access, &snapshot.verification())?;
        if access.digest().as_slice() != row.digest
            || *access.claims() != claims(&snapshot, request, &members, row.issued)?
        {
            return Err(StorageError::Forbidden);
        }
        let connection = verify_network_grant(&row.connectivity, &snapshot.verification())?;
        let path = verify_network_grant(&row.path, &snapshot.verification())?;
        let verified = VerifiedNetworkPath::from_grants(
            &snapshot.verification(),
            members,
            connection,
            path,
            access.digest(),
        )?;
        if verified.purpose() != Purpose::NetworkPacket
            || verified.claims().scope.grant_id != request.path_grant_id
            || verified.claims().scope.not_before_ms != row.issued
            || verified.claims().scope.expires_at_ms != request.expires_at_unix_ms
            || verified.claims().policy
                != (PathPolicy {
                    allow_direct: true,
                    relays: Vec::new(),
                    max_hops: 0,
                })
        {
            return Err(StorageError::Forbidden);
        }
        let GrantClaims::Connectivity(connection) =
            GrantClaims::decode_canonical(&row.connectivity.claims)?
        else {
            return Err(StorageError::Forbidden);
        };
        if connection.scope.grant_id != request.connectivity_grant_id
            || connection.scope.not_before_ms != row.issued
            || connection.scope.expires_at_ms != request.expires_at_unix_ms
        {
            return Err(StorageError::Forbidden);
        }
        Ok(NetworkAccessBundle {
            memberships,
            access: row.access,
            connectivity: row.connectivity,
            path: row.path,
            address_directory,
            subnet_mappings: subnet_mappings
                .into_iter()
                .map(|mapping| mapping.bundle)
                .collect(),
        })
    }

    /// Every ordinary packet owner needs this fresh, online, one-use start.
    /// A lost response consumes the start too: neither readback nor retry can
    /// restore it. Restart requires a new grant and destination approval.
    pub fn start_network_access(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        request: NetworkAccessStart,
        now: u64,
    ) -> Result<(), StorageError> {
        require_id(&request.installation_id)?;
        require_id(&request.owner_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.packet_observation_access(&tx, actor, space, id, now)?;
        let bundle = match self.current_packet_access(&tx, actor, space, id, now) {
            Ok(bundle) => bundle,
            Err(error) => {
                close_failed_observation(&tx, actor, space, id, now)?;
                observe(&tx, space, now)?;
                tx.commit()?;
                return Err(error);
            }
        };
        let endpoint = bundle
            .address_directory
            .addresses
            .iter()
            .position(|address| {
                address.installation_id == request.installation_id
                    && address.account_id == actor.account_id
            })
            .ok_or(StorageError::Forbidden)?;
        // The fixed statements select one endpoint column, and the same
        // IMMEDIATE transaction owns current policy verification and the CAS.
        let statement = match endpoint {
            0 => {
                "UPDATE network_packet_access SET source_claim_owner=?1 WHERE space_id=?2 AND access_grant_id=?3 AND source_installation_id=?4 AND source_claim_owner IS NULL AND revoked=0"
            }
            1 => {
                "UPDATE network_packet_access SET destination_claim_owner=?1 WHERE space_id=?2 AND access_grant_id=?3 AND destination_installation_id=?4 AND destination_claim_owner IS NULL AND revoked=0"
            }
            _ => return Err(StorageError::Forbidden),
        };
        if tx.execute(
            statement,
            params![request.owner_id, space, id, request.installation_id],
        )? != 1
        {
            return Err(StorageError::Forbidden);
        }
        observe(&tx, space, now)?;
        crate::spaces::event(&tx, actor, space, "network_packet_owner_started", id, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Either endpoint may stop exposure. Space managers may deny access, but
    /// their management role never authorizes issuing another account's host.
    pub fn revoke_network_access(
        &mut self,
        actor: &Principal,
        space: &str,
        id: &str,
        expected_revision: u64,
        now: u64,
    ) -> Result<TrustedNetworkPolicySnapshot, StorageError> {
        self.validate_access(actor, checked_seconds(now)?)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        if snapshot.revision != expected_revision {
            return Err(StorageError::Conflict);
        }
        let row = stored(&tx, space, id)?;
        let own_endpoint = [
            row.addresses[0].account_id.as_str(),
            row.addresses[1].account_id.as_str(),
        ]
        .contains(&actor.account_id.as_str());
        // Always validate current space access, including after address/lease
        // expiry. Revocation must remain available when readback is forbidden.
        topology::access(self, actor, space, !own_endpoint, now)?;
        let changed = tx.execute("UPDATE network_packet_access SET revoked=1 WHERE space_id=?1 AND access_grant_id=?2 AND revoked=0",params![space,id])?;
        if changed == 1 {
            tx.execute(
                "UPDATE network_authorities SET revision=?1 WHERE space_id=?2",
                params![next(snapshot.revision)?, space],
            )?;
            crate::spaces::event(&tx, actor, space, "network_packet_access_revoked", id, now)?;
        }
        observe(&tx, space, now)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        tx.commit()?;
        Ok(snapshot)
    }
}

fn close_failed_observation(
    tx: &Transaction<'_>,
    actor: &Principal,
    space: &str,
    id: &str,
    now: u64,
) -> Result<(), StorageError> {
    let snapshot = read_snapshot(tx, space, now)?;
    if tx.execute("UPDATE network_packet_access SET revoked=1 WHERE space_id=?1 AND access_grant_id=?2 AND revoked=0",params![space,id])? == 1 {
        tx.execute("UPDATE network_authorities SET revision=?1 WHERE space_id=?2",params![next(snapshot.revision)?,space])?;
        crate::spaces::event(tx,actor,space,"network_packet_access_invalidated",id,now)?;
    }
    Ok(())
}

/// Include dynamic address/key/account/membership invalidation in every fresh
/// verification snapshot, so retained credentials cannot outlive a readback
/// denial. All three graph IDs are invalidated together.
pub(super) fn collect_revocations(
    connection: &Connection,
    space: &str,
    epoch: u64,
    now: u64,
    revoked: &mut BTreeSet<String>,
) -> Result<(), StorageError> {
    let observed: Option<u64> = connection
        .query_row(
            "SELECT last_observed_ms FROM network_space_address_directories WHERE space_id=?1",
            [space],
            |r| r.get(0),
        )
        .optional()?;
    if observed.is_some_and(|observed| observed > now) {
        return Err(StorageError::Conflict);
    }
    let mut statement = connection.prepare(
        "SELECT e.access_grant_id,e.connectivity_grant_id,e.path_grant_id,
        (e.revoked=1 OR (SELECT count(*) FROM network_subnet_packet_bindings b WHERE b.space_id=e.space_id AND b.access_grant_id=e.access_grant_id)!=e.subnet_binding_count
         OR sa.installation_id IS NULL OR da.installation_id IS NULL
         OR sa.revoked=1 OR da.revoked=1 OR sa.reserved=1 OR da.reserved=1
         OR sa.address_epoch!=json_extract(e.addresses_json,'$[0].address_epoch') OR da.address_epoch!=json_extract(e.addresses_json,'$[1].address_epoch')
         OR sa.ipv4!=json_extract(e.addresses_json,'$[0].ipv4') OR sa.ipv6!=json_extract(e.addresses_json,'$[0].ipv6')
         OR da.ipv4!=json_extract(e.addresses_json,'$[1].ipv4') OR da.ipv6!=json_extract(e.addresses_json,'$[1].ipv6')
         OR sm.installation_id IS NULL OR dm.installation_id IS NULL OR sm.revoked=1 OR dm.revoked=1
         OR sm.public_key!=sa.public_key OR dm.public_key!=da.public_key
         OR sm.membership_epoch!=sa.membership_epoch OR dm.membership_epoch!=da.membership_epoch
         OR sg.grant_id IS NULL OR dg.grant_id IS NULL OR sg.expires_at_ms<=?3 OR dg.expires_at_ms<=?3
         OR sg.installation_id!=e.source_installation_id OR dg.installation_id!=e.destination_installation_id
         OR sg.membership_epoch!=sm.membership_epoch OR dg.membership_epoch!=dm.membership_epoch
         OR sr.grant_id IS NOT NULL OR dr.grant_id IS NOT NULL
         OR sd.id IS NULL OR dd.id IS NULL OR sd.revoked=1 OR dd.revoked=1
         OR (sd.expires_at IS NOT NULL AND sd.expires_at<=?3/1000) OR (dd.expires_at IS NOT NULL AND dd.expires_at<=?3/1000)
         OR sd.account_id!=sa.account_id OR dd.account_id!=da.account_id
         OR sx.public_key IS NULL OR dx.public_key IS NULL OR sx.public_key!=sm.public_key OR dx.public_key!=dm.public_key
         OR su.account_id IS NULL OR du.account_id IS NULL OR su.revoked=1 OR du.revoked=1
         OR su.member_epoch!=sa.account_member_epoch OR du.member_epoch!=da.account_member_epoch
         OR su.role!=sm.role OR du.role!=dm.role OR sac.disabled=1 OR dac.disabled=1)
        FROM network_packet_access e
        LEFT JOIN network_space_addresses sa ON sa.space_id=e.space_id AND sa.installation_id=e.source_installation_id
        LEFT JOIN network_space_addresses da ON da.space_id=e.space_id AND da.installation_id=e.destination_installation_id
        LEFT JOIN network_memberships sm ON sm.space_id=e.space_id AND sm.installation_id=e.source_installation_id
        LEFT JOIN network_memberships dm ON dm.space_id=e.space_id AND dm.installation_id=e.destination_installation_id
        LEFT JOIN network_grants sg ON sg.space_id=e.space_id AND sg.grant_id=e.source_membership_id
        LEFT JOIN network_grants dg ON dg.space_id=e.space_id AND dg.grant_id=e.destination_membership_id
        LEFT JOIN network_grant_revocations sr ON sr.space_id=e.space_id AND sr.grant_id=e.source_membership_id
        LEFT JOIN network_grant_revocations dr ON dr.space_id=e.space_id AND dr.grant_id=e.destination_membership_id
        LEFT JOIN devices sd ON sd.id=e.source_installation_id LEFT JOIN devices dd ON dd.id=e.destination_installation_id
        LEFT JOIN device_details sx ON sx.device_id=sd.id LEFT JOIN device_details dx ON dx.device_id=dd.id
        LEFT JOIN network_space_members su ON su.space_id=e.space_id AND su.account_id=sd.account_id
        LEFT JOIN network_space_members du ON du.space_id=e.space_id AND du.account_id=dd.account_id
        LEFT JOIN accounts sac ON sac.id=sd.account_id LEFT JOIN accounts dac ON dac.id=dd.account_id
        WHERE e.space_id=?1 AND e.policy_epoch=?2 AND e.expires_at_ms>?3 ORDER BY e.access_grant_id LIMIT ?4")?;
    for (count, row) in statement
        .query_map(
            params![space, epoch, now, MAX_PACKET_ACCESS_HISTORY + 1],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<bool>>(3)?,
                ))
            },
        )?
        .enumerate()
    {
        if count >= MAX_PACKET_ACCESS_HISTORY {
            return Err(StorageError::RateLimited);
        }
        let (access, connectivity, path, invalid) = row?;
        if invalid.unwrap_or(true) {
            revoked.extend([access, connectivity, path]);
        }
    }
    subnet::collect_revocations(connection, space, now, revoked)
}
