//! Exact online business-to-mapping association, never inferred from a prefix.
use super::*;
use crate::network_policy::subnet::{self as mappings, SubnetMappingBundle};
use nestlink_protocol::subnet::{SubnetMappingClaims, management::SubnetMappingReference};

pub(super) struct EndpointMapping {
    pub endpoint: usize,
    pub reference: SubnetMappingReference,
    pub bundle: SubnetMappingBundle,
}

pub(super) fn select(store: &Store, snapshot: &TrustedNetworkPolicySnapshot, request: &NetworkAccessRequest, members: &[VerifiedMembership; 2], references: [Option<SubnetMappingReference>; 2], now: u64) -> Result<Vec<EndpointMapping>, StorageError> {
    let mut result = Vec::new();
    for (endpoint, reference) in references.into_iter().enumerate() {
        let Some(reference) = reference else { continue; };
        let bundle = mappings::referenced(store, &snapshot.space_id, &reference, now)?;
        let member = &members[endpoint];
        let (installation, membership, prefixes) = if endpoint == 0 {
            (&request.source_installation_id, &request.source_membership_grant_id, &request.source_prefixes)
        } else {
            (&request.destination_installation_id, &request.destination_membership_grant_id, &request.destination_prefixes)
        };
        let claims = SubnetMappingClaims::decode_canonical(&bundle.mapping.claims)?;
        if prefixes.as_slice() != [claims.alias] || member.claims().public_key != bundle.gateway.public_key || member.peer() != claims.gateway {
            return Err(StorageError::Forbidden);
        }
        let approved: bool = store.connection.query_row("SELECT EXISTS(SELECT 1 FROM network_subnet_installations WHERE space_id=?1 AND mapping_id=?2 AND installation_id=?3 AND membership_grant_id=?4 AND public_key=?5 AND membership_digest=?6 AND mapping_digest=?7 AND mapping_revision=?8)",
            params![snapshot.space_id,reference.mapping_id,installation,membership,bundle.gateway.public_key.as_slice(),member.digest().as_slice(),reference.mapping_digest.as_slice(),reference.expected_mapping_revision], |row| row.get(0))?;
        if !approved { return Err(StorageError::Forbidden); }
        result.push(EndpointMapping { endpoint, reference, bundle });
    }
    Ok(result)
}

pub(super) fn check_prefixes(request: &NetworkAccessRequest, directory: &SpaceAddressDirectory, mappings: &[EndpointMapping]) -> Result<(), StorageError> {
    for (endpoint, prefixes) in [&request.source_prefixes, &request.destination_prefixes].into_iter().enumerate() {
        if !mappings.iter().any(|mapping| mapping.endpoint == endpoint) {
            host_prefixes(prefixes, &directory.addresses[endpoint])?;
        }
    }
    // Independently approved sites still cannot reflect an ambiguous wire
    // prefix through each other, or back to the source host assignment.
    for source in &request.source_prefixes {
        for destination in &request.destination_prefixes {
            let a = ipnet::IpNet::new(source.network, source.prefix_len).map_err(|_| StorageError::Forbidden)?;
            let b = ipnet::IpNet::new(destination.network, destination.prefix_len).map_err(|_| StorageError::Forbidden)?;
            if a.contains(&b.addr()) || b.contains(&a.addr()) { return Err(StorageError::Forbidden); }
        }
    }
    Ok(())
}

pub(super) fn insert(tx: &Transaction<'_>, space: &str, request: &NetworkAccessRequest, digest: [u8;32], mappings: &[EndpointMapping]) -> Result<(), StorageError> {
    for mapping in mappings {
        let (installation,membership) = if mapping.endpoint == 0 { (&request.source_installation_id,&request.source_membership_grant_id) } else { (&request.destination_installation_id,&request.destination_membership_grant_id) };
        tx.execute("INSERT INTO network_subnet_packet_bindings(space_id,access_grant_id,endpoint,mapping_id,installation_id,membership_grant_id,mapping_digest,mapping_revision,access_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![space,request.access_grant_id,mapping.endpoint,mapping.reference.mapping_id,installation,membership,mapping.reference.mapping_digest.as_slice(),mapping.reference.expected_mapping_revision,digest.as_slice()])?;
    }
    Ok(())
}

pub(super) fn current(store: &Store, snapshot: &TrustedNetworkPolicySnapshot, row: &Stored, members: &[VerifiedMembership;2], now: u64) -> Result<Vec<EndpointMapping>, StorageError> {
    let mut statement = store.connection.prepare("SELECT endpoint,mapping_id,mapping_digest,mapping_revision,installation_id,membership_grant_id,access_digest FROM network_subnet_packet_bindings WHERE space_id=?1 AND access_grant_id=?2 ORDER BY endpoint LIMIT 3")?;
    let mut references = [None,None];
    let mut count = 0;
    let rows = statement.query_map(params![snapshot.space_id,row.request.access_grant_id], |r| Ok((r.get::<_,usize>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,u64>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,Vec<u8>>(6)?)))?;
    for entry in rows {
        let (endpoint,id,digest,revision,installation,membership,access_digest) = entry?;
        let (expected_installation, expected_membership) = if endpoint == 0 { (&row.request.source_installation_id,&row.request.source_membership_grant_id) } else { (&row.request.destination_installation_id,&row.request.destination_membership_grant_id) };
        if endpoint > 1 || installation != *expected_installation || membership != *expected_membership || access_digest != row.digest { return Err(StorageError::Forbidden); }
        references[endpoint] = Some(SubnetMappingReference {mapping_id:id,mapping_digest:digest.try_into().map_err(|_| StorageError::Forbidden)?,expected_mapping_revision:revision});
        count += 1;
    }
    if count != row.subnet_binding_count { return Err(StorageError::Forbidden); }
    select(store, snapshot, &row.request, members, references, now)
}

pub(super) fn collect_revocations(connection: &Connection, space: &str, now: u64, revoked: &mut BTreeSet<String>) -> Result<(), StorageError> {
    let mut statement = connection.prepare("SELECT e.access_grant_id,e.connectivity_grant_id,e.path_grant_id,b.mapping_id,
        (m.grant_id IS NULL OR a.mapping_id IS NULL OR m.revoked=1 OR m.expires_at_ms<=?2 OR m.digest!=b.mapping_digest OR m.mapping_revision!=b.mapping_revision
        OR b.access_digest!=e.digest OR a.mapping_digest!=b.mapping_digest OR a.mapping_revision!=b.mapping_revision OR a.public_key!=m.public_key
        OR g.grant_id IS NULL OR a.membership_digest!=g.digest OR g.expires_at_ms<=?2
        OR a.membership_grant_id!=CASE b.endpoint WHEN 0 THEN e.source_membership_id ELSE e.destination_membership_id END
        OR a.installation_id!=CASE b.endpoint WHEN 0 THEN e.source_installation_id ELSE e.destination_installation_id END)
        FROM network_packet_access e JOIN network_subnet_packet_bindings b ON b.space_id=e.space_id AND b.access_grant_id=e.access_grant_id
        LEFT JOIN network_subnet_mappings m ON m.space_id=b.space_id AND m.grant_id=b.mapping_id
        LEFT JOIN network_subnet_installations a ON a.space_id=b.space_id AND a.mapping_id=b.mapping_id
        LEFT JOIN network_grants g ON g.space_id=a.space_id AND g.grant_id=a.membership_grant_id
        WHERE e.space_id=?1 AND e.expires_at_ms>?2 LIMIT ?3")?;
    for (index, entry) in statement.query_map(params![space,now,MAX_PACKET_ACCESS_HISTORY*2+1], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<bool>>(4)?)))?.enumerate() {
        if index >= MAX_PACKET_ACCESS_HISTORY*2 { return Err(StorageError::RateLimited); }
        let (access,connectivity,path,mapping,invalid) = entry?;
        if invalid.unwrap_or(true) || revoked.contains(&mapping) { revoked.extend([access,connectivity,path]); }
    }
    Ok(())
}
