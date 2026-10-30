//! A fresh observation can continue a reservation, but can never renew its
//! grants or revive it after an interrupted edge or publication authority.
use super::*;
use nestlink_protocol::network_topology::{TopologyAdvertisement, TopologyReport};

pub(super) struct InitialBinding {
    publisher: [u8; 32],
    sequence: u64,
    observed_until: u64,
}

fn adjacent(report: &TopologyReport, local: &RelayNode, remote: &RelayNode) -> bool {
    report.incarnation.runtime_id == local.runtime
        && report.incarnation.runtime_generation == local.generation
        && report.peer == PeerId::from_public_key(&local.key)
        && report.neighbors.iter().any(|neighbor| {
            neighbor.up
                && neighbor.local == PeerId::from_public_key(&local.key)
                && neighbor.remote == PeerId::from_public_key(&remote.key)
                && neighbor.local_endpoint_revision == local.endpoint_revision
                && neighbor.remote_endpoint_revision == remote.endpoint_revision
        })
}

pub(super) fn capture(
    store: &Store,
    snapshot: &TrustedNetworkPolicySnapshot,
    node_ids: &[String; 2],
    nodes: &[RelayNode; 2],
    digests: &[[u8; 32]; 2],
    now: u64,
) -> Result<[InitialBinding; 2], StorageError> {
    if node_ids[0] == node_ids[1] || nodes[0].key == nodes[1].key {
        return Err(StorageError::Forbidden);
    }
    let mut bindings = Vec::new();
    for index in 0..2 {
        // The device signature freezes the exact two initial envelopes. Only
        // subsequent, authenticated reports may advance the durable fence.
        let ad = topology::current_advertisement(
            store,
            snapshot,
            &node_ids[index],
            &digests[index],
            now,
        )?;
        let ad = ad.claims();
        if !adjacent(&ad.report, &nodes[index], &nodes[1 - index]) {
            return Err(StorageError::Forbidden);
        }
        bindings.push(InitialBinding {
            publisher: ad.report.publisher_digest,
            sequence: ad.report.sequence,
            observed_until: ad.expires_at_ms,
        });
    }
    bindings.try_into().map_err(|_| StorageError::Conflict)
}

pub(super) fn insert(
    tx: &Transaction<'_>,
    route: &str,
    position: usize,
    binding: &InitialBinding,
) -> Result<(), StorageError> {
    tx.execute(
        "INSERT INTO network_remote_chain_topology_bindings(route_id,position,original_publisher_digest,original_sequence,latest_sequence,observed_until) VALUES(?1,?2,?3,?4,?4,?5)",
        params![route,position as u8,binding.publisher.as_slice(),binding.sequence,binding.observed_until],
    )?;
    Ok(())
}

/// The caller owns the transaction, including the commit of a rejected read.
pub(in crate::network_policy) fn retire(
    tx: &Transaction<'_>,
    space: &str,
    route: &str,
) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE network_remote_chain_hops SET closed=1 WHERE route_id=?1 AND space_id=?2",
        params![route, space],
    )?;
    tx.execute(
        "UPDATE network_remote_paths SET revoked=1 WHERE space_id=?1 AND path_grant_id=(SELECT path_grant_id FROM network_remote_chains WHERE route_id=?2 AND space_id=?1)",
        params![space, route],
    )?;
    Ok(())
}

pub(super) fn current(
    store: &Store,
    tx: &Transaction<'_>,
    snapshot: &TrustedNetworkPolicySnapshot,
    route: &str,
    node_ids: &[String; 2],
    nodes: &[RelayNode; 2],
    now: u64,
) -> Result<(), StorageError> {
    for index in 0..2 {
        type Binding = (Vec<u8>, u64, u64, u64);
        let binding: Option<Binding> = tx.query_row(
            "SELECT original_publisher_digest,original_sequence,latest_sequence,observed_until FROM network_remote_chain_topology_bindings WHERE route_id=?1 AND position=?2",
            params![route,index as u8], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        let (publisher, original, latest, observed_until) =
            binding.ok_or(StorageError::Forbidden)?;
        let ad = topology::current_head(store, snapshot, &node_ids[index], now)?;
        let ad = ad.claims();
        if publisher != ad.report.publisher_digest
            || ad.report.sequence < original
            || ad.report.sequence < latest
            || now >= observed_until
            || ad.expires_at_ms < observed_until
            || !adjacent(&ad.report, &nodes[index], &nodes[1 - index])
        {
            return Err(StorageError::Forbidden);
        }
    }
    Ok(())
}

/// Runs in the authenticated report acceptance transaction, before replacing
/// the head. Recording every accepted transition prevents down/up or expiry/up
/// between resource polls from resurrecting an earlier reservation.
pub(in crate::network_policy) fn report_accepted(
    tx: &Transaction<'_>,
    space: &str,
    ad: &TopologyAdvertisement,
    now: u64,
) -> Result<(), StorageError> {
    let report = &ad.report;
    type BoundHop = (String, u8, Vec<u8>, u64, u64, u64, Vec<u8>, String, u64, u64, Vec<u8>, u64);
    let mut statement = tx.prepare(
        "SELECT h.route_id,h.position,b.original_publisher_digest,b.original_sequence,b.latest_sequence,b.observed_until,h.node_key,h.runtime_id,h.runtime_generation,h.endpoint_revision,o.node_key,o.endpoint_revision
         FROM network_remote_chain_hops h
         JOIN network_remote_chain_topology_bindings b ON b.route_id=h.route_id AND b.position=h.position
         JOIN network_remote_chain_hops o ON o.route_id=h.route_id AND o.position=1-h.position
         WHERE h.space_id=?1 AND h.node_id=?2 AND h.closed=0",
    )?;
    let rows = statement.query_map(params![space,report.node_id], |r|Ok((
        r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,
        r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,
    )))?.collect::<Result<Vec<BoundHop>,_>>()?;
    drop(statement);
    for (route,position,publisher,original,latest,observed_until,key,runtime,generation,revision,remote_key,remote_revision) in rows {
        let local_key: [u8;32] = key.try_into().map_err(|_| StorageError::Forbidden)?;
        let remote_key: [u8;32] = remote_key.try_into().map_err(|_| StorageError::Forbidden)?;
        let uninterrupted = publisher == report.publisher_digest
            && report.sequence >= original
            && report.sequence > latest
            && now < observed_until
            && runtime == report.incarnation.runtime_id
            && generation == report.incarnation.runtime_generation
            && report.peer == PeerId::from_public_key(&local_key)
            && report.neighbors.iter().any(|neighbor| {
                neighbor.up
                    && neighbor.local == report.peer
                    && neighbor.remote == PeerId::from_public_key(&remote_key)
                    && neighbor.local_endpoint_revision == revision
                    && neighbor.remote_endpoint_revision == remote_revision
            });
        if uninterrupted {
            tx.execute(
                "UPDATE network_remote_chain_topology_bindings SET latest_sequence=?1,observed_until=?2 WHERE route_id=?3 AND position=?4",
                params![report.sequence,ad.expires_at_ms,route,position],
            )?;
        } else {
            retire(tx, space, &route)?;
        }
    }
    Ok(())
}

pub(in crate::network_policy) fn withdrawn(
    tx: &Transaction<'_>,
    space: &str,
    node: &str,
) -> Result<(), StorageError> {
    let mut statement = tx.prepare(
        "SELECT route_id FROM network_remote_chain_hops WHERE space_id=?1 AND node_id=?2 AND closed=0",
    )?;
    let routes = statement.query_map(params![space,node], |r|r.get::<_,String>(0))?
        .collect::<Result<Vec<_>,_>>()?;
    drop(statement);
    for route in routes {
        retire(tx, space, &route)?;
    }
    Ok(())
}
