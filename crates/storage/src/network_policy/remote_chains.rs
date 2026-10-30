//! Atomic two-relay reservations. Both transit promises reuse the existing
//! global/account/node quota view and lifecycle fence. No partial commit exists.
use super::*;
use crate::relay_reservations::RelayLifecycle;
use nestlink_identity::{network::remote_chain_reservation_transcript, verify_device_action};
use nestlink_protocol::{
    api::{NetworkRemoteRelayChainRequest, NodeEndpointsView},
    network::{PathPolicy, TransitClaims},
};
use remote_relays::{RelayNode, relay_node};

pub struct NetworkRemoteRelayChainIssuance {
    pub space_id: String,
    pub request_id: String,
    pub request: NetworkRemoteRelayChainRequest,
}
pub struct NetworkRemoteRelayChainBundle {
    pub route_id: String,
    pub path: NetworkRemotePathBundle,
    pub transits: [SignedNetworkGrant; 2],
    pub nodes: [NodeEndpointsView; 2],
    pub topology_digests: [[u8; 32]; 2],
}

fn current_topology(
    store: &Store,
    snapshot: &TrustedNetworkPolicySnapshot,
    node_ids: &[String; 2],
    nodes: &[RelayNode; 2],
    digests: &[[u8; 32]; 2],
    expires: u64,
    now: u64,
) -> Result<(), StorageError> {
    if node_ids[0] == node_ids[1] || nodes[0].key == nodes[1].key {
        return Err(StorageError::Forbidden);
    }
    for index in 0..2 {
        let other = 1 - index;
        let ad = topology::current_advertisement(store, snapshot, &node_ids[index], &digests[index], now)?;
        if expires > ad.claims().expires_at_ms
            || !ad.claims().report.neighbors.iter().any(|neighbor| {
                neighbor.up
                    && neighbor.local == PeerId::from_public_key(&nodes[index].key)
                    && neighbor.remote == PeerId::from_public_key(&nodes[other].key)
                    && neighbor.local_endpoint_revision == nodes[index].endpoint_revision
                    && neighbor.remote_endpoint_revision == nodes[other].endpoint_revision
            })
        {
            return Err(StorageError::Forbidden);
        }
    }
    Ok(())
}

impl Store {
    pub fn issue_network_remote_chain(
        &mut self,
        lifecycle: &RelayLifecycle,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        issuance: NetworkRemoteRelayChainIssuance,
        now: u64,
    ) -> Result<NetworkRemoteRelayChainBundle, StorageError> {
        let NetworkRemoteRelayChainIssuance { space_id, request_id, request } = issuance;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        self.remote(actor, &request_id)?;
        self.resume_relay_reservations(lifecycle, now)?;
        let business = remote_paths::current_business(self, &request_id, now)?;
        let transcript = remote_chain_reservation_transcript(&business, &actor.account_id, &space_id, &request)?;
        let device = self.device_record_at(&request.device_id, now / 1000)?;
        if device.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        if request.device_id == business.controller_device_id {
            self.check_request_login(&request_id, now / 1000, Some(&actor.session_id))?;
        }
        verify_device_action(&transcript, &device.public_key, &crate::control::decode_signature(&request.signature)?)?;
        let nodes = [relay_node(self, &request.node_ids[0], now)?, relay_node(self, &request.node_ids[1], now)?];
        let expires = request.path.expires_at_unix_ms;
        if expires <= now || expires - now > 30_000 || expires > (i64::MAX as u64).saturating_sub(1000)
            || nodes.iter().any(|node| expires > node.lease_end || node.policy != business.policy_revision)
        {
            return Err(StorageError::Forbidden);
        }
        let snapshot = read_snapshot(&tx, &space_id, now)?;
        current_topology(self, &snapshot, &request.node_ids, &nodes, &request.topology_digests, expires, now)?;
        let ids = [&request.path.path_grant_id, &request.path.connectivity_grant_id,
            &request.transit_grant_ids[0], &request.transit_grant_ids[1]];
        if ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len() {
            return Err(StorageError::Conflict);
        }
        for id in &request.transit_grant_ids {
            remote_paths::grant_id_available(&tx, &space_id, id)?;
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM all_relay_capacity WHERE id=?1 UNION ALL SELECT 1 FROM turn_grants WHERE id=?1 UNION ALL SELECT 1 FROM network_remote_chains WHERE route_id=?1)",
            [&request.route_id], |r|r.get(0),
        )?;
        if exists { return Err(StorageError::Conflict); }
        let quota = self.relay_quota_current()?;
        let controller = self.device_record_at(&business.controller_device_id, now / 1000)?;
        let host = self.device_record_at(&business.host_device_id, now / 1000)?;
        let relays = nodes.each_ref().map(|node| PeerId::from_public_key(&node.key));
        let mut allowed = relays.to_vec();
        allowed.sort();
        let path = self.issue_network_path_in_transaction(
            &tx, actor, signer,
            NetworkRemotePathIssuance { space_id: space_id.clone(), request_id, request: request.path },
            PathPolicy { allow_direct: false, relays: allowed, max_hops: 2 }, now,
        )?;
        path.verified().check_route(&snapshot.verification(), &relays)?;
        let references: Vec<u8> = request.topology_digests.into_iter().flatten().collect();
        tx.execute("INSERT INTO network_remote_chains(route_id,space_id,path_grant_id,topology_digests) VALUES(?1,?2,?3,?4)",
            params![request.route_id,space_id,path.verified().claims().scope.grant_id,references])?;
        let mut transits = Vec::new();
        for index in 0..2 {
            let node = &nodes[index];
            // The first insert is visible to the second capacity check inside
            // this same transaction. Any later failure rolls both promises back.
            self.reserve_capacity(&quota, &controller.account, &host.account,
                Some((&request.node_ids[index], node.maximum)), now)?;
            let claims = TransitClaims {
                scope: GrantScope { grant_id: request.transit_grant_ids[index].clone(), ..path.verified().claims().scope.clone() },
                peers: path.verified().peers(), transport_group: path.verified().transport_group_id(),
                route_id: request.route_id.clone(), relay: relays[index],
                previous: if index == 0 { path.verified().peers().first } else { relays[0] },
                next: if index == 0 { relays[1] } else { path.verified().peers().second },
                remaining_hops: (2 - index) as u8, byte_limit: quota.limits.bytes_per_allocation,
            };
            let signed = signer.sign(&GrantClaims::Transit(claims))?;
            verify_network_grant(&signed, &snapshot.verification())?;
            tx.execute("INSERT INTO network_remote_chain_hops(route_id,position,space_id,transit_grant_id,node_id,node_key,runtime_id,runtime_generation,endpoint_revision,security_epoch,policy_revision,quota_revision,control_runtime_id,controller_account_id,host_account_id,byte_limit,promised_until,transit_claims,transit_signature)
                VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
                params![request.route_id,index as u8,space_id,request.transit_grant_ids[index],request.node_ids[index],
                    node.key.as_slice(),node.runtime,node.generation,node.endpoint_revision,business.security_epoch,business.policy_revision,
                    quota.revision,lifecycle.runtime_id,controller.account,host.account,quota.limits.bytes_per_allocation,expires+1000,signed.claims,signed.signature])?;
            transits.push(signed);
        }
        audit(&tx, "network_remote_chain_reserved", &request.route_id, auditing::device(actor, &request.device_id))?;
        observe(&tx, &space_id, now)?;
        tx.commit()?;
        Ok(NetworkRemoteRelayChainBundle {
            route_id: request.route_id, path,
            transits: transits.try_into().map_err(|_| StorageError::Conflict)?,
            nodes: nodes.into_iter().zip(request.node_ids).map(|(node,node_id)| NodeEndpointsView {
                node_id, revision: node.endpoint_revision, endpoints: node.endpoints,
            }).collect::<Vec<_>>().try_into().map_err(|_| StorageError::Conflict)?,
            topology_digests: request.topology_digests,
        })
    }

    pub fn network_remote_chain(
        &mut self, lifecycle: &RelayLifecycle, actor: &Principal,
        space: &str, route: &str, now: u64,
    ) -> Result<NetworkRemoteRelayChainBundle, StorageError> {
        require_id(route)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        self.resume_relay_reservations(lifecycle, now)?;
        let row: Option<(String, Vec<u8>)> = tx.query_row(
            "SELECT path_grant_id,topology_digests FROM network_remote_chains WHERE route_id=?1 AND space_id=?2",
            params![route,space], |r|Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        let (path_id, references) = row.ok_or(StorageError::Forbidden)?;
        let references: [u8;64] = references.try_into().map_err(|_| StorageError::Forbidden)?;
        let digests: [[u8;32];2] = [references[..32].try_into().map_err(|_| StorageError::Forbidden)?, references[32..].try_into().map_err(|_| StorageError::Forbidden)?];
        let path = self.network_path_current_with_hops(&tx, Some(actor), space, &path_id, 2, now)?;
        let business = remote_paths::current_business(self, &path.request_id, now)?;
        let quota = self.relay_quota_current()?;
        let controller = self.device_record_at(&business.controller_device_id, now/1000)?;
        let host = self.device_record_at(&business.host_device_id, now/1000)?;
        let snapshot = read_snapshot(&tx, space, now)?;
        let mut node_ids = Vec::new();
        let mut nodes = Vec::new();
        let mut transits = Vec::new();
        for position in 0..2 {
            type Row = (String, Vec<u8>, String, u64, u64, u64, u64, u64, String, String, String, u64, u64, bool, String, Vec<u8>, Vec<u8>);
            let row: Option<Row> = tx.query_row("SELECT node_id,node_key,runtime_id,runtime_generation,endpoint_revision,security_epoch,policy_revision,quota_revision,control_runtime_id,controller_account_id,host_account_id,byte_limit,promised_until,closed,transit_grant_id,transit_claims,transit_signature FROM network_remote_chain_hops WHERE route_id=?1 AND position=?2 AND space_id=?3",
                params![route,position,space], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?,r.get(16)?))).optional()?;
            let (id,key,runtime,generation,revision,security,policy,quota_revision,control,ca,ha,bytes,held,closed,grant,claims,signature) = row.ok_or(StorageError::Forbidden)?;
            let node = relay_node(self, &id, now)?;
            let signed = SignedNetworkGrant { claims, signature };
            let verified = verify_network_grant(&signed, &snapshot.verification())?;
            let GrantClaims::Transit(transit) = verified.claims() else { return Err(StorageError::Forbidden); };
            if closed || key != node.key || runtime != node.runtime || generation != node.generation
                || revision != node.endpoint_revision || security != self.security_epoch()?
                || policy != node.policy || quota_revision != quota.revision || control != lifecycle.runtime_id
                || ca != controller.account || ha != host.account || bytes != quota.limits.bytes_per_allocation
                || transit.byte_limit != bytes || transit.scope.grant_id != grant
                || transit.route_id != route || transit.relay != PeerId::from_public_key(&node.key)
                || transit.peers != path.verified().peers() || transit.transport_group != path.verified().transport_group_id()
                || transit.scope != (GrantScope { grant_id: grant, ..path.verified().claims().scope.clone() })
                || transit.scope.expires_at_ms > node.lease_end || held != transit.scope.expires_at_ms+1000
            { return Err(StorageError::Forbidden); }
            node_ids.push(id); nodes.push(node); transits.push(signed);
        }
        let node_ids: [String;2] = node_ids.try_into().map_err(|_| StorageError::Forbidden)?;
        let nodes: [RelayNode;2] = nodes.try_into().map_err(|_| StorageError::Forbidden)?;
        current_topology(self, &snapshot, &node_ids, &nodes, &digests, path.verified().claims().scope.expires_at_ms, now)?;
        let peers = path.verified().peers();
        let relays = nodes.each_ref().map(|node| PeerId::from_public_key(&node.key));
        path.verified().check_route(&snapshot.verification(), &relays)?;
        for (position, signed) in transits.iter().enumerate() {
            let GrantClaims::Transit(transit) = GrantClaims::decode_canonical(&signed.claims)? else { return Err(StorageError::Forbidden); };
            if transit.previous != (if position == 0 { peers.first } else { relays[0] })
                || transit.next != (if position == 0 { relays[1] } else { peers.second })
                || transit.remaining_hops != (2-position) as u8 { return Err(StorageError::Forbidden); }
        }
        tx.commit()?;
        Ok(NetworkRemoteRelayChainBundle {
            route_id: route.into(), path,
            transits: transits.try_into().map_err(|_| StorageError::Forbidden)?,
            nodes: nodes.into_iter().zip(node_ids).map(|(node,node_id)|NodeEndpointsView {
                node_id, revision:node.endpoint_revision, endpoints:node.endpoints,
            }).collect::<Vec<_>>().try_into().map_err(|_| StorageError::Forbidden)?, topology_digests:digests,
        })
    }

    pub fn revoke_network_remote_chain(&mut self, actor: &Principal, space: &str, route: &str, now: u64) -> Result<(), StorageError> {
        require_id(route)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        let row: Option<(String,String)> = tx.query_row("SELECT c.path_grant_id,p.request_id FROM network_remote_chains c JOIN network_remote_paths p ON p.space_id=c.space_id AND p.path_grant_id=c.path_grant_id WHERE c.space_id=?1 AND c.route_id=?2",
            params![space,route], |r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (path,request) = row.ok_or(StorageError::Forbidden)?;
        self.remote(actor, &request)?;
        tx.execute("UPDATE network_remote_paths SET revoked=1 WHERE space_id=?1 AND path_grant_id=?2",params![space,path])?;
        if tx.execute("UPDATE network_remote_chain_hops SET closed=1 WHERE route_id=?1 AND closed=0",[route])? > 0 {
            audit(&tx,"network_remote_chain_revoked",route,auditing::management(actor))?;
        }
        observe(&tx,space,now)?;
        tx.commit()?;
        Ok(())
    }
}
