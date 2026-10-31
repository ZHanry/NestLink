//! One original path, two separately metered one-hop allocations. The existing
//! quota view sees the first insert before the second admission in one transaction.
use super::*;
use crate::relay_reservations::RelayLifecycle;
use nestlink_identity::{network::remote_route_set_reservation_transcript, verify_device_action};
use nestlink_protocol::{api::{NetworkRemoteRouteSetRequest, NodeEndpointsView}, network::{PathPolicy, TransitClaims}};
use remote_relays::relay_node;

pub struct NetworkRemoteRouteSetIssuance {
    pub space_id: String,
    pub request_id: String,
    pub request: NetworkRemoteRouteSetRequest,
}
pub struct NetworkRemoteRouteSetMemberBundle {
    pub allocation_id: String,
    pub transit: SignedNetworkGrant,
    pub node: NodeEndpointsView,
    pub available: bool,
}
pub struct NetworkRemoteRouteSetBundle {
    pub set_id: String,
    pub path: NetworkRemotePathBundle,
    pub members: [NetworkRemoteRouteSetMemberBundle; 2],
}
struct StoredMember {
    allocation: String, transit_id: String, node_id: String, key: Vec<u8>,
    runtime: String, generation: u64, revision: u64, security: u64, policy: u64,
    quota: u64, control: String, controller: String, host: String, bytes: u64,
    held: u64, closed: bool, signed: SignedNetworkGrant, endpoints: String,
}

impl Store {
    pub fn issue_network_remote_route_set(
        &mut self,
        lifecycle: &RelayLifecycle,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        issuance: NetworkRemoteRouteSetIssuance,
        now: u64,
    ) -> Result<NetworkRemoteRouteSetBundle, StorageError> {
        let NetworkRemoteRouteSetIssuance { space_id, request_id, request } = issuance;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        self.remote(actor, &request_id)?;
        self.resume_relay_reservations(lifecycle, now)?;
        let business = remote_paths::current_business(self, &request_id, now)?;
        let transcript = remote_route_set_reservation_transcript(&business, &actor.account_id, &space_id, &request)?;
        let device = self.device_record_at(&request.device_id, now / 1000)?;
        if device.account != actor.account_id { return Err(StorageError::Forbidden); }
        if request.device_id == business.controller_device_id {
            self.check_request_login(&request_id, now / 1000, Some(&actor.session_id))?;
        }
        verify_device_action(&transcript, &device.public_key, &crate::control::decode_signature(&request.signature)?)?;
        let nodes = [relay_node(self, &request.members[0].node_id, now)?, relay_node(self, &request.members[1].node_id, now)?];
        let expires = request.path.expires_at_unix_ms;
        if expires <= now || expires - now > 30_000 || expires > (i64::MAX as u64).saturating_sub(1000)
            || nodes.iter().any(|node| expires > node.lease_end || node.policy != business.policy_revision)
            || nodes[0].key == nodes[1].key
        { return Err(StorageError::Forbidden); }
        for id in std::iter::once(&request.set_id).chain(request.members.iter().map(|member| &member.allocation_id)) {
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM all_relay_capacity WHERE id=?1 UNION ALL SELECT 1 FROM turn_grants WHERE id=?1 UNION ALL SELECT 1 FROM network_remote_chains WHERE route_id=?1 UNION ALL SELECT 1 FROM network_remote_route_sets WHERE set_id=?1)", [id], |row| row.get(0))?;
            if exists { return Err(StorageError::Conflict); }
        }
        for member in &request.members { remote_paths::grant_id_available(&tx, &space_id, &member.transit_grant_id)?; }
        let quota = self.relay_quota_current()?;
        if quota.limits.bytes_per_allocation < 2 { return Err(StorageError::RateLimited); }
        let controller = self.device_record_at(&business.controller_device_id, now / 1000)?;
        let host = self.device_record_at(&business.host_device_id, now / 1000)?;
        let mut relays = nodes.each_ref().map(|node| PeerId::from_public_key(&node.key)).to_vec();
        relays.sort();
        let path = self.issue_network_path_in_transaction(&tx, actor, signer,
            NetworkRemotePathIssuance { space_id: space_id.clone(), request_id, request: request.path },
            PathPolicy { allow_direct: false, relays, max_hops: 1 }, now)?;
        tx.execute("INSERT INTO network_remote_route_sets(set_id,space_id,path_grant_id) VALUES(?1,?2,?3)", params![request.set_id,space_id,path.verified().claims().scope.grant_id])?;
        let snapshot = read_snapshot(&tx, &space_id, now)?;
        let mut members = Vec::with_capacity(2);
        for (index, (member, node)) in request.members.into_iter().zip(nodes).enumerate() {
            self.reserve_capacity(&quota, &controller.account, &host.account, Some((&member.node_id, node.maximum)), now)?;
            let relay = PeerId::from_public_key(&node.key);
            path.verified().check_route(&snapshot.verification(), &[relay])?;
            let byte_limit = quota.limits.bytes_per_allocation / 2 + if index == 0 { quota.limits.bytes_per_allocation % 2 } else { 0 };
            let transit = signer.sign(&GrantClaims::Transit(TransitClaims {
                scope: GrantScope { grant_id: member.transit_grant_id.clone(), ..path.verified().claims().scope.clone() },
                peers: path.verified().peers(), transport_group: path.verified().transport_group_id(), route_id: member.allocation_id.clone(),
                relay, previous: path.verified().peers().first, next: path.verified().peers().second,
                remaining_hops: 1, byte_limit,
            }))?;
            verify_network_grant(&transit, &snapshot.verification())?;
            tx.execute("INSERT INTO network_remote_route_set_members(allocation_id,set_id,position,space_id,transit_grant_id,node_id,node_key,runtime_id,runtime_generation,endpoint_revision,security_epoch,policy_revision,quota_revision,control_runtime_id,controller_account_id,host_account_id,byte_limit,promised_until,transit_claims,transit_signature,node_endpoints_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
                params![member.allocation_id,request.set_id,index as u8,space_id,member.transit_grant_id,member.node_id,node.key.as_slice(),node.runtime,node.generation,node.endpoint_revision,business.security_epoch,business.policy_revision,quota.revision,lifecycle.runtime_id,controller.account,host.account,byte_limit,expires+1000,transit.claims,transit.signature,serde_json::to_string(&node.endpoints)?])?;
            members.push(NetworkRemoteRouteSetMemberBundle { allocation_id: member.allocation_id, transit, node: NodeEndpointsView { node_id: member.node_id, revision: node.endpoint_revision, endpoints: node.endpoints }, available: true });
        }
        audit(&tx, "network_remote_route_set_reserved", &request.set_id, auditing::device(actor, &request.device_id))?;
        observe(&tx, &space_id, now)?;
        let members = members.try_into().map_err(|_| StorageError::Conflict)?;
        tx.commit()?;
        Ok(NetworkRemoteRouteSetBundle { set_id: request.set_id, path, members })
    }

    pub fn network_remote_route_set(&mut self, lifecycle: &RelayLifecycle, actor: &Principal, space: &str, set: &str, now: u64) -> Result<NetworkRemoteRouteSetBundle, StorageError> {
        require_id(set)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        self.resume_relay_reservations(lifecycle, now)?;
        let bundle = self.network_route_set_current_in_transaction(&tx, lifecycle, Some(actor), space, set, now)?;
        tx.commit()?;
        Ok(bundle)
    }

    pub(crate) fn network_route_set_current_in_transaction(&self, tx: &Transaction<'_>, lifecycle: &RelayLifecycle, actor: Option<&Principal>, space: &str, set: &str, now: u64) -> Result<NetworkRemoteRouteSetBundle, StorageError> {
        let path_id: Option<String> = tx.query_row("SELECT path_grant_id FROM network_remote_route_sets WHERE space_id=?1 AND set_id=?2", params![space,set], |row| row.get(0)).optional()?;
        let path = self.network_route_set_path_current(tx, actor, space, &path_id.ok_or(StorageError::Forbidden)?, now)?;
        let business = remote_paths::current_business(self, &path.request_id, now)?;
        let controller = self.device_record_at(&business.controller_device_id, now / 1000)?;
        let host = self.device_record_at(&business.host_device_id, now / 1000)?;
        let quota = self.relay_quota_current()?;
        let snapshot = read_snapshot(tx, space, now)?;
        let mut result = Vec::with_capacity(2);
        let mut relays = Vec::with_capacity(2);
        for position in 0..2 {
            let row: Option<StoredMember> = tx.query_row("SELECT allocation_id,transit_grant_id,node_id,node_key,runtime_id,runtime_generation,endpoint_revision,security_epoch,policy_revision,quota_revision,control_runtime_id,controller_account_id,host_account_id,byte_limit,promised_until,closed,transit_claims,transit_signature,node_endpoints_json FROM network_remote_route_set_members WHERE set_id=?1 AND space_id=?2 AND position=?3", params![set,space,position], |row| Ok(StoredMember {
                allocation:row.get(0)?,transit_id:row.get(1)?,node_id:row.get(2)?,key:row.get(3)?,runtime:row.get(4)?,generation:row.get(5)?,revision:row.get(6)?,security:row.get(7)?,policy:row.get(8)?,quota:row.get(9)?,control:row.get(10)?,controller:row.get(11)?,host:row.get(12)?,bytes:row.get(13)?,held:row.get(14)?,closed:row.get(15)?,signed:SignedNetworkGrant {claims:row.get(16)?,signature:row.get(17)?},endpoints:row.get(18)?
            })).optional()?;
            let row = row.ok_or(StorageError::Forbidden)?;
            let endpoints: nestlink_protocol::api::NodeEndpoints = serde_json::from_str(&row.endpoints)?;
            endpoints.validate()?;
            let original_key: [u8;32] = row.key.as_slice().try_into().map_err(|_| StorageError::Forbidden)?;
            let verified = verify_network_grant(&row.signed, &snapshot.verification())?;
            let GrantClaims::Transit(transit) = verified.claims() else { return Err(StorageError::Forbidden); };
            let relay = PeerId::from_public_key(&original_key);
            let expected_bytes = quota.limits.bytes_per_allocation / 2 + if position == 0 { quota.limits.bytes_per_allocation % 2 } else { 0 };
            if row.security != self.security_epoch()? || row.policy != business.policy_revision
                || row.quota != quota.revision || row.control != lifecycle.runtime_id
                || row.controller != controller.account || row.host != host.account
                || row.bytes != expected_bytes || endpoints.quic_uri.is_none()
                || transit.byte_limit != row.bytes || row.held != transit.scope.expires_at_ms + 1000
                || transit.scope != (GrantScope { grant_id: row.transit_id, ..path.verified().claims().scope.clone() })
                || transit.route_id != row.allocation
                || transit.transport_group != path.verified().transport_group_id() || transit.peers != path.verified().peers()
                || transit.relay != relay || transit.previous != path.verified().peers().first
                || transit.next != path.verified().peers().second || transit.remaining_hops != 1
            { return Err(StorageError::Forbidden); }
            // A node's availability is not group revocation. Preserve every
            // original signed byte and endpoint mapping while independently
            // checking this member's current runtime and lease for admission.
            let available = match relay_node(self, &row.node_id, now) {
                Ok(node) => !row.closed && row.key == node.key && row.runtime == node.runtime
                    && row.generation == node.generation && row.revision == node.endpoint_revision
                    && row.policy == node.policy && transit.scope.expires_at_ms <= node.lease_end
                    && serde_json::to_string(&node.endpoints)? == row.endpoints,
                Err(StorageError::Forbidden) => false,
                Err(error) => return Err(error),
            };
            path.verified().check_route(&snapshot.verification(), &[relay])?;
            relays.push(relay);
            result.push(NetworkRemoteRouteSetMemberBundle { allocation_id: row.allocation, transit: row.signed, node: NodeEndpointsView { node_id: row.node_id, revision: row.revision, endpoints }, available });
        }
        relays.sort();
        if relays[0] == relays[1] || path.verified().claims().policy.relays != relays
            || result[0].allocation_id >= result[1].allocation_id || result[0].node.node_id == result[1].node.node_id
        { return Err(StorageError::Forbidden); }
        Ok(NetworkRemoteRouteSetBundle { set_id: set.into(), path, members: result.try_into().map_err(|_| StorageError::Forbidden)? })
    }

    /// Revocation removes all forwarding authority; immutable capacity promises
    /// remain held until their original expiry and the existing hold margin.
    pub fn revoke_network_remote_route_set(&mut self, actor: &Principal, space: &str, set: &str, now: u64) -> Result<(), StorageError> {
        require_id(set)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now)?)?;
        read_snapshot(&tx, space, now)?;
        let row: Option<(String,String)> = tx.query_row("SELECT s.path_grant_id,p.request_id FROM network_remote_route_sets s JOIN network_remote_paths p ON p.space_id=s.space_id AND p.path_grant_id=s.path_grant_id WHERE s.space_id=?1 AND s.set_id=?2", params![space,set], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
        let (path, request) = row.ok_or(StorageError::Forbidden)?;
        self.remote(actor, &request)?;
        tx.execute("UPDATE network_remote_paths SET revoked=1 WHERE space_id=?1 AND path_grant_id=?2", params![space,path])?;
        if tx.execute("UPDATE network_remote_route_set_members SET closed=1 WHERE space_id=?1 AND set_id=?2 AND closed=0", params![space,set])? > 0 {
            audit(&tx, "network_remote_route_set_revoked", set, auditing::management(actor))?;
        }
        observe(&tx, space, now)?;
        tx.commit()?;
        Ok(())
    }

    /// The original node snapshot delegates only that member's original route.
    /// It does not expose the other node's allocation or create a second slot.
    pub(super) fn network_route_set_member_current(&self, tx: &Transaction<'_>, lifecycle: &RelayLifecycle, space: &str, allocation: &str, now: u64) -> Result<NetworkRemoteRelayBundle, StorageError> {
        let set: Option<String> = tx.query_row("SELECT set_id FROM network_remote_route_set_members WHERE space_id=?1 AND allocation_id=?2", params![space,allocation], |row| row.get(0)).optional()?;
        let bundle = self.network_route_set_current_in_transaction(tx, lifecycle, None, space, &set.ok_or(StorageError::Forbidden)?, now)?;
        let member = bundle.members.into_iter().find(|member| member.allocation_id == allocation).ok_or(StorageError::Forbidden)?;
        if !member.available { return Err(StorageError::Forbidden); }
        Ok(NetworkRemoteRelayBundle { allocation_id: member.allocation_id, path: bundle.path, transit: member.transit, node: member.node })
    }
}
