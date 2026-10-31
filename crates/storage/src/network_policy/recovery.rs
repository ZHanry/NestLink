//! A dual-signed successor cannot select a relay outside its original group.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{network::remote_route_binding_digest, reconnection};
use nestlink_protocol::{PermitClaims, api::{ReconnectionChoice, NetworkRemoteRelayRequest}};
use prost::Message;

impl Store {
    pub(super) fn validate_network_recovery_parent(&self, tx: &Transaction<'_>, business: &PermitClaims, now: u64) -> Result<(),StorageError> {
        if let Some(receipt) = self.receipt(&business.session_id)? && receipt.next == *business {
            self.validate_network_recovery_choice(tx,&receipt.previous,&receipt.submission.choice,now)?;
        }
        Ok(())
    }
    pub(super) fn validate_network_recovery_reservation(&self, tx: &Transaction<'_>, business: &PermitClaims,
        space: &str, request: &NetworkRemoteRelayRequest, now: u64) -> Result<(), StorageError> {
        let Some(receipt) = self.receipt(&business.session_id)? else { return Ok(()); };
        if receipt.next != *business { return Ok(()); }
        let choice = &receipt.submission.choice;
        let Some(recovery) = &choice.network_recovery else { return Ok(()); };
        self.validate_network_recovery_choice(tx,&receipt.previous,choice,now)?;
        let id = |purpose| reconnection::network_recovery_id(&receipt.previous,choice,purpose);
        let members: (String,String) = tx.query_row("SELECT controller_membership_id,host_membership_id FROM network_remote_paths WHERE space_id=?1 AND path_grant_id=?2",
            params![recovery.space_id,recovery.path_grant_id], |row| Ok((row.get(0)?,row.get(1)?)))?;
        if space != recovery.space_id || request.allocation.node_id != recovery.target_node_id
            || request.allocation.device_id != business.controller_device_id
            || request.allocation.allocation_id != id("allocation")? || request.transit_grant_id != id("transit")?
            || request.path.path_grant_id != id("path")? || request.path.connectivity_grant_id != id("connectivity")?
            || request.path.controller_membership_grant_id != members.0 || request.path.host_membership_grant_id != members.1
            || request.path.expires_at_unix_ms != recovery.expires_at_unix_ms {
            return Err(StorageError::Forbidden);
        }
        Ok(())
    }
    pub(crate) fn validate_network_recovery_choice(&self, tx: &Transaction<'_>, previous: &PermitClaims,
        choice: &ReconnectionChoice, now: u64) -> Result<(), StorageError> {
        let Some(recovery) = &choice.network_recovery else { return Ok(()); };
        reconnection::validate_network_recovery(previous, recovery)?;
        if now >= recovery.expires_at_unix_ms { return Err(StorageError::Forbidden); }
        let path_id: Option<String> = tx.query_row(
            "SELECT path_grant_id FROM network_remote_route_sets WHERE space_id=?1 AND set_id=?2",
            params![recovery.space_id,recovery.route_set_id], |row| row.get(0)).optional()?;
        if path_id.as_deref() != Some(recovery.path_grant_id.as_str()) { return Err(StorageError::Forbidden); }
        // Only called with a current old permit or the exact previously verified
        // committed receipt. The old generation is never reopened for business.
        let path = self.network_route_set_recovery_path(tx, &recovery.space_id,
            &recovery.path_grant_id, now, previous)?;
        let group = path.verified().transport_group_id();
        if recovery.transport_group != URL_SAFE_NO_PAD.encode(group)
            || recovery.expires_at_unix_ms != path.verified().claims().scope.expires_at_ms {
            return Err(StorageError::Forbidden);
        }
        let snapshot = read_snapshot(tx, &recovery.space_id, now)?;
        let connectivity = verify_network_grant(&path.connectivity, &snapshot.verification())?;
        let mut original_claims = Vec::new();
        let mut target = false;
        for position in 0..2 {
            type Row = (Vec<u8>,Vec<u8>,String,Vec<u8>,String,u64,u64,String,bool);
            let row: Option<Row> = tx.query_row("SELECT transit_claims,transit_signature,node_id,node_key,runtime_id,runtime_generation,endpoint_revision,node_endpoints_json,closed FROM network_remote_route_set_members WHERE space_id=?1 AND set_id=?2 AND position=?3",
                params![recovery.space_id,recovery.route_set_id,position], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?))).optional()?;
            let (claims,signature,node_id,key,runtime,generation,revision,endpoints,closed) = row.ok_or(StorageError::Forbidden)?;
            let signed = SignedNetworkGrant { claims, signature };
            let transit = verify_network_grant(&signed, &snapshot.verification())?;
            let GrantClaims::Transit(forward) = transit.claims() else { return Err(StorageError::Forbidden); };
            let original_key: [u8;32] = key.as_slice().try_into().map_err(|_| StorageError::Forbidden)?;
            if closed || forward.transport_group != group || forward.peers != path.verified().peers()
                || forward.relay != PeerId::from_public_key(&original_key)
                || forward.previous != forward.peers.first || forward.next != forward.peers.second
                || forward.remaining_hops != 1 || forward.scope.expires_at_ms != recovery.expires_at_unix_ms {
                return Err(StorageError::Forbidden);
            }
            path.verified().check_route(&snapshot.verification(), &[forward.relay])?;
            if node_id == recovery.target_node_id {
                let binding = remote_route_binding_digest(group, connectivity.digest(), transit.digest(),
                    digest(&previous.encode_to_vec()), previous.connection_generation);
                let node = remote_relays::relay_node(self, &node_id, now)?;
                if recovery.target_route_binding != URL_SAFE_NO_PAD.encode(binding)
                    || node.key != original_key || node.runtime != runtime || node.generation != generation
                    || node.endpoint_revision != revision || node.policy != previous.policy_revision
                    || node.lease_end < recovery.expires_at_unix_ms
                    || serde_json::to_string(&node.endpoints)? != endpoints { return Err(StorageError::Forbidden); }
                target = true;
            }
            original_claims.push(signed.claims);
        }
        if !target || recovery.original_fingerprint != URL_SAFE_NO_PAD.encode(reconnection::route_set_fingerprint(
            &path.path.claims, [&original_claims[0], &original_claims[1]])) { return Err(StorageError::Forbidden); }
        Ok(())
    }
}
