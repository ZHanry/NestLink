//! Private-purpose routes borrow the original relay capacity and service budget.
use super::*;
use crate::{
    network_policy::{remote_chains::topology_continuity, remote_relays::relay_node},
    relay_reservations::RelayLifecycle,
};
use nestlink_identity::{
    network::{
        NetworkAuthoritySigner, private_service_allocation_binding,
        verify_private_service_route_request,
    },
    nodes::NodePolicySigner,
};
use nestlink_protocol::{
    NodeNetworkRelayResource, NodeResourceQueryClaims, RelayAllocationClaims, RelayTransport,
    api::NodeEndpointsView,
    network::{GrantClaims, GrantScope, PathPolicy, PeerId, PeerPair, TransitClaims},
    service_plane::publication::{SERVICE_DELEGATION_MS, ServiceIssuerDelegation},
};

fn unavailable_authority(error: &StorageError) -> bool {
    matches!(
        error,
        StorageError::Forbidden | StorageError::Unauthorized | StorageError::Conflict
    ) || matches!(error,StorageError::Proof(proof) if matches!(proof.code,nestlink_protocol::ErrorCode::PermissionRequired|nestlink_protocol::ErrorCode::LeaseExpired|nestlink_protocol::ErrorCode::PolicyRevoked))
}

impl Store {
    pub fn private_service_access_space(
        &self,
        actor: &Principal,
        service: &str,
        consumer: &str,
        now: u64,
    ) -> Result<String, StorageError> {
        Ok(self
            .private_consumer(actor, service, consumer, now)?
            .2
            .space_id)
    }
    pub(super) fn private_service_selected_path(
        &self,
        grant: &str,
    ) -> Result<nestlink_protocol::Path, StorageError> {
        let json: Option<String> = self.connection.query_row(
            "SELECT network_json FROM private_service_leases WHERE grant_id=?1",
            [grant],
            |r| r.get(0),
        )?;
        let relay = match json {
            Some(json) => serde_json::from_str::<PrivateServiceNetworkPath>(&json)?
                .relay
                .is_some(),
            None => false,
        };
        Ok(if relay {
            nestlink_protocol::Path::Relay
        } else {
            nestlink_protocol::Path::Direct
        })
    }

    /// The lease, one shared plaintext reservation and every ordered relay hop
    /// commit together. Failure leaves no partial service or transport promise.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_private_service_grant(
        &mut self,
        lifecycle: &RelayLifecycle,
        actor: &Principal,
        service: &str,
        request: PrivateServiceAccessRequest,
        service_signer: &ServiceLeaseSigner,
        network_signer: &NetworkAuthoritySigner,
        node_signer: &NodePolicySigner,
        now: u64,
    ) -> Result<PrivateServiceGrant, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let relay_nodes = match &request.route {
            PrivateServiceRouteRequest::Direct => Vec::new(),
            PrivateServiceRouteRequest::Relay {
                node_ids,
                topology_digests,
                signature,
            } => {
                if !(1..=2).contains(&node_ids.len())
                    || topology_digests.len() != if node_ids.len() == 2 { 2 } else { 0 }
                    || node_ids.len() == 2 && node_ids[0] == node_ids[1]
                {
                    return Err(StorageError::Forbidden);
                }
                let device = self.device_record_at(&request.consumer_device_id, now / 1000)?;
                if device.account != actor.account_id {
                    return Err(StorageError::Forbidden);
                }
                verify_private_service_route_request(
                    service,
                    &request,
                    &device.public_key,
                    &crate::control::decode_signature(signature)?,
                )?;
                self.resume_relay_reservations(lifecycle, now)?;
                node_ids
                    .iter()
                    .map(|id| relay_node(self, id, now))
                    .collect::<Result<Vec<_>, _>>()?
            }
        };
        let lease = self.issue_private_service_in_transaction(
            &tx,
            actor,
            service,
            request.clone(),
            service_signer,
            now,
        )?;
        let business = verify_private_service_lease(&lease, &service_signer.public_key())?;
        let usage: ServiceUsageBudgetGrantClaims = decode_service_message(
            &business.lease().claims().usage_grant.claims,
            SERVICE_USAGE_BYTES,
        )?;
        let old: Option<String> = tx.query_row(
            "SELECT network_json FROM private_service_leases WHERE grant_id=?1",
            [&usage.grant_id],
            |r| r.get(0),
        )?;
        if let Some(json) = old {
            let network = serde_json::from_str(&json)?;
            let snapshot =
                crate::network_policy::read_snapshot(&tx, &business.claims().space_id, now)?;
            network::verify(&snapshot, &network, &business)?;
            self.private_service_relay_current(&tx, &usage.grant_id, &business, now)?;
            let grant =
                Self::private_service_grant_envelope(lease, network, service_signer, node_signer)?;
            tx.commit()?;
            return Ok(grant);
        }
        let peers = PeerPair::new(
            PeerId::from_public_key(&business.claims().consumer_public_key),
            PeerId::from_public_key(&business.claims().host_public_key),
        )?;
        let relay_peers = relay_nodes
            .iter()
            .map(|n| PeerId::from_public_key(&n.key))
            .collect::<Vec<_>>();
        if relay_peers
            .iter()
            .any(|p| *p == peers.first || *p == peers.second)
            || relay_peers.len() == 2 && relay_peers[0] == relay_peers[1]
        {
            return Err(StorageError::Forbidden);
        }
        let mut allowed_relays = relay_peers.clone();
        allowed_relays.sort();
        let mut network = self.issue_private_service_network_path_in_transaction(
            &tx,
            actor,
            &usage.grant_id,
            &business,
            network_signer,
            PathPolicy {
                allow_direct: relay_nodes.is_empty(),
                relays: allowed_relays,
                max_hops: relay_nodes.len() as u8,
            },
            now,
        )?;
        if !relay_nodes.is_empty() {
            let PrivateServiceRouteRequest::Relay {
                node_ids,
                topology_digests,
                ..
            } = &request.route
            else {
                return Err(StorageError::Conflict);
            };
            let snapshot =
                crate::network_policy::read_snapshot(&tx, &business.claims().space_id, now)?;
            let topology = if relay_nodes.len() == 2 {
                let ids: [String; 2] = node_ids
                    .clone()
                    .try_into()
                    .map_err(|_| StorageError::Conflict)?;
                let nodes = [
                    relay_node(self, &ids[0], now)?,
                    relay_node(self, &ids[1], now)?,
                ];
                let digests: [[u8; 32]; 2] = topology_digests
                    .clone()
                    .try_into()
                    .map_err(|_| StorageError::Conflict)?;
                Some(topology_continuity::capture(
                    self, &snapshot, &ids, &nodes, &digests, now,
                )?)
            } else {
                None
            };
            let path_signed = network::signed(&network.path)?;
            let connectivity_signed = network::signed(&network.connectivity)?;
            let c = snapshot.verify_member(
                &network::signed(&network.consumer_membership)?,
                &business.claims().consumer_device_id,
            )?;
            let h = snapshot.verify_member(
                &network::signed(&network.host_membership)?,
                &business.lease().claims().definition.host_device_id,
            )?;
            let context = snapshot.verification();
            let path = nestlink_identity::network::VerifiedNetworkPath::from_grants(
                &context,
                [c, h],
                nestlink_identity::network::verify_network_grant(&connectivity_signed, &context)?,
                nestlink_identity::network::verify_network_grant(&path_signed, &context)?,
                business.digest(),
            )?;
            let quota = self.relay_quota_current()?;
            let wire = private_service_wire_allowance(usage.byte_ceiling)?
                .min(quota.limits.bytes_per_allocation);
            if wire == 0 {
                return Err(StorageError::Forbidden);
            }
            let route_id = random_id();
            let base = business.lease().claims();
            let expires = relay_nodes
                .iter()
                .fold(base.expires_at_unix_ms, |end, node| end.min(node.lease_end));
            if expires <= now {
                return Err(StorageError::Forbidden);
            }
            let mut transits = Vec::new();
            let mut nodes = Vec::new();
            for (index, node) in relay_nodes.iter().enumerate() {
                self.reserve_capacity(
                    &quota,
                    &business.claims().consumer_account_id,
                    &base.account_id,
                    Some((&node_ids[index], node.maximum)),
                    now,
                )?;
                let transit = network_signer.sign(&GrantClaims::Transit(TransitClaims {
                    scope: GrantScope {
                        schema_version: nestlink_protocol::network::SCHEMA_VERSION,
                        deployment_id: base.deployment_id.clone(),
                        space_id: business.claims().space_id.clone(),
                        grant_id: random_id(),
                        policy_epoch: business.claims().space_policy_epoch,
                        not_before_ms: now,
                        expires_at_ms: expires,
                    },
                    route_id: route_id.clone(),
                    peers,
                    relay: relay_peers[index],
                    previous: if index == 0 {
                        peers.first
                    } else {
                        relay_peers[index - 1]
                    },
                    next: if index + 1 == relay_nodes.len() {
                        peers.second
                    } else {
                        relay_peers[index + 1]
                    },
                    transport_group: path.transport_group_id(),
                    remaining_hops: (relay_nodes.len() - index) as u8,
                    byte_limit: wire,
                }))?;
                let GrantClaims::Transit(claims) = GrantClaims::decode_canonical(&transit.claims)?
                else {
                    return Err(StorageError::Conflict);
                };
                let rate: u64 = tx.query_row(
                    "SELECT bytes_per_second FROM data_nodes WHERE id=?1",
                    [&node_ids[index]],
                    |r| r.get(0),
                )?;
                let allocation = RelayAllocationClaims {
                    schema_version: SCHEMA_VERSION,
                    deployment_id: base.deployment_id.clone(),
                    security_epoch: base.security_epoch,
                    allocation_id: claims.scope.grant_id.clone(),
                    session_id: usage.grant_id.clone(),
                    node_id: node_ids[index].clone(),
                    runtime_id: node.runtime.clone(),
                    runtime_generation: node.generation,
                    node_key_sha256: digest(&node.key).to_vec(),
                    controller_device_id: business.claims().consumer_device_id.clone(),
                    host_device_id: base.definition.host_device_id.clone(),
                    controller_key_sha256: digest(&business.claims().consumer_public_key).to_vec(),
                    host_key_sha256: digest(&business.claims().host_public_key).to_vec(),
                    controller_account_id: business.claims().consumer_account_id.clone(),
                    host_account_id: base.account_id.clone(),
                    connection_generation: 1,
                    policy_revision: base.policy_revision,
                    quota_revision: quota.revision,
                    session_binding_sha256: private_service_allocation_binding(&business).to_vec(),
                    transports: vec![RelayTransport::QuicDatagram as i32],
                    node_endpoint_revision: node.endpoint_revision,
                    grant_sequence: 1,
                    issued_at_unix_ms: now,
                    expires_at_unix_ms: expires,
                    bytes_per_second: quota.limits.bytes_per_second.min(rate),
                    bytes_per_allocation: wire,
                };
                allocation.validate()?;
                let topology_binding = topology.as_ref().map(|b| &b[index]);
                tx.execute("INSERT INTO private_service_relay_hops(grant_id,position,route_id,space_id,transit_grant_id,node_id,node_key,runtime_id,runtime_generation,endpoint_revision,security_epoch,policy_revision,quota_revision,control_runtime_id,controller_account_id,host_account_id,byte_limit,promised_until,transit_claims,transit_signature,allocation_json,original_publisher_digest,original_sequence,latest_sequence,observed_until) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?23,?24)",params![usage.grant_id,index as u8,route_id,business.claims().space_id,claims.scope.grant_id,node_ids[index],node.key.as_slice(),node.runtime,node.generation,node.endpoint_revision,base.security_epoch,base.policy_revision,quota.revision,lifecycle.runtime_id,business.claims().consumer_account_id,base.account_id,wire,expires.checked_add(1000).ok_or(StorageError::Conflict)?,transit.claims,transit.signature,serde_json::to_string(&allocation)?,topology_binding.map(|b|b.publisher.as_slice()),topology_binding.map(|b|b.sequence),topology_binding.map(|b|b.observed_until)])?;
                nodes.push(NodeEndpointsView {
                    node_id: node_ids[index].clone(),
                    revision: node.endpoint_revision,
                    endpoints: node.endpoints.clone(),
                });
                transits.push(network::view(transit)?);
            }
            let mut relay = PrivateServiceRelayRoute {
                route_id,
                transits,
                nodes,
                node_public_keys: relay_nodes.iter().map(|n| n.key).collect(),
                topology_digests: topology_digests.clone(),
                signature: Vec::new(),
            };
            relay.signature = service_signer
                .sign_private_service_relay(&business.digest(), &relay)?
                .to_vec();
            network.relay = Some(relay);
            tx.execute(
                "UPDATE private_service_leases SET network_json=?1 WHERE grant_id=?2",
                params![serde_json::to_string(&network)?, usage.grant_id],
            )?;
            network::verify(&snapshot, &network, &business)?;
        }
        let grant =
            Self::private_service_grant_envelope(lease, network, service_signer, node_signer)?;
        nestlink_identity::network::verify_private_service_grant(
            &grant,
            &node_signer.public_key(),
            &business.lease().claims().deployment_id,
            now,
        )?;
        tx.commit()?;
        Ok(grant)
    }

    pub(crate) fn private_service_grant_envelope(
        lease: SignedPrivateServiceLease,
        network: PrivateServiceNetworkPath,
        service_signer: &ServiceLeaseSigner,
        node_signer: &NodePolicySigner,
    ) -> Result<PrivateServiceGrant, StorageError> {
        let base: ServiceLeaseClaims =
            decode_service_message(&lease.service_lease.claims, SERVICE_MESSAGE_BYTES)?;
        let issuer = node_signer.sign_service_issuer_delegation(&ServiceIssuerDelegation {
            schema_version: SCHEMA_VERSION,
            deployment_id: base.deployment_id,
            security_epoch: base.security_epoch,
            policy_revision: base.policy_revision,
            service_issuer: service_signer.public_key(),
            issued_at_unix_ms: base.issued_at_unix_ms,
            expires_at_unix_ms: base
                .issued_at_unix_ms
                .checked_add(SERVICE_DELEGATION_MS)
                .ok_or(StorageError::Conflict)?,
        })?;
        Ok(PrivateServiceGrant {
            lease,
            network,
            issuer,
        })
    }

    pub(super) fn private_service_relay_current(
        &self,
        tx: &Transaction<'_>,
        grant: &str,
        business: &VerifiedPrivateServiceLease,
        now: u64,
    ) -> Result<(), StorageError> {
        let json: Option<String> = tx.query_row(
            "SELECT network_json FROM private_service_leases WHERE grant_id=?1",
            [grant],
            |r| r.get(0),
        )?;
        let Some(json) = json else {
            return Ok(());
        };
        let network: PrivateServiceNetworkPath = serde_json::from_str(&json)?;
        let Some(route) = network.relay else {
            return Ok(());
        };
        let quota = self.relay_quota_current()?;
        let control:String=tx.query_row("SELECT control_runtime_id FROM relay_reservation_settings WHERE singleton=1 AND restore_fenced=0",[],|r|r.get(0)).optional()?.ok_or(StorageError::Forbidden)?;
        if route.nodes.len() != route.transits.len()
            || route.nodes.len() != route.node_public_keys.len()
            || !(1..=2).contains(&route.nodes.len())
        {
            return Err(StorageError::Forbidden);
        }
        let mut nodes = Vec::new();
        for (index, view) in route.nodes.iter().enumerate() {
            let node = relay_node(self, &view.node_id, now)?;
            let row:Option<(String,Vec<u8>,Vec<u8>,bool,u64)>=tx.query_row("SELECT allocation_json,transit_claims,transit_signature,closed,promised_until FROM private_service_relay_hops WHERE grant_id=?1 AND position=?2 AND route_id=?3 AND space_id=?4 AND control_runtime_id=?5",params![grant,index as u8,route.route_id,business.claims().space_id,control],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
            let (allocation, claims, signature, closed, held) =
                row.ok_or(StorageError::Forbidden)?;
            let allocation: RelayAllocationClaims = serde_json::from_str(&allocation)?;
            let signed = network::signed(&route.transits[index])?;
            if closed
                || claims != signed.claims
                || signature != signed.signature
                || node.key != route.node_public_keys[index]
                || node.endpoint_revision != view.revision
                || node.endpoints != view.endpoints
                || allocation.runtime_id != node.runtime
                || allocation.runtime_generation != node.generation
                || allocation.node_endpoint_revision != node.endpoint_revision
                || allocation.security_epoch != self.security_epoch()?
                || allocation.policy_revision != self.policy()?.0
                || allocation.quota_revision != quota.revision
                || allocation.node_key_sha256 != digest(&node.key)
                || allocation.expires_at_unix_ms <= now
                || held
                    != allocation
                        .expires_at_unix_ms
                        .checked_add(1000)
                        .ok_or(StorageError::Conflict)?
            {
                return Err(StorageError::Forbidden);
            }
            nodes.push(node);
        }
        if nodes.len() == 2 {
            let snapshot =
                crate::network_policy::read_snapshot(tx, &business.claims().space_id, now)?;
            topology_continuity::private_current(
                self,
                tx,
                &snapshot,
                grant,
                &route.nodes,
                &nodes,
                now,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn private_service_host_access(
        &self,
        actor: &Principal,
        service: &str,
        runtime: &str,
        query: ServiceQuery,
        signer: &ServiceLeaseSigner,
        node_signer: &NodePolicySigner,
        now: u64,
    ) -> Result<PrivateServiceHostAccessPage, StorageError> {
        require_id(runtime)?;
        self.service_owner(actor, service, now / 1000)?;
        if query.security_epoch != self.security_epoch()? || !(1..=100).contains(&query.limit) {
            return Err(StorageError::Conflict);
        }
        if let Some(after) = &query.after_id {
            require_id(after)?;
        }
        let current:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM private_service_hosts WHERE service_id=?1 AND runtime_id=?2 AND expires_at>?3)",params![service,runtime,now],|r|r.get(0))?;
        if !current {
            return Err(StorageError::Forbidden);
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let mut statement=tx.prepare("SELECT l.grant_id FROM private_service_leases l JOIN service_usage_grants g ON g.grant_id=l.grant_id WHERE l.service_id=?1 AND l.runtime_id=?2 AND l.grant_id>?3 AND l.revoked=0 AND g.terminal=0 AND EXISTS(SELECT 1 FROM private_service_relay_hops h WHERE h.grant_id=l.grant_id AND h.closed=0) ORDER BY l.grant_id LIMIT 4097")?;
        let ids = statement
            .query_map(
                params![service, runtime, query.after_id.as_deref().unwrap_or("")],
                |r| r.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if ids.len() > 4096 {
            return Err(StorageError::RateLimited);
        }
        let mut grants = Vec::new();
        for id in ids {
            let lease = match self.private_service_lease_current(service, &id, signer, now) {
                Ok(lease) => lease,
                Err(error) if unavailable_authority(&error) => continue,
                Err(error) => return Err(error),
            };
            let business = verify_private_service_lease(&lease, &signer.public_key())?;
            match self.private_service_relay_current(&tx, &id, &business, now) {
                Ok(()) => {}
                Err(error) if unavailable_authority(&error) => continue,
                Err(error) => return Err(error),
            }
            let json: String = tx.query_row(
                "SELECT network_json FROM private_service_leases WHERE grant_id=?1",
                [id],
                |r| r.get(0),
            )?;
            let network = serde_json::from_str(&json)?;
            grants.push(Self::private_service_grant_envelope(
                lease,
                network,
                signer,
                node_signer,
            )?);
            if grants.len() > query.limit as usize {
                break;
            }
        }
        let more = grants.len() > query.limit as usize;
        grants.truncate(query.limit as usize);
        let next_id = if more {
            grants.last().map(|g| g.network.grant_id.clone())
        } else {
            None
        };
        tx.commit()?;
        Ok(PrivateServiceHostAccessPage {
            runtime_id: runtime.into(),
            grants,
            next_id,
            more,
        })
    }

    pub(crate) fn node_private_service_resources(
        &self,
        tx: &Transaction<'_>,
        query: &NodeResourceQueryClaims,
        signer: &ServiceLeaseSigner,
        node_signer: &NodePolicySigner,
        now: u64,
    ) -> Result<Vec<NodeNetworkRelayResource>, StorageError> {
        let mut statement=tx.prepare("SELECT h.grant_id,l.service_id,h.allocation_json FROM private_service_relay_hops h JOIN private_service_leases l ON l.grant_id=h.grant_id WHERE h.node_id=?1 AND h.runtime_id=?2 AND h.runtime_generation=?3 AND h.closed=0 AND h.promised_until>?4 ORDER BY h.transit_grant_id LIMIT 4097")?;
        let rows = statement
            .query_map(
                params![
                    query.node_id,
                    query.runtime_id,
                    query.runtime_generation,
                    now
                ],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if rows.len() > 4096 {
            return Err(StorageError::RateLimited);
        }
        let mut resources = Vec::new();
        for (id, service, allocation) in rows {
            let lease = match self.private_service_lease_current(&service, &id, signer, now) {
                Ok(lease) => lease,
                Err(error) if unavailable_authority(&error) => continue,
                Err(error) => return Err(error),
            };
            let business = verify_private_service_lease(&lease, &signer.public_key())?;
            match self.private_service_relay_current(tx, &id, &business, now) {
                Ok(()) => {}
                Err(error) if unavailable_authority(&error) => continue,
                Err(error) => return Err(error),
            };
            let json: String = tx.query_row(
                "SELECT network_json FROM private_service_leases WHERE grant_id=?1",
                [&id],
                |r| r.get(0),
            )?;
            let network: PrivateServiceNetworkPath = serde_json::from_str(&json)?;
            let snapshot =
                crate::network_policy::read_snapshot(tx, &business.claims().space_id, now)?;
            network::verify(&snapshot, &network, &business)?;
            let hops = network
                .relay
                .as_ref()
                .ok_or(StorageError::Forbidden)?
                .nodes
                .len();
            let envelope =
                Self::private_service_grant_envelope(lease, network, signer, node_signer)?;
            let resource = NodeNetworkRelayResource {
                network_schema_version: hops as u32,
                allocation: Some(serde_json::from_str(&allocation)?),
                network_authority_key: business.claims().network_authority_key.to_vec(),
                relay_bundle_json: Vec::new(),
                chain_bundle_json: Vec::new(),
                business_permit: Vec::new(),
                private_service_bundle_json: serde_json::to_vec(&envelope)?,
            };
            nestlink_identity::network::verify_node_private_service_resource(
                &resource,
                &node_signer.public_key(),
                now,
            )?;
            resources.push(resource);
        }
        Ok(resources)
    }
}
