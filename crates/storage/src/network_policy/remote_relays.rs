//! Consent-bound one-hop routes. Capacity uses the existing relay quota and
//! lifecycle barrier. An immutable route never also mints a legacy allocation.
use super::*;
use crate::relay_reservations::RelayLifecycle;
use nestlink_identity::{relay::allocation_transcript, verify_device_action};
use nestlink_protocol::{
    NODE_LEASE_MS, NodeRole,
    api::{NetworkRemoteRelayRequest, NodeEndpoints, NodeEndpointsView},
    network::{PathPolicy, TransitClaims},
};

pub struct NetworkRemoteRelayIssuance {
    pub space_id: String,
    pub request_id: String,
    pub request: NetworkRemoteRelayRequest,
}

pub struct NetworkRemoteRelayBundle {
    pub allocation_id: String,
    pub path: NetworkRemotePathBundle,
    pub transit: SignedNetworkGrant,
    pub node: NodeEndpointsView,
}

struct RelayNode {
    key: [u8; 32],
    runtime: String,
    generation: u64,
    endpoint_revision: u64,
    maximum: u32,
    lease_end: u64,
    policy: u64,
    endpoints: NodeEndpoints,
}
struct StoredRelay {
    path_id: String,
    transit_id: String,
    node_id: String,
    key: Vec<u8>,
    runtime: String,
    generation: u64,
    endpoint_revision: u64,
    security_epoch: u64,
    policy_revision: u64,
    quota_revision: u64,
    control_runtime: String,
    controller_account: String,
    host_account: String,
    byte_limit: u64,
    promised_until: u64,
    closed: bool,
    signed: SignedNetworkGrant,
}

fn relay_node(store: &Store, node_id: &str, now_ms: u64) -> Result<RelayNode, StorageError> {
    require_id(node_id)?;
    type Row = (Vec<u8>, String, u64, u32, u64, u64, String, u64, String);
    let row: Option<Row> = store.connection.query_row(
        "SELECT n.public_key,n.runtime_id,n.runtime_generation,n.max_connections,n.last_issued_at,n.lease_policy_revision,n.roles_json,e.revision,e.endpoints_json FROM data_nodes n JOIN node_endpoints e ON e.node_id=n.id JOIN node_runtimes r ON r.node_id=n.id AND r.runtime_id=n.runtime_id AND r.generation=n.runtime_generation JOIN deployment d ON d.singleton=1 AND r.security_epoch=d.security_epoch WHERE n.id=?1 AND n.revoked=0",
        [node_id], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)),
    ).optional()?;
    let (key, runtime, generation, maximum, last, policy, roles, endpoint_revision, endpoints) =
        row.ok_or(StorageError::Forbidden)?;
    let endpoints: NodeEndpoints = serde_json::from_str(&endpoints)?;
    endpoints.validate()?;
    let lease_end = last
        .checked_add(NODE_LEASE_MS)
        .ok_or(StorageError::Conflict)?;
    if last > now_ms
        || now_ms >= lease_end
        || policy != store.policy()?.0
        || !serde_json::from_str::<Vec<i32>>(&roles)?.contains(&(NodeRole::NodeRelay as i32))
        || endpoints.quic_uri.is_none()
    {
        return Err(StorageError::Forbidden);
    }
    Ok(RelayNode {
        key: key.try_into().map_err(|_| StorageError::Forbidden)?,
        runtime,
        generation,
        endpoint_revision,
        maximum,
        lease_end,
        policy,
        endpoints,
    })
}

impl Store {
    /// Called only after authenticating the signed node query inside the same
    /// snapshot transaction. It bypasses management account visibility, never
    /// current business/member/runtime/policy validation.
    pub(crate) fn node_network_resources(
        &self,
        tx: &Transaction<'_>,
        lifecycle: &RelayLifecycle,
        query: &nestlink_protocol::NodeResourceQueryClaims,
        signer: &nestlink_identity::PermitSigner,
        now_ms: u64,
    ) -> Result<Vec<nestlink_protocol::NodeNetworkRelayResource>, StorageError> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use nestlink_identity::{relay::session_binding, verify_permit};
        use nestlink_protocol::{
            NodeNetworkRelayResource, RelayAllocationClaims, RelayTransport,
            api::{NetworkGrantView, NetworkRemotePathView, NetworkRemoteRelayView},
        };
        use prost::Message;
        let mut statement = tx.prepare("SELECT space_id,allocation_id FROM network_remote_relays WHERE node_id=?1 AND runtime_id=?2 AND runtime_generation=?3 AND closed=0 AND promised_until>?4 ORDER BY allocation_id")?;
        let rows = statement
            .query_map(
                params![
                    query.node_id,
                    query.runtime_id,
                    query.runtime_generation,
                    now_ms
                ],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut resources = Vec::new();
        for (space, id) in rows {
            let bundle = match self
                .network_relay_current_in_transaction(tx, lifecycle, None, &space, &id, now_ms)
            {
                Ok(bundle) => bundle,
                Err(StorageError::Forbidden | StorageError::Unauthorized) => continue,
                Err(StorageError::Proof(error))
                    if error.code == nestlink_protocol::ErrorCode::PolicyRevoked =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            let business = remote_paths::current_business(self, &bundle.path.request_id, now_ms)?;
            let controller =
                self.device_record_at(&business.controller_device_id, now_ms / 1000)?;
            let host = self.device_record_at(&business.host_device_id, now_ms / 1000)?;
            let quota = self.relay_quota_current()?;
            let node = relay_node(self, &bundle.node.node_id, now_ms)?;
            let rate: u64 = tx.query_row(
                "SELECT bytes_per_second FROM data_nodes WHERE id=?1",
                [&bundle.node.node_id],
                |r| r.get(0),
            )?;
            let signed_business = signer.sign(&business)?.encode_to_vec();
            // Re-verify the exact outgoing envelope before delegating it. Ed25519
            // and protobuf encoding are deterministic for the stored permit.
            let verified_business = verify_permit(&signed_business, &signer.public_key())?;
            let snapshot = read_snapshot(tx, &space, now_ms)?;
            let GrantClaims::Transit(transit) =
                GrantClaims::decode_canonical(&bundle.transit.claims)?
            else {
                return Err(StorageError::Forbidden);
            };
            let allocation = RelayAllocationClaims {
                schema_version: nestlink_protocol::SCHEMA_VERSION,
                deployment_id: business.deployment_id.clone(),
                security_epoch: business.security_epoch,
                allocation_id: id,
                session_id: business.session_id.clone(),
                node_id: bundle.node.node_id.clone(),
                runtime_id: node.runtime,
                runtime_generation: node.generation,
                node_key_sha256: digest(&node.key).to_vec(),
                controller_device_id: business.controller_device_id.clone(),
                host_device_id: business.host_device_id.clone(),
                controller_key_sha256: business.controller_key_sha256.clone(),
                host_key_sha256: business.host_key_sha256.clone(),
                controller_account_id: controller.account,
                host_account_id: host.account,
                connection_generation: business.connection_generation,
                policy_revision: business.policy_revision,
                quota_revision: quota.revision,
                session_binding_sha256: session_binding(&business)?.to_vec(),
                transports: vec![RelayTransport::QuicDatagram as i32],
                node_endpoint_revision: node.endpoint_revision,
                grant_sequence: 1,
                issued_at_unix_ms: transit.scope.not_before_ms,
                expires_at_unix_ms: transit.scope.expires_at_ms,
                bytes_per_second: quota.limits.bytes_per_second.min(rate),
                bytes_per_allocation: transit.byte_limit,
            };
            let grant = |signed: SignedNetworkGrant| -> Result<NetworkGrantView, StorageError> {
                let claims = GrantClaims::decode_canonical(&signed.claims)?;
                Ok(NetworkGrantView {
                    schema_version: SCHEMA_VERSION,
                    grant_id: claims.scope().grant_id.clone(),
                    claims: URL_SAFE_NO_PAD.encode(signed.claims),
                    signature: URL_SAFE_NO_PAD.encode(signed.signature),
                })
            };
            let [controller, host] = bundle.path.memberships;
            let view = NetworkRemoteRelayView {
                allocation_id: bundle.allocation_id,
                path: NetworkRemotePathView {
                    request_id: bundle.path.request_id,
                    controller_membership: grant(controller)?,
                    host_membership: grant(host)?,
                    connectivity: grant(bundle.path.connectivity)?,
                    path: grant(bundle.path.path)?,
                },
                transit: grant(bundle.transit)?,
                node: bundle.node,
            };
            let resource = NodeNetworkRelayResource {
                network_schema_version: 1,
                allocation: Some(allocation),
                network_authority_key: snapshot.authority_key.to_vec(),
                relay_bundle_json: serde_json::to_vec(&view)?,
                business_permit: verified_business.signed_envelope().to_vec(),
            };
            nestlink_identity::network::verify_node_network_resource(
                &resource,
                &signer.public_key(),
                now_ms,
            )?;
            resources.push(resource);
            if resources.len() as u64 > nestlink_protocol::NODE_RESOURCE_ALLOCATIONS {
                return Err(StorageError::RateLimited);
            }
        }
        Ok(resources)
    }

    pub fn issue_network_remote_relay(
        &mut self,
        lifecycle: &RelayLifecycle,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        issuance: NetworkRemoteRelayIssuance,
        now_ms: u64,
    ) -> Result<NetworkRemoteRelayBundle, StorageError> {
        let NetworkRemoteRelayIssuance {
            space_id,
            request_id,
            request,
        } = issuance;
        require_id(&request.allocation.allocation_id)?;
        require_id(&request.transit_grant_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now_ms)?)?;
        self.remote(actor, &request_id)?;
        self.resume_relay_reservations(lifecycle, now_ms)?;
        let business = remote_paths::current_business(self, &request_id, now_ms)?;
        let allocation = &request.allocation;
        if allocation.device_id != business.controller_device_id
            && allocation.device_id != business.host_device_id
        {
            return Err(StorageError::Forbidden);
        }
        let endpoint = self.device_record_at(&allocation.device_id, now_ms / 1000)?;
        if endpoint.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        if allocation.device_id == business.controller_device_id {
            self.check_request_login(&request_id, now_ms / 1000, Some(&actor.session_id))?;
        }
        verify_device_action(
            &allocation_transcript(
                &business,
                &actor.account_id,
                &allocation.device_id,
                &allocation.allocation_id,
                &allocation.node_id,
            )?,
            &endpoint.public_key,
            &crate::control::decode_signature(&allocation.signature)?,
        )?;
        let node = relay_node(self, &allocation.node_id, now_ms)?;
        if node.policy != business.policy_revision
            || request.path.expires_at_unix_ms <= now_ms
            || request.path.expires_at_unix_ms > node.lease_end
            || request.path.expires_at_unix_ms - now_ms > 30_000
            || request.path.expires_at_unix_ms > (i64::MAX as u64).saturating_sub(1000)
        {
            return Err(StorageError::Invalid(
                "network relay lifetime exceeds live authority",
            ));
        }
        let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM all_relay_capacity WHERE id=?1 UNION ALL SELECT 1 FROM turn_grants WHERE id=?1)",
            [&allocation.allocation_id], |r|r.get(0))?;
        if exists
            || request.transit_grant_id == request.path.path_grant_id
            || request.transit_grant_id == request.path.connectivity_grant_id
        {
            return Err(StorageError::Conflict);
        }
        remote_paths::grant_id_available(&tx, &space_id, &request.transit_grant_id)?;
        let quota = self.relay_quota_current()?;
        let controller = self.device_record_at(&business.controller_device_id, now_ms / 1000)?;
        let host = self.device_record_at(&business.host_device_id, now_ms / 1000)?;
        self.reserve_capacity(
            &quota,
            &controller.account,
            &host.account,
            Some((&allocation.node_id, node.maximum)),
            now_ms,
        )?;
        let relay = PeerId::from_public_key(&node.key);
        let path = self.issue_network_path_in_transaction(
            &tx,
            actor,
            signer,
            NetworkRemotePathIssuance {
                space_id: space_id.clone(),
                request_id,
                request: request.path,
            },
            PathPolicy {
                allow_direct: false,
                relays: vec![relay],
                max_hops: 1,
            },
            now_ms,
        )?;
        let claims = TransitClaims {
            scope: GrantScope {
                grant_id: request.transit_grant_id.clone(),
                ..path.verified.claims().scope.clone()
            },
            peers: path.verified.peers(),
            transport_group: path.verified.transport_group_id(),
            route_id: allocation.allocation_id.clone(),
            relay,
            previous: path.verified.peers().first,
            next: path.verified.peers().second,
            remaining_hops: 1,
            byte_limit: quota.limits.bytes_per_allocation,
        };
        let transit = signer.sign(&GrantClaims::Transit(claims))?;
        verify_network_grant(
            &transit,
            &read_snapshot(&tx, &space_id, now_ms)?.verification(),
        )?;
        let promised_until = path.verified.claims().scope.expires_at_ms + 1000;
        tx.execute("INSERT INTO network_remote_relays(allocation_id,space_id,path_grant_id,transit_grant_id,node_id,node_key,runtime_id,runtime_generation,endpoint_revision,security_epoch,policy_revision,quota_revision,control_runtime_id,controller_account_id,host_account_id,byte_limit,promised_until,transit_claims,transit_signature)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
            params![allocation.allocation_id,space_id,path.verified.claims().scope.grant_id,request.transit_grant_id,
                allocation.node_id,node.key.as_slice(),node.runtime,node.generation,node.endpoint_revision,
                business.security_epoch,business.policy_revision,quota.revision,lifecycle.runtime_id,
                controller.account,host.account,quota.limits.bytes_per_allocation,promised_until,transit.claims,transit.signature])?;
        audit(
            &tx,
            "network_remote_relay_reserved",
            &allocation.allocation_id,
            auditing::device(actor, &allocation.device_id),
        )?;
        tx.commit()?;
        Ok(NetworkRemoteRelayBundle {
            allocation_id: allocation.allocation_id.clone(),
            path,
            transit,
            node: NodeEndpointsView {
                node_id: allocation.node_id.clone(),
                revision: node.endpoint_revision,
                endpoints: node.endpoints,
            },
        })
    }

    /// Return exact committed credentials only while every parent and node fact
    /// remains current. No read, retry or reopen replenishes the route's budget.
    pub fn network_remote_relay(
        &mut self,
        lifecycle: &RelayLifecycle,
        actor: &Principal,
        space: &str,
        allocation_id: &str,
        now_ms: u64,
    ) -> Result<NetworkRemoteRelayBundle, StorageError> {
        require_id(allocation_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now_ms)?)?;
        self.resume_relay_reservations(lifecycle, now_ms)?;
        let bundle = self.network_relay_current_in_transaction(
            &tx,
            lifecycle,
            Some(actor),
            space,
            allocation_id,
            now_ms,
        )?;
        tx.commit()?;
        Ok(bundle)
    }

    pub(crate) fn network_relay_current_in_transaction(
        &self,
        tx: &Transaction<'_>,
        lifecycle: &RelayLifecycle,
        actor: Option<&Principal>,
        space: &str,
        allocation_id: &str,
        now_ms: u64,
    ) -> Result<NetworkRemoteRelayBundle, StorageError> {
        let row: Option<StoredRelay> = tx.query_row("SELECT path_grant_id,transit_grant_id,node_id,node_key,runtime_id,runtime_generation,endpoint_revision,security_epoch,policy_revision,quota_revision,control_runtime_id,byte_limit,promised_until,closed,transit_claims,transit_signature,controller_account_id,host_account_id FROM network_remote_relays WHERE space_id=?1 AND allocation_id=?2",
            params![space,allocation_id], |r|Ok(StoredRelay {path_id:r.get(0)?,transit_id:r.get(1)?,node_id:r.get(2)?,key:r.get(3)?,runtime:r.get(4)?,generation:r.get(5)?,endpoint_revision:r.get(6)?,security_epoch:r.get(7)?,policy_revision:r.get(8)?,quota_revision:r.get(9)?,control_runtime:r.get(10)?,byte_limit:r.get(11)?,promised_until:r.get(12)?,closed:r.get(13)?,signed:SignedNetworkGrant {claims:r.get(14)?,signature:r.get(15)?},controller_account:r.get(16)?,host_account:r.get(17)?})).optional()?;
        let row = row.filter(|r| !r.closed).ok_or(StorageError::Forbidden)?;
        let path =
            self.network_path_current_in_transaction(tx, actor, space, &row.path_id, true, now_ms)?;
        let business = remote_paths::current_business(self, &path.request_id, now_ms)?;
        let controller = self.device_record_at(&business.controller_device_id, now_ms / 1000)?;
        let host = self.device_record_at(&business.host_device_id, now_ms / 1000)?;
        let quota = self.relay_quota_current()?;
        let node = relay_node(self, &row.node_id, now_ms)?;
        let snapshot = read_snapshot(tx, space, now_ms)?;
        let verified = verify_network_grant(&row.signed, &snapshot.verification())?;
        let GrantClaims::Transit(transit) = verified.claims() else {
            return Err(StorageError::Forbidden);
        };
        let policy = &path.verified.claims().policy;
        if row.key != node.key
            || row.runtime != node.runtime
            || row.generation != node.generation
            || row.endpoint_revision != node.endpoint_revision
            || row.security_epoch != self.security_epoch()?
            || row.policy_revision != node.policy
            || row.quota_revision != quota.revision
            || row.byte_limit != quota.limits.bytes_per_allocation
            || row.controller_account != controller.account
            || row.host_account != host.account
            || row.control_runtime != lifecycle.runtime_id
            || transit.scope.grant_id != row.transit_id
            || transit.scope
                != (GrantScope {
                    grant_id: row.transit_id.clone(),
                    ..path.verified.claims().scope.clone()
                })
            || transit.scope.expires_at_ms > node.lease_end
            || transit.byte_limit != row.byte_limit
            || row.promised_until != transit.scope.expires_at_ms + 1000
            || transit.route_id != allocation_id
            || transit.transport_group != path.verified.transport_group_id()
            || transit.peers != path.verified.peers()
            || transit.relay != PeerId::from_public_key(&node.key)
            || policy.relays.as_slice() != [transit.relay]
            || transit.previous != transit.peers.first
            || transit.next != transit.peers.second
            || transit.remaining_hops != 1
        {
            return Err(StorageError::Forbidden);
        }
        Ok(NetworkRemoteRelayBundle {
            allocation_id: allocation_id.into(),
            path,
            transit: row.signed,
            node: NodeEndpointsView {
                node_id: row.node_id,
                revision: node.endpoint_revision,
                endpoints: node.endpoints,
            },
        })
    }

    /// Revocation does not prove physical teardown, so the original capacity
    /// promise is retained until its fixed expiry plus the mature hold margin.
    pub fn revoke_network_remote_relay(
        &mut self,
        actor: &Principal,
        space: &str,
        allocation_id: &str,
        now_ms: u64,
    ) -> Result<(), StorageError> {
        require_id(allocation_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now_ms)?)?;
        read_snapshot(&tx, space, now_ms)?;
        let row: Option<(String, String)> = tx.query_row("SELECT p.path_grant_id,p.request_id FROM network_remote_relays r JOIN network_remote_paths p ON p.space_id=r.space_id AND p.path_grant_id=r.path_grant_id WHERE r.space_id=?1 AND r.allocation_id=?2",
            params![space,allocation_id], |r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (path_id, request_id) = row.ok_or(StorageError::Forbidden)?;
        self.remote(actor, &request_id)?;
        tx.execute(
            "UPDATE network_remote_paths SET revoked=1 WHERE space_id=?1 AND path_grant_id=?2",
            params![space, path_id],
        )?;
        if tx.execute("UPDATE network_remote_relays SET closed=1 WHERE space_id=?1 AND allocation_id=?2 AND closed=0", params![space,allocation_id])? == 1 {
            audit(&tx, "network_remote_relay_revoked", allocation_id, auditing::management(actor))?;
        }
        observe(&tx, space, now_ms)?;
        tx.commit()?;
        Ok(())
    }
}
