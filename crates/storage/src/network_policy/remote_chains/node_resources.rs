//! Complete chain delegation uses the existing signed, exact-query snapshot.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{relay::session_binding, verify_permit};
use nestlink_protocol::{
    ErrorCode, NodeNetworkRelayResource, NodeResourceQueryClaims, RelayAllocationClaims, RelayTransport,
    api::{NetworkGrantView, NetworkRemotePathView, NetworkRemoteRelayChainView},
};
use prost::Message;

impl Store {
    pub(crate) fn node_network_chain_resources(
        &self,
        tx: &Transaction<'_>,
        lifecycle: &RelayLifecycle,
        query: &NodeResourceQueryClaims,
        signer: &nestlink_identity::PermitSigner,
        now: u64,
    ) -> Result<Vec<NodeNetworkRelayResource>, StorageError> {
        let mut statement = tx.prepare("SELECT c.space_id,c.route_id,h.position FROM network_remote_chains c JOIN network_remote_chain_hops h ON h.route_id=c.route_id WHERE h.node_id=?1 AND h.runtime_id=?2 AND h.runtime_generation=?3 AND h.closed=0 AND h.promised_until>?4 ORDER BY h.transit_grant_id")?;
        let rows = statement.query_map(
            params![query.node_id,query.runtime_id,query.runtime_generation,now],
            |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,usize>(2)?)),
        )?.collect::<Result<Vec<_>,_>>()?;
        drop(statement);
        let mut resources = Vec::new();
        for (space, route_id, index) in rows {
            if index >= 2 { return Err(StorageError::Conflict); }
            let bundle = match self.network_chain_current_in_transaction(tx,lifecycle,None,&space,&route_id,now) {
                Ok(bundle) => bundle,
                Err(StorageError::Forbidden | StorageError::Unauthorized) => continue,
                Err(StorageError::Proof(error)) if error.code == ErrorCode::PolicyRevoked => continue,
                Err(error) => return Err(error),
            };
            let business = remote_paths::current_business(self,&bundle.path.request_id,now)?;
            let controller = self.device_record_at(&business.controller_device_id,now/1000)?;
            let host = self.device_record_at(&business.host_device_id,now/1000)?;
            let quota = self.relay_quota_current()?;
            let node = relay_node(self,&bundle.nodes[index].node_id,now)?;
            let rate: u64 = tx.query_row("SELECT bytes_per_second FROM data_nodes WHERE id=?1",[&query.node_id],|row|row.get(0))?;
            let signed_business = signer.sign(&business)?.encode_to_vec();
            let verified_business = verify_permit(&signed_business,&signer.public_key())?;
            let snapshot = read_snapshot(tx,&space,now)?;
            let GrantClaims::Transit(transit) = GrantClaims::decode_canonical(&bundle.transits[index].claims)? else {
                return Err(StorageError::Forbidden);
            };
            let allocation = RelayAllocationClaims {
                schema_version: nestlink_protocol::SCHEMA_VERSION,
                deployment_id: business.deployment_id.clone(), security_epoch: business.security_epoch,
                allocation_id: transit.scope.grant_id.clone(), session_id: business.session_id.clone(),
                node_id: query.node_id.clone(), runtime_id: node.runtime, runtime_generation: node.generation,
                node_key_sha256: digest(&node.key).to_vec(),
                controller_device_id: business.controller_device_id.clone(), host_device_id: business.host_device_id.clone(),
                controller_key_sha256: business.controller_key_sha256.clone(), host_key_sha256: business.host_key_sha256.clone(),
                controller_account_id: controller.account, host_account_id: host.account,
                connection_generation: business.connection_generation, policy_revision: business.policy_revision,
                quota_revision: quota.revision, session_binding_sha256: session_binding(&business)?.to_vec(),
                transports: vec![RelayTransport::QuicDatagram as i32], node_endpoint_revision: node.endpoint_revision,
                grant_sequence: 1, issued_at_unix_ms: transit.scope.not_before_ms,
                expires_at_unix_ms: transit.scope.expires_at_ms,
                bytes_per_second: quota.limits.bytes_per_second.min(rate), bytes_per_allocation: transit.byte_limit,
            };
            let grant = |signed: SignedNetworkGrant| -> Result<NetworkGrantView,StorageError> {
                let claims = GrantClaims::decode_canonical(&signed.claims)?;
                Ok(NetworkGrantView {
                    schema_version: SCHEMA_VERSION, grant_id: claims.scope().grant_id.clone(),
                    claims: URL_SAFE_NO_PAD.encode(signed.claims), signature: URL_SAFE_NO_PAD.encode(signed.signature),
                })
            };
            let [controller,host] = bundle.path.memberships;
            let [first,second] = bundle.transits;
            let view = NetworkRemoteRelayChainView {
                route_id: bundle.route_id,
                path: NetworkRemotePathView {
                    request_id: bundle.path.request_id, controller_membership: grant(controller)?,
                    host_membership: grant(host)?, connectivity: grant(bundle.path.connectivity)?, path: grant(bundle.path.path)?,
                },
                transits: [grant(first)?,grant(second)?], nodes: bundle.nodes, topology_digests: bundle.topology_digests,
            };
            let resource = NodeNetworkRelayResource {
                network_schema_version: 2, allocation: Some(allocation),
                network_authority_key: snapshot.authority_key.to_vec(), relay_bundle_json: Vec::new(),
                chain_bundle_json: serde_json::to_vec(&view)?, business_permit: verified_business.signed_envelope().to_vec(),
            };
            nestlink_identity::network::verify_node_network_chain_resource(&resource,&signer.public_key(),now)?;
            resources.push(resource);
            if resources.len() as u64 > nestlink_protocol::NODE_RESOURCE_ALLOCATIONS {
                return Err(StorageError::RateLimited);
            }
        }
        Ok(resources)
    }
}
