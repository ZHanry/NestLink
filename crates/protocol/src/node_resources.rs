use crate::{
    ContractError, ErrorCode, NODE_RESOURCE_ALLOCATIONS, NODE_RESOURCE_TTL_MS,
    NodeResourceQueryClaims, NodeResourceSnapshotClaims, SCHEMA_VERSION, valid_id,
};
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid node resource metadata")
}
impl NodeResourceQueryClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [
                &self.deployment_id,
                &self.node_id,
                &self.runtime_id,
                &self.request_id,
            ]
            .iter()
            .any(|s| !valid_id(s))
            || [
                self.security_epoch,
                self.runtime_generation,
                self.policy_revision,
                self.lease_sequence,
                self.request_sequence,
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
            ]
            .iter()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
            || self
                .expires_at_unix_ms
                .checked_sub(self.issued_at_unix_ms)
                .is_none_or(|n| n == 0 || n > NODE_RESOURCE_TTL_MS)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl NodeResourceSnapshotClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        let q = self.query.as_ref().ok_or_else(invalid)?;
        q.validate()?;
        if self.query_sha256.len() != 32
            || self.topology_publications_json.len()
                > crate::network_topology::MAX_NODE_PUBLICATION_BYTES
            || self.allocation_issuer.len() != 32
            || self.quota_revision == 0
            || self.quota_revision > i64::MAX as u64
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms > i64::MAX as u64
            || self.expires_at_unix_ms > q.expires_at_unix_ms
            || self
                .expires_at_unix_ms
                .checked_sub(self.issued_at_unix_ms)
                .is_none_or(|n| n == 0 || n > NODE_RESOURCE_TTL_MS)
            || (self.allocations.len() + self.network_routes.len()) as u64
                > NODE_RESOURCE_ALLOCATIONS
            || self
                .allocations
                .windows(2)
                .any(|p| p[0].allocation_id >= p[1].allocation_id)
        {
            return Err(invalid());
        }
        let mut previous: Option<&str> = None;
        for route in &self.network_routes {
            let allocation = route.allocation.as_ref().ok_or_else(invalid)?;
            let private = !route.private_service_bundle_json.is_empty();
            let bundle_valid = if private {
                matches!(route.network_schema_version, 1 | 2)
                    && route.private_service_bundle_json.len() <= 65_536
                    && route.business_permit.is_empty()
                    && route.relay_bundle_json.is_empty()
                    && route.chain_bundle_json.is_empty()
            } else { match route.network_schema_version {
                1 => {
                    !route.relay_bundle_json.is_empty()
                        && route.relay_bundle_json.len() <= 32_768
                        && route.chain_bundle_json.is_empty()
                }
                2 => {
                    !route.chain_bundle_json.is_empty()
                        && route.chain_bundle_json.len() <= 49_152
                        && route.relay_bundle_json.is_empty()
                }
                _ => false,
            }};
            if !bundle_valid
                || route.network_authority_key.len() != 32
                || (!private && route.business_permit.is_empty())
                || route.business_permit.len() as u64 > crate::PERMIT_BYTES + 128
                || previous.is_some_and(|id| id >= allocation.allocation_id.as_str())
                || self
                    .allocations
                    .iter()
                    .any(|old| old.allocation_id == allocation.allocation_id)
            {
                return Err(invalid());
            }
            previous = Some(&allocation.allocation_id);
        }
        for c in self.allocations.iter().chain(
            self.network_routes
                .iter()
                .filter_map(|route| route.allocation.as_ref()),
        ) {
            c.validate()?;
            if c.deployment_id != q.deployment_id
                || c.security_epoch != q.security_epoch
                || c.node_id != q.node_id
                || c.runtime_id != q.runtime_id
                || c.runtime_generation != q.runtime_generation
                || c.policy_revision != q.policy_revision
                || c.quota_revision != self.quota_revision
                || c.issued_at_unix_ms > self.issued_at_unix_ms
                || c.expires_at_unix_ms <= self.issued_at_unix_ms
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
