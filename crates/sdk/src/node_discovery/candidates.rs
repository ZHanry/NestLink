//! Checked copies may be ranked; signed discovery bytes and order never change.
use super::*;
use nestlink_identity::relay::VerifiedRelayAllocation;

#[derive(Clone)]
pub struct NodeRelayCandidate {
    pub node: DiscoveredRelayNode,
    pub attributes: NodeRelayAttributesView,
}

pub struct NodeRelayCandidates {
    discovery: NodeDiscovery,
    attributes: Vec<NodeRelayAttributesView>,
}

impl NodeRelayCandidates {
    fn new(discovery: NodeDiscovery, attributes: Vec<NodeRelayAttributesView>) -> Result<Self, SdkError> {
        if attributes.len() != discovery.nodes().len() {
            return Err(SdkError::Trust);
        }
        for (node, attributes) in discovery.nodes().iter().zip(&attributes) {
            if node.node_id != attributes.node_id || attributes.revision > i64::MAX as u64 {
                return Err(SdkError::Trust);
            }
            attributes.attributes.validate()?;
        }
        Ok(Self { discovery, attributes })
    }

    fn check(&self, sdk: &Sdk, permit: &VerifiedPermit, installation: &DeviceIdentity) -> Result<f64, SdkError> {
        self.discovery.check(sdk, permit, &installation.device_id)?;
        if digest(&installation.identity.public_key()).as_slice() != self.discovery.verified.claims().device_key_sha256 {
            return Err(SdkError::Trust);
        }
        self.discovery.elapsed_ms()
    }

    /// Returns current candidate copies ordered by known relative cost, then
    /// unknown cost, with stable node-ID ties. Attributes grant no rights.
    pub fn checked(&self, sdk: &Sdk, permit: &VerifiedPermit, installation: &DeviceIdentity) -> Result<Vec<NodeRelayCandidate>, SdkError> {
        let elapsed = self.check(sdk, permit, installation)?;
        let issued = self.discovery.verified.claims().issued_at_unix_ms;
        let mut candidates: Vec<_> = self.discovery.nodes().iter().zip(&self.attributes)
            .filter(|(node, _)| elapsed < (node.expires_at_unix_ms - issued) as f64)
            .map(|(node, attributes)| NodeRelayCandidate { node: node.clone(), attributes: attributes.clone() }).collect();
        candidates.sort_by(|a,b| {
            let a_cost = a.attributes.attributes.cost_weight;
            let b_cost = b.attributes.attributes.cost_weight;
            (a_cost.is_none(), a_cost.unwrap_or(0), &a.node.node_id).cmp(&(b_cost.is_none(), b_cost.unwrap_or(0), &b.node.node_id))
        });
        Ok(candidates)
    }

    /// Selection uses the private signed list, never a caller-edited copy.
    pub fn select(&self, sdk: &Sdk, permit: &VerifiedPermit, installation: &DeviceIdentity, node_id: &str) -> Result<NodeRelayCandidate, SdkError> {
        let elapsed = self.check(sdk, permit, installation)?;
        let index = self.discovery.nodes().binary_search_by(|node| node.node_id.as_str().cmp(node_id)).map_err(|_| SdkError::Trust)?;
        let node = &self.discovery.nodes()[index];
        if elapsed >= (node.expires_at_unix_ms - self.discovery.verified.claims().issued_at_unix_ms) as f64 {
            return Err(SdkError::Trust);
        }
        Ok(NodeRelayCandidate { node: node.clone(), attributes: self.attributes[index].clone() })
    }
}

impl Sdk {
    pub async fn discover_relay_candidates(&self, installation: &DeviceIdentity, permit: &VerifiedPermit) -> Result<NodeRelayCandidates, SdkError> {
        let context = self.discovery_request(installation, permit)?;
        let base = resource("remote", &permit.claims().session_id)?;
        let response: NodeRelayCandidatesResponse = match self.required(Method::POST, &format!("{base}/relay/candidates"), Some(&context.request)).await {
            Ok(response) => response,
            // An old server explicitly lacks this additive advisory endpoint.
            // Retain the original nonce/clock and validate the old signed list.
            Err(SdkError::Api(StatusCode::NOT_FOUND, ErrorCode::ProtocolMismatch)) => {
                let response: NodeDiscoveryResponse = self.required(Method::POST, &format!("{base}/relay/discovery"), Some(&context.request)).await?;
                let discovery = self.verified_discovery_response(context, &response.discovery, installation, permit)?;
                let attributes = discovery.nodes().iter().map(|node| NodeRelayAttributesView { node_id: node.node_id.clone(), revision: 0, attributes: NodeRelayAttributes::default() }).collect();
                let result = NodeRelayCandidates::new(discovery, attributes)?;
                result.check(self, permit, installation)?;
                return Ok(result);
            }
            Err(error) => return Err(error),
        };
        let discovery = self.verified_discovery_response(context, &response.discovery, installation, permit)?;
        let result = NodeRelayCandidates::new(discovery, response.attributes)?;
        result.check(self, permit, installation)?;
        Ok(result)
    }

    /// The original allocation proof independently binds the selected node UUID.
    pub async fn reserve_selected_relay_candidate(&self, candidates: &NodeRelayCandidates, installation: &DeviceIdentity, permit: &VerifiedPermit, allocation_id: &str, node_id: &str) -> Result<VerifiedRelayAllocation, SdkError> {
        let selected = candidates.select(self, permit, installation, node_id)?;
        let allocation = self.reserve_relay_allocation(installation, permit, allocation_id, node_id).await?;
        candidates.select(self, permit, installation, node_id)?;
        let actual = allocation.claims();
        if actual.node_key_sha256 != selected.node.node_key_sha256
            || actual.runtime_id != selected.node.runtime_id
            || actual.runtime_generation != selected.node.runtime_generation
            || actual.node_endpoint_revision != selected.node.endpoint_revision {
            return Err(SdkError::Trust);
        }
        Ok(allocation)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn selected_node_routes(&self, candidates: &NodeRelayCandidates, installation: &DeviceIdentity, permit: &VerifiedPermit, allocation: &VerifiedRelayAllocation) -> Result<(Option<crate::NodeRelayRoute>, Option<crate::NodeQuicRoute>), SdkError> {
        candidates.select(self, permit, installation, &allocation.claims().node_id)?;
        self.discovered_node_routes(&candidates.discovery, installation, permit, allocation).await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
