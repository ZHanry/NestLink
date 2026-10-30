//! Typed topology management. These envelopes remain observations or explicit
//! publication credentials and confer no forwarding or business permission.
use crate::{Sdk, SdkError};
use reqwest::Method;
pub use nestlink_protocol::api::{
    NetworkTopologyPublisherRequest as TopologyPublisherRequest,
    NetworkTopologyQuery as TopologyQuery,
};
pub use nestlink_protocol::network_topology::{
    SignedTopologyPublisher as TopologyPublisherView,
    SignedTopologyUpdate as TopologyUpdateView,
};

fn base(space: &str) -> Result<String, SdkError> {
    if !nestlink_protocol::valid_id(space) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("/network/spaces/{space}/topology"))
}

fn publisher(space: &str, node: &str) -> Result<String, SdkError> {
    if !nestlink_protocol::valid_id(node) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("{}/publishers/{node}", base(space)?))
}

impl Sdk {
    /// Delegate publication to one registered node's current boot incarnation.
    /// RouteExport references in the request are preserved as their independent
    /// grants; a publisher envelope alone never authorizes prefix access.
    pub async fn issue_network_topology_publisher(
        &self,
        space: &str,
        node: &str,
        request: TopologyPublisherRequest,
    ) -> Result<TopologyPublisherView, SdkError> {
        self.required(Method::POST, &publisher(space, node)?, Some(&request))
            .await
    }

    pub async fn network_topology_publisher(
        &self,
        space: &str,
        node: &str,
    ) -> Result<TopologyPublisherView, SdkError> {
        self.required(Method::GET, &publisher(space, node)?, None::<&()>)
            .await
    }

    pub async fn revoke_network_topology_publisher(
        &self,
        space: &str,
        node: &str,
    ) -> Result<(), SdkError> {
        self.call::<_, serde_json::Value>(
            Method::DELETE,
            &publisher(space, node)?,
            None::<&()>,
            true,
        )
        .await
        .map(|_| ())
    }

    /// Read a nonce-bound full snapshot or delta. Callers must authenticate the
    /// authority signature and nonce and apply their saved cursor fence before
    /// consuming the returned observations.
    pub async fn network_topology_update(
        &self,
        space: &str,
        query: TopologyQuery,
    ) -> Result<TopologyUpdateView, SdkError> {
        self.required(Method::POST, &format!("{}/query", base(space)?), Some(&query))
            .await
    }
}
