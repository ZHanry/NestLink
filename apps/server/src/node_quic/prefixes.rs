//! Protected local choices are independent of remote publication authority.
use nestlink_node::control::{LocalPrefixChoice, LocalPrefixOwner, NodeControl};
use nestlink_protocol::{api::NetworkNodeTopologyAuthority, network::IpPrefix,
    network_topology::{MAX_PREFIXES, TopologyPublisherClaims}};
use serde::Deserialize;
use std::{collections::BTreeSet, io, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::time::Instant;

/// A single explicit local approval, bound to one authority grant for this run.
/// It cannot be cloned, loaded from the management plane or rearmed after use.
pub struct LocalPrefixRegistration {
    deployment_id: String,
    node_id: String,
    space_id: String,
    publisher_grant_id: String,
    choice: Option<LocalPrefixChoice>,
    owner: Option<Arc<LocalPrefixOwner>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    schema_version: u32,
    deployment_id: String,
    node_id: String,
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Choice {
    space_id: String,
    publisher_grant_id: String,
    prefix: IpPrefix,
    target: SocketAddr,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid protected local prefix choices")
}

impl LocalPrefixRegistration {
    /// Uses the existing protected-file reader, including its OS owner and ACL
    /// checks. Reading this file does not authorize publication or forwarding.
    pub fn load(path: &Path, deployment: &str, node: &str) -> io::Result<Vec<Self>> {
        let bytes = nestlink_platform_security::read_private(path, 16_384)?;
        Self::decode(&bytes, deployment, node)
    }

    fn decode(bytes: &[u8], deployment: &str, node: &str) -> io::Result<Vec<Self>> {
        let file: File = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if file.schema_version != 1 || file.deployment_id != deployment || file.node_id != node
            || !nestlink_protocol::valid_id(deployment) || !nestlink_protocol::valid_id(node)
            || file.choices.len() > MAX_PREFIXES
        { return Err(invalid()); }
        let mut seen = BTreeSet::new();
        let mut choices = Vec::with_capacity(file.choices.len());
        for choice in file.choices {
            if !nestlink_protocol::valid_id(&choice.space_id)
                || !nestlink_protocol::valid_id(&choice.publisher_grant_id)
                || !seen.insert((choice.space_id.clone(), choice.prefix.network, choice.prefix.prefix_len))
            { return Err(invalid()); }
            let approved = LocalPrefixChoice::approve(choice.prefix, choice.target).map_err(io::Error::other)?;
            choices.push(Self { deployment_id: deployment.into(), node_id: node.into(),
                space_id: choice.space_id, publisher_grant_id: choice.publisher_grant_id,
                choice: Some(approved), owner: None });
        }
        Ok(choices)
    }

    pub(super) fn observe(&mut self, control: &Arc<NodeControl>, authority: &NetworkNodeTopologyAuthority) -> io::Result<()> {
        if self.choice.is_none() { return Ok(()); }
        let claims = TopologyPublisherClaims::decode_canonical(&authority.publisher.claims).map_err(io::Error::other)?;
        if claims.scope.deployment_id != self.deployment_id || claims.node_id != self.node_id
            || claims.scope.space_id != self.space_id || claims.scope.grant_id != self.publisher_grant_id
        { return Ok(()); }
        // Consume once even if the current signature/export or probe admission
        // fails. A later detached grant cannot silently recreate local consent.
        let choice = self.choice.take().ok_or_else(invalid)?;
        self.owner = Some(Arc::new(LocalPrefixOwner::start(control.clone(), authority, choice).map_err(io::Error::other)?));
        Ok(())
    }

    pub(super) fn reachable(&self, authority: &NetworkNodeTopologyAuthority) -> Option<Arc<LocalPrefixOwner>> {
        let claims = TopologyPublisherClaims::decode_canonical(&authority.publisher.claims).ok()?;
        if claims.scope.space_id != self.space_id || claims.scope.grant_id != self.publisher_grant_id { return None; }
        self.owner.as_ref().filter(|owner| owner.is_reachable()).cloned()
    }

    pub(super) fn revoke(&self) {
        if let Some(owner) = &self.owner { owner.revoke(); }
    }

    pub(super) async fn close(&mut self, deadline: Instant) -> io::Result<()> {
        let Some(owner) = self.owner.as_mut() else { return Ok(()); };
        let owner = Arc::get_mut(owner).ok_or_else(|| io::Error::other("local prefix report still owns probe"))?;
        owner.close(deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(5))).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const DEPLOYMENT: &str = "11111111-1111-4111-8111-111111111111";
    const NODE: &str = "22222222-2222-4222-8222-222222222222";
    fn policy() -> serde_json::Value {
        serde_json::json!({"schema_version":1, "deployment_id":DEPLOYMENT, "node_id":NODE,
            "choices":[{"space_id":"33333333-3333-4333-8333-333333333333",
                "publisher_grant_id":"44444444-4444-4444-8444-444444444444",
                "prefix":{"network":"192.0.2.10","prefix_len":32},"target":"192.0.2.10:443"}]})
    }
    #[test]
    fn protected_choices_bind_deployment_node_exact_host_and_unique_space_prefix() -> io::Result<()> {
        let decode = |value: serde_json::Value| LocalPrefixRegistration::decode(value.to_string().as_bytes(), DEPLOYMENT, NODE);
        assert_eq!(decode(policy())?.len(), 1);
        for change in 0..8 {
            let mut value = policy();
            match change {
                0 => value["deployment_id"] = NODE.into(),
                1 => value["node_id"] = DEPLOYMENT.into(),
                2 => value["choices"][0]["target"] = "192.0.2.11:443".into(),
                3 => value["choices"][0]["prefix"]["prefix_len"] = 24.into(),
                4 => value["choices"][0]["target"] = "private.example:443".into(),
                5 => value["choices"][0]["publisher_grant_id"] = "unknown".into(),
                6 => { let duplicate=value["choices"][0].clone(); value["choices"].as_array_mut().ok_or_else(invalid)?.push(duplicate); },
                _ => value["choices"][0]["forward"] = true.into(),
            }
            assert!(decode(value).is_err(), "invalid choice {change}");
        }
        Ok(())
    }
    #[test]
    fn protected_choices_reject_excess_and_allow_explicitly_empty_configuration() -> io::Result<()> {
        let mut value=policy();
        value["choices"]=serde_json::json!([]);
        assert!(LocalPrefixRegistration::decode(value.to_string().as_bytes(), DEPLOYMENT, NODE)?.is_empty());
        let mut value=policy();
        value["choices"]=serde_json::Value::Array(vec![value["choices"][0].clone(); MAX_PREFIXES+1]);
        assert!(LocalPrefixRegistration::decode(value.to_string().as_bytes(), DEPLOYMENT, NODE).is_err());
        Ok(())
    }
}
