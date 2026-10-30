use super::*;
use nestlink_identity::node_discovery::{
    VerifiedNodeDiscovery, discovery_transcript, verify_node_discovery,
};
use nestlink_protocol::{DiscoveredRelayNode, NODE_DISCOVERY_BYTES};
use prost::Message;
mod candidates;
pub use candidates::{NodeRelayCandidate, NodeRelayCandidates};
#[cfg(not(target_arch = "wasm32"))]
type Started = std::time::Instant;
#[cfg(target_arch = "wasm32")]
type Started = f64;
#[cfg(not(target_arch = "wasm32"))]
fn start() -> Result<Started, SdkError> {
    Ok(std::time::Instant::now())
}
#[cfg(target_arch = "wasm32")]
fn start() -> Result<Started, SdkError> {
    Ok(web_sys::window()
        .and_then(|w| w.performance())
        .ok_or(SdkError::BrowserTransport)?
        .now())
}
/// A verified response retains the original request's clock, issuer and login.
/// Reusing it never restarts its five-second validity budget.
pub struct NodeDiscovery {
    pub(crate) verified: VerifiedNodeDiscovery,
    pub(crate) started: Started,
    issuer: [u8; 32],
    login_session: String,
    nonce: [u8; 32],
    origin: Url,
}
impl NodeDiscovery {
    pub fn nodes(&self) -> &[DiscoveredRelayNode] {
        &self.verified.claims().nodes
    }
    fn elapsed_ms(&self) -> Result<f64, SdkError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(self.started.elapsed().as_secs_f64() * 1000.0)
        }
        #[cfg(target_arch = "wasm32")]
        {
            let now = start()?;
            if now < self.started {
                return Err(SdkError::Trust);
            }
            Ok(now - self.started)
        }
    }
    pub(crate) fn check(
        &self,
        sdk: &Sdk,
        permit: &VerifiedPermit,
        device: &str,
    ) -> Result<(), SdkError> {
        let login = sdk.login.as_ref().ok_or(SdkError::SignIn)?;
        let c = self.verified.claims();
        if self.issuer != sdk.trust.permit_issuer
            || self.origin != sdk.origin
            || self.login_session != login.principal.session_id
            || c.security_epoch != sdk.health.security_epoch
            || c.deployment_id != sdk.trust.deployment_id
            || !self.verified.matches(
                permit.claims(),
                &login.principal.account_id,
                device,
                &self.nonce,
            )?
            || self.elapsed_ms()? >= (c.expires_at_unix_ms - c.issued_at_unix_ms) as f64
        {
            return Err(SdkError::Trust);
        }
        Ok(())
    }
}
struct DiscoveryRequestContext {
    request: NodeDiscoveryRequest,
    started: Started,
    nonce: [u8; 32],
    login_session: String,
}

impl Sdk {
    pub async fn node_relay_attributes(&self, id: &str) -> Result<NodeRelayAttributesView, SdkError> {
        self.required(Method::GET, &format!("{}/relay-attributes", resource("nodes", id)?), None::<&()>).await
    }
    pub async fn set_node_relay_attributes(&self, id: &str, update: NodeRelayAttributesUpdate) -> Result<NodeRelayAttributesView, SdkError> {
        update.attributes.validate()?;
        self.required(Method::PUT, &format!("{}/relay-attributes", resource("nodes", id)?), Some(&update)).await
    }
    pub async fn node_endpoints(&self, id: &str) -> Result<NodeEndpointsView, SdkError> {
        self.required(
            Method::GET,
            &format!("{}/endpoints", resource("nodes", id)?),
            None::<&()>,
        )
        .await
    }
    pub async fn set_node_endpoints(
        &self,
        id: &str,
        update: NodeEndpointsUpdate,
    ) -> Result<NodeEndpointsView, SdkError> {
        self.required(
            Method::PUT,
            &format!("{}/endpoints", resource("nodes", id)?),
            Some(&update),
        )
        .await
    }
    pub async fn discover_relay_nodes(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
    ) -> Result<NodeDiscovery, SdkError> {
        let context = self.discovery_request(installation, permit)?;
        let response: NodeDiscoveryResponse = self.required(
            Method::POST,
            &format!("{}/relay/discovery", resource("remote", &permit.claims().session_id)?),
            Some(&context.request),
        ).await?;
        self.verified_discovery_response(context, &response.discovery, installation, permit)
    }

    fn discovery_request(&self, installation: &DeviceIdentity, permit: &VerifiedPermit) -> Result<DiscoveryRequestContext, SdkError> {
        let login = self.login.as_ref().ok_or(SdkError::SignIn)?;
        let c = permit.claims();
        if c.deployment_id != self.trust.deployment_id
            || c.security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        let nonce = nestlink_auth::random_bytes::<32>();
        let proof = discovery_transcript(
            c,
            &login.principal.account_id,
            &installation.device_id,
            &nonce,
        )?;
        let request = NodeDiscoveryRequest {
            device_id: installation.device_id.clone(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            permit_sha256: URL_SAFE_NO_PAD.encode(digest(&c.encode_to_vec())),
            signature: URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&proof)?),
        };
        Ok(DiscoveryRequestContext { request, started: start()?, nonce, login_session: login.principal.session_id.clone() })
    }

    fn verified_discovery_response(&self, context: DiscoveryRequestContext, encoded: &str, installation: &DeviceIdentity, permit: &VerifiedPermit) -> Result<NodeDiscovery, SdkError> {
        if encoded.len() as u64 > (NODE_DISCOVERY_BYTES + 128).div_ceil(3) * 4 {
            return Err(SdkError::Invalid);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| SdkError::Invalid)?;
        let verified = verify_node_discovery(&bytes, &self.trust.permit_issuer)?;
        let result = NodeDiscovery {
            verified,
            started: context.started,
            issuer: self.trust.permit_issuer,
            login_session: context.login_session,
            nonce: context.nonce,
            origin: self.origin.clone(),
        };
        result.check(self, permit, &installation.device_id)?;
        Ok(result)
    }
}
