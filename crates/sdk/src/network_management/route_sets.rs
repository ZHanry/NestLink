//! Authenticated management calls. Only the pinned typed readback verifies grants.
use super::*;

impl Sdk {
    pub async fn reserve_network_remote_route_set(&self, space: &str, installation: &DeviceIdentity, permit: &VerifiedPermit, mut request: NetworkRemoteRouteSetRequest) -> Result<NetworkRemoteRouteSetView, SdkError> {
        let business = permit.claims();
        if business.deployment_id != self.trust.deployment_id || business.security_epoch != self.health.security_epoch { return Err(SdkError::Trust); }
        if request.device_id != installation.device_id { return Err(SdkError::Invalid); }
        let actor = &self.login.as_ref().ok_or(SdkError::SignIn)?.principal;
        let transcript = nestlink_identity::network::remote_route_set_reservation_transcript(business, &actor.account_id, space, &request)?;
        request.signature = URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&transcript)?);
        self.required(Method::POST, &format!("{}/remote/{}/route-sets", base(space)?, business.session_id), Some(&request)).await
    }
    pub async fn network_remote_route_set(&self, space: &str, set: &str) -> Result<NetworkRemoteRouteSetView, SdkError> {
        if !valid_id(set) { return Err(SdkError::Invalid); }
        self.required(Method::GET, &format!("{}/route-sets/{set}", base(space)?), None::<&()>).await
    }
    pub async fn revoke_network_remote_route_set(&self, space: &str, set: &str) -> Result<(), SdkError> {
        if !valid_id(set) { return Err(SdkError::Invalid); }
        self.call::<_, serde_json::Value>(Method::DELETE, &format!("{}/route-sets/{set}", base(space)?), None::<&()>, true).await.map(|_| ())
    }
}
