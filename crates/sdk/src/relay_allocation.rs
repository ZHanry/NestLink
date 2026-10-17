use super::*;
use nestlink_identity::relay::{
    VerifiedRelayAllocation, allocation_transcript, verify_relay_allocation,
};
impl Sdk {
    pub async fn relay_reservations(&self) -> Result<RelayReservationUsage, SdkError> {
        self.required(Method::GET, "/relay/reservations", None::<&()>)
            .await
    }
    /// Reserves relay capacity; the endpoint's verified permit remains mandatory.
    pub async fn reserve_relay_allocation(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        allocation_id: &str,
        node_id: &str,
    ) -> Result<VerifiedRelayAllocation, SdkError> {
        if !valid_id(allocation_id) || !valid_id(node_id) {
            return Err(SdkError::Invalid);
        }
        let c = permit.claims();
        if c.deployment_id != self.trust.deployment_id
            || c.security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        let p = &self.login.as_ref().ok_or(SdkError::SignIn)?.principal;
        let proof = allocation_transcript(
            c,
            &p.account_id,
            &installation.device_id,
            allocation_id,
            node_id,
        )?;
        let request = RelayAllocationRequest {
            allocation_id: allocation_id.into(),
            node_id: node_id.into(),
            device_id: installation.device_id.clone(),
            signature: URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&proof)?),
        };
        let response: RelayAllocationResponse = self
            .required(
                Method::POST,
                &format!("{}/relay/allocation", resource("remote", &c.session_id)?),
                Some(&request),
            )
            .await?;
        if response.allocation.len() > 32768 {
            return Err(SdkError::Invalid);
        }
        let encoded = URL_SAFE_NO_PAD
            .decode(&response.allocation)
            .map_err(|_| SdkError::Invalid)?;
        let allocation = verify_relay_allocation(&encoded, &self.trust.permit_issuer)?;
        let a = allocation.claims();
        if a.allocation_id != allocation_id
            || a.node_id != node_id
            || !allocation.matches(c)?
            || a.expires_at_unix_ms > c.expires_at_unix_ms
        {
            return Err(SdkError::Trust);
        }
        Ok(allocation)
    }
}
