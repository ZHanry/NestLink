//! Raw-IP management is explicit and does not create local operating-system
//! resources. Every returned envelope still requires pinned verification.
use super::*;
use nestlink_protocol::network_access::{NetworkAccessRequest, NetworkAccessStart, NetworkAccessView};

impl Sdk {
    /// Only the destination device's account may approve its exact host access.
    /// Both endpoints still need local opt-in to the verified grant digest.
    pub async fn issue_network_access(&self, space: &str, request: NetworkAccessRequest) -> Result<NetworkAccessView,SdkError> {
        self.required(Method::POST,&format!("{}/packet-access",base(space)?),Some(&request)).await
    }
    /// Read the original signed graph and fresh, scoped endpoint assignments.
    /// This never re-signs an ID, renews its lifetime or restores a stopped TUN.
    pub async fn network_access(&self, space: &str, id: &str) -> Result<NetworkAccessView,SdkError> {
        if !valid_id(id) { return Err(SdkError::Invalid); }
        self.required(Method::GET,&format!("{}/packet-access/{id}",base(space)?),None::<&()>).await
    }
    pub async fn revoke_network_access(&self, space: &str, id: &str, expected_revision: u64) -> Result<NetworkPolicyView,SdkError> {
        if !valid_id(id) { return Err(SdkError::Invalid); }
        self.required(Method::DELETE,&format!("{}/packet-access/{id}",base(space)?),Some(&NetworkRevokeGrantRequest {expected_revision})).await
    }
    /// Perform a new online one-use start for one exact local installation.
    /// Never substitute a saved response or a successful readback. Retrying
    /// any consumed grant, including the same owner ID, is intentionally denied.
    /// A failed/ambiguous response must prevent local OS resource creation.
    pub async fn start_network_access(&self, space: &str, id: &str, request: NetworkAccessStart) -> Result<(),SdkError> {
        if !valid_id(id) || !valid_id(&request.installation_id) || !valid_id(&request.owner_id) { return Err(SdkError::Invalid); }
        let accepted: bool = self.required(Method::POST,&format!("{}/packet-access/{id}/start",base(space)?),Some(&request)).await?;
        if !accepted { return Err(SdkError::Invalid); }
        Ok(())
    }
}
