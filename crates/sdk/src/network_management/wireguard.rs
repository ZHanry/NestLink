//! Management does not create an OS interface. A production portal owner must
//! additionally verify this independent key binding and consume the original
//! OnlinePacketAccess one-use claim before asking for local OS approval.
use super::*;
use nestlink_protocol::wireguard::management::*;
fn binding(space: &str, id: &str) -> Result<String, SdkError> {
    if !valid_id(id) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("{}/wireguard-client-bindings/{id}", base(space)?))
}
impl Sdk {
    pub async fn issue_wireguard_client_binding(
        &self,
        space: &str,
        request: &WireGuardClientBindingRequest,
    ) -> Result<WireGuardClientBindingView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/wireguard-client-bindings", base(space)?),
            Some(request),
        )
        .await
    }
    pub async fn wireguard_client_binding(
        &self,
        space: &str,
        id: &str,
    ) -> Result<WireGuardClientBindingView, SdkError> {
        self.required(Method::GET, &binding(space, id)?, None::<&()>)
            .await
    }
    pub async fn revoke_wireguard_client(
        &self,
        space: &str,
        id: &str,
        request: &WireGuardClientRevoke,
    ) -> Result<NetworkPolicyView, SdkError> {
        self.required(Method::DELETE, &binding(space, id)?, Some(request))
            .await
    }
}
