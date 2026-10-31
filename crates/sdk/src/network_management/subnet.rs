use super::*;
use nestlink_protocol::subnet::management::{
    SubnetMappingRequest, SubnetMappingRevoke, SubnetMappingView,
};

fn mapping(space: &str, id: &str) -> Result<String, SdkError> {
    if !valid_id(id) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("{}/subnet-mappings/{id}", base(space)?))
}
impl Sdk {
    /// Explicit account-owner approval joining independently proven node and
    /// installation identities. Equal keys alone never create this relation.
    pub async fn bind_subnet_gateway_installation(
        &self,
        space: &str,
        id: &str,
        request: &nestlink_protocol::subnet::management::SubnetGatewayInstallationRequest,
    ) -> Result<NetworkPolicyView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/installation", mapping(space, id)?),
            Some(request),
        )
        .await
    }

    pub async fn issue_subnet_network_access(
        &self,
        space: &str,
        request: &nestlink_protocol::subnet::management::SubnetNetworkAccessRequest,
    ) -> Result<nestlink_protocol::network_access::NetworkAccessView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/subnet-packet-access", base(space)?),
            Some(request),
        )
        .await
    }
    /// Manager publication authority only. Explicit local mapping and packet
    /// business approval are still required before an OS resource is created.
    pub async fn issue_subnet_mapping(
        &self,
        space: &str,
        request: &SubnetMappingRequest,
    ) -> Result<SubnetMappingView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/subnet-mappings", base(space)?),
            Some(request),
        )
        .await
    }
    pub async fn subnet_mapping(
        &self,
        space: &str,
        id: &str,
    ) -> Result<SubnetMappingView, SdkError> {
        self.required(Method::GET, &mapping(space, id)?, None::<&()>)
            .await
    }
    pub async fn revoke_subnet_mapping(
        &self,
        space: &str,
        id: &str,
        request: &SubnetMappingRevoke,
    ) -> Result<NetworkPolicyView, SdkError> {
        self.required(Method::DELETE, &mapping(space, id)?, Some(request))
            .await
    }
}
