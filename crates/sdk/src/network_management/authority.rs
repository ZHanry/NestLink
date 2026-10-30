//! Explicit administrator actions. Returned keys never change a local pin.
use super::*;

impl Sdk {
    pub async fn network_authority_state(
        &self,
        space: &str,
    ) -> Result<NetworkAuthorityView, SdkError> {
        self.required(
            Method::GET,
            &format!("{}/authority", base(space)?),
            None::<&()>,
        )
        .await
    }
    pub async fn rotate_network_authority(
        &self,
        space: &str,
        request: NetworkAuthorityChangeRequest,
    ) -> Result<NetworkAuthorityView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/authority/rotate", base(space)?),
            Some(&request),
        )
        .await
    }
    pub async fn revoke_network_authority(
        &self,
        space: &str,
        request: NetworkAuthorityChangeRequest,
    ) -> Result<(), SdkError> {
        self.call::<_, serde_json::Value>(
            Method::DELETE,
            &format!("{}/authority", base(space)?),
            Some(&request),
            true,
        )
        .await
        .map(|_| ())
    }
    pub async fn advance_network_policy_epoch(
        &self,
        space: &str,
        request: NetworkAuthorityChangeRequest,
    ) -> Result<NetworkPolicyView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/policy/advance", base(space)?),
            Some(&request),
        )
        .await
    }
}
