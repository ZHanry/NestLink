use super::*;

fn preparation(space: &str, request: &str) -> Result<String, SdkError> {
    if !valid_id(request) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("{}/remote/{request}/preparation", base(space)?))
}

impl Sdk {
    pub async fn issue_network_remote_preparation(
        &self,
        space: &str,
        request: &str,
        binding: NetworkRemotePreparationRequest,
    ) -> Result<NetworkRemotePreparationView, SdkError> {
        nestlink_identity::network::remote_preparation_grant_ids(space, request, &binding)?;
        self.required(Method::POST, &preparation(space, request)?, Some(&binding)).await
    }

    pub async fn read_network_remote_preparation(
        &self,
        space: &str,
        request: &str,
        binding: NetworkRemotePreparationRequest,
    ) -> Result<NetworkRemotePreparationView, SdkError> {
        nestlink_identity::network::remote_preparation_grant_ids(space, request, &binding)?;
        // The validated digest is canonical base64url and the other fields are
        // bounded integers. No caller-controlled query delimiters reach this URL.
        let url = format!(
            "{}?expected_space_revision={}&expected_policy_epoch={}&connection_generation={}&permit_sha256={}",
            preparation(space, request)?, binding.expected_space_revision,
            binding.expected_policy_epoch, binding.connection_generation, binding.permit_sha256,
        );
        self.required(Method::GET, &url, None::<&()>).await
    }
}
