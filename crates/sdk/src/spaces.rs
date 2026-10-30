//! Typed product space calls; server membership is not business authorization.
use super::{Method, Sdk, SdkError, valid_id};
use nestlink_protocol::spaces::service_publication::*;
use nestlink_protocol::spaces::*;

fn base(space: &str) -> Result<String, SdkError> {
    if !valid_id(space) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("/network/spaces/{space}"))
}

fn resource(space: &str, kind: &str, id: &str) -> Result<String, SdkError> {
    if !valid_id(id) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("{}/{kind}/{id}", base(space)?))
}

impl Sdk {
    pub async fn space_service_policy(
        &self,
        space: &str,
    ) -> Result<SpaceServicePolicyView, SdkError> {
        self.required(
            Method::GET,
            &format!("{}/services", base(space)?),
            None::<&()>,
        )
        .await
    }
    pub async fn bind_space_service(
        &self,
        space: &str,
        service: &str,
        request: SpaceServiceBindingRequest,
    ) -> Result<SpaceView, SdkError> {
        self.required(
            Method::PUT,
            &resource(space, "services", service)?,
            Some(&request),
        )
        .await
    }
    pub async fn revoke_space_service(
        &self,
        space: &str,
        service: &str,
        request: SpaceRevisionRequest,
    ) -> Result<SpaceView, SdkError> {
        self.required(
            Method::DELETE,
            &resource(space, "services", service)?,
            Some(&request),
        )
        .await
    }
    pub async fn grant_space_service_rule(
        &self,
        space: &str,
        service: &str,
        request: SpaceServiceRuleRequest,
    ) -> Result<SpaceView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/rules", resource(space, "services", service)?),
            Some(&request),
        )
        .await
    }
    pub async fn revoke_space_service_rule(
        &self,
        space: &str,
        service: &str,
        rule: &str,
        request: SpaceRevisionRequest,
    ) -> Result<SpaceView, SdkError> {
        if !valid_id(rule) {
            return Err(SdkError::Invalid);
        }
        self.required(
            Method::DELETE,
            &format!("{}/rules/{rule}", resource(space, "services", service)?),
            Some(&request),
        )
        .await
    }
    pub async fn spaces(&self) -> Result<Vec<SpaceView>, SdkError> {
        self.required(Method::GET, "/network/spaces", None::<&()>)
            .await
    }
    pub async fn create_space(&self, request: SpaceCreateRequest) -> Result<SpaceView, SdkError> {
        self.required(Method::POST, "/network/spaces", Some(&request))
            .await
    }
    pub async fn space_details(&self, space: &str) -> Result<SpaceDetails, SdkError> {
        self.required(Method::GET, &base(space)?, None::<&()>).await
    }
    pub async fn archive_space(
        &self,
        space: &str,
        request: SpaceRevisionRequest,
    ) -> Result<SpaceView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/archive", base(space)?),
            Some(&request),
        )
        .await
    }
    pub async fn update_space_member(
        &self,
        space: &str,
        account: &str,
        request: SpaceMemberUpdate,
    ) -> Result<SpaceView, SdkError> {
        self.required(
            Method::PUT,
            &resource(space, "people", account)?,
            Some(&request),
        )
        .await
    }
    pub async fn remove_space_member(
        &self,
        space: &str,
        account: &str,
        request: SpaceMemberRemoval,
    ) -> Result<SpaceView, SdkError> {
        self.required(
            Method::DELETE,
            &resource(space, "people", account)?,
            Some(&request),
        )
        .await
    }
    pub async fn join_space_device(
        &self,
        space: &str,
        request: SpaceDeviceJoin,
    ) -> Result<SpaceView, SdkError> {
        if !valid_id(&request.installation_id) {
            return Err(SdkError::Invalid);
        }
        self.required(
            Method::POST,
            &format!("{}/devices", base(space)?),
            Some(&request),
        )
        .await
    }
    pub async fn remove_space_device(
        &self,
        space: &str,
        installation: &str,
        request: SpaceDeviceRemoval,
    ) -> Result<SpaceView, SdkError> {
        self.required(
            Method::DELETE,
            &resource(space, "devices", installation)?,
            Some(&request),
        )
        .await
    }
    pub async fn invite_to_space(
        &self,
        space: &str,
        request: SpaceInvitationRequest,
    ) -> Result<SpaceInvitationIssued, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/invitations", base(space)?),
            Some(&request),
        )
        .await
    }
    pub async fn revoke_space_invitation(
        &self,
        space: &str,
        invitation: &str,
        request: SpaceRevisionRequest,
    ) -> Result<SpaceView, SdkError> {
        self.required(
            Method::DELETE,
            &resource(space, "invitations", invitation)?,
            Some(&request),
        )
        .await
    }
    pub async fn accept_space_invitation(
        &self,
        space: &str,
        invitation: &str,
        request: SpaceInvitationAcceptance,
    ) -> Result<SpaceView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/accept", resource(space, "invitations", invitation)?),
            Some(&request),
        )
        .await
    }
    pub async fn space_audit(&self, space: &str) -> Result<Vec<SpaceAuditEntry>, SdkError> {
        self.required(Method::GET, &format!("{}/audit", base(space)?), None::<&()>)
            .await
    }
}
