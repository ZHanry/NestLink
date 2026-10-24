//! Explicit signed announcement and approval endpoints; no automatic capability.
use super::*;
use nestlink_protocol::media_authority::{FrozenMediaScope, MediaAnnouncement, MediaDirection};
impl Sdk {
    /// The product must supply an actual direction-specific owned probe receipt.
    /// This signer authenticates data; it does not manufacture backend evidence.
    pub async fn publish_media_announcement(
        &self,
        installation: &DeviceIdentity,
        announcement: MediaAnnouncement,
        now_unix_ms: u64,
    ) -> Result<(), SdkError> {
        announcement.validate(now_unix_ms)?;
        if announcement.device_id != installation.device_id {
            return Err(SdkError::Trust);
        }
        let challenge: EnrollmentChallenge = self
            .required(Method::POST, "/devices/challenge", None::<&()>)
            .await?;
        if challenge.deployment_id != self.trust.deployment_id
            || challenge.security_epoch != self.health.security_epoch
            || challenge.expires_at_unix_ms <= now_unix_ms
        {
            return Err(SdkError::Trust);
        }
        let claims = DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::AnnounceMedia as i32,
            deployment_id: challenge.deployment_id,
            security_epoch: challenge.security_epoch,
            account_id: self.principal().ok_or(SdkError::SignIn)?.account_id.clone(),
            device_id: installation.device_id.clone(),
            resource_id: challenge.id.clone(),
            challenge: URL_SAFE_NO_PAD
                .decode(challenge.nonce)
                .map_err(|_| SdkError::Invalid)?,
            payload_sha256: digest(&serde_json::to_vec(&announcement)?).to_vec(),
            expires_at_unix_ms: challenge.expires_at_unix_ms,
        };
        let direction = announcement.direction.as_str();
        let body = MediaAnnouncementSubmission {
            challenge_id: challenge.id,
            announcement,
            signature: URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&claims)?),
        };
        self.call::<_, serde_json::Value>(
            Method::PUT,
            &format!(
                "{}/media/{direction}",
                resource("devices", &installation.device_id)?
            ),
            Some(&body),
            true,
        )
        .await
        .map(|_| ())
    }
    pub async fn media_announcement(
        &self,
        device_id: &str,
        direction: MediaDirection,
    ) -> Result<Option<MediaAnnouncement>, SdkError> {
        self.required(
            Method::GET,
            &format!(
                "{}/media/{}",
                resource("devices", device_id)?,
                direction.as_str()
            ),
            None::<&()>,
        )
        .await
    }
    pub async fn request_media_remote(
        &self,
        request: RemoteRequest,
    ) -> Result<RemoteView, SdkError> {
        self.required(
            Method::POST,
            "/remote/media",
            Some(&MediaRemoteRequest {
                request,
                media_format_version: 2,
            }),
        )
        .await
    }
    pub async fn remote_media_scope(&self, id: &str) -> Result<Option<FrozenMediaScope>, SdkError> {
        let scope: Option<FrozenMediaScope> = self
            .required(
                Method::GET,
                &format!("{}/media", resource("remote", id)?),
                None::<&()>,
            )
            .await?;
        if let Some(scope) = &scope {
            scope.validate()?;
        }
        Ok(scope)
    }
    /// Caller passes the exact scope shown to the host, rather than accepting a
    /// newer catalog behind the review UI. Storage freezes this scope at request.
    pub async fn approve_media_remote(
        &self,
        installation: &DeviceIdentity,
        view: &RemoteView,
        choice: ApprovalChoice,
        reviewed_scope: &FrozenMediaScope,
    ) -> Result<(), SdkError> {
        reviewed_scope.validate()?;
        if view.host_device_id != installation.device_id
            || self.remote_media_scope(&view.id).await?.as_ref() != Some(reviewed_scope)
        {
            return Err(SdkError::Trust);
        }
        let choice = MediaApprovalChoice {
            choice,
            media_format_sha256: reviewed_scope.sha256.clone(),
        };
        let claims = DeviceActionClaims {
            schema_version: SCHEMA_VERSION,
            action: DeviceAction::Approve as i32,
            deployment_id: self.trust.deployment_id.clone(),
            security_epoch: self.health.security_epoch,
            account_id: self.principal().ok_or(SdkError::SignIn)?.account_id.clone(),
            device_id: installation.device_id.clone(),
            resource_id: view.id.clone(),
            challenge: URL_SAFE_NO_PAD
                .decode(&view.nonce)
                .map_err(|_| SdkError::Invalid)?,
            payload_sha256: digest(&serde_json::to_vec(&(
                "nestlink/media-approval/v2",
                &choice,
                reviewed_scope,
            ))?)
            .to_vec(),
            expires_at_unix_ms: view.expires_at_unix_ms,
        };
        let body = MediaApprovalSubmission {
            choice,
            signature: URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&claims)?),
        };
        self.call::<_, serde_json::Value>(
            Method::POST,
            &format!("{}/media/approval", resource("remote", &view.id)?),
            Some(&body),
            true,
        )
        .await
        .map(|_| ())
    }
}
