use crate::*;

impl Sdk {
    /// Explicit local consent and the registered host key are required.
    pub async fn configure_remote_password(
        &self,
        host: &DeviceIdentity,
        settings: RemotePasswordSettings,
        password: Secret,
    ) -> Result<u64, SdkError> {
        let challenge: EnrollmentChallenge = self
            .required(Method::POST, "/devices/challenge", None::<&()>)
            .await?;
        if challenge.deployment_id != self.trust.deployment_id
            || challenge.security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        let actor = self.principal().ok_or(SdkError::SignIn)?;
        let choice = RemotePasswordChoice {
            settings,
            password: password.expose().into(),
        };
        let proof = nestlink_identity::remote_password::configure_transcript(
            &challenge,
            &actor.account_id,
            &host.device_id,
            &choice,
        )?;
        let body = RemotePasswordSetup {
            challenge_id: challenge.id,
            choice,
            signature: URL_SAFE_NO_PAD.encode(host.identity.sign_action(&proof)?),
        };
        let response: RevisionResponse = self
            .required(
                Method::PUT,
                &format!("{}/remote-password", resource("devices", &host.device_id)?),
                Some(&body),
            )
            .await?;
        Ok(response.revision)
    }
    pub async fn remote_password(&self, host: &str) -> Result<RemotePasswordView, SdkError> {
        self.required(
            Method::GET,
            &format!("{}/remote-password", resource("devices", host)?),
            None::<&()>,
        )
        .await
    }
    pub async fn revoke_remote_password(
        &self,
        host: &str,
        expected_revision: u64,
    ) -> Result<(), SdkError> {
        self.call::<_, serde_json::Value>(
            Method::DELETE,
            &format!("{}/remote-password", resource("devices", host)?),
            Some(&RemotePasswordRevocation { expected_revision }),
            true,
        )
        .await
        .map(|_| ())
    }
    pub async fn remote_password_offer(&self, id: &str) -> Result<RemotePasswordView, SdkError> {
        self.required(
            Method::GET,
            &format!("{}/password", resource("remote", id)?),
            None::<&()>,
        )
        .await
    }
    /// Uses an explicit pending request and pinned configuration revision. Never
    /// falls back to manual approval or silently broadens its permission set.
    pub async fn authorize_remote_password(
        &self,
        controller: &DeviceIdentity,
        view: &RemoteView,
        expected_revision: u64,
        password: Secret,
    ) -> Result<RemoteView, SdkError> {
        if view.controller_device_id != controller.device_id || view.status != "pending" {
            return Err(SdkError::Trust);
        }
        let actor = self.principal().ok_or(SdkError::SignIn)?;
        let attempt = RemotePasswordAttempt {
            expected_revision,
            password: password.expose().into(),
        };
        let proof = nestlink_identity::remote_password::use_transcript(
            &self.trust.deployment_id,
            self.health.security_epoch,
            &actor.account_id,
            view,
            &attempt,
        )?;
        let body = RemotePasswordSubmission {
            attempt,
            signature: URL_SAFE_NO_PAD.encode(controller.identity.sign_action(&proof)?),
        };
        self.required(
            Method::POST,
            &format!("{}/password", resource("remote", &view.id)?),
            Some(&body),
        )
        .await
    }
}
