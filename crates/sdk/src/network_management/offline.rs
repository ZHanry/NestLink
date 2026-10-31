//! Only an authenticated online consume response can reach SDK activation.
use super::*;
use nestlink_identity::offline::{
    OfflineAdmission, OfflineProcess, OfflineVerification, offline_consume_transcript,
    offline_draft_digest, verify_offline_bundle,
};
use nestlink_protocol::offline::management::*;
use std::collections::BTreeSet;

/// Opaque online-consume receipt. Importing a signed file or constructing an
/// identity primitive cannot manufacture the production carrier admission.
pub struct ConsumedOfflineBundle(OfflineAdmission, [u8; 32]);
impl std::ops::Deref for ConsumedOfflineBundle {
    type Target = OfflineAdmission;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for ConsumedOfflineBundle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl ConsumedOfflineBundle {
    pub(crate) fn into_admission(self) -> (OfflineAdmission, [u8; 32]) {
        (self.0, self.1)
    }
}

fn bundle_path(space: &str, id: &str) -> Result<String, SdkError> {
    if !valid_id(id) {
        return Err(SdkError::Invalid);
    }
    Ok(format!("{}/offline/bundles/{id}", base(space)?))
}
fn reviewed(
    view: &OfflineBundleView,
    authority: &[u8; 32],
    digest: [u8; 32],
) -> Result<(), SdkError> {
    if view.authority_public_key != *authority
        || view.draft_digest != digest
        || offline_draft_digest(authority, &view.claims)? != digest
        || !view.live
    {
        return Err(SdkError::Trust);
    }
    Ok(())
}
impl Sdk {
    pub async fn offline_policy(&self, space: &str) -> Result<OfflinePolicyView, SdkError> {
        self.required(
            Method::GET,
            &format!("{}/offline", base(space)?),
            None::<&()>,
        )
        .await
    }
    pub async fn set_offline_enabled(
        &self,
        space: &str,
        request: &OfflineEnableUpdate,
    ) -> Result<OfflinePolicyView, SdkError> {
        self.required(
            Method::PUT,
            &format!("{}/offline", base(space)?),
            Some(request),
        )
        .await
    }
    pub async fn create_offline_private_draft(
        &self,
        space: &str,
        request: &OfflinePrivateDraftRequest,
    ) -> Result<OfflineBundleView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/offline/private-drafts", base(space)?),
            Some(request),
        )
        .await
    }
    pub async fn offline_bundle(
        &self,
        space: &str,
        id: &str,
    ) -> Result<OfflineBundleView, SdkError> {
        self.required(Method::GET, &bundle_path(space, id)?, None::<&()>)
            .await
    }
    pub async fn create_offline_remote_draft(
        &self,
        space: &str,
        request: &OfflineRemoteDraftRequest,
    ) -> Result<OfflineBundleView, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/offline/remote-drafts", base(space)?),
            Some(request),
        )
        .await
    }
    /// `approved_digest` is supplied only after the local user reviewed the
    /// complete fixed draft, budget, deadline and operation list.
    pub async fn approve_offline_bundle(
        &self,
        installation: &DeviceIdentity,
        process: &OfflineProcess,
        view: &OfflineBundleView,
        authority: &[u8; 32],
        endpoint: u8,
        approved_digest: [u8; 32],
    ) -> Result<OfflineBundleView, SdkError> {
        reviewed(view, authority, approved_digest)?;
        let member = view
            .claims
            .members
            .get(usize::from(endpoint))
            .ok_or(SdkError::Invalid)?;
        if member.installation_id != installation.device_id
            || member.public_key != installation.identity.public_key()
            || member.process_nonce != process.nonce()
            || view.claims.deployment_id != self.trust.deployment_id
        {
            return Err(SdkError::Trust);
        }
        let approval = installation.identity.sign_offline_endpoint_approval(
            authority,
            &view.claims,
            endpoint,
            approved_digest,
        )?;
        self.required(
            Method::POST,
            &format!(
                "{}/approval",
                bundle_path(&view.claims.space_id, &view.claims.bundle_id)?
            ),
            Some(&approval),
        )
        .await
    }
    /// Losing a consume response burns the reservation. Retrying cannot mint a
    /// second owner; a newly reviewed bundle is required instead.
    pub async fn activate_offline_bundle(
        &self,
        installation: &DeviceIdentity,
        process: &mut OfflineProcess,
        view: &OfflineBundleView,
        authority: &[u8; 32],
        endpoint: u8,
        approved_digest: [u8; 32],
    ) -> Result<ConsumedOfflineBundle, SdkError> {
        reviewed(view, authority, approved_digest)?;
        let member = view
            .claims
            .members
            .get(usize::from(endpoint))
            .ok_or(SdkError::Invalid)?;
        if member.installation_id != installation.device_id
            || member.public_key != installation.identity.public_key()
            || member.process_nonce != process.nonce()
            || view.claims.deployment_id != self.trust.deployment_id
        {
            return Err(SdkError::Trust);
        }
        let path = bundle_path(&view.claims.space_id, &view.claims.bundle_id)?;
        let challenge: OfflineConsumeChallenge = self
            .required(
                Method::POST,
                &format!("{path}/consume-challenge/{endpoint}"),
                None::<&()>,
            )
            .await?;
        if challenge.draft_digest != approved_digest {
            return Err(SdkError::Trust);
        }
        let proof = offline_consume_transcript(&view.claims, &challenge)?;
        let request = OfflineConsumeRequest {
            endpoint,
            draft_digest: approved_digest,
            process_nonce: process.nonce(),
            signature: installation.identity.sign_action(&proof)?,
        };
        let consumed: OfflineBundleView = self
            .required(Method::POST, &format!("{path}/consume"), Some(&request))
            .await?;
        reviewed(&consumed, authority, approved_digest)?;
        if consumed.claims != view.claims
            || !consumed.consumed[usize::from(endpoint)]
            || consumed.approved != [true, true]
        {
            return Err(SdkError::Trust);
        }
        let revoked = BTreeSet::new();
        let context = OfflineVerification {
            authority,
            deployment_id: &self.trust.deployment_id,
            space_id: &view.claims.space_id,
            policy_epoch: consumed.policy_epoch,
            security_epoch: consumed.security_epoch,
            highest_revocation_epoch: consumed.highest_revocation_epoch,
            revoked_bundle_ids: &revoked,
            now_ms: consumed.observed_at_ms,
        };
        let verified =
            verify_offline_bundle(consumed.signed.as_ref().ok_or(SdkError::Invalid)?, &context)?;
        Ok(ConsumedOfflineBundle(
            process.activate(verified, &context, approved_digest)?,
            *authority,
        ))
    }
    /// Call before further I/O when management connectivity returns. Every
    /// failed synchronization is terminal for this original owner.
    pub async fn synchronize_offline_bundle(
        &self,
        owner: &mut OfflineAdmission,
        authority: &[u8; 32],
    ) -> Result<(), SdkError> {
        let result = async {
            let c = owner.claims().clone();
            let view = self.offline_bundle(&c.space_id, &c.bundle_id).await?;
            let mut revoked = BTreeSet::new();
            if !view.live {
                revoked.insert(c.bundle_id.clone());
            }
            if view.claims != c || view.authority_public_key != *authority {
                return Err(SdkError::Trust);
            }
            let context = OfflineVerification {
                authority,
                deployment_id: &self.trust.deployment_id,
                space_id: &c.space_id,
                policy_epoch: view.policy_epoch,
                security_epoch: view.security_epoch,
                highest_revocation_epoch: view.highest_revocation_epoch,
                revoked_bundle_ids: &revoked,
                now_ms: view.observed_at_ms,
            };
            owner.observe_online(&context)?;
            Ok(())
        }
        .await;
        if result.is_err() {
            owner.stop();
        }
        result
    }
    pub async fn revoke_offline_bundle(
        &self,
        space: &str,
        id: &str,
    ) -> Result<OfflineBundleView, SdkError> {
        self.required(Method::DELETE, &bundle_path(space, id)?, None::<&()>)
            .await
    }
}
