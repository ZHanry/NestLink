//! Private admission and currentness use independently scoped service authority.
use super::*;
use nestlink_identity::services::private::{
    VerifiedPrivateServiceLease, verify_private_service_lease,
};
use nestlink_protocol::services::private::*;
mod network;
#[cfg(not(target_arch = "wasm32"))]
pub(super) mod runtime;

impl Sdk {
    pub async fn service_exposure(
        &self,
        id: &str,
    ) -> Result<Option<ServiceExposureView>, SdkError> {
        let result: Option<ServiceExposureView> = self
            .required(
                Method::GET,
                &format!("{}/exposure", resource("services", id)?),
                None::<&()>,
            )
            .await?;
        if let Some(view) = &result {
            validate_exposure(id, view)?;
        }
        Ok(result)
    }
    pub async fn set_service_exposure(
        &self,
        id: &str,
        body: ServiceExposureUpdate,
    ) -> Result<ServiceExposureView, SdkError> {
        let view: ServiceExposureView = self
            .required(
                Method::PUT,
                &format!("{}/exposure", resource("services", id)?),
                Some(&body),
            )
            .await?;
        validate_exposure(id, &view)?;
        if view.revision
            != body
                .expected_revision
                .checked_add(1)
                .ok_or(SdkError::Invalid)?
            || view.service_revision != body.expected_service_revision
            || view.space_id != body.space_id
            || view.mode != body.mode
            || view.private_maximum_bytes != body.private_maximum_bytes
            || view.public_maximum_bytes != body.public_maximum_bytes
        {
            return Err(SdkError::Trust);
        }
        Ok(view)
    }
    pub async fn private_service_policy(
        &self,
        id: &str,
    ) -> Result<PrivateServicePolicyView, SdkError> {
        let view: PrivateServicePolicyView = self
            .required(
                Method::GET,
                &format!("{}/private-policy", resource("services", id)?),
                None::<&()>,
            )
            .await?;
        validate_policy(id, &view)?;
        Ok(view)
    }
    pub async fn grant_private_service(
        &self,
        id: &str,
        body: PrivateServiceAclUpdate,
    ) -> Result<PrivateServicePolicyView, SdkError> {
        let view: PrivateServicePolicyView = self
            .required(
                Method::POST,
                &format!("{}/private-policy", resource("services", id)?),
                Some(&body),
            )
            .await?;
        validate_policy(id, &view)?;
        if view.exposure.revision != body.expected_exposure_revision {
            return Err(SdkError::Trust);
        }
        Ok(view)
    }
    pub async fn revoke_private_service(
        &self,
        id: &str,
        rule: &str,
        expected: u64,
    ) -> Result<PrivateServicePolicyView, SdkError> {
        if !valid_id(rule) {
            return Err(SdkError::Invalid);
        }
        let view: PrivateServicePolicyView = self
            .required(
                Method::DELETE,
                &format!("{}/private-policy/{rule}", resource("services", id)?),
                Some(&PrivateServiceAclRevocation {
                    expected_exposure_revision: expected,
                }),
            )
            .await?;
        validate_policy(id, &view)?;
        if view.exposure.revision != expected
            || !view.rules.iter().any(|r| r.rule_id == rule && r.revoked)
        {
            return Err(SdkError::Trust);
        }
        Ok(view)
    }
    pub async fn private_services(
        &self,
        consumer: &str,
        after: Option<&str>,
        limit: u16,
    ) -> Result<PrivateServicePage, SdkError> {
        if !valid_id(consumer)
            || !(1..=100).contains(&limit)
            || after.is_some_and(|id| !valid_id(id))
        {
            return Err(SdkError::Invalid);
        }
        let mut path = format!(
            "/private-services/{consumer}?security_epoch={}&limit={limit}",
            self.health.security_epoch
        );
        if let Some(after) = after {
            path.push_str(&format!("&after_id={after}"));
        }
        let page: PrivateServicePage = self.required(Method::GET, &path, None::<&()>).await?;
        if page.security_epoch != self.health.security_epoch
            || page.entries.len() > usize::from(limit)
            || page.more != page.next_id.is_some()
        {
            return Err(SdkError::Trust);
        }
        let mut previous = after.unwrap_or("");
        for entry in &page.entries {
            let service = &entry.service;
            validate_exposure(&service.id, &entry.exposure)?;
            if service.id.as_str() <= previous
                || entry.exposure.service_revision != service.revision
                || !entry.exposure.mode.private_enabled()
                || nestlink_identity::services::definition_digest(&service.definition)?
                    != nestlink_identity::services::decode_digest(&service.definition_sha256)?
                || service
                    .target_sha256
                    .as_deref()
                    .map(nestlink_identity::services::decode_digest)
                    .transpose()?
                    != Some(entry.exposure.target_sha256)
            {
                return Err(SdkError::Trust);
            }
            previous = &service.id;
        }
        if page.more
            && page.next_id.as_deref() != page.entries.last().map(|e| e.service.id.as_str())
        {
            return Err(SdkError::Trust);
        }
        Ok(page)
    }
    pub async fn register_private_service_host(
        &self,
        id: &str,
        signed: &SignedPrivateServiceHost,
    ) -> Result<(), SdkError> {
        self.call::<_, serde_json::Value>(
            Method::POST,
            &format!("{}/private-host", resource("services", id)?),
            Some(signed),
            true,
        )
        .await?;
        Ok(())
    }
    pub async fn withdraw_private_service_host(
        &self,
        id: &str,
        signed: &SignedPrivateServiceHostWithdrawal,
    ) -> Result<(), SdkError> {
        self.call::<_, serde_json::Value>(
            Method::DELETE,
            &format!("{}/private-host", resource("services", id)?),
            Some(signed),
            true,
        )
        .await?;
        Ok(())
    }
    pub async fn request_private_service(
        &self,
        id: &str,
        request: PrivateServiceAccessRequest,
    ) -> Result<VerifiedPrivateServiceLease, SdkError> {
        if !valid_id(&request.request_id)
            || !valid_id(&request.consumer_device_id)
            || request.maximum_bytes == 0
        {
            return Err(SdkError::Invalid);
        }
        let grant: PrivateServiceGrant = self
            .required(
                Method::POST,
                &format!("{}/private-access", resource("services", id)?),
                Some(&request),
            )
            .await?;
        let verified = self.verify_private_service_grant(&grant)?;
        let claims = verified.lease().claims();
        if claims.service_id != id
            || claims.service_revision != request.expected_service_revision
            || verified.claims().exposure_revision != request.expected_exposure_revision
            || verified.claims().consumer_device_id != request.consumer_device_id
            || verified.claims().consumer_account_id
                != self.principal().ok_or(SdkError::SignIn)?.account_id
        {
            return Err(SdkError::Trust);
        }
        let usage: nestlink_protocol::service_plane::ServiceUsageBudgetGrantClaims =
            nestlink_protocol::service_plane::decode_service_message(
                &claims.usage_grant.claims,
                nestlink_protocol::service_plane::SERVICE_USAGE_BYTES,
            )?;
        if usage.byte_ceiling > request.maximum_bytes {
            return Err(SdkError::Trust);
        }
        Ok(verified)
    }
    pub async fn current_private_service(
        &self,
        id: &str,
        reservation: &str,
    ) -> Result<VerifiedPrivateServiceLease, SdkError> {
        if !valid_id(reservation) {
            return Err(SdkError::Invalid);
        }
        let grant: PrivateServiceGrant = self
            .required(
                Method::GET,
                &format!("{}/private-access/{reservation}", resource("services", id)?),
                None::<&()>,
            )
            .await?;
        let verified = self.verify_private_service_grant(&grant)?;
        let base = verified.lease().claims();
        let usage: nestlink_protocol::service_plane::ServiceUsageBudgetGrantClaims =
            nestlink_protocol::service_plane::decode_service_message(
                &base.usage_grant.claims,
                nestlink_protocol::service_plane::SERVICE_USAGE_BYTES,
            )?;
        if base.service_id != id || usage.grant_id != reservation {
            return Err(SdkError::Trust);
        }
        Ok(verified)
    }
    fn verify_private_service_grant(
        &self,
        grant: &PrivateServiceGrant,
    ) -> Result<VerifiedPrivateServiceLease, SdkError> {
        let now = private_wall_ms()?;
        let policy: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&self.health.node_policy_issuer)
            .map_err(|_| SdkError::Trust)?
            .try_into()
            .map_err(|_| SdkError::Trust)?;
        let delegation =
            nestlink_identity::service_plane::publication::verify_service_issuer_delegation(
                &grant.issuer,
                &policy,
                &self.trust.deployment_id,
                now,
            )?;
        delegation.verify_lease(&grant.lease.service_lease, now)?;
        let verified =
            verify_private_service_lease(&grant.lease, &delegation.claims().service_issuer)?;
        verified.check_time(now)?;
        if verified.lease().claims().security_epoch != self.health.security_epoch {
            return Err(SdkError::Trust);
        }
        network::verify(&verified, &grant.network, now)?;
        Ok(verified)
    }
    pub async fn report_private_service_usage(
        &self,
        signed: &SignedPrivateServiceUsage,
    ) -> Result<PrivateServiceUsageAck, SdkError> {
        let claims: PrivateServiceUsageClaims =
            nestlink_protocol::service_plane::decode_service_message(
                &signed.claims,
                PRIVATE_SERVICE_MESSAGE_BYTES,
            )?;
        let ack: PrivateServiceUsageAck = self
            .call(Method::POST, "/private-service-usage", Some(signed), false)
            .await?
            .ok_or(SdkError::Trust)?;
        if ack.grant_id != claims.grant_id
            || ack.report_sequence != claims.report_sequence
            || ack.report_sha256 != nestlink_identity::digest(&signed.claims)
            || ack.terminal != claims.terminal
        {
            return Err(SdkError::Trust);
        }
        Ok(ack)
    }
}
#[cfg(not(target_arch = "wasm32"))]
fn private_wall_ms() -> Result<u64, SdkError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SdkError::Trust)?
        .as_millis()
        .try_into()
        .map_err(|_| SdkError::Trust)
}
#[cfg(target_arch = "wasm32")]
fn private_wall_ms() -> Result<u64, SdkError> {
    let now = js_sys::Date::now();
    if !now.is_finite() || now < 0.0 {
        return Err(SdkError::Trust);
    }
    Ok(now as u64)
}
fn validate_exposure(id: &str, view: &ServiceExposureView) -> Result<(), SdkError> {
    if view.service_id != id
        || !valid_id(id)
        || !valid_id(&view.space_id)
        || !nestlink_protocol::services::revision_valid(view.revision)
        || !nestlink_protocol::services::revision_valid(view.service_revision)
        || view.target_sha256 == [0; 32]
        || view.mode.private_enabled() != (view.private_maximum_bytes > 0)
        || view.mode.public_enabled() != (view.public_maximum_bytes > 0)
    {
        return Err(SdkError::Trust);
    }
    Ok(())
}
fn validate_policy(id: &str, view: &PrivateServicePolicyView) -> Result<(), SdkError> {
    validate_exposure(id, &view.exposure)?;
    if view.rules.len() > 256 || view.rules.iter().any(|r| !valid_id(&r.rule_id)) {
        return Err(SdkError::Trust);
    }
    Ok(())
}
