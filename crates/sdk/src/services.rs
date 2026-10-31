//! Service configuration and explicit local target consent. No listener or target
//! connection is created here, and no remote response chooses the local target.
use crate::*;
#[cfg(not(target_arch = "wasm32"))]
mod local_proxy;
mod private;
#[cfg(not(target_arch = "wasm32"))]
pub use local_proxy::{
    LocalProxyError, LocalProxyServiceChoice, LocalProxyStopReport, LocalProxyWait,
    LocalServiceProxy,
};
use nestlink_protocol::service_plane::publication::{
    ServiceEdgeNamespaceUpdate, ServiceEdgeNamespaceView, ServicePublicationRequest,
};
#[cfg(not(target_arch = "wasm32"))]
pub use private::runtime::{
    PrivateServiceConnection, PrivateServiceHost, PrivateServiceHostConfig,
};
#[cfg(not(target_arch = "wasm32"))]
use std::net::SocketAddr;
#[cfg(not(target_arch = "wasm32"))]
mod publication;
#[cfg(not(target_arch = "wasm32"))]
pub use publication::{
    HttpsBackendTls, LocalServiceRuntime, ServiceHostStopReport, ServiceHostWait,
};

/// Created only from an explicit local choice. It cannot be deserialized from IPC
/// or a server response. Keep this owner beside the local target registration;
/// registry approval alone never authorizes a future socket.
#[cfg(not(target_arch = "wasm32"))]
pub struct LocalServiceTargetConsent {
    original_view: ServiceView,
    service_id: String,
    revision: u64,
    definition_sha256: String,
    host_device_id: String,
    account_id: String,
    target_id: String,
    target_sha256: String,
    protocol: String,
    address: SocketAddr,
    backend_tls: Option<HttpsBackendTls>,
}
#[cfg(not(target_arch = "wasm32"))]
impl LocalServiceTargetConsent {
    /// The caller displays and approves the full definition and fixed address
    /// locally before invoking this function. It does not resolve DNS names.
    pub fn from_local_choice(
        view: &ServiceView,
        protocol: &str,
        address: SocketAddr,
    ) -> Result<Self, SdkError> {
        if view.approval == ServiceApprovalState::Revoked {
            return Err(SdkError::Trust);
        }
        let target_id = random_id();
        let target_sha256 = URL_SAFE_NO_PAD.encode(
            nestlink_identity::services::local_target_digest(view, &target_id, protocol, address)?,
        );
        Ok(Self {
            original_view: view.clone(),
            service_id: view.id.clone(),
            revision: view.revision,
            definition_sha256: view.definition_sha256.clone(),
            host_device_id: view.definition.host_device_id.clone(),
            account_id: view.account_id.clone(),
            target_id,
            target_sha256,
            protocol: protocol.into(),
            address,
            backend_tls: None,
        })
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    /// Local trust material is retained with the chooser owner, and is never
    /// accepted from management JSON or from a visitor stream.
    pub fn with_https_backend_tls(mut self, tls: HttpsBackendTls) -> Result<Self, SdkError> {
        if self.protocol != "https" {
            return Err(SdkError::Invalid);
        }
        self.backend_tls = Some(tls);
        Ok(self)
    }
    pub fn target_digest(&self) -> &str {
        &self.target_sha256
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn protocol(&self) -> &str {
        &self.protocol
    }
}
impl Sdk {
    /// Stop the currently published ingress through the same authoritative
    /// management route used by native clients.
    pub async fn stop_service_publication(&self, id: &str, revision: u64) -> Result<(), SdkError> {
        if !valid_id(id) || !nestlink_protocol::services::revision_valid(revision) {
            return Err(SdkError::Invalid);
        }
        self.call::<_, serde_json::Value>(
            Method::DELETE,
            &format!("{}/publication", resource("services", id)?),
            Some(&ServicePublicationRequest {
                expected_revision: revision,
            }),
            true,
        )
        .await?;
        Ok(())
    }

    pub async fn services(
        &self,
        after_id: Option<&str>,
        limit: u16,
    ) -> Result<ServicePage, SdkError> {
        if !(1..=100).contains(&limit) || after_id.is_some_and(|id| !valid_id(id)) {
            return Err(SdkError::Invalid);
        }
        let mut query = format!(
            "/services?security_epoch={}&limit={limit}",
            self.health.security_epoch
        );
        if let Some(id) = after_id {
            query.push_str(&format!("&after_id={id}"));
        }
        let page: ServicePage = self.required(Method::GET, &query, None::<&()>).await?;
        if page.security_epoch != self.health.security_epoch
            || page.services.len() > usize::from(limit)
            || page
                .services
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
            || page.next_id.as_ref() != page.services.last().map(|v| &v.id)
            || page.more && page.services.len() != usize::from(limit)
            || after_id.is_some_and(|after| {
                page.services
                    .first()
                    .is_some_and(|first| first.id.as_str() <= after)
            })
        {
            return Err(SdkError::Trust);
        }
        for view in &page.services {
            self.validate_service_view(view)?;
        }
        Ok(page)
    }
    pub async fn service(&self, id: &str) -> Result<ServiceView, SdkError> {
        let view: ServiceView = self
            .required(Method::GET, &resource("services", id)?, None::<&()>)
            .await?;
        self.validate_service_view(&view)?;
        if view.id != id {
            return Err(SdkError::Trust);
        }
        Ok(view)
    }
    pub async fn create_service(&self, body: &ServiceCreate) -> Result<ServiceView, SdkError> {
        if !valid_id(&body.id) {
            return Err(SdkError::Invalid);
        }
        body.definition.validate()?;
        let view: ServiceView = self.required(Method::POST, "/services", Some(body)).await?;
        self.validate_service_view(&view)?;
        if view.id != body.id
            || view.definition != body.definition
            || view.revision != 1
            || view.approval != ServiceApprovalState::Pending
        {
            return Err(SdkError::Trust);
        }
        Ok(view)
    }
    pub async fn update_service(
        &self,
        id: &str,
        body: &ServiceUpdate,
    ) -> Result<ServiceView, SdkError> {
        let next = body
            .expected_revision
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(SdkError::Invalid)?;
        body.definition.validate()?;
        let view: ServiceView = self
            .required(Method::PUT, &resource("services", id)?, Some(body))
            .await?;
        self.validate_service_view(&view)?;
        if view.id != id
            || view.definition != body.definition
            || view.revision != next
            || view.approval == ServiceApprovalState::ApprovedTarget
        {
            return Err(SdkError::Trust);
        }
        Ok(view)
    }
    pub async fn revoke_service(
        &self,
        id: &str,
        expected_revision: u64,
    ) -> Result<ServiceView, SdkError> {
        let next = expected_revision
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(SdkError::Invalid)?;
        let view: ServiceView = self
            .required(
                Method::DELETE,
                &resource("services", id)?,
                Some(&ServiceRevocation { expected_revision }),
            )
            .await?;
        self.validate_service_view(&view)?;
        if view.id != id || view.revision != next || view.approval != ServiceApprovalState::Revoked
        {
            return Err(SdkError::Trust);
        }
        Ok(view)
    }
    fn validate_service_view(&self, view: &ServiceView) -> Result<(), SdkError> {
        let principal = self.principal().ok_or(SdkError::SignIn)?;
        if !valid_id(&view.id)
            || !valid_id(&view.management_session_id)
            || view.account_id != principal.account_id
            || !nestlink_protocol::services::revision_valid(view.revision)
            || nestlink_identity::services::definition_digest(&view.definition)?
                != nestlink_identity::services::decode_digest(&view.definition_sha256)?
            || view.target_id.is_some() != view.target_sha256.is_some()
            || view.target_id.is_some() != view.approval_expires_at_unix_ms.is_some()
            || view.approval == ServiceApprovalState::ApprovedTarget && view.target_id.is_none()
            || view.publication == ServicePublicationStatus::Published
                && (view.approval != ServiceApprovalState::ApprovedTarget
                    || view.target_id.is_none())
        {
            return Err(SdkError::Trust);
        }
        if let Some(target) = &view.target_id
            && !valid_id(target)
        {
            return Err(SdkError::Trust);
        }
        if let Some(hash) = &view.target_sha256 {
            nestlink_identity::services::decode_digest(hash)?;
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn approve_service_target(
        &self,
        host: &DeviceIdentity,
        consent: &LocalServiceTargetConsent,
        lifetime_ms: u64,
    ) -> Result<ServiceView, SdkError> {
        use nestlink_identity::services::{approval_transcript, validate_challenge};
        let principal = self.principal().ok_or(SdkError::SignIn)?;
        if host.device_id != consent.host_device_id
            || principal.account_id != consent.account_id
            || lifetime_ms == 0
            || lifetime_ms > nestlink_protocol::services::SERVICE_APPROVAL_LIFETIME_MS
        {
            return Err(SdkError::Trust);
        }
        let challenge: ServiceApprovalChallenge = self
            .required(
                Method::POST,
                &format!(
                    "{}/approval/challenge",
                    resource("services", &consent.service_id)?
                ),
                Some(&ServiceApprovalChallengeRequest {
                    expected_revision: consent.revision,
                }),
            )
            .await?;
        validate_challenge(&challenge)?;
        if challenge.deployment_id != self.trust.deployment_id
            || challenge.security_epoch != self.health.security_epoch
            || challenge.account_id != principal.account_id
            || challenge.management_session_id != principal.session_id
            || challenge.host_device_id != host.device_id
            || challenge.service_id != consent.service_id
            || challenge.service_revision != consent.revision
            || challenge.definition_sha256 != consent.definition_sha256
        {
            return Err(SdkError::Trust);
        }
        let choice = ServiceTargetChoice {
            expected_revision: consent.revision,
            target_id: consent.target_id.clone(),
            target_sha256: consent.target_sha256.clone(),
            expires_at_unix_ms: challenge
                .issued_at_unix_ms
                .checked_add(lifetime_ms)
                .ok_or(SdkError::Invalid)?,
        };
        let signature = URL_SAFE_NO_PAD.encode(
            host.identity
                .sign_action(&approval_transcript(&challenge, &choice)?)?,
        );
        let body = ServiceTargetApproval {
            challenge_id: challenge.id,
            choice,
            signature,
        };
        let view: ServiceView = self
            .required(
                Method::POST,
                &format!("{}/approval", resource("services", &consent.service_id)?),
                Some(&body),
            )
            .await?;
        self.validate_service_view(&view)?;
        if view.id != consent.service_id
            || view.revision != consent.revision.checked_add(1).ok_or(SdkError::Invalid)?
            || view.definition_sha256 != consent.definition_sha256
            || view.approval != ServiceApprovalState::ApprovedTarget
            || view.target_id.as_deref() != Some(consent.target_id.as_str())
            || view.target_sha256.as_deref() != Some(consent.target_sha256.as_str())
            || view.approval_expires_at_unix_ms != Some(body.choice.expires_at_unix_ms)
        {
            return Err(SdkError::Trust);
        }
        Ok(view)
    }
}

impl Sdk {
    pub async fn service_edge_namespace(
        &self,
        node: &str,
    ) -> Result<ServiceEdgeNamespaceView, SdkError> {
        let view: ServiceEdgeNamespaceView = self
            .required(
                Method::GET,
                &format!("{}/service-namespace", resource("nodes", node)?),
                None::<&()>,
            )
            .await?;
        view.config.validate()?;
        if view.node_id != node || view.revision == 0 || view.revision > i64::MAX as u64 {
            return Err(SdkError::Trust);
        }
        Ok(view)
    }
    pub async fn set_service_edge_namespace(
        &self,
        node: &str,
        body: &ServiceEdgeNamespaceUpdate,
    ) -> Result<ServiceEdgeNamespaceView, SdkError> {
        body.config.validate()?;
        let next = body
            .expected_revision
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(SdkError::Invalid)?;
        let view: ServiceEdgeNamespaceView = self
            .required(
                Method::PUT,
                &format!("{}/service-namespace", resource("nodes", node)?),
                Some(body),
            )
            .await?;
        view.config.validate()?;
        if view.node_id != node || view.revision != next || view.config != body.config {
            return Err(SdkError::Trust);
        }
        Ok(view)
    }
}
