//! Private business authority owns the existing service gate and durable meter.
use super::{Error, LocalTargetOwner, PreparedPrivateLocalTunnel, PublicationContext,
    ServicePublication, ServicePublicationHandle};
use crate::service_usage::ServiceUsageStore;
use nestlink_identity::{InstallationIdentity, services::private::VerifiedPrivateServiceLease};
use nestlink_protocol::services::private::PrivateServiceOpen;
use std::{sync::Arc, time::Instant};

pub struct PrivateServicePublication {
    authority: VerifiedPrivateServiceLease,
    publication: ServicePublication,
}
impl PrivateServicePublication {
    pub fn new(authority: VerifiedPrivateServiceLease, context: &PublicationContext,
        request_started: Instant, usage: Arc<ServiceUsageStore>) -> Result<Self, Error> {
        usage.activate_private(&authority).map_err(nestlink_protocol::ContractError::from)?;
        let publication = ServicePublication::new_with_usage_store(
            authority.lease().clone(), context, request_started, usage)?;
        Ok(Self { authority, publication })
    }
    pub fn authority(&self) -> &VerifiedPrivateServiceLease { &self.authority }
    pub fn handle(&self) -> ServicePublicationHandle { self.publication.handle() }
    pub fn revoke(&self) { self.publication.revoke(); }
    /// The carrier creates expected_nonce freshly before receiving this open.
    /// The SDK must recheck current management authority before invoking it.
    pub fn prepare(&self, target: &LocalTargetOwner, open: &PrivateServiceOpen,
        expected_nonce: [u8;32], host: &InstallationIdentity) -> Result<PreparedPrivateLocalTunnel, Error> {
        target.prepare_private(&self.handle(), &self.authority, open, expected_nonce, host)
    }
}
