//! A bounded, public selection handoff. This file grants no access: the native
//! owner must restore its own login/installation and request the original lease.
use crate::SdkError;
use nestlink_protocol::{api::ServiceIngress, services::private::{PrivateServiceAvailability, PrivateServiceEntry}, valid_id};
use serde::{Deserialize, Serialize};
use url::Url;

pub const PRIVATE_WEB_REQUEST_BYTES: usize = 8192;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateWebLaunchRequest {
    pub schema_version: u32,
    pub management_origin: String,
    pub gateway_installation_id: String,
    pub service_id: String,
    pub space_id: String,
    pub expected_service_revision: u64,
    pub expected_exposure_revision: u64,
    pub target_sha256: [u8; 32],
    pub origin: String,
    pub maximum_bytes: u64,
    pub lifetime_seconds: u64,
}
impl PrivateWebLaunchRequest {
    pub fn from_json(bytes: &[u8]) -> Result<Self, SdkError> {
        if bytes.is_empty() || bytes.len() > PRIVATE_WEB_REQUEST_BYTES { return Err(SdkError::Invalid); }
        let request: Self = serde_json::from_slice(bytes)?;
        request.validate(&request.management_origin)?;
        Ok(request)
    }
    pub fn validate(&self, management: &str) -> Result<(), SdkError> {
        let manager = Url::parse(management).map_err(|_| SdkError::Invalid)?;
        let origin = isolated_origin(&self.origin, &manager)?;
        if self.schema_version != 1 || self.management_origin != management
            || [&self.gateway_installation_id, &self.service_id, &self.space_id].iter().any(|id| !valid_id(id))
            || !nestlink_protocol::services::revision_valid(self.expected_service_revision)
            || !nestlink_protocol::services::revision_valid(self.expected_exposure_revision)
            || self.target_sha256 == [0; 32] || self.maximum_bytes == 0 || self.maximum_bytes > i64::MAX as u64
            || !(1..=3600).contains(&self.lifetime_seconds)
            || !origin.host_str().is_some_and(|host| host.starts_with(&format!("{}.", self.service_id)))
        { return Err(SdkError::Invalid); }
        Ok(())
    }
    pub fn checks_entry(&self, installation: &str, entry: &PrivateServiceEntry) -> bool {
        self.gateway_installation_id == installation && self.service_id == entry.service.id
            && self.space_id == entry.exposure.space_id
            && self.expected_service_revision == entry.service.revision
            && self.expected_exposure_revision == entry.exposure.revision
            && self.target_sha256 == entry.exposure.target_sha256
            && entry.exposure.mode.private_enabled()
            && entry.availability == PrivateServiceAvailability::Ready
            && matches!(&entry.service.definition.requested_ingress, ServiceIngress::Http {..} | ServiceIngress::Https {..})
            && self.maximum_bytes <= entry.exposure.private_maximum_bytes
            && self.maximum_bytes <= entry.service.definition.limits.maximum_bytes
    }
    /// The browser may open only this selected service's fragment capability.
    /// It never imports a route bootstrap or a native installation credential.
    pub fn checked_launch_url(&self, value: &str) -> Result<String, SdkError> {
        if value.len() > 4096 { return Err(SdkError::Invalid); }
        let url = Url::parse(value).map_err(|_| SdkError::Invalid)?;
        let ticket = url.fragment().ok_or(SdkError::Invalid)?;
        if url.origin().ascii_serialization() != self.origin || url.path() != "/.nestlink/launch"
            || !url.username().is_empty() || url.password().is_some() || url.query().is_some()
            || ticket.len() != 43 || !ticket.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        { return Err(SdkError::Invalid); }
        Ok(url.to_string())
    }
}

pub(super) fn isolated_origin(value: &str, management: &Url) -> Result<Url, SdkError> {
    let url = Url::parse(value).map_err(|_| SdkError::Invalid)?;
    let host = url.host_str().ok_or(SdkError::Invalid)?;
    let manager = management.host_str().ok_or(SdkError::Invalid)?;
    // Conservative domain isolation also prevents parent-domain management
    // cookie injection without introducing an incomplete public suffix parser.
    let tail = |name: &str| name.rsplit('.').take(2).collect::<Vec<_>>().join(".");
    if value.len() > 2048 || url.scheme() != "https" || url.port().is_some()
        || !url.username().is_empty() || url.password().is_some() || url.path() != "/"
        || url.query().is_some() || url.fragment().is_some() || !host.is_ascii()
        || host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') || host.ends_with('.')
        || tail(host) == tail(manager) || host == manager || host.ends_with(&format!(".{manager}"))
        || manager.ends_with(&format!(".{host}")) || url.origin().ascii_serialization() != value
    { return Err(SdkError::Invalid); }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result = std::result::Result<(), Box<dyn std::error::Error>>;
    fn request() -> PrivateWebLaunchRequest {
        PrivateWebLaunchRequest { schema_version: 1, management_origin: "https://control.example.com".into(), gateway_installation_id: "11111111-1111-4111-8111-111111111111".into(), service_id: "22222222-2222-4222-8222-222222222222".into(), space_id: "33333333-3333-4333-8333-333333333333".into(), expected_service_revision: 1, expected_exposure_revision: 1, target_sha256: [4;32], origin: "https://22222222-2222-4222-8222-222222222222.private.example.net".into(), maximum_bytes: 4096, lifetime_seconds: 300 }
    }
    #[test]
    fn handoff_is_bounded_strict_and_management_origin_bound() -> Result {
        let request = request();
        let bytes = serde_json::to_vec(&request)?;
        assert!(PrivateWebLaunchRequest::from_json(&bytes).is_ok());
        assert!(PrivateWebLaunchRequest::from_json(&vec![b' '; PRIVATE_WEB_REQUEST_BYTES + 1]).is_err());
        assert!(request.validate("https://other.example.org").is_err());
        let mut unknown: serde_json::Value = serde_json::from_slice(&bytes)?;
        unknown["public_grant"] = serde_json::json!(true);
        assert!(PrivateWebLaunchRequest::from_json(&serde_json::to_vec(&unknown)?).is_err());
        for origin in ["https://22222222-2222-4222-8222-222222222222.private.example.com", "https://other.private.example.net", "https://22222222-2222-4222-8222-222222222222.private.example.net:444"] {
            let mut changed = request.clone(); changed.origin = origin.into();
            assert!(changed.validate(&changed.management_origin).is_err());
        }
        Ok(())
    }
    #[test]
    fn launch_link_cannot_select_another_service_or_leak_ticket_to_query() {
        let request = request(); let ticket = "a".repeat(43);
        assert!(request.checked_launch_url(&format!("{}/.nestlink/launch#{ticket}", request.origin)).is_ok());
        for value in [format!("https://other.private.example.net/.nestlink/launch#{ticket}"), format!("{}/.nestlink/launch?ticket={ticket}", request.origin), format!("{}/app#{ticket}", request.origin)] {
            assert!(request.checked_launch_url(&value).is_err());
        }
    }
}
