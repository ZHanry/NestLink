//! A relay route is derived from the approved management origin. Signed peer
//! candidates cannot redirect its bearer credential to a peer-supplied server.
use crate::{DeviceIdentity, Sdk, SdkError, resource};
use nestlink_identity::{VerifiedPermit, digest};
use nestlink_protocol::{
    API_BASE, Path,
    api::{Candidate, CandidateKind, Transport},
};
use prost::Message;
use std::{net::SocketAddr, time::Duration};

pub struct RelayRoute<'a> {
    sdk: &'a Sdk,
    url: url::Url,
    addresses: Vec<SocketAddr>,
    permit_digest: [u8; 32],
}
impl Sdk {
    /// Resolve once with a bounded budget. Every attempt connects the resulting
    /// literal address and retains the configured authority's TLS validation.
    pub async fn relay_route(&self, permit: &VerifiedPermit) -> Result<RelayRoute<'_>, SdkError> {
        if !permit.claims().paths.contains(&(Path::Relay as i32)) {
            return Err(SdkError::Trust);
        }
        if permit.claims().deployment_id != self.trust.deployment_id
            || permit.claims().security_epoch != self.health.security_epoch
        {
            return Err(SdkError::Trust);
        }
        self.login.as_ref().ok_or(SdkError::SignIn)?;
        let mut url = self
            .origin
            .join(&format!(
                "{API_BASE}{}/relay",
                resource("remote", &permit.claims().session_id)?
            ))
            .map_err(|_| SdkError::Invalid)?;
        let port = self
            .origin
            .port_or_known_default()
            .ok_or(SdkError::Invalid)?;
        url.set_scheme(if self.origin.scheme() == "https" {
            "wss"
        } else {
            "ws"
        })
        .map_err(|_| SdkError::Invalid)?;
        let mut addresses = match self.origin.host().ok_or(SdkError::Invalid)? {
            url::Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
            url::Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
            url::Host::Domain(host) => tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::lookup_host((host, port)),
            )
            .await
            .map_err(|_| SdkError::Timeout)?
            .map_err(|_| SdkError::Invalid)?
            .take(32)
            .collect(),
        };
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty()
            || addresses
                .iter()
                .any(|a| a.ip().is_unspecified() || a.ip().is_multicast())
            || (url.scheme() == "ws" && addresses.iter().any(|a| !a.ip().is_loopback()))
        {
            return Err(SdkError::Invalid);
        }
        Ok(RelayRoute {
            sdk: self,
            url,
            addresses,
            permit_digest: digest(&permit.claims().encode_to_vec()),
        })
    }
}
impl RelayRoute<'_> {
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
    pub fn candidates(&self, generation: u64) -> Vec<Candidate> {
        self.addresses
            .iter()
            .map(|address| Candidate {
                address: *address,
                kind: CandidateKind::Relay,
                transport: Transport::Wss,
                generation,
            })
            .collect()
    }
    pub(crate) fn allows(&self, permit: &VerifiedPermit, address: SocketAddr) -> bool {
        self.permit_digest == digest(&permit.claims().encode_to_vec())
            && self.addresses.contains(&address)
    }
    pub(crate) async fn connect(
        &self,
        local: &DeviceIdentity,
        permit: &VerifiedPermit,
        address: SocketAddr,
    ) -> Result<tokio_rustls::TlsStream<nestlink_transport_wss::ByteStream>, SdkError> {
        if !self.allows(permit, address) {
            return Err(SdkError::Trust);
        }
        let login = self.sdk.login.as_ref().ok_or(SdkError::SignIn)?;
        Ok(nestlink_transport_wss::connect_at(
            self.url.as_str(),
            login.access.expose(),
            &login.principal.account_id,
            (&local.device_id, &local.identity),
            permit,
            address,
        )
        .await?)
    }
}
