//! Data-node authority comes from operator approval or signed control discovery.
use crate::{DeviceIdentity, Sdk, SdkError, parse_origin};
use nestlink_identity::{VerifiedPermit, digest, relay::VerifiedRelayAllocation};
use nestlink_protocol::{
    RelayTransport,
    api::{Candidate, CandidateKind, Transport},
};
use prost::Message;
use std::{
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[derive(Clone, Copy)]
struct DiscoveryDeadline {
    monotonic: Instant,
    unix_ms: u64,
}
impl DiscoveryDeadline {
    fn live(self) -> bool {
        Instant::now() < self.monotonic
            && SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .is_ok_and(|d| d.as_millis() < u128::from(self.unix_ms))
    }
}
pub struct NodeRelayRoute {
    url: url::Url,
    addresses: Vec<SocketAddr>,
    permit_digest: [u8; 32],
    allocation: VerifiedRelayAllocation,
    discovery_deadline: Option<DiscoveryDeadline>,
}
impl Sdk {
    /// `approved_origin` is explicit administrator-approved local configuration.
    pub async fn node_relay_route(
        &self,
        approved_origin: &str,
        allow_loopback_http: bool,
        permit: &VerifiedPermit,
        allocation: &VerifiedRelayAllocation,
    ) -> Result<NodeRelayRoute, SdkError> {
        self.login.as_ref().ok_or(SdkError::SignIn)?;
        if permit.claims().deployment_id != self.trust.deployment_id
            || permit.claims().security_epoch != self.health.security_epoch
            || !allocation.matches(permit.claims())?
        {
            return Err(SdkError::Trust);
        }
        let origin = parse_origin(approved_origin, allow_loopback_http)?;
        let port = origin.port_or_known_default().ok_or(SdkError::Invalid)?;
        let mut addresses: Vec<_> = match origin.host().ok_or(SdkError::Invalid)? {
            url::Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
            url::Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
            url::Host::Domain(host) => tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::lookup_host((host, port)),
            )
            .await
            .map_err(|_| SdkError::Timeout)?
            .map_err(|_| SdkError::Invalid)?
            .take(33)
            .collect(),
        };
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty()
            || addresses.len() > 32
            || addresses.iter().any(|a| {
                a.ip().to_canonical().is_unspecified()
                    || a.ip().to_canonical().is_multicast()
                    || (origin.scheme() == "http" && !a.ip().to_canonical().is_loopback())
            })
        {
            return Err(SdkError::Invalid);
        }
        let c = allocation.claims();
        let mut url = origin
            .join(&format!(
                "/api/v3/nodes/{}/relay/{}",
                c.node_id, c.allocation_id
            ))
            .map_err(|_| SdkError::Invalid)?;
        url.set_scheme(if origin.scheme() == "https" {
            "wss"
        } else {
            "ws"
        })
        .map_err(|_| SdkError::Invalid)?;
        Ok(NodeRelayRoute {
            url,
            addresses,
            permit_digest: digest(&permit.claims().encode_to_vec()),
            allocation: allocation.clone(),
            discovery_deadline: None,
        })
    }
}
impl NodeRelayRoute {
    pub(crate) fn allows(&self, permit: &VerifiedPermit, address: SocketAddr) -> bool {
        self.addresses.contains(&address)
            && self.discovery_deadline.is_none_or(DiscoveryDeadline::live)
            && self.permit_digest == digest(&permit.claims().encode_to_vec())
            && self
                .allocation
                .claims()
                .transports
                .contains(&(RelayTransport::WssStream as i32))
    }
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
    /// A scheduler may choose only a literal address from this resolved route.
    pub async fn connect_at(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        address: SocketAddr,
    ) -> Result<tokio_rustls::TlsStream<nestlink_transport_wss::ByteStream>, SdkError> {
        if !self.allows(permit, address) {
            return Err(SdkError::Trust);
        }
        let connect = nestlink_transport_wss::node::connect_at(
            self.url.as_str(),
            (&installation.device_id, &installation.identity),
            permit,
            &self.allocation,
            address,
        );
        if let Some(d) = self.discovery_deadline {
            Ok(tokio::time::timeout_at(d.monotonic.into(), connect)
                .await
                .map_err(|_| SdkError::Timeout)??)
        } else {
            Ok(connect.await?)
        }
    }
}
pub struct NodeQuicRoute {
    addresses: Vec<SocketAddr>,
    permit_digest: [u8; 32],
    allocation: VerifiedRelayAllocation,
    discovery_deadline: Option<DiscoveryDeadline>,
}
impl Sdk {
    /// The QUIC URI is explicit administrator-approved configuration. The node
    /// TLS key comes only from the verified allocation, never DNS or a peer.
    pub async fn node_quic_route(
        &self,
        approved_uri: &str,
        allow_loopback: bool,
        permit: &VerifiedPermit,
        allocation: &VerifiedRelayAllocation,
    ) -> Result<NodeQuicRoute, SdkError> {
        self.login.as_ref().ok_or(SdkError::SignIn)?;
        if permit.claims().deployment_id != self.trust.deployment_id
            || permit.claims().security_epoch != self.health.security_epoch
            || !allocation.matches(permit.claims())?
            || !allocation
                .claims()
                .transports
                .contains(&(RelayTransport::QuicDatagram as i32))
        {
            return Err(SdkError::Trust);
        }
        let uri = url::Url::parse(approved_uri).map_err(|_| SdkError::Invalid)?;
        if uri.scheme() != "quic"
            || !uri.username().is_empty()
            || uri.password().is_some()
            || uri.query().is_some()
            || uri.fragment().is_some()
            || !matches!(uri.path(), "" | "/")
        {
            return Err(SdkError::Invalid);
        }
        let port = uri.port().filter(|n| *n != 0).ok_or(SdkError::Invalid)?;
        let mut addresses: Vec<_> = match uri.host().ok_or(SdkError::Invalid)? {
            url::Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
            url::Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
            url::Host::Domain(host) => tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::lookup_host((host, port)),
            )
            .await
            .map_err(|_| SdkError::Timeout)?
            .map_err(|_| SdkError::Invalid)?
            .take(33)
            .collect(),
        };
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty()
            || addresses.len() > 32
            || addresses.iter().any(|a| {
                a.ip().to_canonical().is_unspecified()
                    || a.ip().to_canonical().is_multicast()
                    || (!allow_loopback && a.ip().to_canonical().is_loopback())
            })
        {
            return Err(SdkError::Invalid);
        }
        Ok(NodeQuicRoute {
            addresses,
            permit_digest: digest(&permit.claims().encode_to_vec()),
            allocation: allocation.clone(),
            discovery_deadline: None,
        })
    }
}
impl NodeQuicRoute {
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
    pub(crate) fn allows(&self, permit: &VerifiedPermit, address: SocketAddr) -> bool {
        self.addresses.contains(&address)
            && self.discovery_deadline.is_none_or(DiscoveryDeadline::live)
            && self.permit_digest == digest(&permit.claims().encode_to_vec())
    }
    pub async fn connect_at(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        address: SocketAddr,
    ) -> Result<nestlink_transport_quic::node::Connected, SdkError> {
        if !self.allows(permit, address) {
            return Err(SdkError::Trust);
        }
        let connect = nestlink_transport_quic::node::connect_at(
            address,
            (&installation.device_id, &installation.identity),
            permit,
            &self.allocation,
        );
        if let Some(d) = self.discovery_deadline {
            tokio::time::timeout_at(d.monotonic.into(), connect)
                .await
                .map_err(|_| SdkError::Timeout)?
                .map_err(SdkError::NodeQuic)
        } else {
            connect.await.map_err(SdkError::NodeQuic)
        }
    }
}
impl Sdk {
    /// DNS occurs only after the signature/request/full permit, allocated node
    /// key/runtime/configuration revision and original request deadline match.
    pub async fn discovered_node_routes(
        &self,
        discovery: &crate::NodeDiscovery,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        allocation: &VerifiedRelayAllocation,
    ) -> Result<(Option<NodeRelayRoute>, Option<NodeQuicRoute>), SdkError> {
        discovery.check(self, permit, &installation.device_id)?;
        nestlink_identity::relay::verify_relay_allocation(
            allocation.signed_bytes(),
            &self.trust.permit_issuer,
        )?;
        let a = allocation.claims();
        let n = discovery
            .nodes()
            .iter()
            .find(|n| n.node_id == a.node_id)
            .ok_or(SdkError::Trust)?;
        if !allocation.matches(permit.claims())?
            || n.node_key_sha256 != a.node_key_sha256
            || n.runtime_id != a.runtime_id
            || n.runtime_generation != a.runtime_generation
            || n.endpoint_revision != a.node_endpoint_revision
        {
            return Err(SdkError::Trust);
        }
        let c = discovery.verified.claims();
        let deadline = DiscoveryDeadline {
            monotonic: discovery.started
                + Duration::from_millis(n.expires_at_unix_ms - c.issued_at_unix_ms),
            unix_ms: n.expires_at_unix_ms,
        };
        if !deadline.live() {
            return Err(SdkError::Trust);
        }
        let resolve = async {
            let wss = if !n.wss_origin.is_empty()
                && a.transports.contains(&(RelayTransport::WssStream as i32))
            {
                let mut r = self
                    .node_relay_route(&n.wss_origin, n.allow_loopback, permit, allocation)
                    .await?;
                if !n.allow_loopback
                    && r.addresses
                        .iter()
                        .any(|a| a.ip().to_canonical().is_loopback())
                {
                    return Err(SdkError::Trust);
                }
                r.discovery_deadline = Some(deadline);
                Some(r)
            } else {
                None
            };
            let quic = if !n.quic_uri.is_empty()
                && a.transports
                    .contains(&(RelayTransport::QuicDatagram as i32))
            {
                let mut r = self
                    .node_quic_route(&n.quic_uri, n.allow_loopback, permit, allocation)
                    .await?;
                r.discovery_deadline = Some(deadline);
                Some(r)
            } else {
                None
            };
            Ok((wss, quic))
        };
        let routes = tokio::time::timeout_at(deadline.monotonic.into(), resolve)
            .await
            .map_err(|_| SdkError::Timeout)??;
        if !deadline.live() {
            return Err(SdkError::Trust);
        }
        Ok(routes)
    }
}
/// Only these locally verified routes may supply relay candidates to the race.
#[derive(Clone, Copy)]
pub enum NativeRelayRoute<'a> {
    Combined(&'a crate::RelayRoute<'a>),
    Wss(&'a NodeRelayRoute),
    Quic(&'a NodeQuicRoute),
}
impl NativeRelayRoute<'_> {
    pub(crate) fn allows(&self, permit: &VerifiedPermit, c: &Candidate) -> bool {
        if c.kind != CandidateKind::Relay {
            return false;
        }
        match self {
            Self::Combined(r) => c.transport == Transport::Wss && r.allows(permit, c.address),
            Self::Wss(r) => c.transport == Transport::Wss && r.allows(permit, c.address),
            Self::Quic(r) => c.transport == Transport::Quic && r.allows(permit, c.address),
        }
    }
    pub fn candidates(&self, generation: u64) -> Result<Vec<Candidate>, SdkError> {
        if match self {
            Self::Combined(_) => false,
            Self::Wss(r) => r.discovery_deadline.is_some_and(|d| !d.live()),
            Self::Quic(r) => r.discovery_deadline.is_some_and(|d| !d.live()),
        } {
            return Err(SdkError::Trust);
        }
        let (addresses, transport) = match self {
            Self::Combined(r) => (r.addresses(), Transport::Wss),
            Self::Wss(r) => (r.addresses(), Transport::Wss),
            Self::Quic(r) => (r.addresses(), Transport::Quic),
        };
        addresses
            .iter()
            .map(|address| {
                let c = Candidate {
                    kind: CandidateKind::Relay,
                    transport,
                    address: *address,
                    generation,
                };
                c.validate()?;
                Ok(c)
            })
            .collect()
    }
    pub(crate) async fn connect(
        &self,
        local: &DeviceIdentity,
        permit: &VerifiedPermit,
        c: &Candidate,
    ) -> Result<crate::native::NativeTransport, SdkError> {
        if !self.allows(permit, c) {
            return Err(SdkError::Trust);
        }
        match self {
            Self::Combined(r) => r
                .connect(local, permit, c.address)
                .await
                .map(|io| crate::native::NativeTransport::Wss(Box::new(io))),
            Self::Wss(r) => r
                .connect_at(local, permit, c.address)
                .await
                .map(|io| crate::native::NativeTransport::Wss(Box::new(io))),
            Self::Quic(r) => r.connect_at(local, permit, c.address).await.map(|io| {
                crate::native::NativeTransport::Quic {
                    connection: io.connection,
                    endpoint: io.endpoint,
                    carrier: Some(Box::new(io.carrier)),
                }
            }),
        }
    }
}
