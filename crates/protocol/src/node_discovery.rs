//! Approved native node locations are bounded and validated before DNS access.
use crate::{
    ContractError, ErrorCode, NODE_DISCOVERY_COUNT, NODE_DISCOVERY_MS, NodeDiscoveryClaims,
    SCHEMA_VERSION, api::NodeEndpoints, valid_id,
};
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid node discovery")
}
pub fn endpoint_url(
    value: &str,
    quic: bool,
    allow_loopback: bool,
) -> Result<url::Url, ContractError> {
    if value.is_empty()
        || value.len() > 1024
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(invalid());
    }
    let u = url::Url::parse(value).map_err(|_| invalid())?;
    if !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || !matches!(u.path(), "" | "/")
        || u.port_or_known_default().is_none_or(|p| p == 0)
        || (quic && (u.scheme() != "quic" || u.port().is_none()))
        || (!quic && !matches!(u.scheme(), "https" | "http"))
    {
        return Err(invalid());
    }
    let ip = match u.host().ok_or_else(invalid)? {
        url::Host::Ipv4(ip) => Some(std::net::IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => Some(std::net::IpAddr::V6(ip)),
        // QUIC is a non-special URL scheme: numeric IPv4 is an opaque Domain.
        // Parse it before classification so IPv4 aliases cannot bypass deny.
        url::Host::Domain(host) if !host.is_empty() => {
            match url::Host::parse(host).map_err(|_| invalid())? {
                url::Host::Ipv4(ip) => Some(std::net::IpAddr::V4(ip)),
                url::Host::Ipv6(ip) => Some(std::net::IpAddr::V6(ip)),
                url::Host::Domain(_) => None,
            }
        }
        _ => return Err(invalid()),
    };
    let ip = ip.map(|ip| ip.to_canonical());
    if ip.is_some_and(|ip| {
        ip.is_unspecified()
            || ip.is_multicast()
            || ip == std::net::Ipv4Addr::BROADCAST
            || (!allow_loopback && ip.is_loopback())
    }) || (u.scheme() == "http" && (!allow_loopback || !ip.is_some_and(|ip| ip.is_loopback())))
    {
        return Err(invalid());
    }
    Ok(u)
}
impl NodeEndpoints {
    /// Empty endpoints explicitly withdraw a node from discovery.
    pub fn validate(&self) -> Result<(), ContractError> {
        if let Some(u) = &self.quic_uri {
            endpoint_url(u, true, self.allow_loopback)?;
        }
        if let Some(u) = &self.wss_origin {
            endpoint_url(u, false, self.allow_loopback)?;
        }
        Ok(())
    }
}
impl NodeDiscoveryClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [
                &self.deployment_id,
                &self.session_id,
                &self.account_id,
                &self.device_id,
            ]
            .iter()
            .any(|s| !valid_id(s))
            || [
                &self.device_key_sha256,
                &self.permit_sha256,
                &self.request_sha256,
                &self.nonce,
            ]
            .iter()
            .any(|s| s.len() != 32)
            || [
                self.security_epoch,
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
            ]
            .iter()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
            || self
                .expires_at_unix_ms
                .checked_sub(self.issued_at_unix_ms)
                .is_none_or(|n| n == 0 || n > NODE_DISCOVERY_MS)
            || self.nodes.len() as u64 > NODE_DISCOVERY_COUNT
        {
            return Err(invalid());
        }
        for (i, n) in self.nodes.iter().enumerate() {
            if !valid_id(&n.node_id)
                || !valid_id(&n.runtime_id)
                || n.node_key_sha256.len() != 32
                || [n.runtime_generation, n.endpoint_revision]
                    .iter()
                    .any(|v| *v == 0 || *v > i64::MAX as u64)
                || (n.quic_uri.is_empty() && n.wss_origin.is_empty())
                || n.expires_at_unix_ms <= self.issued_at_unix_ms
                || n.expires_at_unix_ms > self.expires_at_unix_ms
                || (i > 0 && self.nodes[i - 1].node_id >= n.node_id)
            {
                return Err(invalid());
            }
            NodeEndpoints {
                quic_uri: (!n.quic_uri.is_empty()).then(|| n.quic_uri.clone()),
                wss_origin: (!n.wss_origin.is_empty()).then(|| n.wss_origin.clone()),
                allow_loopback: n.allow_loopback,
            }
            .validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoints_reject_ambient_authority_and_require_explicit_loopback_exception() {
        for (u, q) in [
            ("https://user@relay.example", false),
            ("https://relay.example/path", false),
            ("https://relay.example?x", false),
            ("https://relay.example#x", false),
            ("http://relay.example", false),
            ("http://127.0.0.1", false),
            ("quic://127.0.0.1:1234", true),
            ("quic://relay.example", true),
            ("quic://0.0.0.0:1234", true),
            ("quic://[ff02::1]:1234", true),
            ("https:// relay.example", false),
        ] {
            assert!(endpoint_url(u, q, false).is_err(), "{u}");
        }
        assert!(endpoint_url("https://relay.example", false, false).is_ok());
        assert!(endpoint_url("quic://relay.example:28743", true, false).is_ok());
        assert!(endpoint_url("http://127.0.0.1:1234", false, true).is_ok());
        assert!(endpoint_url("http://localhost:1234", false, true).is_err());
        assert!(endpoint_url("quic://[::1]:1234", true, true).is_ok());
        assert!(endpoint_url("quic://[::ffff:127.0.0.1]:1234", true, false).is_err());
        for host in ["127.1", "2130706433", "0x7f000001", "0177.0.0.1"] {
            assert!(endpoint_url(&format!("quic://{host}:1234"), true, false).is_err());
        }
    }
}
