//! Bounded service metadata; it supplies no network or publication authority.
pub mod private;
use crate::{ContractError, ErrorCode, api::*, valid_id};
use std::net::{IpAddr, SocketAddr};

pub const SERVICE_DEFINITION_BYTES: usize = 16 * 1024;
pub const SERVICE_APPROVAL_LIFETIME_MS: u64 = 60 * 60 * 1000;
pub const SERVICE_CHALLENGE_MS: u64 = 60 * 1000;

fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid service metadata")
}
pub fn revision_valid(value: u64) -> bool {
    value > 0 && value <= i64::MAX as u64
}
impl ServiceDefinition {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.name.is_empty()
            || self.name.len() > 128
            || self.name.trim() != self.name
            || self.name.chars().any(char::is_control)
            || !valid_id(&self.host_device_id)
            || !valid_id(&self.edge_node_id)
            || self.allowed_sources.len() > 32
            || !(1..=128).contains(&self.limits.maximum_connections)
            || !(1..=1_073_741_824).contains(&self.limits.bytes_per_second)
            || !(1..=1_099_511_627_776).contains(&self.limits.maximum_bytes)
            || !(1..=300).contains(&self.limits.idle_timeout_seconds)
        {
            return Err(invalid());
        }
        match &self.requested_ingress {
            ServiceIngress::Http { hostname } | ServiceIngress::Https { hostname } => {
                if !valid_hostname(hostname) {
                    return Err(invalid());
                }
            }
            ServiceIngress::Tcp { port } | ServiceIngress::Udp { port } => {
                if *port == 0 {
                    return Err(invalid());
                }
            }
        }
        for (index, source) in self.allowed_sources.iter().enumerate() {
            source.validate()?;
            if self.allowed_sources[..index].contains(source) {
                return Err(invalid());
            }
        }
        if serde_json::to_vec(self).map_err(|_| invalid())?.len() > SERVICE_DEFINITION_BYTES {
            return Err(invalid());
        }
        Ok(())
    }
}
impl ServiceSourceNetwork {
    pub fn validate(&self) -> Result<(), ContractError> {
        let ip: IpAddr = self.address.parse().map_err(|_| invalid())?;
        if ip.to_string() != self.address {
            return Err(invalid());
        }
        let canonical = match ip {
            IpAddr::V4(ip) => {
                self.prefix <= 32 && (self.prefix == 32 || u32::from(ip) << self.prefix == 0)
            }
            IpAddr::V6(ip) => {
                self.prefix <= 128 && (self.prefix == 128 || u128::from(ip) << self.prefix == 0)
            }
        };
        if !canonical {
            return Err(invalid());
        }
        Ok(())
    }
}
/// Call only for a local user's explicit selection. Never resolve a remotely
/// submitted target string; the caller supplies the already fixed socket address.
pub fn validate_local_target(
    ingress: &ServiceIngress,
    protocol: &str,
    address: SocketAddr,
) -> Result<(), ContractError> {
    let compatible = match ingress {
        ServiceIngress::Http { .. } | ServiceIngress::Https { .. } => {
            matches!(protocol, "http" | "https")
        }
        ServiceIngress::Tcp { .. } => protocol == "tcp",
        ServiceIngress::Udp { .. } => protocol == "udp",
    };
    if !compatible
        || address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(invalid());
    }
    Ok(())
}
fn valid_hostname(hostname: &str) -> bool {
    hostname.len() <= 253
        && hostname.contains('.')
        && !hostname.ends_with('.')
        && hostname.parse::<IpAddr>().is_err()
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_networks_are_canonical_and_bounded() {
        for (address, prefix, valid) in [
            ("192.0.2.0", 24, true),
            ("192.0.2.1", 24, false),
            ("0.0.0.0", 0, true),
            ("192.0.2.1", 32, true),
            ("::", 0, true),
            ("2001:db8::", 32, true),
            ("2001:db8::1", 32, false),
            ("::1", 128, true),
            ("::1", 129, false),
            ("1.2.3.4", 33, false),
        ] {
            assert_eq!(
                ServiceSourceNetwork {
                    address: address.into(),
                    prefix
                }
                .validate()
                .is_ok(),
                valid
            );
        }
    }
    #[test]
    fn hostnames_reject_header_injection_urls_aliases_and_wildcards() {
        assert!(valid_hostname("app.svc.example.test"));
        for hostname in [
            "https://svc.test",
            "svc.test:443",
            "*.svc.test",
            "Svc.test",
            "svc.test.",
            "svc\r\n.test",
            "127.0.0.1",
            "-svc.test",
            "svc-.test",
            "svc..test",
        ] {
            assert!(!valid_hostname(hostname));
        }
    }
    #[test]
    fn explicit_local_target_checks_transport_and_unsafe_address_classes()
    -> Result<(), Box<dyn std::error::Error>> {
        let tcp = ServiceIngress::Tcp { port: 29100 };
        assert!(validate_local_target(&tcp, "tcp", "127.0.0.1:8080".parse()?).is_ok());
        for address in [
            "0.0.0.0:80",
            "224.0.0.1:80",
            "255.255.255.255:80",
            "[::]:80",
            "127.0.0.1:0",
        ] {
            assert!(validate_local_target(&tcp, "tcp", address.parse()?).is_err());
        }
        assert!(validate_local_target(&tcp, "udp", "127.0.0.1:80".parse()?).is_err());
        Ok(())
    }
}
