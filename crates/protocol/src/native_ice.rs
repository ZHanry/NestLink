//! Bounded native ICE signaling. The mature ICE library parses and performs
//! STUN transactions; this contract only restricts peer-directed destinations.
use crate::{ContractError, ErrorCode, api::NativeIceParameters, signaling::safe_peer_address};
use std::net::{IpAddr, SocketAddr};

pub const VERSION: u32 = 1;
pub const CAPABILITY: &str = "native-ice-quic-v1";
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid native ICE parameters")
}
impl NativeIceParameters {
    pub fn address(&self) -> Result<SocketAddr, ContractError> {
        let credential = |value: &str, minimum: usize| {
            (minimum..=256).contains(&value.len())
                && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        };
        if self.version != VERSION
            || !credential(&self.username_fragment, 4)
            || !credential(&self.password, 22)
            || self.candidate.len() > 2048
            || self.candidate.contains(['\r', '\n', '\0'])
        {
            return Err(invalid());
        }
        let fields: Vec<_> = self.candidate.split_whitespace().collect();
        if fields.len() < 8
            || !fields.len().is_multiple_of(2)
            || fields[0].is_empty()
            || fields[1] != "1"
            || !fields[2].eq_ignore_ascii_case("udp")
            || fields[3].parse::<u32>().ok().filter(|v| *v != 0).is_none()
            || fields[6] != "typ"
            || !matches!(fields[7], "host" | "srflx")
        {
            return Err(invalid());
        }
        let ip: IpAddr = fields[4].parse().map_err(|_| invalid())?;
        let port: u16 = fields[5].parse().map_err(|_| invalid())?;
        if !safe_peer_address(ip) || port == 0 {
            return Err(invalid());
        }
        let mut related_address = false;
        let mut related_port = false;
        for extension in fields[8..].chunks_exact(2) {
            match extension {
                ["raddr", value] if !related_address => {
                    let related: IpAddr = value.parse().map_err(|_| invalid())?;
                    if !related.is_unspecified() && !safe_peer_address(related) {
                        return Err(invalid());
                    }
                    related_address = true;
                }
                ["rport", value] if !related_port && value.parse::<u16>().is_ok() => {
                    related_port = true;
                }
                _ => return Err(invalid()),
            }
        }
        if related_address != related_port {
            return Err(invalid());
        }
        Ok(SocketAddr::new(ip, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parameters() -> NativeIceParameters {
        NativeIceParameters {
            version: VERSION,
            username_fragment: "abcdefgh".into(),
            password: "abcdefghijklmnopqrstuvwx".into(),
            candidate: "1234 1 udp 2130706431 203.0.113.7 45678 typ host".into(),
        }
    }
    #[test]
    fn destination_and_credentials_are_bounded_and_debug_is_redacted() -> Result<(), ContractError> {
        let valid = parameters();
        assert_eq!(valid.address()?, "203.0.113.7:45678".parse().map_err(|_| invalid())?);
        let debug = format!("{valid:?}");
        assert!(!debug.contains(&valid.password));
        assert!(!debug.contains(&valid.username_fragment));
        assert!(!debug.contains("203.0.113.7"));
        for raw in [
            "1234 1 udp 123 127.0.0.1 45678 typ host",
            "1234 1 udp 123 169.254.169.254 80 typ host",
            "1234 1 udp 123 203.0.113.7 0 typ host",
            "1234 2 udp 123 203.0.113.7 45678 typ host",
            "1234 1 tcp 123 203.0.113.7 45678 typ host",
            "1234 1 udp 123 peer.example 45678 typ host",
            "1234 1 udp 123 203.0.113.7 45678 typ relay",
            "1234 1 udp 123 203.0.113.7 45678 typ host ufrag injected",
            "1234 1 udp 123 203.0.113.7 45678 typ host\r\n",
            "1234 1 udp 123 203.0.113.7 45678 typ srflx raddr 169.254.169.254 rport 80",
        ] {
            let mut denied = valid.clone();
            denied.candidate = raw.into();
            assert!(denied.address().is_err(), "{raw}");
        }
        let mut denied = valid;
        denied.password.clear();
        assert!(denied.address().is_err());
        Ok(())
    }
}
