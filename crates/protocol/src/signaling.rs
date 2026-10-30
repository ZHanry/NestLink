//! Bounded endpoint declarations. Signing a candidate does not grant an arbitrary probe.
use crate::{CANDIDATE_COUNT, ContractError, ErrorCode, Path, PermitClaims, api::*};
use std::net::{IpAddr, Ipv4Addr};

fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}
impl Candidate {
    pub fn path(&self) -> Path {
        if self.kind == CandidateKind::Relay {
            Path::Relay
        } else {
            Path::Direct
        }
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.generation == 0
            || self.address.port() == 0
            || self.address.ip().is_unspecified()
            || self.address.ip().is_multicast()
            || (self.transport == Transport::Wss && self.kind != CandidateKind::Relay)
            || (self.kind == CandidateKind::Ipv6 && !self.address.is_ipv6())
        {
            return Err(invalid("invalid connection candidate"));
        }
        Ok(())
    }
}
/// Blocks loopback, link-local/cloud metadata, mapped IPv4 and non-unicast ranges.
/// Private LAN addresses additionally require the endpoint's configured address policy
/// before dialing; this contract is the shared minimum, not that local policy.
pub fn safe_peer_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && ip != Ipv4Addr::BROADCAST
                && octets[0] != 0
                && octets[0] < 224
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
                && octets[..3] != [192, 0, 0]
                && octets[..2] != [198, 18]
                && octets[..2] != [198, 19]
                && ip != Ipv4Addr::new(168, 63, 129, 16)
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
                && ip.to_ipv4_mapped().is_none()
                && ip.segments()[0] != 0
                && ip != std::net::Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254)
        }
    }
}
impl SignalPayload {
    pub fn validate(&self, permit: &PermitClaims) -> Result<(), ContractError> {
        permit.validate()?;
        if self.connection_generation != permit.connection_generation
            || self.lease_sequence != permit.lease_sequence
            || self.network_generation == 0
            || self.sequence == 0
            || self.network_generation > i64::MAX as u64
            || self.sequence > i64::MAX as u64
        {
            return Err(ContractError::new(
                ErrorCode::ReplayRejected,
                "stale signaling generation",
            ));
        }
        if self.candidates.len() > CANDIDATE_COUNT as usize
            || (self.candidates.is_empty()
                && self.description.is_none()
                && self.rendezvous.is_none())
        {
            return Err(invalid("invalid signal candidate count"));
        }
        if self.rendezvous.is_some()
            && (!permit.paths.contains(&(Path::Relay as i32))
                || self.description.is_some()
                || self.ice.is_some()
                || !self.candidates.is_empty())
        {
            return Err(invalid("invalid native relay rendezvous"));
        }
        for (index, candidate) in self.candidates.iter().enumerate() {
            candidate.validate()?;
            if candidate.generation != self.network_generation
                || !safe_peer_address(candidate.address.ip())
                || !permit.paths.contains(&(candidate.path() as i32))
                || self.candidates[..index].contains(candidate)
            {
                return Err(invalid(
                    "candidate violates signal address, path or generation",
                ));
            }
        }
        if let Some(description) = &self.description {
            description.validate(permit)?;
        }
        self.validate_ice(permit)?;
        Ok(())
    }
}
impl WebRtcDescription {
    pub fn validate(&self, permit: &PermitClaims) -> Result<(), ContractError> {
        if !matches!(self.kind.as_str(), "offer" | "answer")
            || self.sdp.is_empty()
            || self.sdp.len() > 65536
            || self.dtls_sha256.len() != 32
            || self.sdp.contains('\0')
            || match self.kind.as_str() {
                "offer" => self.in_reply_to_sequence.is_some(),
                "answer" => self
                    .in_reply_to_sequence
                    .is_none_or(|sequence| sequence == 0),
                _ => true,
            }
        {
            return Err(invalid("invalid WebRTC description"));
        }
        let mut fingerprint_seen = false;
        let mut candidate_count = 0;
        for line in self.sdp.lines() {
            if line.len() > 2048 {
                return Err(invalid("SDP line exceeds budget"));
            }
            if let Some(value) = line.strip_prefix("a=fingerprint:") {
                let value = value
                    .strip_prefix("sha-256 ")
                    .ok_or_else(|| invalid("DTLS must use SHA-256"))?;
                let bytes: Vec<_> = value
                    .split(':')
                    .map(|part| {
                        if part.len() != 2 {
                            return Err(invalid("invalid DTLS fingerprint"));
                        }
                        u8::from_str_radix(part, 16)
                            .map_err(|_| invalid("invalid DTLS fingerprint"))
                    })
                    .collect::<Result<_, _>>()?;
                if bytes != self.dtls_sha256 {
                    return Err(invalid("SDP DTLS fingerprint mismatch"));
                }
                fingerprint_seen = true;
            }
            if let Some(value) = line.strip_prefix("a=candidate:") {
                candidate_count += 1;
                let fields: Vec<_> = value.split_whitespace().collect();
                if fields.len() < 8
                    || !fields.len().is_multiple_of(2)
                    || fields[6] != "typ"
                    || !matches!(fields[2].to_ascii_lowercase().as_str(), "udp" | "tcp")
                    || !matches!(fields[7], "host" | "srflx" | "prflx" | "relay")
                    || candidate_count > CANDIDATE_COUNT
                {
                    return Err(invalid("invalid ICE candidate"));
                }
                let port: u16 = fields[5].parse().map_err(|_| invalid("invalid ICE port"))?;
                let path = if fields[7] == "relay" {
                    Path::Relay
                } else {
                    Path::Direct
                };
                let address_allowed = match fields[4].parse::<IpAddr>() {
                    Ok(ip) => safe_peer_address(ip),
                    Err(_) => fields[7] == "host" && mdns_host(fields[4]),
                };
                if port == 0 || !address_allowed || !permit.paths.contains(&(path as i32)) {
                    return Err(invalid("ICE candidate violates address or path policy"));
                }
                for pair in fields[8..].chunks_exact(2) {
                    if pair[0] == "raddr" {
                        let related: IpAddr = pair[1]
                            .parse()
                            .map_err(|_| invalid("invalid related ICE address"))?;
                        if !related.is_unspecified() && !safe_peer_address(related) {
                            return Err(invalid("unsafe related ICE address"));
                        }
                    }
                }
            }
        }
        if !fingerprint_seen {
            return Err(invalid("missing DTLS fingerprint"));
        }
        Ok(())
    }
}

// Browser host candidates may use a local mDNS label. Ordinary DNS destinations
// remain prohibited; native dialing consumes literal Candidate addresses only.
fn mdns_host(value: &str) -> bool {
    value.strip_suffix(".local").is_some_and(|name| {
        !name.is_empty()
            && name.len() <= 63
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn permit() -> PermitClaims {
        let id = |n| format!("{n:08}-1111-4111-8111-111111111111");
        PermitClaims {
            media_format_version: 0,
            media_formats: Vec::new(),
            media_format_sha256: Vec::new(),
            schema_version: crate::SCHEMA_VERSION,
            deployment_id: id(1),
            session_id: id(2),
            account_id: id(3),
            controller_device_id: id(4),
            host_device_id: id(5),
            resource_id: id(6),
            controller_key_sha256: vec![1; 32],
            host_key_sha256: vec![2; 32],
            capability_sha256: vec![3; 32],
            permissions: vec![1],
            paths: vec![1],
            security_epoch: 1,
            policy_revision: 1,
            connection_generation: 1,
            lease_sequence: 1,
            issued_at_unix_ms: 1000000,
            expires_at_unix_ms: 1015000,
            required_capabilities: vec!["vp8".into()],
        }
    }
    fn description(candidate: &str) -> WebRtcDescription {
        let fingerprint = std::iter::repeat_n("AB", 32).collect::<Vec<_>>().join(":");
        WebRtcDescription {
            kind: "offer".into(),
            dtls_sha256: vec![0xab; 32],
            sdp: format!(
                "v=0\r\na=fingerprint:sha-256 {fingerprint}\r\na=candidate:1 1 UDP 2122260223 {candidate} 28743 typ host\r\n"
            ),
            in_reply_to_sequence: None,
        }
    }
    #[test]
    fn native_relay_rendezvous_has_no_peer_target_and_requires_relay_permission()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut permit = permit();
        let mut signal = SignalPayload {
            connection_generation: permit.connection_generation,
            lease_sequence: permit.lease_sequence,
            network_generation: 1,
            sequence: 1,
            candidates: Vec::new(),
            description: None,
            ice: None,
            rendezvous: Some(NativeRendezvous::CombinedRelay),
        };
        assert!(signal.validate(&permit).is_err());
        permit.paths.push(Path::Relay as i32);
        signal.validate(&permit)?;
        let mut encoded = serde_json::to_value(&signal)?;
        encoded["rendezvous"] = serde_json::json!("http://169.254.169.254");
        assert!(serde_json::from_value::<SignalPayload>(encoded).is_err());
        signal.description = Some(description("192.168.1.10"));
        assert!(signal.validate(&permit).is_err());
        signal.description = None;
        signal.candidates.push(Candidate {
            address: "127.0.0.1:28743".parse()?,
            kind: CandidateKind::Relay,
            transport: Transport::Wss,
            generation: 1,
        });
        assert!(signal.validate(&permit).is_err());
        signal.candidates.clear();
        signal.network_generation = 0;
        assert!(signal.validate(&permit).is_err());
        signal.network_generation = 1;
        signal.rendezvous = None;
        assert!(signal.validate(&permit).is_err());
        signal.description = Some(description("192.168.1.10"));
        signal.validate(&permit)?;
        let legacy = serde_json::to_value(&signal)?;
        assert!(legacy.get("rendezvous").is_none());
        assert_eq!(serde_json::from_value::<SignalPayload>(legacy)?, signal);
        Ok(())
    }

    #[test]
    fn browser_description_binds_fingerprints_and_rejects_unsafe_or_forbidden_ice() {
        let permit = permit();
        assert!(description("192.168.1.10").validate(&permit).is_ok());
        assert!(
            description("6baa57ee-3d74-4e64-8a05-5277b8c56391.local")
                .validate(&permit)
                .is_ok()
        );
        for address in [
            "127.0.0.1",
            "169.254.169.254",
            "168.63.129.16",
            "fd00:ec2::254",
            "metadata.example.com",
        ] {
            assert!(description(address).validate(&permit).is_err());
        }
        let mut mismatched = description("192.168.1.10");
        mismatched.dtls_sha256[0] = 0;
        assert!(mismatched.validate(&permit).is_err());
        let mut missing = description("192.168.1.10");
        missing.sdp = "v=0\r\n".into();
        assert!(missing.validate(&permit).is_err());
        let mut relay = description("192.168.1.10");
        relay.sdp = relay.sdp.replace("typ host", "typ relay");
        assert!(relay.validate(&permit).is_err());
    }

    #[test]
    fn answer_must_name_the_offer_sequence_and_offer_cannot_claim_a_response_parent() {
        let permit = permit();
        let mut answer = description("192.168.1.10");
        answer.kind = "answer".into();
        assert!(answer.validate(&permit).is_err());
        answer.in_reply_to_sequence = Some(1);
        assert!(answer.validate(&permit).is_ok());
        answer.in_reply_to_sequence = Some(0);
        assert!(answer.validate(&permit).is_err());

        let mut offer = description("192.168.1.10");
        offer.in_reply_to_sequence = Some(1);
        assert!(offer.validate(&permit).is_err());
    }
}
