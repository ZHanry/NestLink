//! Strict, independently signed TURN resources and exact paired ICE addresses.
use crate::{
    ContractError, ErrorCode, NODE_RESOURCE_ALLOCATIONS, NODE_RESOURCE_TTL_MS, SCHEMA_VERSION,
    SESSION_LEASE_MS, TurnCredentialsClaims, TurnGrantClaims, TurnPeerBindingClaims, TurnPurpose,
    TurnResourceQueryClaims, TurnResourceSnapshotClaims, decode_bounded, valid_id,
};
use std::net::SocketAddr;

pub const TURN_BINDING_BYTES: u64 = 16_384;
pub const TURN_PEERS: usize = 32;

/// TURN runs on a public relay, so its signed peer allowlist must contain only
/// globally reachable unicast addresses. The direct ICE path has its own
/// endpoint policy and intentionally continues to use `safe_peer_address`.
pub fn safe_turn_peer_address(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            crate::signaling::safe_peer_address(ip.into())
                && !(a == 10
                    || (a == 172 && (16..=31).contains(&b))
                    || (a == 192 && b == 168)
                    || (a == 192 && b == 0 && c == 2) // TEST-NET-1
                    || (a == 192 && b == 88 && c == 99) // 6to4 relay anycast
                    || (a == 198 && b == 51 && c == 100) // TEST-NET-2
                    || (a == 203 && b == 0 && c == 113)) // TEST-NET-3
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            let global_unicast = (0x2000..=0x3fff).contains(&segments[0]);
            let special_use = ip.to_ipv4_mapped().is_some()
                || (segments[0] == 0x2001 && segments[1] <= 0x01ff) // IETF protocol assignments
                || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
                || segments[0] == 0x2002 // 6to4
                || (segments[0] == 0x3fff && segments[1] <= 0x0fff); // documentation
            global_unicast && !special_use && crate::signaling::safe_peer_address(ip.into())
        }
    }
}

/// Exact numeric UDP component-one candidates from an already validated signed
/// SDP. mDNS hostnames cannot grant TURN forwarding authority.
pub fn ice_candidate_addresses(sdp: &str) -> Result<Vec<String>, ContractError> {
    optional_ice_candidate_addresses(sdp)?.ok_or_else(invalid)
}

/// Freeze relay peers only after a validated cumulative snapshot is complete.
/// The caller must validate the signed signal and advance IceSnapshotCursor
/// first. Partial snapshots grant no forwarding authority; completed snapshots
/// cannot subsequently grow. Legacy complete-SDP signaling is unchanged.
pub fn completed_signal_candidate_addresses(
    signal: &crate::api::SignalPayload,
) -> Result<Option<Vec<String>>, ContractError> {
    let description = signal.description.as_ref().ok_or_else(invalid)?;
    let Some(ice) = &signal.ice else {
        return optional_ice_candidate_addresses(&description.sdp);
    };
    if !ice.end_of_candidates {
        return Ok(None);
    }
    let mut sdp = description.sdp.clone();
    for candidate in &ice.candidates {
        if candidate.candidate.contains(['\r', '\n', '\0']) {
            return Err(invalid());
        }
        sdp.push_str("\r\na=");
        sdp.push_str(&candidate.candidate);
        sdp.push_str("\r\n");
    }
    optional_ice_candidate_addresses(&sdp)
}

/// Inspect an already validated signed SDP without granting TURN authority.
/// A valid LAN/mDNS-only description has no public TURN peers; callers may
/// still use a separately authorized direct path. Signing a TURN binding must
/// continue to use `ice_candidate_addresses`, which requires a nonempty list.
pub fn optional_ice_candidate_addresses(sdp: &str) -> Result<Option<Vec<String>>, ContractError> {
    if sdp.len() > 65536 {
        return Err(invalid());
    }
    let mut addresses = Vec::new();
    for line in sdp.lines() {
        let Some(candidate) = line.strip_prefix("a=candidate:") else {
            continue;
        };
        let fields: Vec<_> = candidate.split_whitespace().collect();
        if fields.len() < 8 || fields[6] != "typ" {
            return Err(invalid());
        }
        if fields[1] != "1" || !fields[2].eq_ignore_ascii_case("udp") {
            continue;
        }
        let Ok(ip) = fields[4].parse::<std::net::IpAddr>() else {
            continue;
        };
        let port: u16 = fields[5].parse().map_err(|_| invalid())?;
        if port == 0 {
            return Err(invalid());
        }
        if !safe_turn_peer_address(ip) {
            // Local host candidates are expected in browser SDP. They are
            // useful to direct ICE, but a public TURN node must never receive
            // authority to forward to them. Other unsafe candidate types are
            // malformed for this public-relay allowlist and fail closed.
            if fields[7] == "host" {
                continue;
            }
            return Err(invalid());
        }
        addresses.push(SocketAddr::new(ip, port).to_string());
        if addresses.len() > crate::CANDIDATE_COUNT as usize {
            return Err(invalid());
        }
    }
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Ok(None);
    }
    if !candidates(&addresses) {
        return Err(invalid());
    }
    Ok(Some(addresses))
}
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid TURN resource binding")
}
fn counters(values: &[u64]) -> bool {
    values.iter().all(|n| *n > 0 && *n <= i64::MAX as u64)
}
fn interval(issued: u64, expires: u64, maximum: u64) -> bool {
    counters(&[issued, expires])
        && expires
            .checked_sub(issued)
            .is_some_and(|n| n > 0 && n <= maximum)
}
pub fn valid_realm(realm: &str) -> bool {
    !realm.is_empty()
        && realm.len() <= 128
        && realm
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
pub fn valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 128
        && username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'-' | b'_'))
}
/// Deployment URLs are explicit, credential-free TURN endpoints. No redirect,
/// userinfo, path, fragment, or arbitrary query is accepted.
pub fn valid_endpoint(endpoint: &str, allow_loopback: bool) -> bool {
    let (secure, tail) = if let Some(tail) = endpoint.strip_prefix("turns:") {
        (true, tail)
    } else if let Some(tail) = endpoint.strip_prefix("turn:") {
        (false, tail)
    } else {
        return false;
    };
    let Some((authority, transport)) = tail.split_once("?transport=") else {
        return false;
    };
    if endpoint.len() > 256 || (secure && transport != "tcp") || !matches!(transport, "udp" | "tcp")
    {
        return false;
    }
    if authority
        .bytes()
        .any(|b| matches!(b, b'@' | b'/' | b'\\' | b'#' | b'%' | b'?'))
    {
        return false;
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    if port.parse::<u16>().is_err()
        || port
            .parse::<u16>()
            .is_ok_and(|p| p == 0 || p.to_string() != port)
    {
        return false;
    }
    let Ok(parsed) = url::Host::parse(host) else {
        return false;
    };
    match parsed {
        url::Host::Ipv4(ip) => {
            ip.to_string() == host
                && (crate::signaling::safe_peer_address(ip.into())
                    || (allow_loopback && ip.is_loopback()))
        }
        url::Host::Ipv6(ip) => {
            format!("[{ip}]") == host
                && (crate::signaling::safe_peer_address(ip.into())
                    || (allow_loopback && ip.is_loopback()))
        }
        url::Host::Domain(domain) => {
            domain == host
                && !host.is_empty()
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
                && (allow_loopback || (host != "localhost" && !host.ends_with(".localhost")))
        }
    }
}
impl TurnResourceQueryClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || [
                &self.deployment_id,
                &self.node_id,
                &self.runtime_id,
                &self.request_id,
            ]
            .iter()
            .any(|s| !valid_id(s))
            || !counters(&[
                self.security_epoch,
                self.runtime_generation,
                self.policy_revision,
                self.lease_sequence,
                self.request_sequence,
            ])
            || !interval(
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
                NODE_RESOURCE_TTL_MS,
            )
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl crate::api::TurnEndpointConfig {
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_realm(&self.realm)
            || self.endpoints.len() > 8
            || self.endpoints.windows(2).any(|p| p[0] >= p[1])
            || self
                .endpoints
                .iter()
                .any(|u| !valid_endpoint(u, self.allow_loopback))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl TurnCredentialsClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || self.purpose != TurnPurpose::BrowserWebRtc as i32
            || [
                &self.deployment_id,
                &self.session_id,
                &self.allocation_id,
                &self.device_id,
                &self.temporary_identity,
                &self.node_id,
                &self.runtime_id,
            ]
            .iter()
            .any(|s| !valid_id(s))
            || !counters(&[
                self.security_epoch,
                self.runtime_generation,
                self.network_generation,
                self.connection_generation,
                self.lease_sequence,
                self.grant_sequence,
                self.endpoint_revision,
            ])
            || self.permit_sha256.len() != 32
            || self.request_sha256.len() != 32
            || !interval(
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
                SESSION_LEASE_MS,
            )
            || !valid_username(&self.username)
            || !valid_realm(&self.realm)
            || self.password.len() != 43
            || !self
                .password
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || self.endpoints.is_empty()
            || self.endpoints.len() > 8
            || self.endpoints.windows(2).any(|p| p[0] >= p[1])
            || self
                .endpoints
                .iter()
                .any(|u| !valid_endpoint(u, self.allow_loopback))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl TurnGrantClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || self.purpose != TurnPurpose::BrowserWebRtc as i32
            || [
                &self.deployment_id,
                &self.allocation_id,
                &self.session_id,
                &self.temporary_identity,
                &self.node_id,
                &self.runtime_id,
                &self.device_id,
                &self.controller_device_id,
                &self.host_device_id,
            ]
            .iter()
            .any(|s| !valid_id(s))
            || self.temporary_identity != self.controller_device_id
            || self.controller_device_id == self.host_device_id
            || ![&self.controller_device_id, &self.host_device_id].contains(&&self.device_id)
            || [
                &self.node_key_sha256,
                &self.controller_key_sha256,
                &self.host_key_sha256,
                &self.permit_sha256,
            ]
            .iter()
            .any(|d| d.len() != 32)
            || self.controller_public_key.len() != 32
            || self.host_public_key.len() != 32
            || self.session_binding_sha256.len() != 32
            || self.controller_key_sha256 == self.host_key_sha256
            || !counters(&[
                self.security_epoch,
                self.runtime_generation,
                self.network_generation,
                self.connection_generation,
                self.lease_sequence,
                self.policy_revision,
                self.quota_revision,
                self.grant_sequence,
                self.endpoint_revision,
            ])
            || !interval(
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
                SESSION_LEASE_MS,
            )
            || !valid_username(&self.username)
            || !valid_realm(&self.realm)
            || self.auth_key.len() != 16
            || !(1..=1_073_741_824).contains(&self.bytes_per_second)
            || !(1..=1_099_511_627_776).contains(&self.bytes_per_allocation)
            || self.max_peers == 0
            || self.max_peers as usize > TURN_PEERS
        {
            return Err(invalid());
        }
        Ok(())
    }
}
fn candidates(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= TURN_PEERS
        && !values.windows(2).any(|p| p[0] >= p[1])
        && values.iter().all(|s| {
            s.parse::<SocketAddr>().is_ok_and(|a| {
                a.to_string() == *s && a.port() != 0 && safe_turn_peer_address(a.ip())
            })
        })
}
impl TurnPeerBindingClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || self.purpose != TurnPurpose::BrowserWebRtc as i32
            || [
                &self.deployment_id,
                &self.session_id,
                &self.temporary_identity,
                &self.controller_allocation_id,
                &self.host_allocation_id,
                &self.controller_device_id,
                &self.host_device_id,
            ]
            .iter()
            .any(|s| !valid_id(s))
            || self.temporary_identity != self.controller_device_id
            || self.controller_device_id == self.host_device_id
            || self.controller_allocation_id == self.host_allocation_id
            || [
                &self.controller_key_sha256,
                &self.host_key_sha256,
                &self.permit_sha256,
            ]
            .iter()
            .any(|d| d.len() != 32)
            || self.controller_key_sha256 == self.host_key_sha256
            || !counters(&[
                self.security_epoch,
                self.controller_network_generation,
                self.host_network_generation,
                self.connection_generation,
                self.lease_sequence,
            ])
            || !interval(
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
                SESSION_LEASE_MS,
            )
            || !candidates(&self.controller_candidates)
            || !candidates(&self.host_candidates)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn matches_grant(&self, grant: &TurnGrantClaims) -> bool {
        let controller = grant.device_id == self.controller_device_id;
        self.deployment_id == grant.deployment_id
            && self.security_epoch == grant.security_epoch
            && self.session_id == grant.session_id
            && self.temporary_identity == grant.temporary_identity
            && self.purpose == grant.purpose
            && self.controller_device_id == grant.controller_device_id
            && self.host_device_id == grant.host_device_id
            && self.controller_key_sha256 == grant.controller_key_sha256
            && self.host_key_sha256 == grant.host_key_sha256
            && self.connection_generation == grant.connection_generation
            && self.lease_sequence == grant.lease_sequence
            && self.permit_sha256 == grant.permit_sha256
            && &grant.allocation_id
                == if controller {
                    &self.controller_allocation_id
                } else {
                    &self.host_allocation_id
                }
            && grant.network_generation
                == if controller {
                    self.controller_network_generation
                } else {
                    self.host_network_generation
                }
            && self.expires_at_unix_ms <= grant.expires_at_unix_ms
    }
    pub fn peers_for<'a>(&'a self, grant: &TurnGrantClaims) -> &'a [String] {
        if grant.device_id == self.controller_device_id {
            &self.host_candidates
        } else {
            &self.controller_candidates
        }
    }
}
impl TurnResourceSnapshotClaims {
    pub fn validate(&self) -> Result<(), ContractError> {
        let q = self.query.as_ref().ok_or_else(invalid)?;
        q.validate()?;
        if self.query_sha256.len() != 32
            || !counters(&[self.snapshot_sequence, self.quota_revision])
            || !interval(
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
                NODE_RESOURCE_TTL_MS,
            )
            || self.expires_at_unix_ms > q.expires_at_unix_ms
            || self.grants.len() as u64 > NODE_RESOURCE_ALLOCATIONS * 2
            || self.peer_bindings.len() as u64 > NODE_RESOURCE_ALLOCATIONS
            || self
                .grants
                .windows(2)
                .any(|p| p[0].allocation_id >= p[1].allocation_id)
        {
            return Err(invalid());
        }
        for grant in &self.grants {
            grant.validate()?;
            if grant.deployment_id != q.deployment_id
                || grant.security_epoch != q.security_epoch
                || grant.node_id != q.node_id
                || grant.runtime_id != q.runtime_id
                || grant.runtime_generation != q.runtime_generation
                || grant.policy_revision != q.policy_revision
                || grant.quota_revision != self.quota_revision
                || grant.issued_at_unix_ms > self.issued_at_unix_ms
                || grant.expires_at_unix_ms <= self.issued_at_unix_ms
            {
                return Err(invalid());
            }
        }
        let mut seen = std::collections::HashSet::new();
        for signed in &self.peer_bindings {
            let binding: TurnPeerBindingClaims =
                decode_bounded(&signed.claims, TURN_BINDING_BYTES)?;
            binding.validate()?;
            if signed.controller_signature.len() != 64
                || signed.host_signature.len() != 64
                || !seen.insert(binding.session_id.clone())
                || !self.grants.iter().any(|g| binding.matches_grant(g))
                || binding.issued_at_unix_ms > self.issued_at_unix_ms
                || binding.expires_at_unix_ms <= self.issued_at_unix_ms
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_peer_addresses_must_be_global_unicast() -> Result<(), Box<dyn std::error::Error>> {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2001::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            let ip = address.parse()?;
            assert!(
                !safe_turn_peer_address(ip),
                "unsafe TURN peer accepted: {address}"
            );
        }
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2001:4860:4860::8888",
        ] {
            let ip = address.parse()?;
            assert!(
                safe_turn_peer_address(ip),
                "public TURN peer rejected: {address}"
            );
        }
        if let Ok(scoped) = "[fe80::1%3]:1234".parse::<SocketAddr>() {
            assert!(!safe_turn_peer_address(scoped.ip()));
        }
        Ok(())
    }

    #[test]
    fn ice_binding_skips_private_hosts_but_keeps_public_reflexive_and_relay_candidates()
    -> Result<(), Box<dyn std::error::Error>> {
        let sdp = concat!(
            "a=candidate:1 1 UDP 100 192.168.1.10 5000 typ host\r\n",
            "a=candidate:2 1 UDP 90 8.8.8.8 5001 typ srflx raddr 192.168.1.10 rport 5000\r\n",
            "a=candidate:3 1 UDP 80 2001:4860:4860::8888 5002 typ relay\r\n",
        );
        assert_eq!(
            ice_candidate_addresses(sdp)?,
            vec!["8.8.8.8:5001", "[2001:4860:4860::8888]:5002"]
        );
        Ok(())
    }

    #[test]
    fn lan_only_ice_can_connect_directly_but_cannot_grant_turn_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let sdp = concat!(
            "a=candidate:1 1 UDP 100 192.168.1.10 5000 typ host\r\n",
            "a=candidate:2 1 UDP 90 temporary.local 5001 typ host\r\n",
        );
        assert_eq!(optional_ice_candidate_addresses(sdp)?, None);
        assert!(ice_candidate_addresses(sdp).is_err());
        for invalid in [
            "a=candidate:1 1 UDP 100 192.168.1.10 5000 typ relay\r\n",
            "a=candidate:1 1 UDP 100 203.0.113.8 5000 typ srflx\r\n",
            "a=candidate:1 1 UDP 100 11.254.15.1 0 typ host\r\n",
            "a=candidate:1 1 UDP\r\n",
        ] {
            assert!(optional_ice_candidate_addresses(invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn ice_binding_rejects_private_non_host_and_documentation_destinations()
    -> Result<(), Box<dyn std::error::Error>> {
        for address in ["192.168.1.10", "169.254.169.254", "203.0.113.8"] {
            let sdp = format!("a=candidate:1 1 UDP 100 {address} 5000 typ srflx\r\n");
            assert!(
                ice_candidate_addresses(&sdp).is_err(),
                "unsafe destination accepted: {address}"
            );
        }
        Ok(())
    }

    #[test]
    fn turn_proto_and_management_response_json_reject_unknown_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let query = crate::TurnResourceQueryClaims {
            schema_version: crate::SCHEMA_VERSION,
            deployment_id: "00000001-1111-4111-8111-111111111111".into(),
            security_epoch: 1,
            node_id: "00000002-1111-4111-8111-111111111111".into(),
            runtime_id: "00000003-1111-4111-8111-111111111111".into(),
            runtime_generation: 1,
            policy_revision: 1,
            lease_sequence: 1,
            request_id: "00000004-1111-4111-8111-111111111111".into(),
            request_sequence: 1,
            issued_at_unix_ms: 1,
            expires_at_unix_ms: 2,
        };
        let mut claim_json = serde_json::to_value(query)?;
        claim_json
            .as_object_mut()
            .ok_or("protobuf claims serialize to an object")?
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<crate::TurnResourceQueryClaims>(claim_json).is_err());

        let mut signed_json = serde_json::to_value(crate::SignedTurnResourceQuery {
            claims: vec![],
            signature: vec![],
        })?;
        signed_json
            .as_object_mut()
            .ok_or("signed TURN wrappers serialize to an object")?
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<crate::SignedTurnResourceQuery>(signed_json).is_err());

        let mut endpoints_json = serde_json::to_value(crate::api::TurnEndpointsView {
            node_id: "00000005-1111-4111-8111-111111111111".into(),
            revision: 1,
            config: crate::api::TurnEndpointConfig {
                realm: "nestlink".into(),
                endpoints: vec![],
                allow_loopback: false,
            },
        })?;
        endpoints_json
            .as_object_mut()
            .ok_or("endpoint response serializes to an object")?
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<crate::api::TurnEndpointsView>(endpoints_json).is_err());

        let mut state_json = serde_json::to_value(crate::api::TurnBindingState {
            controller_allocation_id: None,
            host_allocation_id: None,
            controller_expires_at_unix_ms: None,
            host_expires_at_unix_ms: None,
            binding: None,
        })?;
        state_json
            .as_object_mut()
            .ok_or("binding state serializes to an object")?
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<crate::api::TurnBindingState>(state_json).is_err());
        Ok(())
    }
}
#[test]
fn partial_snapshots_grant_no_relay_peers_and_completion_freezes_the_exact_public_set()
-> Result<(), Box<dyn std::error::Error>> {
    let sdp = concat!(
        "v=0\r\na=ice-ufrag:abc123\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\n",
        "a=candidate:1 1 UDP 100 192.168.1.10 5000 typ host\r\n",
        "a=candidate:2 1 UDP 90 8.8.8.8 5001 typ srflx\r\n",
    );
    let partial = crate::ice::snapshot(sdp, 1, false)?;
    let mut signal = crate::api::SignalPayload {
        ice: Some(partial.clone()),
        connection_generation: 1,
        lease_sequence: 1,
        network_generation: 1,
        sequence: 1,
        candidates: vec![],
        description: Some(crate::api::WebRtcDescription {
            kind: "offer".into(),
            sdp: crate::ice::without_candidates(sdp),
            dtls_sha256: vec![1; 32],
            in_reply_to_sequence: None,
        }),
    };
    let mut cursor = crate::ice::IceSnapshotCursor::default();
    cursor.apply(&partial)?;
    assert_eq!(completed_signal_candidate_addresses(&signal)?, None);
    let full_sdp = format!("{sdp}a=candidate:3 1 UDP 80 1.1.1.1 6000 typ relay\r\n");
    let complete = crate::ice::snapshot(&full_sdp, 1, true)?;
    cursor.apply(&complete)?;
    signal.ice = Some(complete.clone());
    assert_eq!(
        completed_signal_candidate_addresses(&signal)?,
        Some(vec!["1.1.1.1:6000".into(), "8.8.8.8:5001".into()])
    );
    assert!(cursor.apply(&partial).is_err());
    let widened = crate::ice::snapshot(
        &format!("{full_sdp}a=candidate:4 1 UDP 70 9.9.9.9 7000 typ relay\r\n"),
        1,
        true,
    )?;
    assert!(cursor.apply(&widened).is_err());
    // A completed snapshot has exactly the same address policy as legacy
    // complete SDP; signed strings cannot grant private relay access.
    signal.ice.as_mut().ok_or("snapshot missing")?.candidates[1].candidate =
        "candidate:2 1 UDP 90 169.254.169.254 5001 typ srflx".into();
    assert!(completed_signal_candidate_addresses(&signal).is_err());
    signal.ice.as_mut().ok_or("snapshot missing")?.candidates[1].candidate =
            "candidate:2 1 UDP 90 8.8.8.8 5001 typ srflx\r\na=candidate:4 1 UDP 70 9.9.9.9 7000 typ relay".into();
    assert!(completed_signal_candidate_addresses(&signal).is_err());
    Ok(())
}
