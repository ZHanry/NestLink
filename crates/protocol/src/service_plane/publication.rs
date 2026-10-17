use super::*;
pub const SERVICE_ALPN: &[u8] = b"nestlink-service/1";
pub const SERVICE_DELEGATION_MS: u64 = 60 * 60 * 1000;
pub const SERVICE_POLL_MS: u64 = 250;
pub const SERVICE_MAX_OPENINGS: usize = 128;

pub fn service_socket(value: &str) -> Result<SocketAddr, ContractError> {
    let address: SocketAddr = value.parse().map_err(|_| invalid())?;
    if address.to_string() != value
        || address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || matches!(address.ip(),IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(invalid());
    }
    Ok(address)
}
pub fn service_dns(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && !value.ends_with('.')
        && value.parse::<IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceEdgeNamespace {
    pub service_suffix: String,
    pub management_hostname: String,
    pub public_ports: Vec<u16>,
    pub quic_address: String,
}
impl ServiceEdgeNamespace {
    pub fn validate(&self) -> Result<(), ContractError> {
        service_socket(&self.quic_address)?;
        if !service_dns(&self.service_suffix)
            || !service_dns(&self.management_hostname)
            || self.management_hostname == self.service_suffix
            || self
                .management_hostname
                .ends_with(&format!(".{}", self.service_suffix))
            || self.public_ports.is_empty()
            || self.public_ports.len() > 1024
            || self
                .public_ports
                .iter()
                .any(|p| *p < 1024 || (28743..=29055).contains(p))
            || self.public_ports.windows(2).any(|p| p[0] >= p[1])
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn permits(&self, ingress: &ServiceIngress) -> bool {
        match ingress {
            ServiceIngress::Tcp { port } | ServiceIngress::Udp { port } => {
                self.public_ports.binary_search(port).is_ok()
            }
            ServiceIngress::Http { hostname } | ServiceIngress::Https { hostname } => {
                service_dns(hostname)
                    && hostname.ends_with(&format!(".{}", self.service_suffix))
                    && hostname != &self.management_hostname
            }
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceEdgeNamespaceUpdate {
    pub expected_revision: u64,
    pub config: ServiceEdgeNamespace,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceEdgeNamespaceView {
    pub node_id: String,
    pub revision: u64,
    pub config: ServiceEdgeNamespace,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServicePublicationRequest {
    pub expected_revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceIssuerDelegation {
    pub schema_version: u32,
    pub deployment_id: String,
    pub security_epoch: u64,
    pub policy_revision: u64,
    pub service_issuer: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}
impl ServiceIssuerDelegation {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION
            || !valid_id(&self.deployment_id)
            || [
                self.security_epoch,
                self.policy_revision,
                self.issued_at_unix_ms,
                self.expires_at_unix_ms,
            ]
            .iter()
            .any(|n| !revision_valid(*n))
            || self
                .expires_at_unix_ms
                .checked_sub(self.issued_at_unix_ms)
                .is_none_or(|n| n == 0 || n > SERVICE_DELEGATION_MS)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceIssuerDelegation {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServicePublicationGrant {
    pub lease: SignedServiceLease,
    pub issuer: SignedServiceIssuerDelegation,
    pub edge_public_key: [u8; 32],
}
/// Resource authentication is unchanged; this outer response also supplies a
/// separately policy-signed issuer delegation for the host renewal stream.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceResourceGrant {
    pub snapshot: SignedServiceResourceSnapshot,
    pub issuer: SignedServiceIssuerDelegation,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceLeaseRenewal {
    pub lease: SignedServiceLease,
    pub issuer: SignedServiceIssuerDelegation,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceAttachmentChallenge {
    pub lease_sha256: [u8; 32],
    pub nonce: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}
impl ServiceAttachmentChallenge {
    pub fn validate(&self, lease: &ServiceLeaseClaims) -> Result<(), ContractError> {
        lease.validate()?;
        if self.issued_at_unix_ms < lease.issued_at_unix_ms
            || self.expires_at_unix_ms > lease.expires_at_unix_ms
            || self
                .expires_at_unix_ms
                .checked_sub(self.issued_at_unix_ms)
                .is_none_or(|n| n == 0 || n > SERVICE_RESOURCE_MS)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceAttachmentChallenge {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceAttachmentProof {
    pub host_runtime_id: String,
    pub lease_sha256: [u8; 32],
    pub challenge_sha256: [u8; 32],
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceHostIntroduction {
    pub publication_id: String,
    pub generation: u64,
    pub host_public_key: [u8; 32],
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceAttachmentOffer {
    pub lease: SignedServiceLease,
    pub challenge: SignedServiceAttachmentChallenge,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceStreamOffer {
    pub lease: SignedServiceLease,
    pub challenge: SignedServiceTunnelChallenge,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceStreamReady {
    pub stream_id: String,
    pub lease_sha256: [u8; 32],
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceAttachmentReady {
    pub publication_id: String,
    pub generation: u64,
    pub host_runtime_id: String,
    pub lease_sha256: [u8; 32],
}
/// The existing Ready representation stays byte-compatible. After possession
/// proof, web setup may deliver independently signed renewals while public DNS
/// and a normal TLS certificate become ready. Neither variant extends a lease.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ServiceAttachmentStatus {
    Renewal(ServiceLeaseRenewal),
    Ready(ServiceAttachmentReady),
}
#[cfg(test)]
mod tests {
    use super::*;
    fn namespace() -> ServiceEdgeNamespace {
        ServiceEdgeNamespace {
            service_suffix: "svc.example.test".into(),
            management_hostname: "control.example.test".into(),
            public_ports: vec![29100, 29101],
            quic_address: "192.0.2.1:29199".into(),
        }
    }
    #[test]
    fn namespace_keeps_management_reserved_ports_and_ambiguous_addresses_out() {
        assert!(namespace().validate().is_ok());
        for ports in [
            vec![80],
            vec![28744],
            vec![29100, 29100],
            vec![29101, 29100],
        ] {
            let mut n = namespace();
            n.public_ports = ports;
            assert!(n.validate().is_err());
        }
        let mut n = namespace();
        n.management_hostname = "control.svc.example.test".into();
        assert!(n.validate().is_err());
        for address in [
            "host.example.test:29199",
            "0.0.0.0:29199",
            "127.0.0.1:0",
            "127.0.0.1:029199",
        ] {
            assert!(service_socket(address).is_err());
        }
    }
    #[test]
    fn web_host_ownership_is_explicitly_below_the_service_suffix() {
        let n = namespace();
        assert!(n.permits(&ServiceIngress::Http {
            hostname: "app.svc.example.test".into()
        }));
        for host in [
            "control.example.test",
            "svc.example.test",
            "app.svc.example.test.attacker.test",
            "App.svc.example.test",
        ] {
            assert!(!n.permits(&ServiceIngress::Https {
                hostname: host.into()
            }));
        }
    }
    #[test]
    fn attachment_status_keeps_the_ready_wire_and_rejects_mixed_envelopes()
    -> Result<(), Box<dyn std::error::Error>> {
        let ready = ServiceAttachmentReady {
            publication_id: "publication".into(),
            generation: 1,
            host_runtime_id: "host".into(),
            lease_sha256: [2; 32],
        };
        let raw = serde_json::to_vec(&ready)?;
        assert!(matches!(
            serde_json::from_slice::<ServiceAttachmentStatus>(&raw)?,
            ServiceAttachmentStatus::Ready(_)
        ));
        assert_eq!(
            raw,
            serde_json::to_vec(&ServiceAttachmentStatus::Ready(ready))?
        );
        let mut mixed: serde_json::Value = serde_json::from_slice(&raw)?;
        mixed["lease"] = serde_json::json!({"claims":[],"signature":[]});
        mixed["issuer"] = serde_json::json!({"claims":[],"signature":[]});
        assert!(serde_json::from_value::<ServiceAttachmentStatus>(mixed).is_err());
        Ok(())
    }
}
