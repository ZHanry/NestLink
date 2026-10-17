use super::{
    ContractError, ErrorCode, Signer, SigningKey, digest, domain_message, verify_signature,
};
use nestlink_protocol::{
    NodeChallenge, NodeLeaseClaims, NodeProof, NodeUsageAckClaims, NodeUsageClaims,
    SignedNodeLease, SignedNodeUsage, SignedNodeUsageAck, decode_bounded,
    nodes::NODE_MESSAGE_BYTES,
    service_plane::{
        SERVICE_USAGE_BYTES, ServiceUsageReportAckClaims, ServiceUsageReportClaims,
        ServiceUsageRuntimeStopClaims, SignedServiceUsageReport, SignedServiceUsageReportAck,
        SignedServiceUsageRuntimeStop, decode_service_message, encode_service_message,
    },
};
use prost::Message;
use zeroize::Zeroizing;
pub mod closes;
pub mod resources;
pub mod services;
pub mod turn;
const LEASE_DOMAIN: &[u8] = b"NestLink/v15/node-policy-lease/v1\0";
const PROOF_DOMAIN: &[u8] = b"NestLink/v15/node-control-proof/v2\0";
const USAGE_DOMAIN: &[u8] = b"NestLink/v15/node-usage-report/v1\0";
const ACK_DOMAIN: &[u8] = b"NestLink/v15/node-usage-ack/v1\0";
const SERVICE_USAGE_DOMAIN: &[u8] = b"NestLink/v15/service-usage-report/v1\0";
const SERVICE_STOP_DOMAIN: &[u8] = b"NestLink/v15/service-runtime-stop/v1\0";
const SERVICE_USAGE_ACK_DOMAIN: &[u8] = b"NestLink/v15/service-usage-ack/v1\0";

pub struct NodePolicySigner {
    key: SigningKey,
}
pub struct NodeIdentity {
    key: SigningKey,
}
impl NodePolicySigner {
    pub fn from_master_seed(seed: &[u8; 32]) -> Result<Self, ContractError> {
        let mut derived = Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(Some(b"NestLink/v15/deployment-signing-keys/v1"), seed)
            .expand(b"node-policy-ed25519", &mut *derived)
            .map_err(|_| {
                ContractError::new(
                    ErrorCode::InternalError,
                    "node policy key derivation failed",
                )
            })?;
        Ok(Self {
            key: SigningKey::from_bytes(&derived),
        })
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    pub fn sign(&self, claims: &NodeLeaseClaims) -> Result<SignedNodeLease, ContractError> {
        claims.validate()?;
        let bytes = claims.encode_to_vec();
        if bytes.len() as u64 > NODE_MESSAGE_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "node policy size exceeded",
            ));
        }
        let signature = self
            .key
            .sign(&domain_message(LEASE_DOMAIN, &bytes))
            .to_bytes()
            .to_vec();
        Ok(SignedNodeLease {
            claims: bytes,
            signature,
        })
    }
    pub fn sign_usage_ack(
        &self,
        claims: &NodeUsageAckClaims,
    ) -> Result<SignedNodeUsageAck, ContractError> {
        claims.validate()?;
        let bytes = claims.encode_to_vec();
        Ok(SignedNodeUsageAck {
            signature: self
                .key
                .sign(&domain_message(ACK_DOMAIN, &bytes))
                .to_bytes()
                .to_vec(),
            claims: bytes,
        })
    }
    pub fn sign_service_usage_ack(
        &self,
        claims: &ServiceUsageReportAckClaims,
    ) -> Result<SignedServiceUsageReportAck, ContractError> {
        claims.validate()?;
        let claims = encode_service_message(claims, SERVICE_USAGE_BYTES)?;
        Ok(SignedServiceUsageReportAck {
            signature: self
                .key
                .sign(&domain_message(SERVICE_USAGE_ACK_DOMAIN, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
impl NodeIdentity {
    /// Short-lived zeroized encoding for the pinned outer data-node TLS adapter.
    pub fn tls_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, ContractError> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        self.key
            .to_pkcs8_der()
            .map(|der| Zeroizing::new(der.as_bytes().to_vec()))
            .map_err(|_| {
                ContractError::new(ErrorCode::InternalError, "node TLS key encoding failed")
            })
    }
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut rand_core::OsRng),
        }
    }
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    pub fn prove(
        &self,
        challenge: &NodeChallenge,
        runtime_id: &str,
    ) -> Result<NodeProof, ContractError> {
        challenge.validate()?;
        if !nestlink_protocol::valid_id(runtime_id) {
            return Err(ContractError::new(
                ErrorCode::InvalidMessage,
                "invalid node runtime",
            ));
        }
        if challenge.node_key_sha256 != digest(&self.public_key()) {
            return Err(ContractError::new(
                ErrorCode::IdentityMismatch,
                "node key does not match challenge",
            ));
        }
        let mut proof = NodeProof {
            challenge: Some(challenge.clone()),
            runtime_id: runtime_id.into(),
            signature: Vec::new(),
        };
        proof.signature = self
            .key
            .sign(&domain_message(PROOF_DOMAIN, &proof.encode_to_vec()))
            .to_bytes()
            .to_vec();
        Ok(proof)
    }
    pub fn sign_usage(&self, claims: &NodeUsageClaims) -> Result<SignedNodeUsage, ContractError> {
        claims.validate()?;
        let bytes = claims.encode_to_vec();
        Ok(SignedNodeUsage {
            signature: self
                .key
                .sign(&domain_message(USAGE_DOMAIN, &bytes))
                .to_bytes()
                .to_vec(),
            claims: bytes,
        })
    }
    pub fn sign_service_usage(
        &self,
        claims: &ServiceUsageReportClaims,
    ) -> Result<SignedServiceUsageReport, ContractError> {
        claims.validate()?;
        let claims = encode_service_message(claims, SERVICE_USAGE_BYTES)?;
        Ok(SignedServiceUsageReport {
            signature: self
                .key
                .sign(&domain_message(SERVICE_USAGE_DOMAIN, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
    pub fn sign_service_usage_stop(
        &self,
        claims: &ServiceUsageRuntimeStopClaims,
    ) -> Result<SignedServiceUsageRuntimeStop, ContractError> {
        claims.validate()?;
        let claims = encode_service_message(claims, SERVICE_USAGE_BYTES)?;
        Ok(SignedServiceUsageRuntimeStop {
            signature: self
                .key
                .sign(&domain_message(SERVICE_STOP_DOMAIN, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
pub fn verify_proof(proof: &NodeProof, public_key: &[u8; 32]) -> Result<(), ContractError> {
    let challenge = proof
        .challenge
        .as_ref()
        .ok_or_else(|| ContractError::new(ErrorCode::InvalidMessage, "missing node challenge"))?;
    challenge.validate()?;
    if !nestlink_protocol::valid_id(&proof.runtime_id) {
        return Err(ContractError::new(
            ErrorCode::InvalidMessage,
            "invalid node runtime",
        ));
    }
    if challenge.node_key_sha256 != digest(public_key) {
        return Err(ContractError::new(
            ErrorCode::IdentityMismatch,
            "node proof key mismatch",
        ));
    }
    let mut transcript = proof.clone();
    transcript.signature.clear();
    verify_signature(
        public_key,
        PROOF_DOMAIN,
        &transcript.encode_to_vec(),
        &proof.signature,
    )
}
pub fn verify_usage(
    signed: &SignedNodeUsage,
    public_key: &[u8; 32],
) -> Result<NodeUsageClaims, ContractError> {
    if signed.claims.len() as u64 > NODE_MESSAGE_BYTES {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "node usage size exceeded",
        ));
    }
    verify_signature(public_key, USAGE_DOMAIN, &signed.claims, &signed.signature)?;
    let claims: NodeUsageClaims = decode_bounded(&signed.claims, NODE_MESSAGE_BYTES)?;
    claims.validate()?;
    Ok(claims)
}
pub fn verify_usage_ack(
    signed: &SignedNodeUsageAck,
    trusted_policy_issuer: &[u8; 32],
) -> Result<NodeUsageAckClaims, ContractError> {
    if signed.claims.len() as u64 > NODE_MESSAGE_BYTES {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "node usage ack size exceeded",
        ));
    }
    verify_signature(
        trusted_policy_issuer,
        ACK_DOMAIN,
        &signed.claims,
        &signed.signature,
    )?;
    let claims: NodeUsageAckClaims = decode_bounded(&signed.claims, NODE_MESSAGE_BYTES)?;
    claims.validate()?;
    Ok(claims)
}
pub fn verify_service_usage_report(
    signed: &SignedServiceUsageReport,
    public_key: &[u8; 32],
) -> Result<ServiceUsageReportClaims, ContractError> {
    if signed.claims.len() > SERVICE_USAGE_BYTES || signed.signature.len() != 64 {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "service usage report size exceeded",
        ));
    }
    verify_signature(
        public_key,
        SERVICE_USAGE_DOMAIN,
        &signed.claims,
        &signed.signature,
    )?;
    let claims: ServiceUsageReportClaims =
        decode_service_message(&signed.claims, SERVICE_USAGE_BYTES)?;
    claims.validate()?;
    Ok(claims)
}
pub fn verify_service_usage_stop(
    signed: &SignedServiceUsageRuntimeStop,
    public_key: &[u8; 32],
) -> Result<ServiceUsageRuntimeStopClaims, ContractError> {
    if signed.claims.len() > SERVICE_USAGE_BYTES || signed.signature.len() != 64 {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "service stop size exceeded",
        ));
    }
    verify_signature(
        public_key,
        SERVICE_STOP_DOMAIN,
        &signed.claims,
        &signed.signature,
    )?;
    let claims: ServiceUsageRuntimeStopClaims =
        decode_service_message(&signed.claims, SERVICE_USAGE_BYTES)?;
    claims.validate()?;
    Ok(claims)
}
pub fn verify_service_usage_ack(
    signed: &SignedServiceUsageReportAck,
    trusted_policy_issuer: &[u8; 32],
) -> Result<ServiceUsageReportAckClaims, ContractError> {
    if signed.claims.len() > SERVICE_USAGE_BYTES || signed.signature.len() != 64 {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "service usage acknowledgement size exceeded",
        ));
    }
    verify_signature(
        trusted_policy_issuer,
        SERVICE_USAGE_ACK_DOMAIN,
        &signed.claims,
        &signed.signature,
    )?;
    let claims: ServiceUsageReportAckClaims =
        decode_service_message(&signed.claims, SERVICE_USAGE_BYTES)?;
    claims.validate()?;
    Ok(claims)
}
pub fn verify_lease(
    bytes: &[u8],
    trusted_policy_issuer: &[u8; 32],
) -> Result<NodeLeaseClaims, ContractError> {
    let signed: SignedNodeLease = decode_bounded(bytes, NODE_MESSAGE_BYTES + 128)?;
    if signed.claims.len() as u64 > NODE_MESSAGE_BYTES {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "node policy size exceeded",
        ));
    }
    verify_signature(
        trusted_policy_issuer,
        LEASE_DOMAIN,
        &signed.claims,
        &signed.signature,
    )?;
    let claims: NodeLeaseClaims = decode_bounded(&signed.claims, NODE_MESSAGE_BYTES)?;
    claims.validate()?;
    Ok(claims)
}
