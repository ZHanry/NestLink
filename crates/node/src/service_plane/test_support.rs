use super::{LocalTargetOwner, PublicationContext, ServicePublication};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{
    InstallationIdentity, digest,
    nodes::NodeIdentity,
    service_plane::{ServiceLeaseSigner, VerifiedServiceLease, verify_service_lease},
    services::{definition_digest, local_target_digest},
};
use nestlink_protocol::{
    SCHEMA_VERSION,
    api::{
        ServiceApprovalState, ServiceDefinition, ServiceIngress, ServiceLimits,
        ServicePublicationStatus, ServiceSourceNetwork, ServiceView,
    },
    service_plane::ServiceUsageBudgetGrantClaims,
    service_plane::{ServiceLeaseClaims, ServiceTunnelTransport},
};
use std::{
    net::SocketAddr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub(crate) fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
pub(crate) fn wall() -> TestResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
pub(crate) struct Fixture {
    pub host: InstallationIdentity,
    pub edge: NodeIdentity,
    pub signer: ServiceLeaseSigner,
    pub context: PublicationContext,
    pub original: ServiceView,
    pub claims: ServiceLeaseClaims,
    pub protocol: String,
    pub address: SocketAddr,
}
impl Fixture {
    pub fn new(
        ingress: ServiceIngress,
        protocol: &str,
        address: SocketAddr,
        lifetime_ms: u64,
    ) -> TestResult<Self> {
        let host = InstallationIdentity::generate();
        let edge = NodeIdentity::generate();
        let signer = ServiceLeaseSigner::from_master_seed(&[71; 32])?;
        let definition = ServiceDefinition {
            name: "fixed local test service".into(),
            host_device_id: id(7),
            edge_node_id: id(8),
            requested_ingress: ingress,
            allowed_sources: vec![ServiceSourceNetwork {
                address: "127.0.0.0".into(),
                prefix: 8,
            }],
            limits: ServiceLimits {
                maximum_connections: 2,
                bytes_per_second: 1_048_576,
                maximum_bytes: 16_777_216,
                idle_timeout_seconds: 5,
            },
        };
        let definition_sha256 = definition_digest(&definition)?;
        let original = ServiceView {
            id: id(3),
            account_id: id(4),
            management_session_id: id(5),
            revision: 3,
            definition,
            definition_sha256: URL_SAFE_NO_PAD.encode(definition_sha256),
            approval: ServiceApprovalState::Pending,
            target_id: None,
            target_sha256: None,
            approval_expires_at_unix_ms: None,
            publication: ServicePublicationStatus::NotPublished,
        };
        let target_id = id(9);
        let target_sha256 = local_target_digest(&original, &target_id, protocol, address)?;
        let now = wall()?;
        let usage_grant = signer.sign_usage_budget_grant(&ServiceUsageBudgetGrantClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            policy_revision: 2,
            quota_revision: 1,
            account_id: original.account_id.clone(),
            host_device_id: original.definition.host_device_id.clone(),
            service_id: original.id.clone(),
            edge_node_id: original.definition.edge_node_id.clone(),
            publication_id: id(2),
            publication_generation: 1,
            service_revision: 4,
            definition_sha256,
            target_sha256,
            ingress_claim_id: id(11),
            ingress_claim_revision: 1,
            edge_runtime_id: id(10),
            edge_runtime_generation: 1,
            grant_id: id(12),
            grant_sequence: 1,
            byte_ceiling: original.definition.limits.maximum_bytes,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + lifetime_ms + 60_000,
        })?;
        let claims = ServiceLeaseClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            policy_revision: 2,
            publication_id: id(2),
            publication_generation: 1,
            service_id: original.id.clone(),
            service_revision: 4,
            choice_revision: 3,
            account_id: original.account_id.clone(),
            creator_login_id: original.management_session_id.clone(),
            approving_login_id: id(6),
            definition: original.definition.clone(),
            definition_sha256,
            host_key_sha256: digest(&host.public_key()),
            target_id,
            target_sha256,
            edge_key_sha256: digest(&edge.public_key()),
            edge_service_address: "127.0.0.1:29199".into(),
            edge_runtime_id: id(10),
            edge_runtime_generation: 1,
            ingress_claim_id: id(11),
            ingress_claim_revision: 1,
            usage_grant,
            lease_sequence: 1,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + lifetime_ms,
        };
        let context = PublicationContext {
            deployment_id: id(1),
            security_epoch: 1,
            policy_revision: 2,
            service_lease_issuer: signer.public_key(),
        };
        Ok(Self {
            host,
            edge,
            signer,
            context,
            original,
            claims,
            protocol: protocol.into(),
            address,
        })
    }
    /// Re-issue the nested grant after a test explicitly changes its lease.
    /// Validation is never bypassed or repaired implicitly by verified().
    pub fn refresh_usage_binding(&mut self) -> TestResult {
        let c = &self.claims;
        let mut grant: ServiceUsageBudgetGrantClaims =
            nestlink_protocol::service_plane::decode_service_message(
                &c.usage_grant.claims,
                nestlink_protocol::service_plane::SERVICE_USAGE_BYTES,
            )?;
        grant.deployment_id = c.deployment_id.clone();
        grant.security_epoch = c.security_epoch;
        grant.policy_revision = c.policy_revision;
        grant.account_id = c.account_id.clone();
        grant.host_device_id = c.definition.host_device_id.clone();
        grant.service_id = c.service_id.clone();
        grant.edge_node_id = c.definition.edge_node_id.clone();
        grant.publication_id = c.publication_id.clone();
        grant.publication_generation = c.publication_generation;
        grant.service_revision = c.service_revision;
        grant.definition_sha256 = c.definition_sha256;
        grant.target_sha256 = c.target_sha256;
        grant.ingress_claim_id = c.ingress_claim_id.clone();
        grant.ingress_claim_revision = c.ingress_claim_revision;
        grant.edge_runtime_id = c.edge_runtime_id.clone();
        grant.edge_runtime_generation = c.edge_runtime_generation;
        grant.byte_ceiling = grant.byte_ceiling.min(c.definition.limits.maximum_bytes);
        self.claims.usage_grant = self.signer.sign_usage_budget_grant(&grant)?;
        Ok(())
    }
    pub fn verified(&self) -> TestResult<VerifiedServiceLease> {
        Ok(verify_service_lease(
            &self.signer.sign(&self.claims)?,
            &self.signer.public_key(),
        )?)
    }
    pub fn publication(&self) -> TestResult<ServicePublication> {
        Ok(ServicePublication::new(
            self.verified()?,
            &self.context,
            Instant::now(),
        )?)
    }
    pub fn owner(&self) -> TestResult<LocalTargetOwner> {
        Ok(LocalTargetOwner::from_local_choice(
            self.context.clone(),
            self.original.clone(),
            self.claims.target_id.clone(),
            self.protocol.clone(),
            self.address,
            self.host.public_key(),
        )?)
    }
    pub fn prepare(
        &self,
        owner: &LocalTargetOwner,
        publication: &ServicePublication,
    ) -> TestResult<super::PreparedLocalTunnel> {
        let lease = publication.handle().lease()?;
        let transport = if self.protocol == "udp" {
            ServiceTunnelTransport::NativeDatagram
        } else {
            ServiceTunnelTransport::Stream
        };
        let challenge = self.edge.challenge_service_tunnel(
            &lease,
            uuid::Uuid::new_v4().to_string(),
            "127.0.0.1:43210".parse()?,
            transport,
            wall()?,
        )?;
        Ok(owner.prepare(
            &publication.handle(),
            &challenge,
            &self.edge.public_key(),
            &self.host,
        )?)
    }
}
