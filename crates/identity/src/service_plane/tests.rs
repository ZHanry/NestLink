use super::publication::*;
use super::*;
mod private_network;
mod groups;
use crate::nodes::{NodeIdentity, NodePolicySigner};
use nestlink_protocol::service_plane::publication::*;
use nestlink_protocol::{
    SCHEMA_VERSION,
    api::{ServiceDefinition, ServiceIngress, ServiceLimits, ServiceSourceNetwork},
};
fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
struct Fixture {
    service: ServiceLeaseSigner,
    policy: NodePolicySigner,
    edge: NodeIdentity,
    host: InstallationIdentity,
    claims: ServiceLeaseClaims,
}
impl Fixture {
    fn new() -> Result<Self, ContractError> {
        let root = PermitSigner::from_seed([71; 32]);
        let service = root.service_lease_signer()?;
        let policy = root.node_policy_signer()?;
        let edge = NodeIdentity::generate();
        let host = InstallationIdentity::generate();
        let definition = ServiceDefinition {
            name: "separate authority".into(),
            host_device_id: id(7),
            edge_node_id: id(8),
            requested_ingress: ServiceIngress::Tcp { port: 29100 },
            allowed_sources: vec![ServiceSourceNetwork {
                address: "127.0.0.0".into(),
                prefix: 8,
            }],
            limits: ServiceLimits {
                maximum_connections: 2,
                bytes_per_second: 4096,
                maximum_bytes: 65536,
                idle_timeout_seconds: 5,
            },
        };
        let definition_sha256 = definition_digest(&definition)?;
        let target_sha256 = [3; 32];
        let usage_grant = service.sign_usage_budget_grant(&ServiceUsageBudgetGrantClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            policy_revision: 2,
            quota_revision: 1,
            account_id: id(4),
            host_device_id: id(7),
            service_id: id(3),
            edge_node_id: id(8),
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
            byte_ceiling: definition.limits.maximum_bytes,
            issued_at_unix_ms: 9_000,
            expires_at_unix_ms: 30_000,
        })?;
        let claims = ServiceLeaseClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            policy_revision: 2,
            publication_id: id(2),
            publication_generation: 1,
            service_id: id(3),
            service_revision: 4,
            choice_revision: 3,
            account_id: id(4),
            creator_login_id: id(5),
            approving_login_id: id(6),
            definition_sha256,
            definition,
            host_key_sha256: digest(&host.public_key()),
            target_id: id(9),
            target_sha256,
            edge_key_sha256: digest(&edge.public_key()),
            edge_service_address: "127.0.0.1:29199".into(),
            edge_runtime_id: id(10),
            edge_runtime_generation: 1,
            ingress_claim_id: id(11),
            ingress_claim_revision: 1,
            edge_group: None,
            usage_grant,
            lease_sequence: 1,
            issued_at_unix_ms: 10000,
            expires_at_unix_ms: 20000,
        };
        Ok(Self {
            service,
            policy,
            edge,
            host,
            claims,
        })
    }
    fn resign_usage_grant(&self, claims: &mut ServiceLeaseClaims) -> Result<(), ContractError> {
        claims.usage_grant =
            self.service
                .sign_usage_budget_grant(&ServiceUsageBudgetGrantClaims {
                    schema_version: claims.schema_version,
                    deployment_id: claims.deployment_id.clone(),
                    security_epoch: claims.security_epoch,
                    policy_revision: claims.policy_revision,
                    quota_revision: 1,
                    account_id: claims.account_id.clone(),
                    host_device_id: claims.definition.host_device_id.clone(),
                    service_id: claims.service_id.clone(),
                    edge_node_id: claims.accounting_node_id().into(),
                    publication_id: claims.publication_id.clone(),
                    publication_generation: claims.publication_generation,
                    service_revision: claims.service_revision,
                    definition_sha256: claims.definition_sha256,
                    target_sha256: claims.target_sha256,
                    ingress_claim_id: claims.ingress_claim_id.clone(),
                    ingress_claim_revision: claims.ingress_claim_revision,
                    edge_runtime_id: claims.edge_runtime_id.clone(),
                    edge_runtime_generation: claims.edge_runtime_generation,
                    grant_id: id(12),
                    grant_sequence: 1,
                    byte_ceiling: claims.effective_limits().maximum_bytes,
                    issued_at_unix_ms: 9_000,
                    expires_at_unix_ms: 30_000,
                })?;
        Ok(())
    }
    fn verified(&self) -> Result<VerifiedServiceLease, ContractError> {
        verify_service_lease(
            &self.service.sign(&self.claims)?,
            &self.service.public_key(),
        )
    }
    fn query(&self) -> NodeResourceQueryClaims {
        NodeResourceQueryClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            node_id: id(8),
            runtime_id: id(10),
            runtime_generation: 1,
            policy_revision: 2,
            lease_sequence: 1,
            request_id: id(12),
            request_sequence: 1,
            issued_at_unix_ms: 10000,
            expires_at_unix_ms: 11000,
        }
    }
    fn snapshot(
        &self,
        request: &SignedServiceResourceQuery,
    ) -> Result<ServiceResourceSnapshot, ContractError> {
        Ok(ServiceResourceSnapshot {
            query: verify_service_query(request, &self.edge.public_key())?,
            query_sha256: digest(&request.claims),
            service_lease_issuer: self.service.public_key(),
            issued_at_unix_ms: 10001,
            expires_at_unix_ms: 11000,
            leases: vec![self.service.sign(&self.claims)?],
        })
    }
}
#[test]
fn service_key_and_signature_purpose_are_distinct_from_node_and_remote_permits()
-> Result<(), ContractError> {
    let root = PermitSigner::from_seed([71; 32]);
    let fixture = Fixture::new()?;
    assert_ne!(fixture.service.public_key(), root.public_key());
    assert_ne!(fixture.service.public_key(), fixture.policy.public_key());
    let signed = fixture.service.sign(&fixture.claims)?;
    fixture.verified()?;
    assert!(verify_service_lease(&signed, &root.public_key()).is_err());
    assert!(
        verify_signature(
            &fixture.service.public_key(),
            b"NestLink/v15/session-permit/v1\0",
            &signed.claims,
            &signed.signature
        )
        .is_err()
    );
    assert!(
        verify_signature(
            &fixture.service.public_key(),
            QUERY,
            &signed.claims,
            &signed.signature
        )
        .is_err()
    );
    let mut tampered = signed.clone();
    let mut claims = fixture.claims.clone();
    claims.approving_login_id = id(99);
    tampered.claims = encode(&claims, SERVICE_MESSAGE_BYTES)?;
    assert!(verify_service_lease(&tampered, &fixture.service.public_key()).is_err());
    Ok(())
}
#[test]
fn binding_retains_target_choice_revision_both_logins_ingress_and_runtime()
-> Result<(), ContractError> {
    let fixture = Fixture::new()?;
    let original = fixture.verified()?;
    let mut renewed = fixture.claims.clone();
    renewed.lease_sequence += 1;
    renewed.issued_at_unix_ms += 100;
    renewed.expires_at_unix_ms += 100;
    let renewed = verify_service_lease(
        &fixture.service.sign(&renewed)?,
        &fixture.service.public_key(),
    )?;
    assert_eq!(original.binding(), renewed.binding());
    assert_ne!(original.digest(), renewed.digest());
    let mut alternatives = Vec::new();
    let mut c = fixture.claims.clone();
    c.creator_login_id = id(98);
    alternatives.push(c);
    let mut c = fixture.claims.clone();
    c.approving_login_id = id(98);
    alternatives.push(c);
    let mut c = fixture.claims.clone();
    c.ingress_claim_revision += 1;
    alternatives.push(c);
    let mut c = fixture.claims.clone();
    c.edge_runtime_generation += 1;
    alternatives.push(c);
    let mut c = fixture.claims.clone();
    c.choice_revision += 1;
    c.service_revision += 1;
    alternatives.push(c);
    let mut c = fixture.claims.clone();
    c.target_sha256 = [98; 32];
    alternatives.push(c);
    for c in alternatives {
        let mut c = c;
        fixture.resign_usage_grant(&mut c)?;
        assert_ne!(original.binding(), publication_binding(&c)?);
    }
    Ok(())
}
#[test]
fn snapshots_bind_exact_signed_query_keys_delegation_and_strict_publication_order()
-> Result<(), ContractError> {
    let fixture = Fixture::new()?;
    let request = fixture.edge.sign_service_query(&fixture.query())?;
    let snapshot = fixture.snapshot(&request)?;
    let signed = fixture.policy.sign_service_snapshot(&snapshot)?;
    let verified = verify_service_snapshot(
        &signed,
        &fixture.policy.public_key(),
        &request,
        &fixture.edge.public_key(),
    )?;
    assert_eq!(verified.policy_issuer(), fixture.policy.public_key());
    assert_eq!(
        verified.node_key_sha256(),
        digest(&fixture.edge.public_key())
    );
    let mut bad_request = request.clone();
    bad_request.signature[0] ^= 1;
    assert!(
        verify_service_snapshot(
            &signed,
            &fixture.policy.public_key(),
            &bad_request,
            &fixture.edge.public_key()
        )
        .is_err()
    );
    let mut other_query = fixture.query();
    other_query.request_sequence += 1;
    let other_request = fixture.edge.sign_service_query(&other_query)?;
    assert!(
        verify_service_snapshot(
            &signed,
            &fixture.policy.public_key(),
            &other_request,
            &fixture.edge.public_key()
        )
        .is_err()
    );
    let wrong_node = NodeIdentity::generate();
    assert!(
        verify_service_snapshot(
            &signed,
            &fixture.policy.public_key(),
            &request,
            &wrong_node.public_key()
        )
        .is_err()
    );
    let mut duplicate = snapshot.clone();
    duplicate.leases.push(duplicate.leases[0].clone());
    assert!(
        verify_service_snapshot(
            &fixture.policy.sign_service_snapshot(&duplicate)?,
            &fixture.policy.public_key(),
            &request,
            &fixture.edge.public_key()
        )
        .is_err()
    );
    let mut changed = snapshot.clone();
    changed.service_lease_issuer = wrong_node.public_key();
    assert!(
        verify_service_snapshot(
            &fixture.policy.sign_service_snapshot(&changed)?,
            &fixture.policy.public_key(),
            &request,
            &fixture.edge.public_key()
        )
        .is_err()
    );
    let mut c = fixture.claims.clone();
    c.publication_id = id(1);
    fixture.resign_usage_grant(&mut c)?;
    let mut unsorted = snapshot;
    unsorted.leases.push(fixture.service.sign(&c)?);
    assert!(
        verify_service_snapshot(
            &fixture.policy.sign_service_snapshot(&unsorted)?,
            &fixture.policy.public_key(),
            &request,
            &fixture.edge.public_key()
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn host_proof_authenticates_the_exact_edge_challenge_and_lease()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let lease = fixture.verified()?;
    let challenge = fixture.edge.challenge_service_tunnel(
        &lease,
        id(13),
        "127.0.0.1:12345".parse()?,
        ServiceTunnelTransport::Stream,
        10001,
    )?;
    let proof = fixture.host.prove_service_tunnel(
        &lease,
        &challenge,
        &fixture.edge.public_key(),
        &id(14),
    )?;
    verify_tunnel_proof(
        &lease,
        &challenge,
        &proof,
        &fixture.host.public_key(),
        &fixture.edge.public_key(),
    )?;
    let mut tampered = challenge.clone();
    tampered.signature[0] ^= 1;
    assert!(
        verify_tunnel_proof(
            &lease,
            &tampered,
            &proof,
            &fixture.host.public_key(),
            &fixture.edge.public_key()
        )
        .is_err()
    );
    let other = fixture.edge.challenge_service_tunnel(
        &lease,
        id(15),
        "127.0.0.1:12345".parse()?,
        ServiceTunnelTransport::Stream,
        10001,
    )?;
    assert!(
        verify_tunnel_proof(
            &lease,
            &other,
            &proof,
            &fixture.host.public_key(),
            &fixture.edge.public_key()
        )
        .is_err()
    );
    let wrong_host = InstallationIdentity::generate();
    assert!(
        verify_tunnel_proof(
            &lease,
            &challenge,
            &proof,
            &wrong_host.public_key(),
            &fixture.edge.public_key()
        )
        .is_err()
    );
    let mut c = fixture.claims.clone();
    c.lease_sequence += 1;
    let renewed = verify_service_lease(&fixture.service.sign(&c)?, &fixture.service.public_key())?;
    assert!(
        verify_tunnel_proof(
            &renewed,
            &challenge,
            &proof,
            &fixture.host.public_key(),
            &fixture.edge.public_key()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn delegation_requires_the_pinned_policy_issuer_realm_and_current_time() -> Result<(), ContractError>
{
    let f = Fixture::new()?;
    let claims = ServiceIssuerDelegation {
        schema_version: SCHEMA_VERSION,
        deployment_id: f.claims.deployment_id.clone(),
        security_epoch: 1,
        policy_revision: 2,
        service_issuer: f.service.public_key(),
        issued_at_unix_ms: 9000,
        expires_at_unix_ms: 30000,
    };
    let signed = f.policy.sign_service_issuer_delegation(&claims)?;
    let delegated = verify_service_issuer_delegation(
        &signed,
        &f.policy.public_key(),
        &f.claims.deployment_id,
        10000,
    )?;
    delegated.verify_lease(&f.service.sign(&f.claims)?, 10000)?;
    assert!(
        verify_service_issuer_delegation(
            &signed,
            &f.service.public_key(),
            &f.claims.deployment_id,
            10000
        )
        .is_err()
    );
    assert!(
        verify_service_issuer_delegation(&signed, &f.policy.public_key(), &id(99), 10000).is_err()
    );
    assert!(
        verify_service_issuer_delegation(
            &signed,
            &f.policy.public_key(),
            &f.claims.deployment_id,
            30000
        )
        .is_err()
    );
    let mut wrong = f.claims.clone();
    wrong.security_epoch = 2;
    f.resign_usage_grant(&mut wrong)?;
    assert!(
        delegated
            .verify_lease(&f.service.sign(&wrong)?, 10000)
            .is_err()
    );
    Ok(())
}
#[test]
fn attachment_proof_cannot_be_reused_as_visitor_authority_or_at_another_nonce()
-> Result<(), ContractError> {
    let f = Fixture::new()?;
    let lease = f.verified()?;
    let challenge = f.edge.challenge_service_attachment(&lease, 10000)?;
    let proof = f.host.prove_service_attachment(
        &lease,
        &challenge,
        &f.edge.public_key(),
        &id(43),
        10000,
    )?;
    verify_attachment_proof(
        &lease,
        &challenge,
        &proof,
        &f.host.public_key(),
        &f.edge.public_key(),
        10001,
    )?;
    let other = f.edge.challenge_service_attachment(&lease, 10000)?;
    assert!(
        verify_attachment_proof(
            &lease,
            &other,
            &proof,
            &f.host.public_key(),
            &f.edge.public_key(),
            10001
        )
        .is_err()
    );
    assert!(
        verify_attachment_proof(
            &lease,
            &challenge,
            &proof,
            &f.host.public_key(),
            &f.edge.public_key(),
            12000
        )
        .is_err()
    );
    let visitor = SignedServiceTunnelChallenge {
        claims: challenge.claims,
        signature: challenge.signature,
    };
    assert!(verify_tunnel_challenge(&visitor, &lease, &f.edge.public_key()).is_err());
    Ok(())
}
#[test]
fn operator_address_is_part_of_immutable_publication_binding() -> Result<(), ContractError> {
    let f = Fixture::new()?;
    let original = publication_binding(&f.claims)?;
    let mut changed = f.claims.clone();
    changed.edge_service_address = "127.0.0.1:29200".into();
    assert_ne!(original, publication_binding(&changed)?);
    Ok(())
}
