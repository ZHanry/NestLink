use super::*;
use nestlink_identity::{
    PermitSigner,
    nodes::{NodeIdentity, NodePolicySigner},
    service_plane::ServiceLeaseSigner,
    services::definition_digest,
};
use nestlink_node::service_plane::{LocalTargetOwner, PublicationContext, ServicePublication};
use nestlink_protocol::api::{ServiceApprovalState, ServicePublicationStatus, ServiceView};
use nestlink_protocol::{
    SCHEMA_VERSION,
    api::{ServiceDefinition, ServiceLimits, ServiceSourceNetwork},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
struct Fixture {
    policy: NodePolicySigner,
    service: ServiceLeaseSigner,
    edge: NodeIdentity,
    host: Arc<DeviceIdentity>,
    target_owner: Arc<LocalTargetOwner>,
    claims: ServiceLeaseClaims,
}
impl Fixture {
    fn new(at: u64) -> Result<Self> {
        let root = PermitSigner::from_seed([77; 32]);
        let policy = root.node_policy_signer()?;
        let service = root.service_lease_signer()?;
        let edge = NodeIdentity::generate();
        let host = Arc::new(DeviceIdentity::generate());
        let definition = ServiceDefinition {
            name: "short signed issuer renewal".into(),
            host_device_id: host.device_id.clone(),
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
        let target_id = id(9);
        let context = PublicationContext {
            deployment_id: id(1),
            security_epoch: 1,
            policy_revision: 2,
            service_lease_issuer: service.public_key(),
        };
        let original = ServiceView {
            id: id(3),
            account_id: id(4),
            management_session_id: id(5),
            revision: 3,
            definition: definition.clone(),
            definition_sha256: URL_SAFE_NO_PAD.encode(definition_sha256),
            approval: ServiceApprovalState::Pending,
            target_id: None,
            target_sha256: None,
            approval_expires_at_unix_ms: None,
            publication: ServicePublicationStatus::NotPublished,
        };
        let target_owner = Arc::new(LocalTargetOwner::from_local_choice(
            context,
            original,
            target_id.clone(),
            "tcp".into(),
            "127.0.0.1:29101".parse()?,
            host.identity.public_key(),
        )?);
        let target_sha256 = target_owner.target_sha256();
        let usage_grant = service.sign_usage_budget_grant(&ServiceUsageBudgetGrantClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            policy_revision: 2,
            quota_revision: 1,
            account_id: id(4),
            host_device_id: host.device_id.clone(),
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
            issued_at_unix_ms: at,
            expires_at_unix_ms: at + 6500,
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
            host_key_sha256: digest(&host.identity.public_key()),
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
            issued_at_unix_ms: at,
            expires_at_unix_ms: at + 2800,
        };
        Ok(Self {
            policy,
            service,
            edge,
            host,
            target_owner,
            claims,
        })
    }
    fn issuer(&self, at: u64, end: u64) -> ServiceIssuerDelegation {
        ServiceIssuerDelegation {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            policy_revision: 2,
            service_issuer: self.service.public_key(),
            issued_at_unix_ms: at,
            expires_at_unix_ms: end,
        }
    }
    fn initial(&self, at: u64) -> Result<(ServiceIssuerOwner, SignedServiceIssuerDelegation)> {
        let signed = self
            .policy
            .sign_service_issuer_delegation(&self.issuer(at, at + 3000))?;
        let verified =
            verify_service_issuer_delegation(&signed, &self.policy.public_key(), &id(1), at)?;
        Ok((ServiceIssuerOwner::new(verified), signed))
    }
}
struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn actual_quic_signed_refresh_keeps_publication_alive_past_original_issuer_deadline() -> Result
{
    let at = wall()?;
    let began = tokio::time::Instant::now();
    let f = Fixture::new(at)?;
    let context = PublicationContext {
        deployment_id: id(1),
        security_epoch: 1,
        policy_revision: 2,
        service_lease_issuer: f.service.public_key(),
    };
    let target = f.target_owner.clone();
    let (owner, first_proof) = f.initial(at)?;
    let owner = Arc::new(owner);
    let initial = f.service.sign(&f.claims)?;
    let publication = Arc::new(ServicePublication::new(
        owner.verify_lease(&initial, at)?,
        &context,
        Instant::now(),
    )?);
    let endpoint = carrier::listener("127.0.0.1:0".parse()?, &f.edge)?;
    let address = endpoint.local_addr()?;
    let mut next = f.claims.clone();
    next.lease_sequence = 2;
    next.issued_at_unix_ms = at + 800;
    next.expires_at_unix_ms = at + 6000;
    let renewal = ServiceLeaseRenewal {
        lease: f.service.sign(&next)?,
        issuer: f
            .policy
            .sign_service_issuer_delegation(&f.issuer(at + 800, at + 6500))?,
    };
    let sent = renewal.clone();
    let mut server = Abort(tokio::spawn(async move {
        let incoming = endpoint
            .accept()
            .await
            .ok_or(std::io::ErrorKind::ConnectionAborted)?;
        let connection = incoming.await.map_err(std::io::Error::other)?;
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(std::io::Error::other)?;
        let _: u8 = read_message(&mut recv).await?;
        tokio::time::sleep_until(began + Duration::from_millis(800)).await;
        write_message(&mut send, &sent).await?;
        connection.closed().await;
        endpoint.close(0u32.into(), b"issuer test done");
        endpoint.wait_idle().await;
        Ok::<(), std::io::Error>(())
    }));
    let connected =
        carrier::connect(address, &f.host.identity, digest(&f.edge.public_key())).await?;
    let (mut send, recv) = connected.connection.open_bi().await?;
    write_message(&mut send, &0u8).await?;
    let (stop, stopping) = watch::channel(false);
    let revoke = Revoke {
        publication: publication.clone(),
        target: target.clone(),
        connection: connected.connection.clone(),
    };
    let mut runtime = Abort(tokio::spawn(run(
        RunContext {
            connected,
            host: f.host.clone(),
            delegation: owner.clone(),
            publication: publication.clone(),
            target,
            edge_key: f.edge.public_key(),
            control_send: send,
            control_recv: recv,
            stop: stopping,
            backend_tls: None,
        },
        revoke,
    )));
    tokio::time::sleep_until(began + Duration::from_millis(3200)).await;
    assert!(
        verify_service_issuer_delegation(&first_proof, &f.policy.public_key(), &id(1), wall()?)
            .is_err()
    );
    owner.check_live(wall()?)?;
    assert_eq!(
        owner
            .verify_lease(&renewal.lease, wall()?)?
            .claims()
            .lease_sequence,
        2
    );
    assert_eq!(publication.handle().lease()?.claims().lease_sequence, 2);
    assert!(!runtime.0.is_finished());
    stop.send_replace(true);
    let report = tokio::time::timeout(Duration::from_secs(3), &mut runtime.0).await??;
    assert_eq!(report, ServiceHostStopReport { failed: false });
    tokio::time::timeout(Duration::from_secs(3), &mut server.0).await???;
    Ok(())
}

#[test]
fn issuer_refresh_rejects_scope_rotation_tampering_and_deadline_rollback() -> Result {
    let at = wall()?;
    let f = Fixture::new(at)?;
    let (owner, _) = f.initial(at)?;
    let mut next = f.claims.clone();
    next.lease_sequence = 2;
    next.expires_at_unix_ms = at + 2900;
    let lease = f.service.sign(&next)?;
    let valid = f.issuer(at, at + 6500);
    for change in 0..5 {
        let mut issuer = valid.clone();
        match change {
            0 => issuer.security_epoch += 1,
            1 => issuer.policy_revision += 1,
            2 => issuer.service_issuer = [99; 32],
            3 => issuer.deployment_id = id(99),
            _ => issuer.expires_at_unix_ms = at + 2950,
        }
        let signed = f.policy.sign_service_issuer_delegation(&issuer)?;
        assert!(
            owner
                .prepare(
                    &ServiceLeaseRenewal {
                        lease: lease.clone(),
                        issuer: signed
                    },
                    at
                )
                .is_err()
        );
    }
    let mut tampered = f.policy.sign_service_issuer_delegation(&valid)?;
    tampered.signature[0] ^= 1;
    assert!(
        owner
            .prepare(
                &ServiceLeaseRenewal {
                    lease,
                    issuer: tampered
                },
                at
            )
            .is_err()
    );
    owner.check_live(at + 2999)?;
    assert!(owner.check_live(at + 3000).is_err());
    Ok(())
}
