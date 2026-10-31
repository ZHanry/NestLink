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
            edge_group: None,
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
    let mut progress = Vec::new();
    for (sequence, offset) in [(3, 1600), (4, 2400)] {
        let mut claims = next.clone();
        claims.lease_sequence = sequence;
        claims.issued_at_unix_ms = at + offset;
        progress.push((offset, ServiceLeaseRenewal {
            lease: f.service.sign(&claims)?,
            issuer: renewal.issuer.clone(),
        }));
    }
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
        // A healthy edge supplies continuing increasing signed progress. One
        // response at 800ms cannot keep a silent edge healthy past its fixed
        // two-second observation cap, even if its delegated lease lasts longer.
        for (offset, renewal) in progress {
            tokio::time::sleep_until(began + Duration::from_millis(offset)).await;
            write_message(&mut send, &renewal).await?;
        }
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
    assert_eq!(publication.handle().lease()?.claims().lease_sequence, 4);
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

#[test]
fn actual_signed_lease_observation_discovers_pins_renews_and_rejects_retired_or_expired() -> Result
{
    use crate::services::publication::observation::{paired, sample};
    use nestlink_protocol::service_plane::observation::ServiceLeaseObservationRequest;
    let at = wall()?;
    let f = Fixture::new(at)?;
    let (issuer, _) = f.initial(at)?;
    let signed = f.service.sign(&f.claims)?;
    let verified = issuer.verify_lease(&signed, at)?;
    let context = PublicationContext {
        deployment_id: id(1),
        security_epoch: 1,
        policy_revision: 2,
        service_lease_issuer: f.service.public_key(),
    };
    let publication = ServicePublication::new(verified.clone(), &context, Instant::now())?;
    let request = ServiceLeaseObservationRequest {
        service_id: id(3),
        approved_revision: 4,
        expected_publication_id: None,
    };
    let first = sample(&publication.handle(), &request, || (false, false))?;
    assert_eq!(first.publication_id, id(2));
    assert_eq!(first.runtime_generation, None);
    assert_eq!(first.lease_sequence, 1);
    assert_eq!(first.lease_claims_sha256, digest(&signed.claims));
    assert_eq!(first.verified_issuer_ed25519, f.service.public_key());
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&first.issuer_signature_base64url)?,
        signed.signature
    );
    let mut bytes = b"NestLink/v15/service-signed-lease-observation/v1\0".to_vec();
    bytes.extend_from_slice(&(signed.claims.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&signed.claims);
    bytes.extend_from_slice(&(signed.signature.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&signed.signature);
    assert_eq!(first.signed_lease_envelope_sha256, digest(&bytes));
    let encoded = serde_json::to_value(&first)?;
    assert!(serde_json::to_vec(&first)?.len() <= 4096);
    for forbidden in [
        "claims",
        "account_id",
        "creator_login_id",
        "approving_login_id",
        "token",
        "private_key",
    ] {
        assert!(encoded.get(forbidden).is_none());
    }
    let pinned = ServiceLeaseObservationRequest {
        expected_publication_id: Some(first.publication_id),
        ..request.clone()
    };
    let wrong = ServiceLeaseObservationRequest {
        expected_publication_id: Some(id(99)),
        ..request.clone()
    };
    assert!(sample(&publication.handle(), &wrong, || (false, false)).is_err());
    let wrong_revision = ServiceLeaseObservationRequest {
        approved_revision: 5,
        ..pinned.clone()
    };
    assert!(sample(&publication.handle(), &wrong_revision, || (false, false)).is_err());
    assert!(sample(&publication.handle(), &pinned, || (true, false)).is_err());
    assert!(sample(&publication.handle(), &pinned, || (false, true)).is_err());
    // Stop arriving after counters were collected must reject the entire sample.
    let state_reads = std::sync::atomic::AtomicUsize::new(0);
    assert!(
        sample(&publication.handle(), &pinned, || {
            (
                state_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0,
                false,
            )
        })
        .is_err()
    );
    assert_eq!(state_reads.load(std::sync::atomic::Ordering::SeqCst), 2);
    let mut renewed_claims = f.claims.clone();
    renewed_claims.lease_sequence = 2;
    renewed_claims.expires_at_unix_ms += 100;
    let renewed = issuer.verify_lease(&f.service.sign(&renewed_claims)?, at)?;
    // A renewal between lease reads must fail rather than mixing the two receipts.
    assert!(
        paired(
            &verified,
            &renewed,
            &pinned,
            at,
            at,
            Default::default(),
            false,
            false
        )
        .is_err()
    );
    assert!(
        paired(
            &verified,
            &verified,
            &pinned,
            at,
            f.claims.expires_at_unix_ms,
            Default::default(),
            false,
            false
        )
        .is_err()
    );
    publication.renew(renewed, Instant::now())?;
    let second = sample(&publication.handle(), &pinned, || (false, false))?;
    assert_eq!(second.lease_sequence, 2);
    assert_ne!(second.lease_claims_sha256, first.lease_claims_sha256);
    assert_ne!(
        second.signed_lease_envelope_sha256,
        first.signed_lease_envelope_sha256
    );
    publication.revoke();
    assert!(sample(&publication.handle(), &pinned, || (false, false)).is_err());
    // An actual signed fixture cannot be forged into a VerifiedServiceLease.
    let mut changed = signed;
    changed.signature[0] ^= 1;
    assert!(
        nestlink_identity::service_plane::verify_service_lease(&changed, &f.service.public_key())
            .is_err()
    );
    Ok(())
}

#[test]
fn original_public_delegation_evidence_is_exact_bound_live_and_changes_on_refresh() -> Result {
    let at = wall()?;
    let f = Fixture::new(at)?;
    let (owner, original) = f.initial(at)?;
    let signed_lease = f.service.sign(&f.claims)?;
    let lease = owner.verify_lease(&signed_lease, at)?;
    let first = owner.observation(&lease, at)?;
    assert_eq!(first.claims, original.claims);
    assert_eq!(first.signature, original.signature);
    assert_eq!(first.verified_policy_issuer_ed25519, f.policy.public_key());
    let retained = verify_service_issuer_delegation(
        &SignedServiceIssuerDelegation {
            claims: first.claims.clone(),
            signature: first.signature.clone(),
        },
        &f.policy.public_key(),
        &id(1),
        at,
    )?;
    assert_eq!(retained.signed().claims, original.claims);
    assert_eq!(retained.signed().signature, original.signature);
    assert_eq!(
        retained.verify_lease(&signed_lease, at)?.digest(),
        lease.digest()
    );
    assert!(owner.observation(&lease, at + 3000).is_err());
    let mut wrong_scope = f.issuer(at, at + 4000);
    wrong_scope.policy_revision += 1;
    let wrong_signed = f.policy.sign_service_issuer_delegation(&wrong_scope)?;
    let wrong_owner = ServiceIssuerOwner::new(verify_service_issuer_delegation(
        &wrong_signed,
        &f.policy.public_key(),
        &id(1),
        at,
    )?);
    assert!(wrong_owner.observation(&lease, at).is_err());
    let mut tampered = original.clone();
    tampered.signature[0] ^= 1;
    assert!(
        verify_service_issuer_delegation(&tampered, &f.policy.public_key(), &id(1), at).is_err()
    );
    let fresh = f
        .policy
        .sign_service_issuer_delegation(&f.issuer(at, at + 4000))?;
    owner.install(verify_service_issuer_delegation(
        &fresh,
        &f.policy.public_key(),
        &id(1),
        at,
    )?)?;
    let second = owner.observation(&lease, at)?;
    assert_ne!(first, second); // A collection spanning refresh must reject the changed proof.
    assert_eq!(second.claims, fresh.claims);
    assert_eq!(second.signature, fresh.signature);
    Ok(())
}
