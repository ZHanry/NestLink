//! Both modes reserve and settle through the original public service ledgers.
use super::*;
use nestlink_identity::network::NetworkAuthoritySigner;
use nestlink_identity::services::private::verify_private_service_lease;
use nestlink_protocol::{services::private::*, spaces::*};

struct PrivateAccess {
    network: NetworkAuthoritySigner,
    consumer: String,
    exposure: ServiceExposureView,
    runtime: String,
}
fn configure(f: &mut Fixture) -> Result<PrivateAccess> {
    let network = NetworkAuthoritySigner::from_master_seed(&[216; 32])?;
    let mut space = f.store.create_space(
        &f.creator,
        SpaceCreateRequest {
            name: "Shared service allowance".into(),
        },
        network.public_key(),
        now()?,
    )?;
    let consumer_identity = InstallationIdentity::generate();
    let consumer = random_id();
    let challenge = f.store.enrollment_challenge(&f.creator, now()? / 1000)?;
    let mut registration = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: consumer.clone(),
            name: "exact private consumer".into(),
            platform: "windows".into(),
            public_key: URL_SAFE_NO_PAD.encode(consumer_identity.public_key()),
            capabilities: vec!["host".into(), "vp8".into()],
            path_mode: "direct_only".into(),
        },
        signature: String::new(),
    };
    registration.signature = URL_SAFE_NO_PAD.encode(
        consumer_identity.sign_action(&f.store.registration_transcript(
            &f.creator,
            &registration,
            now()? / 1000,
        )?)?,
    );
    f.store
        .register_device(&f.creator, registration, now()? / 1000)?;
    for installation in [&f.host_id, &consumer] {
        space = f.store.join_space_device(
            &f.creator,
            &space.space_id,
            SpaceDeviceJoin {
                expected_revision: space.revision,
                expected_membership_epoch: 0,
                installation_id: installation.clone(),
            },
            now()?,
        )?;
    }
    let half = f.view.definition.limits.maximum_bytes / 2;
    let exposure = f.store.set_service_exposure(
        &f.creator,
        &f.view.id,
        ServiceExposureUpdate {
            expected_revision: 0,
            expected_service_revision: f.view.revision,
            space_id: space.space_id,
            mode: ServiceAccessMode::Both,
            private_maximum_bytes: half,
            public_maximum_bytes: half,
        },
        now()?,
    )?;
    f.store.grant_private_service(
        &f.creator,
        &f.view.id,
        PrivateServiceAclUpdate {
            expected_exposure_revision: exposure.revision,
            subject: PrivateServiceSubject::Installation {
                installation_id: consumer.clone(),
            },
            expires_at_unix_ms: now()? + 30_000,
        },
        now()?,
    )?;
    let at = now()?;
    let runtime = random_id();
    let presence = PrivateServiceHostClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: f.store.deployment_id()?,
        security_epoch: f.store.security_epoch()?,
        policy_revision: f.store.policy()?.0,
        service_id: f.view.id.clone(),
        service_revision: f.view.revision,
        exposure_revision: exposure.revision,
        target_sha256: nestlink_identity::services::decode_digest(
            f.view.target_sha256.as_deref().ok_or("target missing")?,
        )?,
        host_device_id: f.host_id.clone(),
        runtime_id: runtime.clone(),
        request_sequence: 1,
        address: "127.0.0.1:29888".into(),
        issued_at_unix_ms: at,
        expires_at_unix_ms: at + 10_000,
    };
    f.store.register_private_service_host(
        &f.creator,
        &f.host.sign_private_service_host(&presence)?,
        at,
    )?;
    Ok(PrivateAccess {
        network,
        consumer,
        exposure,
        runtime,
    })
}
fn request(f: &Fixture, access: &PrivateAccess) -> PrivateServiceAccessRequest {
    PrivateServiceAccessRequest {
        request_id: random_id(),
        consumer_device_id: access.consumer.clone(),
        expected_service_revision: f.view.revision,
        expected_exposure_revision: access.exposure.revision,
        maximum_bytes: access.exposure.private_maximum_bytes,
    }
}
fn ledgers(f: &mut Fixture, spent: u64, outstanding: u64) -> Result {
    for (scope, scope_key) in [
        (ServiceQuotaScope::Account, f.creator.account_id.clone()),
        (ServiceQuotaScope::Device, f.host_id.clone()),
        (ServiceQuotaScope::Node, f.node.node_id.clone()),
        (ServiceQuotaScope::Resource, f.view.id.clone()),
    ] {
        let usage = f.store.service_quota_usage(
            &f.creator,
            ServiceQuotaUsageQuery { scope, scope_key },
            now()?,
        )?;
        assert_eq!(usage.spent_bytes, spent);
        assert_eq!(usage.outstanding_bytes, outstanding);
    }
    Ok(())
}

#[test]
fn both_modes_share_durable_allowance_exact_network_graph_and_terminal_private_owner() -> Result {
    let mut f = Fixture::new()?;
    let access = configure(&mut f)?;
    let body = request(&f, &access);
    let private = f.store.issue_private_service(
        &f.creator,
        &f.view.id,
        body.clone(),
        &f.service_signer,
        now()?,
    )?;
    let verified = verify_private_service_lease(&private, &f.service_signer.public_key())?;
    let grant: ServiceUsageBudgetGrantClaims = decode_service_message(
        &verified.lease().claims().usage_grant.claims,
        SERVICE_USAGE_BYTES,
    )?;
    let graph = f.store.issue_private_service_network_path(
        &f.creator,
        &f.view.id,
        &grant.grant_id,
        &f.service_signer,
        &access.network,
        now()?,
    )?;
    let repeated =
        f.store
            .issue_private_service(&f.creator, &f.view.id, body, &f.service_signer, now()?)?;
    assert_eq!(
        serde_json::to_vec(&private)?,
        serde_json::to_vec(&repeated)?
    );
    let repeated = f.store.issue_private_service_network_path(
        &f.creator,
        &f.view.id,
        &grant.grant_id,
        &f.service_signer,
        &access.network,
        now()?,
    )?;
    assert_eq!(serde_json::to_vec(&graph)?, serde_json::to_vec(&repeated)?);
    let readback = f.store.private_service_network_path(
        &f.approver,
        &f.view.id,
        &grant.grant_id,
        &f.service_signer,
        now()?,
    )?;
    assert_eq!(serde_json::to_vec(&graph)?, serde_json::to_vec(&readback)?);
    let public = f.publish()?;
    let public: ServiceUsageBudgetGrantClaims =
        decode_service_message(&public.claims.usage_grant.claims, SERVICE_USAGE_BYTES)?;
    assert_ne!(grant.grant_id, public.grant_id);
    assert_eq!(grant.byte_ceiling, access.exposure.private_maximum_bytes);
    assert_eq!(public.byte_ceiling, access.exposure.public_maximum_bytes);
    let total = f.view.definition.limits.maximum_bytes;
    ledgers(&mut f, 0, total)?;
    assert!(
        f.store
            .issue_private_service(
                &f.creator,
                &f.view.id,
                request(&f, &access),
                &f.service_signer,
                now()?
            )
            .is_err()
    );

    let report = PrivateServiceUsageClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: grant.deployment_id.clone(),
        security_epoch: grant.security_epoch,
        grant_id: grant.grant_id.clone(),
        grant_sha256: digest(&private.service_lease.claims),
        host_device_id: f.host_id.clone(),
        runtime_id: access.runtime.clone(),
        report_sequence: 1,
        admitted_bytes: 7,
        opened_connections: 1,
        closed_connections: 1,
        terminal: true,
        sampled_at_unix_ms: now()?,
    };
    // Accounting pins the original usage grant rather than the enclosing
    // business lease. A correctly signed report with the wrong binding fails.
    assert!(
        f.store
            .accept_private_service_usage(&f.host.sign_private_service_usage(&report)?, now()?)
            .is_err()
    );
    let mut report = report;
    report.grant_sha256 = digest(&verified.lease().claims().usage_grant.claims);
    let mut wrong = report.clone();
    wrong.runtime_id = random_id();
    assert!(
        f.store
            .accept_private_service_usage(&f.host.sign_private_service_usage(&wrong)?, now()?)
            .is_err()
    );
    ledgers(&mut f, 0, total)?;
    let signed = f.host.sign_private_service_usage(&report)?;
    let ack = f.store.accept_private_service_usage(&signed, now()?)?;
    let repeated = f.store.accept_private_service_usage(&signed, now()?)?;
    assert_eq!(serde_json::to_vec(&ack)?, serde_json::to_vec(&repeated)?);
    let mut altered = report;
    altered.admitted_bytes = 8;
    assert!(
        f.store
            .accept_private_service_usage(&f.host.sign_private_service_usage(&altered)?, now()?)
            .is_err()
    );
    ledgers(&mut f, 7, public.byte_ceiling)?;

    let next = f.store.issue_private_service(
        &f.creator,
        &f.view.id,
        request(&f, &access),
        &f.service_signer,
        now()?,
    )?;
    let next: ServiceUsageBudgetGrantClaims = decode_service_message(
        &verify_private_service_lease(&next, &f.service_signer.public_key())?
            .lease()
            .claims()
            .usage_grant
            .claims,
        SERVICE_USAGE_BYTES,
    )?;
    assert_eq!(next.byte_ceiling, access.exposure.private_maximum_bytes - 7);
    ledgers(&mut f, 7, total - 7)?;
    f.store.set_service_exposure(
        &f.creator,
        &f.view.id,
        ServiceExposureUpdate {
            expected_revision: access.exposure.revision,
            expected_service_revision: f.view.revision,
            space_id: access.exposure.space_id,
            mode: ServiceAccessMode::Public,
            private_maximum_bytes: 0,
            public_maximum_bytes: total,
        },
        now()?,
    )?;
    assert!(
        f.store
            .private_service_lease(
                &f.creator,
                &f.view.id,
                &next.grant_id,
                &f.service_signer,
                now()?
            )
            .is_err()
    );
    // Mode switching revoked business access and withdrew publication, but
    // neither owner supplied the second terminal seal. Both promises remain.
    assert!(f.publish().is_err());
    ledgers(&mut f, 7, total - 7)?;
    Ok(())
}
