//! Both modes reserve and settle through the original public service ledgers.
use super::*;
use nestlink_identity::network::NetworkAuthoritySigner;
use nestlink_identity::services::private::verify_private_service_lease;
use nestlink_protocol::{services::private::*, spaces::*};

struct PrivateAccess {
    network: NetworkAuthoritySigner,
    consumer: String,
    consumer_identity:InstallationIdentity,
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
            path_mode: if f.store.policy()?.1.peer_path_mode==PeerPathMode::DirectOnly {"direct_only"} else {"direct_preferred"}.into(),
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
        consumer_identity,
        exposure,
        runtime,
    })
}
fn request(f: &Fixture, access: &PrivateAccess) -> PrivateServiceAccessRequest {
    PrivateServiceAccessRequest {
        route:PrivateServiceRouteRequest::Direct,
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

#[test]
fn private_relay_preserves_original_budget_pinned_metadata_snapshot_and_close_receipt()->Result{
    use nestlink_identity::{PermitSigner,network::{verify_private_service_grant,verify_node_private_service_resource},relay::allocation_binding};
    use nestlink_protocol::{NodeResourceQueryClaims,RelayCloseClaims};
    let mut f=Fixture::with_paths(PeerPathMode::DirectPreferred)?;
    let access=configure(&mut f)?;
    let lifecycle=f.store.relay_lifecycle(now()?)?;
    let relay=NodeIdentity::generate();let relay_id=random_id();
    f.store.register_node(&f.creator,NodeRegistration{id:relay_id.clone(),name:"private route original relay owner".into(),public_key:URL_SAFE_NO_PAD.encode(relay.public_key()),roles:vec![NodeRole::NodeRelay as i32],max_connections:16,bytes_per_second:1048576})?;
    f.store.set_node_endpoints(&f.creator,&relay_id,NodeEndpointsUpdate{expected_revision:0,endpoints:NodeEndpoints{quic_uri:Some("quic://127.0.0.1:29999".into()),wss_origin:None,allow_loopback:true}},now()?)?;
    let challenge=f.store.node_challenge(&relay_id,now()?)?;
    let node=f.store.issue_node_lease(&relay.prove(&challenge,&random_id())?,now()?)?;
    let node_signer=NodePolicySigner::from_master_seed(&[220;32])?;
    let permit_signer=PermitSigner::from_seed([221;32]);
    let mut body=request(&f,&access);body.maximum_bytes=4096;
    body.route=PrivateServiceRouteRequest::Relay{node_ids:vec![relay_id.clone()],topology_digests:vec![],signature:String::new()};
    let signature=URL_SAFE_NO_PAD.encode(access.consumer_identity.sign_private_service_route(&f.view.id,&body)?);
    if let PrivateServiceRouteRequest::Relay{signature:value,..}=&mut body.route{*value=signature;}
    let grant=f.store.issue_private_service_grant(&lifecycle,&f.creator,&f.view.id,body.clone(),&f.service_signer,&access.network,&node_signer,now()?)?;
    let repeat=f.store.issue_private_service_grant(&lifecycle,&f.creator,&f.view.id,body.clone(),&f.service_signer,&access.network,&node_signer,now()?)?;
    assert_eq!(serde_json::to_vec(&grant)?,serde_json::to_vec(&repeat)?);
    let deployment=f.store.deployment_id()?;
    let (business,_,_,transits)=verify_private_service_grant(&grant,&node_signer.public_key(),&deployment,now()?)?;
    assert_eq!(transits.len(),1);
    let usage:ServiceUsageBudgetGrantClaims=decode_service_message(&business.lease().claims().usage_grant.claims,SERVICE_USAGE_BYTES)?;
    assert_eq!(usage.byte_ceiling,4096);
    ledgers(&mut f,0,4096)?;
    let held:u64=f.store.connection.query_row("SELECT count(*) FROM all_relay_capacity WHERE promised_until>?1",[now()?],|r|r.get(0))?;
    assert_eq!(held,1);
    let remote:u64=f.store.connection.query_row("SELECT (SELECT count(*) FROM remote_requests)+(SELECT count(*) FROM relay_reservations)",[],|r|r.get(0))?;
    assert_eq!(remote,0);
    let mut tampered=grant.clone();
    tampered.network.relay.as_mut().ok_or("relay missing")?.nodes[0].revision+=1;
    assert!(verify_private_service_grant(&tampered,&node_signer.public_key(),&deployment,now()?).is_err());
    let mut changed=body;changed.maximum_bytes+=1;
    assert!(f.store.issue_private_service_grant(&lifecycle,&f.creator,&f.view.id,changed,&f.service_signer,&access.network,&node_signer,now()?).is_err());
    ledgers(&mut f,0,4096)?;
    let at=now()?;
    let query=relay.sign_resource_query(&NodeResourceQueryClaims{schema_version:SCHEMA_VERSION,deployment_id:deployment.clone(),security_epoch:node.security_epoch,node_id:relay_id.clone(),runtime_id:node.runtime_id.clone(),runtime_generation:node.runtime_generation,policy_revision:node.policy_revision,lease_sequence:node.lease_sequence,request_id:random_id(),request_sequence:1,issued_at_unix_ms:at,expires_at_unix_ms:(at+NODE_RESOURCE_TTL_MS).min(node.expires_at_unix_ms)})?;
    let snapshot=f.store.node_resource_snapshot_with_private_services(&lifecycle,&query,&permit_signer,&f.service_signer,&node_signer,now()?)?;
    assert!(snapshot.allocations.is_empty());assert_eq!(snapshot.network_routes.len(),1);
    let resource=&snapshot.network_routes[0];
    assert!(resource.business_permit.is_empty());assert!(resource.relay_bundle_json.is_empty());
    verify_node_private_service_resource(resource,&node_signer.public_key(),now()?)?;
    assert!(nestlink_identity::network::verify_node_network_resource(resource,&permit_signer.public_key(),now()?).is_err());
    let allocation=resource.allocation.as_ref().ok_or("allocation missing")?;
    assert_eq!(allocation.bytes_per_allocation,private_service_wire_allowance(4096)?.min(f.store.relay_quota_current()?.limits.bytes_per_allocation));
    let page=f.store.private_service_host_access(&f.creator,&f.view.id,&access.runtime,ServiceQuery{security_epoch:f.store.security_epoch()?,after_id:None,limit:10},&f.service_signer,&node_signer,now()?)?;
    assert_eq!(page.grants.len(),1);assert_eq!(page.grants[0].network.grant_id,usage.grant_id);
    f.store.revoke_private_service(&f.creator,&f.view.id,&business.claims().acl_rule_id,access.exposure.revision,now()?)?;
    assert!(f.store.private_service_network_path(&f.creator,&f.view.id,&usage.grant_id,&f.service_signer,now()?).is_err());
    ledgers(&mut f,0,4096)?;
    let close=relay.sign_relay_close(&RelayCloseClaims{schema_version:SCHEMA_VERSION,deployment_id:deployment,security_epoch:node.security_epoch,node_id:relay_id,runtime_id:node.runtime_id,runtime_generation:node.runtime_generation,allocation_id:allocation.allocation_id.clone(),allocation_binding_sha256:allocation_binding(allocation)?.to_vec(),observed_grant_sequence:1,opened_connections:2,closed_connections:2,admitted_bytes:0,closed_at_unix_ms:now()?})?;
    let ack=f.store.accept_relay_close(&lifecycle,&close,now()?)?;
    assert_eq!(ack.released_endpoint_slots,2);
    assert_eq!(f.store.accept_relay_close(&lifecycle,&close,now()?)?,ack);
    let held:u64=f.store.connection.query_row("SELECT count(*) FROM all_relay_capacity WHERE promised_until>?1",[now()?],|r|r.get(0))?;
    assert_eq!(held,0);ledgers(&mut f,0,4096)?;
    Ok(())
}
