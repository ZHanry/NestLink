use super::*;
mod private_policy;
mod space_policy;
use nestlink_auth::{VaultKey, hash_password};
use nestlink_identity::{
    InstallationIdentity, digest,
    nodes::{NodeIdentity, NodePolicySigner},
    services::{approval_transcript, local_target_digest},
};
use nestlink_policy::{NetworkPolicy, PeerPathMode, PublicIngress, ServerForwarding};
use nestlink_protocol::{
    NODE_RESOURCE_TTL_MS, NodeLeaseClaims, SCHEMA_VERSION,
    service_plane::{
        SERVICE_USAGE_BYTES, ServiceQuotaLimitUpdate, ServiceQuotaScope, ServiceQuotaUsageQuery,
        ServiceUsageBudgetGrantClaims, ServiceUsageReportClaims, ServiceUsageRuntimeStopClaims,
        decode_service_message,
    },
};
use std::time::{SystemTime, UNIX_EPOCH};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
struct Fixture {
    store: Store,
    creator: Principal,
    approver: Principal,
    host: InstallationIdentity,
    host_id: String,
    edge: NodeIdentity,
    service_signer: ServiceLeaseSigner,
    node: NodeLeaseClaims,
    life: ServiceLifecycle,
    view: ServiceView,
}
impl Fixture {
    fn new() -> Result<Self> {
        Self::with_paths(PeerPathMode::DirectOnly)
    }
    fn with_paths(path_mode: PeerPathMode) -> Result<Self> {
        let mut store = Store::in_memory(&random_id())?;
        let password = "service-runtime-test-password";
        store.bootstrap_admin("service-admin", password)?;
        let vault = VaultKey::from_bytes([62; 32]);
        let dummy = hash_password("service-runtime-dummy-password")?;
        let creator = store
            .login(
                "service-admin",
                password,
                None,
                now()? / 1000,
                &vault,
                &dummy,
            )?
            .principal;
        let approver = store
            .login(
                "service-admin",
                password,
                None,
                now()? / 1000,
                &vault,
                &dummy,
            )?
            .principal;
        let host = InstallationIdentity::generate();
        let challenge = store.enrollment_challenge(&creator, now()? / 1000)?;
        let device = DeviceDescriptor {
            id: random_id(),
            name: "explicit service target".into(),
            platform: "windows".into(),
            public_key: URL_SAFE_NO_PAD.encode(host.public_key()),
            capabilities: vec!["host".into(), "vp8".into()],
            path_mode: if path_mode == PeerPathMode::DirectOnly {
                "direct_only"
            } else {
                "direct_preferred"
            }
            .into(),
        };
        let host_id = device.id.clone();
        let mut registration = DeviceRegistration {
            challenge_id: challenge.id,
            device,
            signature: String::new(),
        };
        registration.signature = URL_SAFE_NO_PAD.encode(host.sign_action(
            &store.registration_transcript(&creator, &registration, now()? / 1000)?,
        )?);
        store.register_device(&creator, registration, now()? / 1000)?;
        store.apply_policy(
            store.policy()?.0,
            NetworkPolicy {
                server_forwarding: ServerForwarding::Allow,
                peer_path_mode: path_mode,
                public_ingress: PublicIngress::Enabled,
            },
        )?;
        let edge = NodeIdentity::generate();
        let node_id = random_id();
        store.register_node(
            &creator,
            NodeRegistration {
                id: node_id.clone(),
                name: "tcp service edge".into(),
                public_key: URL_SAFE_NO_PAD.encode(edge.public_key()),
                roles: vec![NodeRole::NodeEdge as i32],
                max_connections: 16,
                bytes_per_second: 1_048_576,
            },
        )?;
        store.set_service_edge_namespace(
            &creator,
            &node_id,
            ServiceEdgeNamespaceUpdate {
                expected_revision: 0,
                config: ServiceEdgeNamespace {
                    service_suffix: "svc.example.test".into(),
                    management_hostname: "control.example.test".into(),
                    public_ports: vec![29100, 29101],
                    quic_address: "127.0.0.1:29199".into(),
                },
            },
            now()? / 1000,
        )?;
        let challenge = store.node_challenge(&node_id, now()?)?;
        let node = store.issue_node_lease(&edge.prove(&challenge, &random_id())?, now()?)?;
        let pending = store.create_service(
            &creator,
            ServiceCreate {
                id: random_id(),
                definition: ServiceDefinition {
                    name: "tcp explicit local target".into(),
                    host_device_id: host_id.clone(),
                    edge_node_id: node_id,
                    requested_ingress: ServiceIngress::Tcp { port: 29100 },
                    allowed_sources: vec![ServiceSourceNetwork {
                        address: "127.0.0.1".into(),
                        prefix: 32,
                    }],
                    limits: ServiceLimits {
                        maximum_connections: 8,
                        bytes_per_second: 65536,
                        maximum_bytes: 10485760,
                        idle_timeout_seconds: 5,
                    },
                },
            },
            now()? / 1000,
        )?;
        let view = approve(&mut store, &approver, &host, pending)?;
        let service_signer = ServiceLeaseSigner::from_master_seed(&[75; 32])?;
        let life = store.service_lifecycle(now()?)?;
        Ok(Self {
            store,
            creator,
            approver,
            host,
            host_id,
            edge,
            service_signer,
            node,
            life,
            view,
        })
    }
    fn publish(&mut self) -> Result<ServicePublicationIssue> {
        Ok(self.store.publish_service(
            &self.life,
            &self.creator,
            &self.view.id,
            self.view.revision,
            &self.service_signer,
            now()?,
        )?)
    }
    fn query(&self, sequence: u64) -> Result<SignedServiceResourceQuery> {
        let at = now()?;
        Ok(self.edge.sign_service_query(&NodeResourceQueryClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: self.node.deployment_id.clone(),
            security_epoch: self.node.security_epoch,
            node_id: self.node.node_id.clone(),
            runtime_id: self.node.runtime_id.clone(),
            runtime_generation: self.node.runtime_generation,
            policy_revision: self.node.policy_revision,
            lease_sequence: self.node.lease_sequence,
            request_id: random_id(),
            request_sequence: sequence,
            issued_at_unix_ms: at,
            expires_at_unix_ms: (at + SERVICE_RESOURCE_MS.min(NODE_RESOURCE_TTL_MS))
                .min(self.node.expires_at_unix_ms),
        })?)
    }
    fn second(&mut self, port: u16) -> Result<ServiceView> {
        let mut definition = self.view.definition.clone();
        definition.host_device_id = self.host_id.clone();
        definition.requested_ingress = ServiceIngress::Tcp { port };
        let pending = self.store.create_service(
            &self.creator,
            ServiceCreate {
                id: random_id(),
                definition,
            },
            now()? / 1000,
        )?;
        approve(&mut self.store, &self.approver, &self.host, pending)
    }
}
fn approve(
    store: &mut Store,
    actor: &Principal,
    host: &InstallationIdentity,
    pending: ServiceView,
) -> Result<ServiceView> {
    let challenge =
        store.service_approval_challenge(actor, &pending.id, pending.revision, now()? / 1000)?;
    let target_id = random_id();
    let choice = ServiceTargetChoice {
        expected_revision: pending.revision,
        target_sha256: URL_SAFE_NO_PAD.encode(local_target_digest(
            &pending,
            &target_id,
            "tcp",
            "127.0.0.1:8080".parse()?,
        )?),
        target_id,
        expires_at_unix_ms: challenge.issued_at_unix_ms + 60000,
    };
    let signature =
        URL_SAFE_NO_PAD.encode(host.sign_action(&approval_transcript(&challenge, &choice)?)?);
    Ok(store.approve_service_target(
        actor,
        &pending.id,
        ServiceTargetApproval {
            challenge_id: challenge.id,
            choice,
            signature,
        },
        now()? / 1000,
    )?)
}
#[test]
fn issuance_retains_choice_n_and_checks_both_independent_logins() -> Result {
    for revoke_creator in [true, false] {
        let mut f = Fixture::new()?;
        let issue = f.publish()?;
        assert_ne!(
            issue.claims.creator_login_id,
            issue.claims.approving_login_id
        );
        assert_eq!(
            issue.claims.choice_revision + 1,
            issue.claims.service_revision
        );
        let login = if revoke_creator {
            &f.creator.session_id
        } else {
            &f.approver.session_id
        };
        f.store.connection.execute(
            "UPDATE management_sessions SET revoked=1 WHERE id=?1",
            [login],
        )?;
        let still_live = if revoke_creator {
            &f.approver
        } else {
            &f.creator
        };
        let view = f.store.service(still_live, &f.view.id, now()? / 1000)?;
        assert_eq!(view.approval, ServiceApprovalState::Invalidated);
        assert_eq!(view.publication, ServicePublicationStatus::Stopping);
        let query = f.query(1)?;
        let signer = ServiceLeaseSigner::from_master_seed(&[75; 32])?;
        assert!(
            f.store
                .service_resource_snapshot(&f.life, &query, &signer, now()?, |_| Ok(()))?
                .leases
                .is_empty()
        );
        let state: u32 = f.store.connection.query_row(
            "SELECT state FROM service_publications WHERE id=?1",
            [&issue.claims.publication_id],
            |r| r.get(0),
        )?;
        assert_eq!(state, 1);
    }
    Ok(())
}
#[test]
fn stop_retains_the_original_promise_and_ingress_until_physical_expiry() -> Result {
    let mut f = Fixture::new()?;
    let issue = f.publish()?;
    assert_eq!(
        f.store
            .service(&f.creator, &f.view.id, now()? / 1000)?
            .publication,
        ServicePublicationStatus::Published
    );
    let held: u64 = f.store.connection.query_row(
        "SELECT promised_until FROM service_publications WHERE id=?1",
        [&issue.claims.publication_id],
        |r| r.get(0),
    )?;
    assert!(matches!(
        f.store.stop_service_publication(
            &f.creator,
            &f.view.id,
            f.view.revision - 1,
            now()? / 1000,
        ),
        Err(StorageError::Conflict)
    ));
    let expired_lease = f.store.service(
        &f.creator,
        &f.view.id,
        issue.claims.expires_at_unix_ms.div_ceil(1000),
    )?;
    assert_eq!(
        expired_lease.publication,
        ServicePublicationStatus::Stopping
    );
    f.store
        .stop_service_publication(&f.creator, &f.view.id, f.view.revision, now()? / 1000)?;
    // Repeating stop with the same definition revision is safe and does not
    // change the independent target approval or free its outstanding promise.
    f.store
        .stop_service_publication(&f.creator, &f.view.id, f.view.revision, now()? / 1000)?;
    let view = f.store.service(&f.creator, &f.view.id, now()? / 1000)?;
    assert_eq!(view.approval, ServiceApprovalState::ApprovedTarget);
    assert_eq!(view.revision, f.view.revision);
    assert_eq!(view.publication, ServicePublicationStatus::Stopping);
    let page = f.store.services(
        &f.creator,
        ServiceQuery {
            security_epoch: f.store.security_epoch()?,
            after_id: None,
            limit: 100,
        },
        now()? / 1000,
    )?;
    assert_eq!(
        page.services[0].publication,
        ServicePublicationStatus::Stopping
    );
    let (state, still_held): (u32, u64) = f.store.connection.query_row(
        "SELECT state,promised_until FROM service_publications WHERE id=?1",
        [&issue.claims.publication_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!(state, 1);
    assert_eq!(held, still_held);
    assert!(held > now()?);
    assert_eq!(
        f.store
            .service(&f.creator, &f.view.id, held.div_ceil(1000))?
            .publication,
        ServicePublicationStatus::NotPublished
    );
    assert!(matches!(
        f.store.publish_service(
            &f.life,
            &f.creator,
            &f.view.id,
            f.view.revision,
            &f.service_signer,
            now()?
        ),
        Err(StorageError::RateLimited)
    ));
    Ok(())
}
#[test]
fn definition_changes_and_revocation_drain_an_existing_publication() -> Result {
    let mut f = Fixture::new()?;
    let issue = f.publish()?;
    let mut definition = f.view.definition.clone();
    definition.name = "changed after publication".into();
    let changed = f.store.update_service(
        &f.creator,
        &f.view.id,
        ServiceUpdate {
            expected_revision: f.view.revision,
            definition,
        },
        now()? / 1000,
    )?;
    assert_eq!(changed.approval, ServiceApprovalState::Invalidated);
    assert_eq!(changed.publication, ServicePublicationStatus::Stopping);
    let (state, promised): (u32, u64) = f.store.connection.query_row(
        "SELECT state,promised_until FROM service_publications WHERE id=?1",
        [&issue.claims.publication_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!(state, 1);
    assert_eq!(promised, issue.claims.expires_at_unix_ms + HOLD_MARGIN_MS);
    let revoked =
        f.store
            .revoke_service(&f.creator, &f.view.id, changed.revision, now()? / 1000)?;
    assert_eq!(revoked.approval, ServiceApprovalState::Revoked);
    assert_eq!(revoked.publication, ServicePublicationStatus::Stopping);
    Ok(())
}
#[test]
fn stopping_a_publication_is_account_scoped_and_audit_atomic() -> Result {
    let mut f = Fixture::new()?;
    f.publish()?;
    f.store
        .create_member(&f.creator, "unrelated", "unrelated-service-password")?;
    let other = f
        .store
        .login(
            "unrelated",
            "unrelated-service-password",
            None,
            now()? / 1000,
            &VaultKey::from_bytes([64; 32]),
            &hash_password("unrelated-service-dummy")?,
        )?
        .principal;
    assert!(matches!(
        f.store
            .stop_service_publication(&other, &f.view.id, f.view.revision, now()? / 1000),
        Err(StorageError::Forbidden)
    ));
    f.store.connection.execute_batch(
        "CREATE TEMP TRIGGER stop_audit_failure BEFORE INSERT ON audit WHEN NEW.event='service_publication_stopped' BEGIN SELECT RAISE(FAIL,'test stop audit failure'); END;",
    )?;
    assert!(
        f.store
            .stop_service_publication(&f.creator, &f.view.id, f.view.revision, now()? / 1000)
            .is_err()
    );
    assert_eq!(
        f.store
            .service(&f.creator, &f.view.id, now()? / 1000)?
            .publication,
        ServicePublicationStatus::Published
    );
    Ok(())
}
#[test]
fn duplicate_ingress_and_node_capacity_cannot_be_bypassed_with_new_publication_ids() -> Result {
    let mut f = Fixture::new()?;
    f.publish()?;
    let collision = f.second(29100)?;
    assert!(
        f.store
            .publish_service(
                &f.life,
                &f.creator,
                &collision.id,
                collision.revision,
                &f.service_signer,
                now()?
            )
            .is_err()
    );
    let second = f.second(29101)?;
    f.store.publish_service(
        &f.life,
        &f.creator,
        &second.id,
        second.revision,
        &f.service_signer,
        now()?,
    )?;
    let third = f.second(29101)?;
    assert!(matches!(
        f.store.publish_service(
            &f.life,
            &f.creator,
            &third.id,
            third.revision,
            &f.service_signer,
            now()?
        ),
        Err(StorageError::RateLimited)
    ));
    Ok(())
}
#[test]
fn exact_service_query_is_consumed_and_namespace_change_omits_old_binding() -> Result {
    let mut f = Fixture::new()?;
    f.publish()?;
    let signer = ServiceLeaseSigner::from_master_seed(&[75; 32])?;
    let query = f.query(1)?;
    assert_eq!(
        f.store
            .service_resource_snapshot(&f.life, &query, &signer, now()?, |_| Ok(()))?
            .leases
            .len(),
        1
    );
    assert!(matches!(
        f.store
            .service_resource_snapshot(&f.life, &query, &signer, now()?, |_| Ok(())),
        Err(StorageError::Conflict)
    ));
    let view = f
        .store
        .service_edge_namespace(&f.creator, &f.node.node_id, now()? / 1000)?;
    f.store.set_service_edge_namespace(
        &f.creator,
        &f.node.node_id,
        ServiceEdgeNamespaceUpdate {
            expected_revision: view.revision,
            config: view.config,
        },
        now()? / 1000,
    )?;
    let query = f.query(2)?;
    assert!(
        f.store
            .service_resource_snapshot(&f.life, &query, &signer, now()?, |_| Ok(()))?
            .leases
            .is_empty()
    );
    Ok(())
}
#[test]
fn restart_and_restore_fence_prevent_early_reuse_even_with_a_future_snapshot_clock() -> Result {
    let mut f = Fixture::new()?;
    let issue = f.publish()?;
    let at = now()?;
    f.store.connection.execute(
        "UPDATE service_publications SET promised_until=?1 WHERE id=?2",
        params![at + 3600000, issue.claims.publication_id],
    )?;
    let mut restarted = f.store.service_lifecycle(at)?;
    assert!(matches!(
        f.store.publish_service(
            &restarted,
            &f.creator,
            &f.view.id,
            f.view.revision,
            &f.service_signer,
            at
        ),
        Err(StorageError::RateLimited)
    ));
    // Simulate only the passage of the required monotonic fence, without a
    // slow wall-clock sleep or trusting a restored promised_until timestamp.
    let elapsed = SERVICE_LEASE_MS + HOLD_MARGIN_MS + 50;
    restarted.started -= Duration::from_millis(elapsed);
    restarted.wall -= elapsed;
    restarted.clock = Mutex::new((restarted.wall, false));
    // Physical expiry frees ingress, but cannot refund an unreported grant.
    assert!(matches!(
        f.store.publish_service(
            &restarted,
            &f.creator,
            &f.view.id,
            f.view.revision,
            &f.service_signer,
            now()?,
        ),
        Err(StorageError::RateLimited)
    ));
    let query = ServiceQuotaUsageQuery {
        scope: ServiceQuotaScope::Resource,
        scope_key: f.view.id.clone(),
    };
    let retained = f
        .store
        .service_quota_usage(&f.creator, query.clone(), now()?)?;
    assert_eq!(retained.spent_bytes, 0);
    assert_eq!(
        retained.outstanding_bytes,
        f.view.definition.limits.maximum_bytes
    );
    assert_eq!(retained.active_grants, 1);
    // A deliberate admin limit increase supplies new capacity; it does not
    // rewrite the original lifetime debt or fabricate a terminal node seal.
    f.store.set_service_quota_limit(
        &f.creator,
        ServiceQuotaLimitUpdate {
            scope: query.scope,
            scope_key: query.scope_key.clone(),
            expected_revision: retained.limit_revision,
            limit_bytes: retained
                .limit_bytes
                .checked_mul(2)
                .ok_or("quota overflow")?,
        },
        now()?,
    )?;
    let recovered = f.store.publish_service(
        &restarted,
        &f.creator,
        &f.view.id,
        f.view.revision,
        &f.service_signer,
        now()?,
    )?;
    assert_ne!(recovered.claims.publication_id, issue.claims.publication_id);
    assert!(recovered.claims.publication_generation > issue.claims.publication_generation);
    Ok(())
}

#[test]
fn signed_query_sequence_survives_control_restart_without_active_publications() -> Result {
    let mut f = Fixture::new()?;
    let signer = ServiceLeaseSigner::from_master_seed(&[75; 32])?;
    let query = f.query(1)?;
    assert!(
        f.store
            .service_resource_snapshot(&f.life, &query, &signer, now()?, |_| Ok(()))?
            .leases
            .is_empty()
    );
    let restarted = f.store.service_lifecycle(now()?)?;
    assert!(!restarted.fenced);
    assert_ne!(restarted.runtime_id, f.life.runtime_id);
    assert!(matches!(
        f.store
            .service_resource_snapshot(&restarted, &query, &signer, now()?, |_| Ok(())),
        Err(StorageError::Conflict)
    ));
    let fresh = f.query(2)?;
    assert!(
        f.store
            .service_resource_snapshot(&restarted, &fresh, &signer, now()?, |_| Ok(()))?
            .leases
            .is_empty()
    );
    Ok(())
}

#[test]
fn first_quota_limit_update_uses_the_revision_returned_by_an_empty_scope_read() -> Result {
    let mut f = Fixture::new()?;
    let scope = ServiceQuotaScope::Account;
    let scope_key = f.creator.account_id.clone();
    let before = f.store.service_quota_usage(
        &f.creator,
        ServiceQuotaUsageQuery {
            scope,
            scope_key: scope_key.clone(),
        },
        now()?,
    )?;
    assert_eq!(before.limit_revision, 0);
    assert!(!before.reconciliation_required);
    assert_eq!(before.limit_bytes, 4 * 1024 * 1024 * 1024 * 1024);

    let after = f.store.set_service_quota_limit(
        &f.creator,
        ServiceQuotaLimitUpdate {
            scope,
            scope_key,
            expected_revision: before.limit_revision,
            limit_bytes: 4096,
        },
        now()?,
    )?;
    assert_eq!(after.limit_revision, 1);
    assert_eq!(after.limit_bytes, 4096);
    Ok(())
}

#[test]
fn restoring_a_pre_usage_snapshot_keeps_quota_grants_fenced_after_service_recovery() -> Result {
    let mut f = Fixture::new()?;
    // This authentic snapshot predates both grant creation and all later
    // acknowledged usage, reproducing the rollback window an epoch rotation
    // alone cannot account for.
    let old_snapshot = f.store.snapshot()?;
    let issue = f.publish()?;
    let grant: ServiceUsageBudgetGrantClaims =
        decode_service_message(&issue.claims.usage_grant.claims, SERVICE_USAGE_BYTES)?;
    let grant_sha256 = digest(&issue.claims.usage_grant.claims);
    let ack_signer = NodePolicySigner::from_master_seed(&[91; 32])?;
    let report = f.edge.sign_service_usage(&ServiceUsageReportClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: grant.deployment_id.clone(),
        security_epoch: grant.security_epoch,
        policy_revision: grant.policy_revision,
        node_id: grant.edge_node_id.clone(),
        node_runtime_id: grant.edge_runtime_id.clone(),
        node_runtime_generation: grant.edge_runtime_generation,
        grant_id: grant.grant_id.clone(),
        grant_sha256,
        publication_id: grant.publication_id.clone(),
        publication_generation: grant.publication_generation,
        account_id: grant.account_id.clone(),
        host_device_id: grant.host_device_id.clone(),
        service_id: grant.service_id.clone(),
        report_sequence: 1,
        admitted_bytes: 4096,
        opened_connections: 0,
        closed_connections: 0,
        sampled_at_unix_ms: now()?,
    })?;
    f.store
        .accept_service_usage_report(&report, &ack_signer, now()?)?;
    let spent_stop = f
        .edge
        .sign_service_usage_stop(&ServiceUsageRuntimeStopClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: grant.deployment_id.clone(),
            security_epoch: grant.security_epoch,
            policy_revision: grant.policy_revision,
            node_id: grant.edge_node_id.clone(),
            node_runtime_id: grant.edge_runtime_id.clone(),
            node_runtime_generation: grant.edge_runtime_generation,
            grant_id: grant.grant_id.clone(),
            grant_sha256,
            publication_id: grant.publication_id.clone(),
            publication_generation: grant.publication_generation,
            final_report_sequence: 1,
            final_report_sha256: digest(&report.claims),
            admitted_bytes: 4096,
            opened_connections: 0,
            closed_connections: 0,
            stop_nonce: [0xB1; 32],
            stopped_at_unix_ms: now()?,
        })?;
    f.store.accept_service_usage_stop(&spent_stop, now()?)?;
    for (scope, scope_key) in [
        (ServiceQuotaScope::Account, grant.account_id.clone()),
        (ServiceQuotaScope::Device, grant.host_device_id.clone()),
        (ServiceQuotaScope::Node, grant.edge_node_id.clone()),
        (ServiceQuotaScope::Resource, grant.service_id.clone()),
    ] {
        assert_eq!(
            f.store
                .service_quota_usage(
                    &f.creator,
                    ServiceQuotaUsageQuery { scope, scope_key },
                    now()?,
                )?
                .spent_bytes,
            4096
        );
    }

    let mut restored = Store::from_snapshot(&old_snapshot, &grant.deployment_id)?;
    restored.invalidate_after_restore()?;
    let vault = VaultKey::from_bytes([62; 32]);
    let dummy = hash_password("service-runtime-dummy-password")?;
    let restored_creator = restored
        .login(
            "service-admin",
            "service-runtime-test-password",
            None,
            now()? / 1000,
            &vault,
            &dummy,
        )?
        .principal;
    let restored_approver = restored
        .login(
            "service-admin",
            "service-runtime-test-password",
            None,
            now()? / 1000,
            &vault,
            &dummy,
        )?
        .principal;
    for (scope, scope_key) in [
        (
            ServiceQuotaScope::Account,
            restored_creator.account_id.clone(),
        ),
        (ServiceQuotaScope::Device, f.host_id.clone()),
        (ServiceQuotaScope::Node, grant.edge_node_id.clone()),
        (ServiceQuotaScope::Resource, f.view.id.clone()),
    ] {
        assert_eq!(
            restored
                .service_quota_usage(
                    &restored_creator,
                    ServiceQuotaUsageQuery { scope, scope_key },
                    now()?,
                )?
                .spent_bytes,
            0
        );
    }
    let readable_fence = restored.service_quota_restore_fenced(&restored_creator, now()?)?;
    assert!(readable_fence);
    let updated_quota = restored.set_service_quota_limit(
        &restored_creator,
        ServiceQuotaLimitUpdate {
            scope: ServiceQuotaScope::Account,
            scope_key: restored_creator.account_id.clone(),
            expected_revision: 0,
            limit_bytes: 1024,
        },
        now()?,
    )?;
    assert!(updated_quota.reconciliation_required);
    assert!(restored.service_quota_restore_fenced(&restored_creator, now()?)?);
    let pending = restored.update_service(
        &restored_creator,
        &f.view.id,
        ServiceUpdate {
            expected_revision: f.view.revision,
            definition: f.view.definition.clone(),
        },
        now()? / 1000,
    )?;
    let approved = approve(&mut restored, &restored_approver, &f.host, pending)?;
    let challenge = restored.node_challenge(&grant.edge_node_id, now()?)?;
    restored.issue_node_lease(&f.edge.prove(&challenge, &random_id())?, now()?)?;

    let fence_started = now()?;
    let mut restored_lifecycle = restored.service_lifecycle(fence_started)?;
    let elapsed = SERVICE_LEASE_MS + HOLD_MARGIN_MS + 50;
    restored_lifecycle.started -= Duration::from_millis(elapsed);
    restored_lifecycle.wall -= elapsed;
    restored_lifecycle.clock = Mutex::new((restored_lifecycle.wall, false));
    let publish_at = now()?;
    assert!(matches!(
        restored.publish_service(
            &restored_lifecycle,
            &restored_creator,
            &approved.id,
            approved.revision,
            &f.service_signer,
            publish_at,
        ),
        Err(StorageError::RateLimited)
    ));
    assert!(restored.service_quota_restore_fenced(&restored_creator, now()?)?);
    use nestlink_identity::service_quota_recovery::{
        ExternalServiceQuotaSigner, verify_service_quota_reconciliation,
    };
    use nestlink_protocol::service_quota_recovery::ServiceQuotaRecoveredTotal;
    // The independent live fixture acknowledged and sealed 4096 bytes after
    // this old snapshot. Its external ledger supplies those missing totals.
    let request = restored.service_quota_recovery_request()?;
    let totals = [
        (ServiceQuotaScope::Account, grant.account_id.clone()),
        (ServiceQuotaScope::Device, grant.host_device_id.clone()),
        (ServiceQuotaScope::Node, grant.edge_node_id.clone()),
        (ServiceQuotaScope::Resource, grant.service_id.clone()),
    ]
    .into_iter()
    .map(|(scope, scope_key)| ServiceQuotaRecoveredTotal {
        scope,
        scope_key,
        charged_bytes: 4096,
    })
    .collect();
    let external = ExternalServiceQuotaSigner::from_external_seed(&[0x9c; 32]);
    let signed = external.sign(&external_recovery_claims(&request, totals)?)?;
    let proof =
        verify_service_quota_reconciliation(&signed, &external.public_key(), &request, now()?)?;
    restored.reconcile_service_quota_after_restore(&proof, now()?)?;
    assert!(!restored.service_quota_restore_fenced(&restored_creator, now()?)?);
    // Reconciliation must not silently increase the deliberately low 1024
    // account limit above. A separate explicit quota edit is still required.
    assert!(
        restored
            .publish_service(
                &restored_lifecycle,
                &restored_creator,
                &approved.id,
                approved.revision,
                &f.service_signer,
                now()?
            )
            .is_err()
    );
    let account = restored.service_quota_usage(
        &restored_creator,
        ServiceQuotaUsageQuery {
            scope: ServiceQuotaScope::Account,
            scope_key: grant.account_id.clone(),
        },
        now()?,
    )?;
    assert_eq!(account.spent_bytes, 4096);
    assert_eq!(account.limit_bytes, 1024);
    restored.set_service_quota_limit(
        &restored_creator,
        ServiceQuotaLimitUpdate {
            scope: account.scope,
            scope_key: account.scope_key,
            expected_revision: account.limit_revision,
            limit_bytes: f.view.definition.limits.maximum_bytes * 2,
        },
        now()?,
    )?;
    let republished = restored.publish_service(
        &restored_lifecycle,
        &restored_creator,
        &approved.id,
        approved.revision,
        &f.service_signer,
        now()?,
    )?;
    let next_grant: ServiceUsageBudgetGrantClaims =
        decode_service_message(&republished.claims.usage_grant.claims, SERVICE_USAGE_BYTES)?;
    assert_eq!(
        next_grant.byte_ceiling,
        f.view.definition.limits.maximum_bytes - 4096
    );
    assert_ne!(next_grant.grant_id, grant.grant_id);
    assert!(
        restored
            .accept_service_usage_report(&report, &ack_signer, now()?)
            .is_err()
    );
    Ok(())
}

#[test]
fn resource_budget_is_after_authentication_and_before_renewal_or_snapshot_construction() -> Result {
    use std::cell::Cell;
    let mut f = Fixture::new()?;
    let issue = f.publish()?;
    let signer = ServiceLeaseSigner::from_master_seed(&[75; 32])?;
    let charged = Cell::new(0);
    let charge = |node: &str| {
        assert_eq!(node, f.node.node_id);
        if charged.get() >= 2 {
            return Err(StorageError::RateLimited);
        }
        charged.set(charged.get() + 1);
        Ok(())
    };
    let first = f.query(1)?;
    assert_eq!(
        f.store
            .service_resource_snapshot(&f.life, &first, &signer, now()?, charge)?
            .leases
            .len(),
        1
    );
    let mut forged = f.query(2)?;
    forged.signature[0] ^= 1;
    assert!(
        f.store
            .service_resource_snapshot(&f.life, &forged, &signer, now()?, charge)
            .is_err()
    );
    assert_eq!(charged.get(), 1);
    assert!(matches!(
        f.store
            .service_resource_snapshot(&f.life, &first, &signer, now()?, charge),
        Err(StorageError::Conflict)
    ));
    assert_eq!(charged.get(), 1);
    let second = f.query(2)?;
    f.store
        .service_resource_snapshot(&f.life, &second, &signer, now()?, charge)?;
    let (json, promised): (String, u64) = f.store.connection.query_row(
        "SELECT claims_json,promised_until FROM service_publications WHERE id=?1",
        [&issue.claims.publication_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    // A sentinel makes construction observable: parsing this row would return
    // a JSON error. The exhausted budget must return RateLimited before it.
    let poison = serde_json::to_string("unparseable snapshot sentinel")?;
    f.store.connection.execute(
        "UPDATE service_publications SET claims_json=?1 WHERE id=?2",
        params![poison, issue.claims.publication_id],
    )?;
    let third = f.query(3)?;
    assert!(matches!(
        f.store
            .service_resource_snapshot(&f.life, &third, &signer, now()?, charge),
        Err(StorageError::RateLimited)
    ));
    let (still_json, still_promised): (String, u64) = f.store.connection.query_row(
        "SELECT claims_json,promised_until FROM service_publications WHERE id=?1",
        [&issue.claims.publication_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!(still_json, poison);
    assert_eq!(still_promised, promised);
    let sequence: u64 = f.store.connection.query_row(
        "SELECT request_sequence FROM service_node_polls WHERE node_id=?1",
        [&f.node.node_id],
        |r| r.get(0),
    )?;
    assert_eq!(sequence, 2);
    f.store.connection.execute(
        "UPDATE service_publications SET claims_json=?1 WHERE id=?2",
        params![json, issue.claims.publication_id],
    )?;
    assert_eq!(
        f.store
            .service_resource_snapshot(&f.life, &third, &signer, now()?, |_| Ok(()))?
            .leases
            .len(),
        1
    );
    Ok(())
}

#[test]
fn stop_requires_report_ack_for_exact_final_highwater() -> Result {
    let mut f = Fixture::new()?;
    let issue = f.publish()?;
    let grant: ServiceUsageBudgetGrantClaims =
        decode_service_message(&issue.claims.usage_grant.claims, SERVICE_USAGE_BYTES)?;
    let grant_sha256 = digest(&issue.claims.usage_grant.claims);
    let ack_signer = NodePolicySigner::from_master_seed(&[91; 32])?;

    let first_report = f.edge.sign_service_usage(&ServiceUsageReportClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: grant.deployment_id.clone(),
        security_epoch: grant.security_epoch,
        policy_revision: grant.policy_revision,
        node_id: grant.edge_node_id.clone(),
        node_runtime_id: grant.edge_runtime_id.clone(),
        node_runtime_generation: grant.edge_runtime_generation,
        grant_id: grant.grant_id.clone(),
        grant_sha256,
        publication_id: grant.publication_id.clone(),
        publication_generation: grant.publication_generation,
        account_id: grant.account_id.clone(),
        host_device_id: grant.host_device_id.clone(),
        service_id: grant.service_id.clone(),
        report_sequence: 1,
        admitted_bytes: 0,
        opened_connections: 0,
        closed_connections: 0,
        sampled_at_unix_ms: now()?,
    })?;
    f.store
        .accept_service_usage_report(&first_report, &ack_signer, now()?)?;

    let unreported_stop = f
        .edge
        .sign_service_usage_stop(&ServiceUsageRuntimeStopClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: grant.deployment_id.clone(),
            security_epoch: grant.security_epoch,
            policy_revision: grant.policy_revision,
            node_id: grant.edge_node_id.clone(),
            node_runtime_id: grant.edge_runtime_id.clone(),
            node_runtime_generation: grant.edge_runtime_generation,
            grant_id: grant.grant_id.clone(),
            grant_sha256,
            publication_id: grant.publication_id.clone(),
            publication_generation: grant.publication_generation,
            final_report_sequence: 1,
            final_report_sha256: digest(&first_report.claims),
            admitted_bytes: 1,
            opened_connections: 0,
            closed_connections: 0,
            stop_nonce: [0xA1; 32],
            stopped_at_unix_ms: now()?,
        })?;
    assert!(matches!(
        f.store.accept_service_usage_stop(&unreported_stop, now()?),
        Err(StorageError::Conflict)
    ));
    let still_held = f.store.service_quota_usage(
        &f.creator,
        ServiceQuotaUsageQuery {
            scope: ServiceQuotaScope::Account,
            scope_key: grant.account_id.clone(),
        },
        now()?,
    )?;
    assert_eq!(still_held.spent_bytes, 0);
    assert_eq!(still_held.outstanding_bytes, grant.byte_ceiling);
    assert_eq!(still_held.active_grants, 1);

    let final_report = f.edge.sign_service_usage(&ServiceUsageReportClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: grant.deployment_id.clone(),
        security_epoch: grant.security_epoch,
        policy_revision: grant.policy_revision,
        node_id: grant.edge_node_id.clone(),
        node_runtime_id: grant.edge_runtime_id.clone(),
        node_runtime_generation: grant.edge_runtime_generation,
        grant_id: grant.grant_id.clone(),
        grant_sha256,
        publication_id: grant.publication_id.clone(),
        publication_generation: grant.publication_generation,
        account_id: grant.account_id.clone(),
        host_device_id: grant.host_device_id.clone(),
        service_id: grant.service_id.clone(),
        report_sequence: 2,
        admitted_bytes: 1,
        opened_connections: 0,
        closed_connections: 0,
        sampled_at_unix_ms: now()?,
    })?;
    f.store
        .accept_service_usage_report(&final_report, &ack_signer, now()?)?;
    let stop = f
        .edge
        .sign_service_usage_stop(&ServiceUsageRuntimeStopClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: grant.deployment_id.clone(),
            security_epoch: grant.security_epoch,
            policy_revision: grant.policy_revision,
            node_id: grant.edge_node_id.clone(),
            node_runtime_id: grant.edge_runtime_id.clone(),
            node_runtime_generation: grant.edge_runtime_generation,
            grant_id: grant.grant_id.clone(),
            grant_sha256,
            publication_id: grant.publication_id.clone(),
            publication_generation: grant.publication_generation,
            final_report_sequence: 2,
            final_report_sha256: digest(&final_report.claims),
            admitted_bytes: 1,
            opened_connections: 0,
            closed_connections: 0,
            stop_nonce: [0xA2; 32],
            stopped_at_unix_ms: now()?,
        })?;
    f.store.accept_service_usage_stop(&stop, now()?)?;
    f.store.accept_service_usage_stop(&stop, now()?)?;
    let released = f.store.service_quota_usage(
        &f.creator,
        ServiceQuotaUsageQuery {
            scope: ServiceQuotaScope::Account,
            scope_key: grant.account_id,
        },
        now()?,
    )?;
    assert_eq!(released.spent_bytes, 1);
    assert_eq!(released.outstanding_bytes, 0);
    assert_eq!(released.active_grants, 0);
    Ok(())
}

#[test]
fn usage_reports_preserve_all_scope_totals_across_retries_and_rejections() -> Result {
    let mut f = Fixture::new()?;
    let issue = f.publish()?;
    let grant: ServiceUsageBudgetGrantClaims =
        decode_service_message(&issue.claims.usage_grant.claims, SERVICE_USAGE_BYTES)?;
    let grant_sha256 = digest(&issue.claims.usage_grant.claims);
    let ack_signer = NodePolicySigner::from_master_seed(&[91; 32])?;
    let report_for = |report_sequence,
                      admitted_bytes,
                      service_id: String|
     -> Result<nestlink_protocol::service_plane::SignedServiceUsageReport> {
        Ok(f.edge.sign_service_usage(&ServiceUsageReportClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: grant.deployment_id.clone(),
            security_epoch: grant.security_epoch,
            policy_revision: grant.policy_revision,
            node_id: grant.edge_node_id.clone(),
            node_runtime_id: grant.edge_runtime_id.clone(),
            node_runtime_generation: grant.edge_runtime_generation,
            grant_id: grant.grant_id.clone(),
            grant_sha256,
            publication_id: grant.publication_id.clone(),
            publication_generation: grant.publication_generation,
            account_id: grant.account_id.clone(),
            host_device_id: grant.host_device_id.clone(),
            service_id,
            report_sequence,
            admitted_bytes,
            opened_connections: 0,
            closed_connections: 0,
            sampled_at_unix_ms: now()?,
        })?)
    };
    let correct_scope = grant.service_id.clone();
    let first = report_for(1, 1024, correct_scope.clone())?;
    let first_ack = f
        .store
        .accept_service_usage_report(&first, &ack_signer, now()?)?;
    let replay_ack = f
        .store
        .accept_service_usage_report(&first, &ack_signer, now()?)?;
    assert_eq!(replay_ack.claims, first_ack.claims);
    assert_eq!(replay_ack.signature, first_ack.signature);

    let bad_scope = report_for(2, 2048, random_id())?;
    assert!(matches!(
        f.store
            .accept_service_usage_report(&bad_scope, &ack_signer, now()?),
        Err(StorageError::Unauthorized)
    ));
    let out_of_order = report_for(3, 2048, correct_scope.clone())?;
    assert!(matches!(
        f.store
            .accept_service_usage_report(&out_of_order, &ack_signer, now()?),
        Err(StorageError::Conflict)
    ));
    let low_watermark = report_for(2, 1023, correct_scope.clone())?;
    assert!(matches!(
        f.store
            .accept_service_usage_report(&low_watermark, &ack_signer, now()?),
        Err(StorageError::Conflict)
    ));

    let final_report = report_for(2, 2048, correct_scope)?;
    f.store
        .accept_service_usage_report(&final_report, &ack_signer, now()?)?;
    let scopes = [
        (ServiceQuotaScope::Account, grant.account_id.clone()),
        (ServiceQuotaScope::Device, grant.host_device_id.clone()),
        (ServiceQuotaScope::Node, grant.edge_node_id.clone()),
        (ServiceQuotaScope::Resource, grant.service_id.clone()),
    ];
    for (scope, scope_key) in &scopes {
        let usage = f.store.service_quota_usage(
            &f.creator,
            ServiceQuotaUsageQuery {
                scope: *scope,
                scope_key: scope_key.clone(),
            },
            now()?,
        )?;
        assert_eq!(usage.spent_bytes, 2048);
        assert_eq!(usage.outstanding_bytes, grant.byte_ceiling - 2048);
        assert_eq!(
            usage.spent_bytes + usage.outstanding_bytes,
            grant.byte_ceiling
        );
        assert_eq!(usage.active_grants, 1);
    }

    let stop = f
        .edge
        .sign_service_usage_stop(&ServiceUsageRuntimeStopClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: grant.deployment_id.clone(),
            security_epoch: grant.security_epoch,
            policy_revision: grant.policy_revision,
            node_id: grant.edge_node_id.clone(),
            node_runtime_id: grant.edge_runtime_id.clone(),
            node_runtime_generation: grant.edge_runtime_generation,
            grant_id: grant.grant_id.clone(),
            grant_sha256,
            publication_id: grant.publication_id.clone(),
            publication_generation: grant.publication_generation,
            final_report_sequence: 2,
            final_report_sha256: digest(&final_report.claims),
            admitted_bytes: 2048,
            opened_connections: 0,
            closed_connections: 0,
            stop_nonce: [0xB2; 32],
            stopped_at_unix_ms: now()?,
        })?;
    f.store.accept_service_usage_stop(&stop, now()?)?;
    for (scope, scope_key) in scopes {
        let usage = f.store.service_quota_usage(
            &f.creator,
            ServiceQuotaUsageQuery { scope, scope_key },
            now()?,
        )?;
        assert_eq!(usage.spent_bytes, 2048);
        assert_eq!(usage.outstanding_bytes, 0);
        assert_eq!(usage.active_grants, 0);
    }
    Ok(())
}

fn external_recovery_claims(
    request: &nestlink_protocol::service_quota_recovery::ServiceQuotaRecoveryRequest,
    totals: Vec<nestlink_protocol::service_quota_recovery::ServiceQuotaRecoveredTotal>,
) -> Result<nestlink_protocol::service_quota_recovery::ServiceQuotaReconciliationClaims> {
    use nestlink_identity::service_quota_recovery::service_quota_recovery_request_digest;
    let at = now()?;
    Ok(
        nestlink_protocol::service_quota_recovery::ServiceQuotaReconciliationClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: request.deployment_id.clone(),
            restored_security_epoch: request.restored_security_epoch,
            policy_revision: request.policy_revision,
            quota_revision: request.quota_revision,
            request_sha256: service_quota_recovery_request_digest(request)?,
            ledger_id: random_id(),
            checkpoint_id: random_id(),
            checkpoint_sha256: [0x7c; 32],
            all_prior_grants_accounted: true,
            prior_authority_stopped_at_unix_ms: at - 12000,
            issued_at_unix_ms: at,
            expires_at_unix_ms: at + 60000,
            totals,
        },
    )
}

#[test]
fn external_reconciliation_preserves_unknown_debt_and_is_atomic_and_single_restore() -> Result {
    use nestlink_identity::service_quota_recovery::{
        ExternalServiceQuotaSigner, verify_service_quota_reconciliation,
    };
    use nestlink_protocol::service_quota_recovery::ServiceQuotaRecoveredTotal;
    let mut f = Fixture::new()?;
    let original = f.publish()?;
    let deployment = f.node.deployment_id.clone();
    let snapshot = f.store.snapshot()?;
    let mut restored = Store::from_snapshot(&snapshot, &deployment)?;
    restored.invalidate_after_restore()?;
    let request = restored.service_quota_recovery_request()?;
    assert_eq!(request.floors.len(), 4);
    let mut totals = request
        .floors
        .iter()
        .map(|floor| ServiceQuotaRecoveredTotal {
            scope: floor.scope,
            scope_key: floor.scope_key.clone(),
            charged_bytes: floor.spent_bytes + floor.outstanding_bytes + 4096,
        })
        .collect::<Vec<_>>();
    // Four IDs that did not exist in the snapshot still carry permanent debt.
    let missing_id = random_id();
    for scope in [
        ServiceQuotaScope::Account,
        ServiceQuotaScope::Device,
        ServiceQuotaScope::Node,
        ServiceQuotaScope::Resource,
    ] {
        totals.push(ServiceQuotaRecoveredTotal {
            scope,
            scope_key: missing_id.clone(),
            charged_bytes: 2048,
        });
    }
    totals.sort_by(|a, b| (a.scope.as_str(), &a.scope_key).cmp(&(b.scope.as_str(), &b.scope_key)));
    let claims = external_recovery_claims(&request, totals)?;
    let external = ExternalServiceQuotaSigner::from_external_seed(&[0x9d; 32]);
    let signed = external.sign(&claims)?;
    let proof =
        verify_service_quota_reconciliation(&signed, &external.public_key(), &request, now()?)?;
    // Even a verified proof is not allowed to reduce one known outstanding
    // promise, or omit all known dimensions while submitting other valid IDs.
    let mut smaller = claims.clone();
    for total in &mut smaller.totals {
        if total.scope_key != missing_id {
            total.charged_bytes = 1;
        }
    }
    let smaller = verify_service_quota_reconciliation(
        &external.sign(&smaller)?,
        &external.public_key(),
        &request,
        now()?,
    )?;
    assert!(
        restored
            .reconcile_service_quota_after_restore(&smaller, now()?)
            .is_err()
    );
    let mut omitted = claims.clone();
    omitted.totals.retain(|total| total.scope_key == missing_id);
    let omitted = verify_service_quota_reconciliation(
        &external.sign(&omitted)?,
        &external.public_key(),
        &request,
        now()?,
    )?;
    assert!(
        restored
            .reconcile_service_quota_after_restore(&omitted, now()?)
            .is_err()
    );
    assert_eq!(restored.service_quota_recovery_request()?, request);
    // A failure at the last write must roll back every imported ledger and ID.
    restored.connection.execute_batch("CREATE TEMP TRIGGER deny_quota_recovery BEFORE UPDATE ON service_quota_settings BEGIN SELECT RAISE(ABORT,'injected commit failure'); END;")?;
    assert!(
        restored
            .reconcile_service_quota_after_restore(&proof, now()?)
            .is_err()
    );
    assert_eq!(restored.service_quota_recovery_request()?, request);
    restored
        .connection
        .execute_batch("DROP TRIGGER deny_quota_recovery;")?;
    restored.reconcile_service_quota_after_restore(&proof, now()?)?;
    assert!(
        restored
            .reconcile_service_quota_after_restore(&proof, now()?)
            .is_err()
    );
    assert!(restored.service_quota_recovery_request().is_err());
    for floor in &request.floors {
        let spent: u64 = restored.connection.query_row(
            "SELECT spent_bytes FROM service_quota_ledgers WHERE scope_kind=?1 AND scope_key=?2",
            params![floor.scope.as_str(), floor.scope_key],
            |row| row.get(0),
        )?;
        assert_eq!(spent, floor.spent_bytes + 4096);
    }
    let missing: u64 = restored.connection.query_row(
        "SELECT count(*) FROM service_quota_ledgers g JOIN service_quota_limits l USING(scope_kind,scope_key) WHERE g.scope_key=?1 AND g.spent_bytes=2048 AND l.limit_bytes=0",
        [&missing_id], |row| row.get(0))?;
    assert_eq!(missing, 4);
    let grant_terminal: bool = restored.connection.query_row(
        "SELECT terminal FROM service_usage_grants WHERE publication_id=?1",
        [&original.claims.publication_id],
        |row| row.get(0),
    )?;
    assert!(!grant_terminal);
    let active_approvals: u64 = restored.connection.query_row(
        "SELECT count(*) FROM service_target_approvals WHERE revoked=0",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(active_approvals, 0);
    // A new restore receives a distinct epoch. Prior signed evidence cannot
    // clear its fence even if the same snapshot and external key are reused.
    let reconciled = restored.snapshot()?;
    let mut next_restore = Store::from_snapshot(&reconciled, &deployment)?;
    next_restore.invalidate_after_restore()?;
    assert!(
        next_restore
            .reconcile_service_quota_after_restore(&proof, now()?)
            .is_err()
    );
    assert!(next_restore.service_quota_recovery_request().is_ok());
    Ok(())
}

#[test]
fn external_reconciliation_rejects_forged_stale_and_incomplete_statements() -> Result {
    use nestlink_identity::service_quota_recovery::{
        ExternalServiceQuotaSigner, verify_service_quota_reconciliation,
    };
    use nestlink_protocol::service_quota_recovery::ServiceQuotaRecoveredTotal;
    let mut f = Fixture::new()?;
    f.publish()?;
    f.store.invalidate_after_restore()?;
    let request = f.store.service_quota_recovery_request()?;
    let totals = request
        .floors
        .iter()
        .map(|floor| ServiceQuotaRecoveredTotal {
            scope: floor.scope,
            scope_key: floor.scope_key.clone(),
            charged_bytes: floor.spent_bytes + floor.outstanding_bytes,
        })
        .collect();
    let claims = external_recovery_claims(&request, totals)?;
    let external = ExternalServiceQuotaSigner::from_external_seed(&[0x9e; 32]);
    let other = ExternalServiceQuotaSigner::from_external_seed(&[0x9f; 32]);
    let signed = external.sign(&claims)?;
    assert!(
        verify_service_quota_reconciliation(
            &other.sign(&claims)?,
            &external.public_key(),
            &request,
            now()?
        )
        .is_err()
    );
    let mut corrupt = signed.clone();
    corrupt.claims[0] ^= 1;
    assert!(
        verify_service_quota_reconciliation(&corrupt, &external.public_key(), &request, now()?)
            .is_err()
    );
    for mutation in 0..6 {
        let mut invalid = claims.clone();
        match mutation {
            0 => invalid.restored_security_epoch += 1,
            1 => invalid.request_sha256[0] ^= 1,
            2 => invalid.policy_revision += 1,
            3 => invalid.quota_revision += 1,
            4 => invalid.deployment_id = random_id(),
            _ => invalid.issued_at_unix_ms += 5000,
        }
        assert!(
            verify_service_quota_reconciliation(
                &external.sign(&invalid)?,
                &external.public_key(),
                &request,
                now()?
            )
            .is_err()
        );
    }
    assert!(
        verify_service_quota_reconciliation(
            &signed,
            &external.public_key(),
            &request,
            claims.expires_at_unix_ms
        )
        .is_err()
    );
    let mut partial = claims.clone();
    partial.all_prior_grants_accounted = false;
    assert!(external.sign(&partial).is_err());
    partial = claims.clone();
    partial.prior_authority_stopped_at_unix_ms = partial.issued_at_unix_ms;
    assert!(external.sign(&partial).is_err());
    partial = claims.clone();
    partial.totals.pop();
    assert!(external.sign(&partial).is_err());
    partial = claims.clone();
    partial.totals.insert(0, partial.totals[0].clone());
    assert!(external.sign(&partial).is_err());
    let verified =
        verify_service_quota_reconciliation(&signed, &external.public_key(), &request, now()?)?;
    // A concurrent quota edit invalidates a previously verified request before
    // any ledger is modified; export and verify the new state instead.
    f.store
        .connection
        .execute("UPDATE service_quota_settings SET revision=revision+1", [])?;
    assert!(
        f.store
            .reconcile_service_quota_after_restore(&verified, now()?)
            .is_err()
    );
    assert!(f.store.service_quota_recovery_request().is_ok());
    Ok(())
}
