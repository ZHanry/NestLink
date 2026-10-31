use super::*;
use nestlink_identity::{nodes::NodeIdentity, relay::allocation_transcript};
use nestlink_protocol::{
    NodeRole,
    api::{
        NetworkRemoteRelayRequest, NodeEndpoints, NodeEndpointsUpdate, NodeRegistration,
        RelayAllocationRequest, RelayQuotaUpdate,
    },
};
use nestlink_storage::relay_reservations::RelayLifecycle;

struct RelayFixture {
    base: Setup,
    node: NodeIdentity,
    node_id: String,
    lifecycle: RelayLifecycle,
    lease: nestlink_protocol::NodeLeaseClaims,
}
impl RelayFixture {
    fn new(direct: bool, maximum: u32) -> Result<Self> {
        let mut base = Setup::with_path(true, direct)?;
        let node = NodeIdentity::generate();
        let node_id = random_id();
        base.store.register_node(
            &base.controller,
            NodeRegistration {
                id: node_id.clone(),
                name: "network relay".into(),
                public_key: URL_SAFE_NO_PAD.encode(node.public_key()),
                roles: vec![NodeRole::NodeRelay as i32],
                max_connections: maximum,
                bytes_per_second: 100_000,
            },
        )?;
        base.store.set_node_endpoints(
            &base.controller,
            &node_id,
            NodeEndpointsUpdate {
                expected_revision: 0,
                endpoints: NodeEndpoints {
                    quic_uri: Some("quic://127.0.0.1:28744".into()),
                    wss_origin: None,
                    allow_loopback: true,
                },
            },
            NOW,
        )?;
        let challenge = base.store.node_challenge(&node_id, NOW)?;
        let lease = base
            .store
            .issue_node_lease(&node.prove(&challenge, &random_id())?, NOW)?;
        let lifecycle = base.store.relay_lifecycle(NOW)?;
        Ok(Self {
            base,
            node,
            node_id,
            lifecycle,
            lease,
        })
    }
    fn issuance(&self) -> Result<NetworkRemoteRelayIssuance> {
        let business = self.base.store.current_permit(
            &self.base.controller,
            &self.base.request,
            NOW / 1000,
        )?;
        let allocation_id = random_id();
        Ok(NetworkRemoteRelayIssuance {
            space_id: self.base.space.clone(),
            request_id: self.base.request.clone(),
            request: NetworkRemoteRelayRequest {
                path: self.base.issuance().request,
                transit_grant_id: random_id(),
                allocation: RelayAllocationRequest {
                    allocation_id: allocation_id.clone(),
                    node_id: self.node_id.clone(),
                    device_id: business.controller_device_id.clone(),
                    signature: URL_SAFE_NO_PAD.encode(self.base.controller_identity.sign_action(
                        &allocation_transcript(
                            &business,
                            &self.base.controller.account_id,
                            &business.controller_device_id,
                            &allocation_id,
                            &self.node_id,
                        )?,
                    )?),
                },
            },
        })
    }
    fn issue(
        &mut self,
        issuance: NetworkRemoteRelayIssuance,
    ) -> std::result::Result<NetworkRemoteRelayBundle, StorageError> {
        self.base.store.issue_network_remote_relay(
            &self.lifecycle,
            &self.base.controller,
            &self.base.signer,
            issuance,
            NOW,
        )
    }
}

#[test]
fn migration_34_preserves_original_single_relay_credentials_and_capacity() -> Result {
    let mut f = RelayFixture::new(false, 2)?;
    let request = f.issuance()?;
    let allocation = request.request.allocation.allocation_id.clone();
    let original = f.issue(request)?;
    edit_snapshot(&mut f.base, |db| {
        db.execute_batch(
        "DROP TABLE network_packet_access; DROP VIEW all_relay_capacity; DROP TABLE private_service_relay_hops; DROP TABLE private_service_usage_reports; DROP TABLE private_service_leases; DROP TABLE private_service_hosts; DROP TABLE private_service_acl; DROP TABLE service_exposures; DROP TABLE network_space_addresses; DROP TABLE network_space_address_directories; DROP TABLE network_remote_chain_topology_bindings; DROP TABLE network_topology_publisher_exports; DROP TABLE network_route_exports; DROP TABLE network_remote_route_set_members; DROP TABLE network_remote_route_sets; DROP TABLE network_remote_chain_hops; DROP TABLE network_remote_chains;
         CREATE VIEW all_relay_capacity AS SELECT id,kind,controller_account_id,host_account_id,node_id,promised_until FROM relay_reservations UNION ALL SELECT allocation_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_relays;
         PRAGMA user_version=33;"
    )
    })?;
    let read = f.base.store.network_remote_relay(
        &f.lifecycle,
        &f.base.host,
        &f.base.space,
        &allocation,
        NOW,
    )?;
    assert_eq!(read.transit.claims, original.transit.claims);
    assert_eq!(read.transit.signature, original.transit.signature);
    assert_eq!(read.path.path.claims, original.path.path.claims);
    assert_eq!(
        f.base
            .store
            .relay_reservation_usage(&f.base.controller, NOW)?
            .held_allocations,
        1
    );
    Ok(())
}

#[test]
fn node_snapshot_delegates_exact_network_chain_and_permit_and_removes_revoked_routes() -> Result {
    use nestlink_identity::{
        PermitSigner, network::verify_node_network_resource,
        node_resources::verify_resource_snapshot, verify_permit,
    };
    use nestlink_protocol::NodeResourceQueryClaims;
    let mut f = RelayFixture::new(false, 2)?;
    let issuance = f.issuance()?;
    let allocation_id = issuance.request.allocation.allocation_id.clone();
    let issued = f.issue(issuance)?;
    let root = PermitSigner::from_seed([44; 32]);
    let policy = root.node_policy_signer()?;
    let mut query = NodeResourceQueryClaims {
        schema_version: nestlink_protocol::SCHEMA_VERSION,
        deployment_id: f.lease.deployment_id.clone(),
        security_epoch: f.lease.security_epoch,
        node_id: f.node_id.clone(),
        runtime_id: f.lease.runtime_id.clone(),
        runtime_generation: f.lease.runtime_generation,
        policy_revision: f.lease.policy_revision,
        lease_sequence: f.lease.lease_sequence,
        request_id: random_id(),
        request_sequence: 1,
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: NOW + 1000,
    };
    let signed_query = f.node.sign_resource_query(&query)?;
    let snapshot = f.base.store.node_resource_snapshot_with_network(
        &f.lifecycle,
        &signed_query,
        &root,
        NOW,
    )?;
    assert!(snapshot.allocations.is_empty());
    assert_eq!(snapshot.network_routes.len(), 1);
    let signed_snapshot = policy.sign_resource_snapshot(&snapshot)?;
    let verified = verify_resource_snapshot(&signed_snapshot, &policy.public_key(), &signed_query)?;
    let route = &verified.network_routes[0];
    let binding = verify_node_network_resource(route, &root.public_key(), NOW)?;
    assert_eq!(
        binding.relay,
        nestlink_protocol::network::PeerId::from_public_key(&f.node.public_key())
    );
    let view: nestlink_protocol::api::NetworkRemoteRelayView =
        serde_json::from_slice(&route.relay_bundle_json)?;
    assert_eq!(
        URL_SAFE_NO_PAD.decode(view.transit.claims)?,
        issued.transit.claims
    );
    assert_eq!(
        URL_SAFE_NO_PAD.decode(view.transit.signature)?,
        issued.transit.signature
    );
    let permit = verify_permit(&route.business_permit, &root.public_key())?;
    assert_eq!(permit.signed_envelope(), route.business_permit.as_slice());
    let mut changed = route.clone();
    changed.business_permit[0] ^= 1;
    assert!(verify_node_network_resource(&changed, &root.public_key(), NOW).is_err());
    let mut changed = route.clone();
    changed.network_authority_key[0] ^= 1;
    assert!(verify_node_network_resource(&changed, &root.public_key(), NOW).is_err());
    let mut changed = snapshot.clone();
    changed.network_routes[0].network_schema_version = 2;
    assert!(policy.sign_resource_snapshot(&changed).is_err());
    query.request_id = random_id();
    query.request_sequence += 1;
    let new_query = f.node.sign_resource_query(&query)?;
    assert!(verify_resource_snapshot(&signed_snapshot, &policy.public_key(), &new_query).is_err());
    f.base
        .store
        .revoke_network_remote_relay(&f.base.host, &f.base.space, &allocation_id, NOW)?;
    let revoked =
        f.base
            .store
            .node_resource_snapshot_with_network(&f.lifecycle, &new_query, &root, NOW)?;
    assert!(revoked.network_routes.is_empty());
    assert_eq!(
        f.base
            .store
            .relay_reservation_usage(&f.base.controller, NOW)?
            .held_endpoint_slots,
        2
    );
    Ok(())
}

#[test]
fn a_reserved_relay_chain_survives_reopen_without_resigning_or_refunding() -> Result {
    let mut f = RelayFixture::new(false, 2)?;
    let issuance = f.issuance()?;
    let allocation = issuance.request.allocation.allocation_id.clone();
    let path_id = issuance.request.path.path_grant_id.clone();
    let bundle = f.issue(issuance)?;
    assert!(!bundle.path.verified().claims().policy.allow_direct);
    assert_eq!(
        bundle.path.verified().claims().policy.relays,
        vec![nestlink_protocol::network::PeerId::from_public_key(
            &f.node.public_key()
        )]
    );
    let snapshot = f.base.store.network_policy_snapshot(&f.base.space, NOW)?;
    let transit = verify_network_grant(&bundle.transit, &snapshot.verification())?;
    let GrantClaims::Transit(claims) = transit.claims() else {
        return Err("not transit".into());
    };
    assert_eq!(claims.route_id, allocation);
    assert_eq!(
        claims.transport_group,
        bundle.path.verified().transport_group_id()
    );
    assert_eq!(claims.previous, claims.peers.first);
    assert_eq!(claims.next, claims.peers.second);
    assert_eq!(claims.remaining_hops, 1);
    assert_eq!(
        claims.byte_limit,
        f.base
            .store
            .relay_quota_current()?
            .limits
            .bytes_per_allocation
    );
    let deployment = f.base.store.deployment_id()?;
    f.base.store = Store::from_snapshot(&f.base.store.snapshot()?, &deployment)?;
    let read = f.base.store.network_remote_relay(
        &f.lifecycle,
        &f.base.host,
        &f.base.space,
        &allocation,
        NOW,
    )?;
    assert_eq!(read.transit.claims, bundle.transit.claims);
    assert_eq!(read.transit.signature, bundle.transit.signature);
    assert_eq!(read.path.path.claims, bundle.path.path.claims);
    assert_eq!(
        read.path.connectivity.claims,
        bundle.path.connectivity.claims
    );
    assert!(
        f.base
            .store
            .network_remote_path(&f.base.controller, &f.base.space, &path_id, NOW)
            .is_err()
    );
    for _ in 0..2 {
        f.base
            .store
            .revoke_network_remote_relay(&f.base.host, &f.base.space, &allocation, NOW)?;
    }
    assert!(
        f.base
            .store
            .network_remote_relay(
                &f.lifecycle,
                &f.base.controller,
                &f.base.space,
                &allocation,
                NOW
            )
            .is_err()
    );
    assert_eq!(
        f.base
            .store
            .relay_reservation_usage(&f.base.controller, NOW)?
            .held_endpoint_slots,
        2
    );
    let revoked = f.base.store.network_policy_snapshot(&f.base.space, NOW)?;
    assert!(transit.check_current(&revoked.verification()).is_err());
    assert!(
        bundle
            .path
            .verified()
            .check_current(&revoked.verification())
            .is_err()
    );
    Ok(())
}

#[test]
fn network_routes_and_legacy_relays_share_the_original_capacity_budget() -> Result {
    let mut f = RelayFixture::new(false, 100)?;
    let quota = f.base.store.relay_quota_current()?;
    let mut limits = quota.limits;
    limits.max_allocations = 1;
    f.base.store.set_relay_quota(
        &f.base.controller,
        RelayQuotaUpdate {
            expected_revision: quota.revision,
            limits,
        },
        NOW / 1000,
    )?;
    let issuance = f.issuance()?;
    let allocation = issuance.request.allocation.allocation_id.clone();
    f.issue(issuance)?;
    let second = f.issuance()?;
    assert!(matches!(f.issue(second), Err(StorageError::RateLimited)));
    let legacy = f.issuance()?.request.allocation;
    assert!(matches!(
        f.base.store.reserve_node_relay(
            &f.lifecycle,
            &f.base.controller,
            &f.base.request,
            legacy,
            NOW
        ),
        Err(StorageError::RateLimited)
    ));
    f.base.store.revoke_network_remote_relay(
        &f.base.controller,
        &f.base.space,
        &allocation,
        NOW,
    )?;
    let second = f.issuance()?;
    assert!(matches!(f.issue(second), Err(StorageError::RateLimited)));
    assert_eq!(
        f.base
            .store
            .relay_reservation_usage(&f.base.controller, NOW)?
            .held_allocations,
        1
    );
    Ok(())
}

#[test]
fn failed_relay_audit_rolls_back_the_entire_signed_chain_and_capacity_promise() -> Result {
    let mut f = RelayFixture::new(false, 2)?;
    edit_snapshot(&mut f.base, |db| {
        db.execute_batch("CREATE TRIGGER reject_network_relay BEFORE INSERT ON audit WHEN NEW.event='network_remote_relay_reserved' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;")
    })?;
    let issuance = f.issuance()?;
    let allocation = issuance.request.allocation.allocation_id.clone();
    let path = issuance.request.path.path_grant_id.clone();
    assert!(matches!(f.issue(issuance), Err(StorageError::Sqlite(_))));
    assert_eq!(
        f.base
            .store
            .relay_reservation_usage(&f.base.controller, NOW)?
            .held_allocations,
        0
    );
    assert!(
        f.base
            .store
            .network_remote_relay(&f.lifecycle, &f.base.host, &f.base.space, &allocation, NOW)
            .is_err()
    );
    assert!(
        f.base
            .store
            .network_remote_path(&f.base.host, &f.base.space, &path, NOW)
            .is_err()
    );
    Ok(())
}

#[test]
fn device_proof_crossed_membership_ids_and_direct_only_consent_fail_admission() -> Result {
    let mut f = RelayFixture::new(false, 100)?;
    for fault in 0..6 {
        let mut issuance = f.issuance()?;
        match fault {
            0 => issuance.request.allocation.signature = URL_SAFE_NO_PAD.encode([0; 64]),
            1 => issuance.request.path.host_membership_grant_id = f.base.controller_member.clone(),
            2 => issuance.request.path.expected_policy_epoch = 2,
            3 => issuance.request.path.expires_at_unix_ms = NOW + 30_001,
            4 => issuance.request.transit_grant_id = f.base.controller_member.clone(),
            _ => issuance.request.transit_grant_id = issuance.request.path.path_grant_id.clone(),
        }
        assert!(f.issue(issuance).is_err(), "fault {fault}");
    }
    assert_eq!(
        f.base
            .store
            .relay_reservation_usage(&f.base.controller, NOW)?
            .held_allocations,
        0
    );
    // Construct a genuinely signed, initially legal relay request first. Then
    // narrow the authoritative policy through its production API before
    // admission. The current-business boundary must reject this stale consent,
    // independently of the SDK's allocation-transcript preflight.
    let mut direct = RelayFixture::new(false, 2)?;
    let issuance = direct.issuance()?;
    let revision = direct.base.store.policy()?.0;
    direct
        .base
        .store
        .apply_policy(revision, nestlink_policy::NetworkPolicy::default())?;
    assert!(matches!(
        direct.issue(issuance),
        Err(StorageError::Forbidden)
    ));
    assert_eq!(
        direct
            .base
            .store
            .relay_reservation_usage(&direct.base.controller, NOW)?
            .held_allocations,
        0
    );
    Ok(())
}

#[test]
fn current_node_business_and_persisted_route_bindings_are_required_on_readback() -> Result {
    let mut f = RelayFixture::new(false, 100)?;
    let issuance = f.issuance()?;
    let allocation = issuance.request.allocation.allocation_id.clone();
    f.issue(issuance)?;
    let deployment = f.base.store.deployment_id()?;
    let original = f.base.store.snapshot()?;
    for fault in 0..10 {
        f.base.store = Store::from_snapshot(&original, &deployment)?;
        edit_snapshot(&mut f.base, |db| {
            let sql = match fault {
                0 => "UPDATE data_nodes SET revoked=1",
                1 => "UPDATE node_endpoints SET revision=revision+1",
                2 => "UPDATE network_remote_relays SET runtime_generation=runtime_generation+1",
                3 => "UPDATE network_remote_relays SET byte_limit=byte_limit+1",
                4 => "UPDATE network_remote_relays SET promised_until=promised_until+1",
                5 => "UPDATE network_remote_relays SET quota_revision=quota_revision+1",
                6 => "UPDATE sessions SET connection_generation=connection_generation+1",
                7 => "UPDATE network_memberships SET membership_epoch=membership_epoch+1",
                8 => "UPDATE network_remote_paths SET revoked=1",
                _ => "UPDATE network_remote_relays SET controller_account_id=host_account_id",
            };
            db.execute(sql, [])?;
            Ok(())
        })?;
        assert!(
            f.base
                .store
                .network_remote_relay(&f.lifecycle, &f.base.host, &f.base.space, &allocation, NOW)
                .is_err(),
            "fault {fault}"
        );
    }
    f.base.store = Store::from_snapshot(&original, &deployment)?;
    let restarted = f.base.store.relay_lifecycle(NOW)?;
    assert!(!restarted.ready());
    assert!(matches!(
        f.base.store.network_remote_relay(
            &restarted,
            &f.base.host,
            &f.base.space,
            &allocation,
            NOW
        ),
        Err(StorageError::RateLimited)
    ));
    Ok(())
}

#[test]
fn simultaneous_sqlite_admission_cannot_overbook_the_shared_global_limit() -> Result {
    use std::sync::{Arc, Barrier};
    let f = RelayFixture::new(false, 100)?;
    let first = f.issuance()?;
    let second = f.issuance()?;
    let RelayFixture {
        mut base,
        lifecycle,
        ..
    } = f;
    let quota = base.store.relay_quota_current()?;
    let mut limits = quota.limits;
    limits.max_allocations = 1;
    base.store.set_relay_quota(
        &base.controller,
        RelayQuotaUpdate {
            expected_revision: quota.revision,
            limits,
        },
        NOW / 1000,
    )?;
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("network-concurrency.sqlite3");
    let deployment = base.store.deployment_id()?;
    std::fs::write(&database, base.store.snapshot()?)?;
    let lifecycle = Arc::new(lifecycle);
    let barrier = Arc::new(Barrier::new(2));
    let stores = [
        Store::open_existing(&database, &deployment)?,
        Store::open_existing(&database, &deployment)?,
    ];
    let workers = stores
        .into_iter()
        .zip([first, second])
        .map(|(mut store, issuance)| {
            let (actor, lifecycle, barrier) =
                (base.controller.clone(), lifecycle.clone(), barrier.clone());
            std::thread::spawn(move || -> std::result::Result<bool, StorageError> {
                barrier.wait();
                let signer = NetworkAuthoritySigner::from_master_seed(&[63; 32])?;
                match store.issue_network_remote_relay(&lifecycle, &actor, &signer, issuance, NOW) {
                    Ok(_) => Ok(true),
                    Err(StorageError::RateLimited) => Ok(false),
                    Err(error) => Err(error),
                }
            })
        })
        .collect::<Vec<_>>();
    let mut admitted = 0;
    for worker in workers {
        admitted += usize::from(worker.join().map_err(|_| "admission worker panicked")??);
    }
    assert_eq!(admitted, 1);
    let store = Store::open_existing(&database, &deployment)?;
    assert_eq!(
        store
            .relay_reservation_usage(&base.controller, NOW)?
            .held_endpoint_slots,
        2
    );
    Ok(())
}
