//! The real SQLite journal, registered node proofs, space ACL and signatures.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password, random_id};
use nestlink_identity::{
    network::NetworkAuthoritySigner,
    network_topology::{
        SignedTopologyPublisher, SignedTopologyReport, verify_topology_publisher,
        verify_topology_update,
    },
    nodes::NodeIdentity,
};
use nestlink_protocol::{
    NodeRole,
    api::{NodeEndpoints, NodeEndpointsUpdate, NodeRegistration},
    network::PeerId,
    network_topology::{
        BootIncarnation, TopologyAdvertisement, TopologyChange, TopologyNeighbor,
        TopologyPublisherClaims, TopologyReport, TopologySync,
    },
    spaces::SpaceCreateRequest,
};
use nestlink_storage::{
    StorageError, Store,
    accounts::Principal,
    network_policy::topology::{TopologyPublisherRequest, TopologyQuery},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[path = "network_topology/route_exports.rs"]
mod route_exports;
const NOW: u64 = 1_000_000;
struct Fixture {
    directory: tempfile::TempDir,
    deployment: String,
    store: Store,
    actor: Principal,
    stranger: Principal,
    signer: NetworkAuthoritySigner,
    space: String,
    nodes: [(String, NodeIdentity, BootIncarnation); 2],
    publishers: [SignedTopologyPublisher; 2],
}
impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let deployment = random_id();
        let mut store = Store::open(&directory.path().join("control.sqlite3"), &deployment)?;
        let vault = VaultKey::from_bytes([27; 32]);
        let dummy = hash_password("topology-test-dummy")?;
        store.bootstrap_admin("owner", "topology-test-password")?;
        let actor = store
            .login(
                "owner",
                "topology-test-password",
                None,
                NOW / 1000,
                &vault,
                &dummy,
            )?
            .principal;
        store.create_member(&actor, "stranger", "topology-test-password")?;
        let stranger = store
            .login(
                "stranger",
                "topology-test-password",
                None,
                NOW / 1000,
                &vault,
                &dummy,
            )?
            .principal;
        let signer = NetworkAuthoritySigner::from_master_seed(&[23; 32])?;
        let space = store
            .create_space(
                &actor,
                SpaceCreateRequest {
                    name: "topology space".into(),
                },
                signer.public_key(),
                NOW,
            )?
            .space_id;
        let mut registered = Vec::new();
        for index in 0..2 {
            let identity = NodeIdentity::generate();
            let id = random_id();
            store.register_node(
                &actor,
                NodeRegistration {
                    id: id.clone(),
                    name: format!("topology-{index}"),
                    public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
                    roles: vec![NodeRole::NodeRelay as i32],
                    max_connections: 16,
                    bytes_per_second: 1024 * 1024,
                },
            )?;
            store.set_node_endpoints(
                &actor,
                &id,
                NodeEndpointsUpdate {
                    expected_revision: 0,
                    endpoints: NodeEndpoints {
                        quic_uri: Some(format!("quic://127.0.0.1:{}", 31000 + index)),
                        allow_loopback: true,
                        ..NodeEndpoints::default()
                    },
                },
                NOW,
            )?;
            let runtime_id = random_id();
            let challenge = store.node_challenge(&id, NOW)?;
            let lease =
                store.issue_node_lease(&identity.prove(&challenge, &runtime_id)?, NOW + 1)?;
            registered.push((
                id,
                identity,
                BootIncarnation {
                    runtime_id,
                    runtime_generation: lease.runtime_generation,
                },
            ));
        }
        let nodes: [_; 2] = registered.try_into().map_err(|_| "node fixture count")?;
        let mut publications = Vec::new();
        for index in 0..2 {
            publications.push(store.issue_topology_publisher(
                &actor,
                &signer,
                &space,
                &nodes[index].0,
                TopologyPublisherRequest {
                    route_export_grant_ids: Vec::new(),
                    publisher_id: random_id(),
                    expected_policy_epoch: 1,
                    allowed_node_ids: vec![nodes[1 - index].0.clone()],
                    expires_at_ms: NOW + 60_000,
                },
                NOW + 2,
            )?);
        }
        let publishers = publications
            .try_into()
            .map_err(|_| "publisher fixture count")?;
        Ok(Self {
            directory,
            deployment,
            store,
            actor,
            stranger,
            signer,
            space,
            nodes,
            publishers,
        })
    }
    fn report(&mut self, index: usize, sequence: u64, now: u64) -> Result<SignedTopologyReport> {
        let snapshot = self.store.network_policy_snapshot(&self.space, now)?;
        let (id, key, incarnation) = &self.nodes[index];
        let publisher = verify_topology_publisher(
            &self.publishers[index],
            &snapshot.verification(),
            id,
            &key.public_key(),
            incarnation,
            &[],
        )?;
        Ok(key.sign_topology_report(&TopologyReport {
            schema_version: 1,
            deployment_id: self.deployment.clone(),
            space_id: self.space.clone(),
            policy_epoch: 1,
            node_id: id.clone(),
            peer: PeerId::from_public_key(&key.public_key()),
            publisher_digest: publisher.digest(),
            incarnation: incarnation.clone(),
            sequence,
            not_before_ms: now,
            expires_at_ms: now + 1000,
            neighbors: vec![TopologyNeighbor {
                local: PeerId::from_public_key(&key.public_key()),
                remote: PeerId::from_public_key(&self.nodes[1 - index].1.public_key()),
                local_endpoint_revision: 1,
                remote_endpoint_revision: 1,
                up: true,
            }],
            prefixes: Vec::new(),
        })?)
    }
    fn accept(
        &mut self,
        index: usize,
        signed: &SignedTopologyReport,
        now: u64,
    ) -> Result<nestlink_identity::network_topology::SignedTopologyAdvertisement> {
        Ok(self.store.accept_topology_report(
            &self.signer,
            &self.space,
            &self.nodes[index].0,
            signed,
            now,
        )?)
    }
    fn sync(&mut self, after: Option<u64>, now: u64) -> Result<TopologySync> {
        let nonce = [39; 32];
        let signed = self.store.topology_update(
            &self.actor,
            &self.signer,
            &self.space,
            TopologyQuery {
                after_cursor: after,
                nonce,
            },
            now,
        )?;
        let snapshot = self.store.network_policy_snapshot(&self.space, now)?;
        Ok(
            verify_topology_update(&signed, &snapshot.verification(), &nonce)?
                .claims()
                .sync
                .clone(),
        )
    }
    fn restart(&mut self) -> Result {
        self.store = Store::open_existing(
            &self.directory.path().join("control.sqlite3"),
            &self.deployment,
        )?;
        Ok(())
    }
}

#[test]
fn exact_retry_is_idempotent_without_ttl_extension_and_sequence_survives_restart() -> Result {
    let mut f = Fixture::new()?;
    let signed = f.report(0, 1, NOW + 10)?;
    let first = f.accept(0, &signed, NOW + 10)?;
    f.restart()?;
    let retry = f.accept(0, &signed, NOW + 20)?;
    assert_eq!(first.claims, retry.claims);
    assert_eq!(first.signature, retry.signature);
    let original = TopologyAdvertisement::decode_canonical(&first.claims)?;
    assert_eq!(original.expires_at_ms, NOW + 1010);
    let mut changed = TopologyReport::decode_canonical(&signed.claims)?;
    changed.neighbors.clear();
    let conflicting = f.nodes[0].1.sign_topology_report(&changed)?;
    assert!(f.accept(0, &conflicting, NOW + 120).is_err());
    let second = f.report(0, 2, NOW + 220)?;
    f.accept(0, &second, NOW + 220)?;
    assert!(f.accept(0, &signed, NOW + 320).is_err());
    match f.sync(Some(0), NOW + 320)? {
        TopologySync::Delta {
            cursor, changes, ..
        } => {
            assert_eq!(cursor, 2);
            assert_eq!(changes.len(), 2);
        }
        _ => return Err("expected delta".into()),
    }
    Ok(())
}

#[test]
fn expiry_emits_signed_withdrawal_without_losing_report_high_watermark() -> Result {
    let mut f = Fixture::new()?;
    let signed = f.report(0, 7, NOW + 10)?;
    f.accept(0, &signed, NOW + 10)?;
    match f.sync(None, NOW + 20)? {
        TopologySync::Full {
            cursor,
            advertisements,
        } => {
            assert_eq!(cursor, 1);
            assert_eq!(advertisements.len(), 1);
        }
        _ => return Err("expected full".into()),
    }
    match f.sync(Some(1), NOW + 1010)? {
        TopologySync::Delta {
            cursor, changes, ..
        } => {
            assert_eq!(cursor, 2);
            assert!(matches!(&changes[0].change,TopologyChange::Withdraw(w) if w.sequence==7));
        }
        _ => return Err("expected withdrawal".into()),
    }
    f.restart()?;
    let replay = f.report(0, 7, NOW + 1110)?;
    assert!(f.accept(0, &replay, NOW + 1110).is_err());
    let next = f.report(0, 8, NOW + 1210)?;
    f.accept(0, &next, NOW + 1210)?;
    assert!(matches!(
        f.sync(None, NOW + 1210)?,
        TopologySync::Full { cursor: 3, .. }
    ));
    Ok(())
}

#[test]
fn space_manager_revoke_withdraws_both_endpoints_and_old_grant_cannot_revive() -> Result {
    let mut f = Fixture::new()?;
    for index in 0..2 {
        let signed = f.report(index, 1, NOW + 10)?;
        f.accept(index, &signed, NOW + 10)?;
    }
    assert!(
        f.store
            .revoke_topology_publisher(&f.stranger, &f.space, &f.nodes[0].0, NOW + 20)
            .is_err()
    );
    assert!(
        f.store
            .topology_update(
                &f.stranger,
                &f.signer,
                &f.space,
                TopologyQuery {
                    after_cursor: None,
                    nonce: [1; 32]
                },
                NOW + 20
            )
            .is_err()
    );
    f.store
        .revoke_topology_publisher(&f.actor, &f.space, &f.nodes[0].0, NOW + 20)?;
    match f.sync(Some(2), NOW + 20)? {
        TopologySync::Delta {
            cursor, changes, ..
        } => {
            assert_eq!(cursor, 4);
            assert_eq!(changes.len(), 2);
            assert!(
                changes
                    .iter()
                    .all(|c| matches!(c.change, TopologyChange::Withdraw(_)))
            );
        }
        _ => return Err("expected revoke delta".into()),
    }
    let old = f.report(0, 2, NOW + 120)?;
    assert!(f.accept(0, &old, NOW + 120).is_err());
    Ok(())
}

#[test]
fn current_endpoint_revisions_runtime_and_registered_key_are_admission_facts() -> Result {
    let mut f = Fixture::new()?;
    let signed = f.report(0, 1, NOW + 10)?;
    let mut stale = TopologyReport::decode_canonical(&signed.claims)?;
    stale.neighbors[0].remote_endpoint_revision = 2;
    let stale = f.nodes[0].1.sign_topology_report(&stale)?;
    assert!(f.accept(0, &stale, NOW + 10).is_err());
    let mut bad_signature = signed.clone();
    bad_signature.signature[0] ^= 1;
    assert!(f.accept(0, &bad_signature, NOW + 10).is_err());
    f.accept(0, &signed, NOW + 10)?;
    let id = f.nodes[0].0.clone();
    let runtime = random_id();
    let challenge = f.store.node_challenge(&id, NOW + 110)?;
    f.store
        .issue_node_lease(&f.nodes[0].1.prove(&challenge, &runtime)?, NOW + 110)?;
    assert!(f.accept(0, &signed, NOW + 120).is_err());
    assert!(
        matches!(f.sync(None,NOW+120)?,TopologySync::Full {advertisements,..} if advertisements.is_empty())
    );
    Ok(())
}

#[test]
fn publisher_reissue_preserves_same_runtime_sequence_and_report_flood_is_bounded() -> Result {
    let mut f = Fixture::new()?;
    let first = f.report(0, 50, NOW + 10)?;
    f.accept(0, &first, NOW + 10)?;
    let fast = f.report(0, 51, NOW + 11)?;
    assert!(matches!(
        f.store
            .accept_topology_report(&f.signer, &f.space, &f.nodes[0].0, &fast, NOW + 11),
        Err(StorageError::RateLimited)
    ));
    let id = f.nodes[0].0.clone();
    let old_claims = TopologyPublisherClaims::decode_canonical(&f.publishers[0].claims)?;
    f.publishers[0] = f.store.issue_topology_publisher(
        &f.actor,
        &f.signer,
        &f.space,
        &id,
        TopologyPublisherRequest {
            route_export_grant_ids: Vec::new(),
            publisher_id: random_id(),
            expected_policy_epoch: 1,
            allowed_node_ids: vec![f.nodes[1].0.clone()],
            expires_at_ms: NOW + 60_000,
        },
        NOW + 120,
    )?;
    let reset = f.report(0, 1, NOW + 220)?;
    assert!(f.accept(0, &reset, NOW + 220).is_err());
    let next = f.report(0, 51, NOW + 220)?;
    f.accept(0, &next, NOW + 220)?;
    assert!(
        f.store
            .issue_topology_publisher(
                &f.actor,
                &f.signer,
                &f.space,
                &id,
                TopologyPublisherRequest {
                    route_export_grant_ids: Vec::new(),
                    publisher_id: old_claims.scope.grant_id,
                    expected_policy_epoch: 1,
                    allowed_node_ids: Vec::new(),
                    expires_at_ms: NOW + 60_000
                },
                NOW + 320
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn compacted_delta_cursor_requires_full_snapshot_and_clock_rollback_is_rejected() -> Result {
    let mut f = Fixture::new()?;
    let signed = f.report(0, 1, NOW + 10)?;
    f.accept(0, &signed, NOW + 10)?;
    let connection = rusqlite::Connection::open(f.directory.path().join("control.sqlite3"))?;
    connection.execute(
        "UPDATE network_topology_cursors SET retained_after=1 WHERE space_id=?1",
        [&f.space],
    )?;
    assert!(f.sync(Some(0), NOW + 20).is_err());
    assert!(matches!(
        f.sync(None, NOW + 20)?,
        TopologySync::Full { cursor: 1, .. }
    ));
    assert!(f.sync(None, NOW + 19).is_err());
    Ok(())
}

#[test]
fn new_policy_epoch_requires_full_snapshot_without_signing_old_epoch_upserts() -> Result {
    let mut f = Fixture::new()?;
    let signed = f.report(0, 1, NOW + 10)?;
    f.accept(0, &signed, NOW + 10)?;
    let current = f
        .store
        .network_authority_state(&f.actor, &f.space, NOW + 20)?;
    f.store.advance_network_policy_epoch(
        &f.actor,
        nestlink_storage::network_policy::NetworkAuthorityChange {
            space_id: f.space.clone(),
            expected_revision: current.revision,
            expected_policy_epoch: current.policy_epoch,
        },
        NOW + 20,
    )?;
    assert!(f.sync(Some(0), NOW + 20).is_err());
    assert!(
        matches!(f.sync(None,NOW+20)?,TopologySync::Full {advertisements,..} if advertisements.is_empty())
    );
    // The withdrawal appended after the epoch barrier must not lower it.
    assert!(f.sync(Some(0), NOW + 20).is_err());
    assert!(f.accept(0, &signed, NOW + 120).is_err());
    Ok(())
}
