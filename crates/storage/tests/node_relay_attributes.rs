//! Real SQLite persistence, live authority, CAS and atomic audit regressions.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password, random_id};
use nestlink_identity::nodes::NodeIdentity;
use nestlink_protocol::{
    NodeRole,
    api::{NodeRegistration, NodeRelayAttributes, NodeRelayAttributesUpdate},
};
use nestlink_storage::{StorageError, Store, accounts::Principal};
use rusqlite::{Connection, params};
use std::path::PathBuf;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_000_000;
const PASSWORD: &str = "node-relay-attributes-storage-password";

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    deployment: String,
    store: Store,
    admin: Principal,
    member: Principal,
    node: NodeRegistration,
    identity: NodeIdentity,
}
impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("control.sqlite3");
        let deployment = random_id();
        let mut store = Store::open(&path, &deployment)?;
        let vault = VaultKey::from_bytes([7; 32]);
        let dummy = hash_password("relay-attributes-dummy-password")?;
        store.bootstrap_admin("admin", PASSWORD)?;
        let admin = store
            .login("admin", PASSWORD, None, NOW / 1000, &vault, &dummy)?
            .principal;
        store.create_member(&admin, "member", PASSWORD)?;
        let member = store
            .login("member", PASSWORD, None, NOW / 1000, &vault, &dummy)?
            .principal;
        let identity = NodeIdentity::generate();
        let node = NodeRegistration {
            id: random_id(),
            name: "existing-relay".into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            roles: vec![NodeRole::NodeRelay as i32],
            max_connections: 8,
            bytes_per_second: 1048576,
        };
        store.register_node(&admin, node.clone())?;
        Ok(Self {
            _directory: directory,
            path,
            deployment,
            store,
            admin,
            member,
            node,
            identity,
        })
    }
}
fn update(
    expected_revision: u64,
    region: Option<&str>,
    cost_weight: Option<u32>,
) -> NodeRelayAttributesUpdate {
    NodeRelayAttributesUpdate {
        expected_revision,
        attributes: NodeRelayAttributes {
            region: region.map(str::to_owned),
            cost_weight,
        },
    }
}

#[test]
fn relay_metadata_has_live_admin_cas_atomic_audit_and_durable_unknown_values() -> Result {
    let mut f = Fixture::new()?;
    let id = f.node.id.clone();
    let initial = f.store.node_relay_attributes(&f.admin, &id, NOW)?;
    assert_eq!(initial.revision, 0);
    assert_eq!(initial.attributes, NodeRelayAttributes::default());
    let probe = Connection::open(&f.path)?;
    assert_eq!(
        probe.query_row("SELECT count(*) FROM node_relay_attributes", [], |row| row
            .get::<_, u64>(
            0
        ))?,
        0
    );
    let mut forged = f.member.clone();
    forged.is_admin = true;
    for actor in [&f.member, &forged] {
        assert!(f.store.node_relay_attributes(actor, &id, NOW).is_err());
        assert!(
            f.store
                .set_node_relay_attributes(actor, &id, update(0, Some("us-west"), Some(1)), NOW)
                .is_err()
        );
    }
    assert!(
        f.store
            .node_relay_attributes(&f.admin, &random_id(), NOW)
            .is_err()
    );
    let edge = NodeRegistration {
        id: random_id(),
        name: "edge-only".into(),
        public_key: URL_SAFE_NO_PAD.encode(NodeIdentity::generate().public_key()),
        roles: vec![NodeRole::NodeEdge as i32],
        ..f.node.clone()
    };
    f.store.register_node(&f.admin, edge.clone())?;
    assert!(
        f.store
            .node_relay_attributes(&f.admin, &edge.id, NOW)
            .is_err()
    );
    assert!(
        f.store
            .set_node_relay_attributes(&f.admin, &edge.id, update(0, None, None), NOW)
            .is_err()
    );

    let challenge = f.store.node_challenge(&id, NOW)?;
    let lease = f
        .store
        .issue_node_lease(&f.identity.prove(&challenge, &random_id())?, NOW + 1)?;
    let first = f.store.set_node_relay_attributes(
        &f.admin,
        &id,
        update(0, Some("us-west"), Some(0)),
        NOW + 1,
    )?;
    assert_eq!(first.revision, 1);
    assert_eq!(
        first.attributes,
        update(0, Some("us-west"), Some(0)).attributes
    );
    let mut other = Store::open_existing(&f.path, &f.deployment)?;
    assert!(matches!(
        other.set_node_relay_attributes(
            &f.admin,
            &id,
            update(0, Some("eu-west"), Some(1)),
            NOW + 1
        ),
        Err(StorageError::Conflict)
    ));
    assert!(f.store.node_lease_current(&lease)?);
    let nodes = f.store.nodes(&f.admin)?;
    let unchanged = nodes
        .iter()
        .find(|node| node.node.id == id)
        .ok_or("relay missing")?;
    assert_eq!(
        serde_json::to_value(&unchanged.node)?,
        serde_json::to_value(&f.node)?
    );
    for region in [
        "",
        "US",
        "us west",
        "a/b",
        "é",
        "abcdefghijklmnopqrstuvwxyz0123456",
    ] {
        assert!(
            f.store
                .set_node_relay_attributes(&f.admin, &id, update(1, Some(region), Some(1)), NOW + 1)
                .is_err()
        );
    }
    assert!(
        f.store
            .set_node_relay_attributes(&f.admin, &id, update(1, None, Some(1_000_001)), NOW + 1)
            .is_err()
    );
    assert_eq!(
        f.store
            .node_relay_attributes(&f.admin, &id, NOW + 1)?
            .revision,
        1
    );
    probe.execute_batch("CREATE TRIGGER reject_relay_metadata BEFORE INSERT ON audit WHEN NEW.event='node_relay_attributes_updated' BEGIN SELECT RAISE(ABORT,'injected metadata audit failure'); END;")?;
    assert!(
        f.store
            .set_node_relay_attributes(&f.admin, &id, update(1, Some("eu-west"), Some(10)), NOW + 1)
            .is_err()
    );
    let after = f.store.node_relay_attributes(&f.admin, &id, NOW + 1)?;
    assert_eq!(after.revision, 1);
    assert_eq!(after.attributes, first.attributes);
    probe.execute_batch("DROP TRIGGER reject_relay_metadata;")?;
    let cleared =
        f.store
            .set_node_relay_attributes(&f.admin, &id, update(1, None, None), NOW + 1)?;
    assert_eq!(cleared.revision, 2);
    assert_eq!(cleared.attributes, NodeRelayAttributes::default());
    drop(other);
    drop(f.store);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    let restored = f.store.node_relay_attributes(&f.admin, &id, NOW + 1)?;
    assert_eq!(restored.revision, 2);
    assert_eq!(restored.attributes, NodeRelayAttributes::default());
    assert_eq!(probe.query_row("SELECT count(*) FROM audit WHERE event='node_relay_attributes_updated' AND resource_id=?1",[&id],|row|row.get::<_,u64>(0))?,2);
    assert!(
        f.store
            .node_relay_attributes(&f.admin, &id, f.admin.access_expires * 1000)
            .is_err()
    );
    f.store.revoke_node(&f.admin, &id)?;
    assert!(
        f.store
            .node_relay_attributes(&f.admin, &id, NOW + 1)
            .is_err()
    );
    assert!(
        f.store
            .set_node_relay_attributes(&f.admin, &id, update(2, None, None), NOW + 1)
            .is_err()
    );
    assert_eq!(
        probe.query_row(
            "SELECT revision FROM node_relay_attributes WHERE node_id=?1",
            params![id],
            |row| row.get::<_, u64>(0)
        )?,
        2
    );
    let live = NodeRegistration {
        id: random_id(),
        public_key: URL_SAFE_NO_PAD.encode(NodeIdentity::generate().public_key()),
        ..f.node.clone()
    };
    f.store.register_node(&f.admin, live.clone())?;
    f.store.node_relay_attributes(&f.admin, &live.id, NOW + 1)?;
    f.store.logout(&f.admin)?;
    assert!(
        f.store
            .node_relay_attributes(&f.admin, &live.id, NOW + 1)
            .is_err()
    );
    assert!(
        f.store
            .set_node_relay_attributes(&f.admin, &live.id, update(0, None, None), NOW + 1)
            .is_err()
    );
    Ok(())
}

#[test]
fn populated_schema_thirty_one_upgrade_preserves_registration_and_creates_no_metadata_authority()
-> Result {
    let mut f = Fixture::new()?;
    let id = f.node.id.clone();
    drop(f.store);
    let probe = Connection::open(&f.path)?;
    probe.execute_batch(
        "DROP TABLE private_service_relay_hops; DROP TABLE private_service_usage_reports; DROP TABLE private_service_leases; DROP TABLE private_service_hosts; DROP TABLE private_service_acl; DROP TABLE service_exposures; DROP TABLE network_space_addresses; DROP TABLE network_space_address_directories; DROP TABLE network_remote_chain_topology_bindings; DROP TABLE network_topology_publisher_exports; DROP TABLE network_route_exports; DROP VIEW all_relay_capacity; DROP TABLE network_remote_route_set_members; DROP TABLE network_remote_route_sets;
         DROP TABLE network_remote_chain_hops;
         DROP TABLE network_remote_chains;
         CREATE VIEW all_relay_capacity AS
          SELECT id,kind,controller_account_id,host_account_id,node_id,promised_until FROM relay_reservations
          UNION ALL
          SELECT allocation_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_relays;
         DROP TABLE network_topology_changes;
         DROP TABLE network_topology_cursors;
         DROP TABLE network_topology_heads;
         DROP TABLE network_topology_publishers;
         DROP TABLE node_relay_attributes;
         PRAGMA user_version=31;",
    )?;
    drop(probe);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    let view = f.store.node_relay_attributes(&f.admin, &id, NOW)?;
    assert_eq!(view.revision, 0);
    assert_eq!(view.attributes, NodeRelayAttributes::default());
    let nodes = f.store.nodes(&f.admin)?;
    assert_eq!(
        serde_json::to_value(&nodes[0].node)?,
        serde_json::to_value(&f.node)?
    );
    let view = f.store.set_node_relay_attributes(
        &f.admin,
        &id,
        update(0, Some("ap-east"), Some(1_000_000)),
        NOW,
    )?;
    assert_eq!(view.revision, 1);
    let probe = Connection::open(&f.path)?;
    assert_eq!(
        probe.pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))?,
        nestlink_storage::SCHEMA_VERSION
    );
    Ok(())
}
