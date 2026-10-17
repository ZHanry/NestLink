use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password, random_id};
use nestlink_identity::nodes::NodeIdentity;
use nestlink_policy::{NetworkPolicy, ServerForwarding};
use nestlink_protocol::{NodeRole, api::NodeRegistration};
use nestlink_storage::{StorageError, Store};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
fn node_registration_proofs_roles_replay_throttle_and_revoke_are_enforced() -> Result {
    let mut store = Store::in_memory(&random_id())?;
    let vault = VaultKey::from_bytes([7; 32]);
    let dummy = hash_password("node-dummy-password")?;
    store.bootstrap_admin("administrator", "node-test-password")?;
    let admin = store
        .login(
            "administrator",
            "node-test-password",
            None,
            1000,
            &vault,
            &dummy,
        )?
        .principal;
    let key = NodeIdentity::generate();
    let id = random_id();
    let node = NodeRegistration {
        id: id.clone(),
        name: "relay-1".into(),
        public_key: URL_SAFE_NO_PAD.encode(key.public_key()),
        roles: vec![NodeRole::NodeRelay as i32],
        max_connections: 128,
        bytes_per_second: 16777216,
    };
    let mut member = admin.clone();
    member.is_admin = false;
    assert!(store.register_node(&member, node.clone()).is_err());
    assert!(store.nodes(&member).is_err());
    store.register_node(&admin, node.clone())?;
    let mut alias = node;
    alias.id = random_id();
    assert!(store.register_node(&admin, alias).is_err());
    let challenge = store.node_challenge(&id, 1000000)?;
    let runtime = random_id();
    let proof = key.prove(&challenge, &runtime)?;
    let mut invalid_proof = proof.clone();
    invalid_proof.signature = vec![0; 64];
    assert!(store.issue_node_lease(&invalid_proof, 1000001).is_err());
    let first = store.issue_node_lease(&proof, 1000001)?;
    assert_eq!(first.lease_sequence, 1);
    assert!(!first.server_forwarding_allowed);
    assert!(store.node_lease_current(&first)?);
    assert!(store.issue_node_lease(&proof, 1000002).is_err());
    assert!(matches!(
        store.issue_node_lease(&proof, 1003001),
        Err(StorageError::Conflict)
    ));
    let expired = store.node_challenge(&id, 1003002)?;
    assert!(
        store
            .issue_node_lease(&key.prove(&expired, &runtime)?, 1008002)
            .is_err()
    );
    let next = store.node_challenge(&id, 1003002)?;
    let second = store.issue_node_lease(&key.prove(&next, &runtime)?, 1003003)?;
    assert_eq!(second.lease_sequence, 2);
    assert!(!store.node_lease_current(&first)?);
    assert!(store.revoke_node(&member, &id).is_err());
    store.revoke_node(&admin, &id)?;
    assert!(!store.node_lease_current(&second)?);
    assert!(store.node_challenge(&id, 1006003).is_err());
    Ok(())
}
#[test]
fn policy_updates_and_restore_epoch_invalidate_node_leases_and_old_proofs() -> Result {
    let mut store = Store::in_memory(&random_id())?;
    let vault = VaultKey::from_bytes([8; 32]);
    let dummy = hash_password("node-dummy-password")?;
    store.bootstrap_admin("administrator", "node-test-password")?;
    let admin = store
        .login(
            "administrator",
            "node-test-password",
            None,
            1000,
            &vault,
            &dummy,
        )?
        .principal;
    let key = NodeIdentity::generate();
    let id = random_id();
    store.register_node(
        &admin,
        NodeRegistration {
            id: id.clone(),
            name: "edge-1".into(),
            public_key: URL_SAFE_NO_PAD.encode(key.public_key()),
            roles: vec![NodeRole::NodeEdge as i32],
            max_connections: 1,
            bytes_per_second: 1024,
        },
    )?;
    let challenge = store.node_challenge(&id, 1000000)?;
    let runtime = random_id();
    let first = store.issue_node_lease(&key.prove(&challenge, &runtime)?, 1000001)?;
    store.apply_policy(
        1,
        NetworkPolicy {
            server_forwarding: ServerForwarding::Allow,
            ..NetworkPolicy::default()
        },
    )?;
    assert!(!store.node_lease_current(&first)?);
    let pending = store.node_challenge(&id, 1003002)?;
    let proof = key.prove(&pending, &runtime)?;
    let new = store.issue_node_lease(&proof, 1003003)?;
    assert!(new.server_forwarding_allowed);
    assert!(!new.public_ingress_allowed);
    let pending = store.node_challenge(&id, 1006004)?;
    let proof = key.prove(&pending, &runtime)?;
    let snapshot = store.snapshot()?;
    let mut restored = Store::from_snapshot(&snapshot, &store.deployment_id()?)?;
    restored.invalidate_after_restore()?;
    assert!(!restored.node_lease_current(&new)?);
    assert!(restored.issue_node_lease(&proof, 1006005).is_err());
    let fresh = restored.node_challenge(&id, 1006006)?;
    assert_ne!(fresh.security_epoch, pending.security_epoch);
    assert!(
        restored
            .issue_node_lease(&key.prove(&fresh, &random_id())?, 1006007)
            .is_ok()
    );
    Ok(())
}
