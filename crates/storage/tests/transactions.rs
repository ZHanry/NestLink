#![allow(clippy::unwrap_used, clippy::expect_used)]
use nestlink_policy::{NetworkPolicy, PeerPathMode, PublicIngress, ServerForwarding};
use nestlink_storage::Store;
use rusqlite::Connection;

fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn fixture() -> Store {
    let mut store = Store::in_memory(&id(1)).unwrap();
    store.add_account(&id(2), "owner").unwrap();
    store.add_account(&id(3), "other").unwrap();
    store.add_device(&id(4), &id(2), &[4; 32]).unwrap();
    store.add_device(&id(5), &id(2), &[5; 32]).unwrap();
    store
        .register_credential(&id(6), &id(4), "background", &[6; 32])
        .unwrap();
    store
        .register_approved_session(&id(7), &id(4), &id(5))
        .unwrap();
    store.add_lease(&id(8), &id(7)).unwrap();
    store
}

#[test]
fn refresh_has_single_consumer_and_enforces_device_purpose_and_generation() {
    let mut store = fixture();
    assert!(
        store
            .rotate_credential(&id(6), &id(5), "background", 1, &[6; 32], &[9; 32])
            .is_err()
    );
    assert!(
        store
            .rotate_credential(&id(6), &id(4), "management", 1, &[6; 32], &[9; 32])
            .is_err()
    );
    assert_eq!(
        store
            .rotate_credential(&id(6), &id(4), "background", 1, &[6; 32], &[9; 32])
            .unwrap(),
        2
    );
    assert!(
        store
            .rotate_credential(&id(6), &id(4), "background", 1, &[6; 32], &[10; 32])
            .is_err()
    );
    assert_eq!(store.audit_count().unwrap(), 1);
}

#[test]
fn device_revoke_is_atomic_account_scoped_and_idempotent() {
    let mut store = fixture();
    assert!(store.revoke_device(&id(9), &id(4), &id(3)).is_err());
    assert!(store.session_is_active(&id(7)).unwrap());
    store.revoke_device(&id(9), &id(4), &id(2)).unwrap();
    assert!(!store.session_is_active(&id(7)).unwrap());
    assert!(!store.lease_is_active(&id(8)).unwrap());
    assert!(
        store
            .rotate_credential(&id(6), &id(4), "background", 1, &[6; 32], &[9; 32])
            .is_err()
    );
    assert!(store.add_lease(&id(10), &id(7)).is_err());
    store.revoke_device(&id(9), &id(4), &id(2)).unwrap();
    assert_eq!(store.audit_count().unwrap(), 1);
    assert!(store.revoke_device(&id(9), &id(5), &id(2)).is_err());
}

#[test]
fn policy_updates_validate_complete_config_and_compare_revision_atomically() {
    let mut store = fixture();
    assert_eq!(store.policy().unwrap(), (1, NetworkPolicy::default()));
    let invalid = NetworkPolicy {
        peer_path_mode: PeerPathMode::RelayOnly,
        ..NetworkPolicy::default()
    };
    assert!(store.apply_policy(1, invalid).is_err());
    assert_eq!(store.policy().unwrap().0, 1);
    assert!(store.lease_is_active(&id(8)).unwrap());
    let allowed = NetworkPolicy {
        server_forwarding: ServerForwarding::Allow,
        peer_path_mode: PeerPathMode::DirectOnly,
        public_ingress: PublicIngress::Enabled,
    };
    assert_eq!(store.apply_policy(1, allowed).unwrap(), 2);
    assert!(!store.lease_is_active(&id(8)).unwrap());
    assert!(!store.session_is_active(&id(7)).unwrap());
    assert!(store.apply_policy(1, NetworkPolicy::default()).is_err());
    assert_eq!(store.policy().unwrap(), (2, allowed));
}

#[test]
fn restore_uses_fresh_epoch_and_invalidates_every_old_credential_and_lease() {
    let mut store = fixture();
    let old = store.security_epoch().unwrap();
    let fresh = store.invalidate_after_restore().unwrap();
    assert_ne!(old, fresh);
    assert!(!store.session_is_active(&id(7)).unwrap());
    assert!(!store.lease_is_active(&id(8)).unwrap());
    assert!(
        store
            .rotate_credential(&id(6), &id(4), "background", 1, &[6; 32], &[9; 32])
            .is_err()
    );
    assert_ne!(store.invalidate_after_restore().unwrap(), fresh);
}

#[test]
fn foreign_database_is_refused_without_mutating_it() {
    let path =
        std::env::temp_dir().join(format!("nestlink-foreign-{}.sqlite3", std::process::id()));
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE old_identity(id INTEGER); INSERT INTO old_identity VALUES(14);")
        .unwrap();
    assert!(Store::open(&path, &id(1)).is_err());
    let count: i64 = db
        .query_row("SELECT count(*) FROM old_identity", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let app: i32 = db
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .unwrap();
    assert_eq!(app, 0);
    drop(db);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn key_uniqueness_and_foreign_keys_prevent_installation_aliasing() {
    let mut store = fixture();
    assert!(store.add_device(&id(10), &id(2), &[4; 32]).is_err());
    assert!(store.add_device(&id(10), &id(11), &[10; 32]).is_err());
    assert!(
        store
            .register_approved_session(&id(10), &id(4), &id(4))
            .is_err()
    );
}
