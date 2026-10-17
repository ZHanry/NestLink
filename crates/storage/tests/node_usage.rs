use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password, random_id};
use nestlink_identity::nodes::NodeIdentity;
use nestlink_protocol::{
    NodeLeaseClaims, NodeRole, NodeUsageClaims, SCHEMA_VERSION,
    api::{AuditActor, AuditQuery, NodeRegistration, NodeUsageQuery},
};
use nestlink_storage::{Store, accounts::Principal};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const PASSWORD: &str = "node-meter-test-password";
fn setup(mut s: Store) -> Result<(Store, Principal, NodeIdentity, String)> {
    s.bootstrap_admin("administrator", PASSWORD)?;
    let p = s
        .login(
            "administrator",
            PASSWORD,
            None,
            1000,
            &VaultKey::from_bytes([8; 32]),
            &hash_password(PASSWORD)?,
        )?
        .principal;
    let key = NodeIdentity::generate();
    let id = random_id();
    s.register_node(
        &p,
        NodeRegistration {
            id: id.clone(),
            name: "metered-node".into(),
            public_key: URL_SAFE_NO_PAD.encode(key.public_key()),
            roles: vec![NodeRole::NodeRelay as i32],
            max_connections: 2,
            bytes_per_second: 1024,
        },
    )?;
    Ok((s, p, key, id))
}
fn issue(
    s: &mut Store,
    key: &NodeIdentity,
    id: &str,
    runtime: &str,
    now: u64,
) -> Result<NodeLeaseClaims> {
    let c = s.node_challenge(id, now)?;
    Ok(s.issue_node_lease(&key.prove(&c, runtime)?, now + 1)?)
}
fn report(c: &NodeLeaseClaims) -> NodeUsageClaims {
    NodeUsageClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        node_id: c.node_id.clone(),
        runtime_id: c.runtime_id.clone(),
        runtime_generation: c.runtime_generation,
        policy_revision: c.policy_revision,
        lease_sequence: c.lease_sequence,
        report_sequence: 1,
        opened_connections: 1,
        closed_connections: 0,
        admitted_bytes: 512,
        sampled_at_unix_ms: c.issued_at_unix_ms + 1,
    }
}
fn query(s: &Store, after_generation: u64, limit: u16) -> Result<NodeUsageQuery> {
    Ok(NodeUsageQuery {
        security_epoch: s.security_epoch()?,
        after_generation,
        limit,
    })
}
#[test]
fn reports_are_signed_bounded_monotonic_and_duplicate_confirmation_survives_renewal() -> Result {
    let (mut s, p, key, id) = setup(Store::in_memory(&random_id())?)?;
    let runtime = random_id();
    let lease = issue(&mut s, &key, &id, &runtime, 1000000)?;
    let mut c = report(&lease);
    let signed = key.sign_usage(&c)?;
    let ack = s.accept_node_usage(&signed, 1000002)?;
    assert_eq!(s.accept_node_usage(&signed, 1000003)?, ack);
    let mut wrong = c.clone();
    wrong.admitted_bytes += 1;
    assert!(
        s.accept_node_usage(&key.sign_usage(&wrong)?, 1000003)
            .is_err()
    );
    assert!(
        s.accept_node_usage(&NodeIdentity::generate().sign_usage(&c)?, 1000003)
            .is_err()
    );
    let lease = issue(&mut s, &key, &id, &runtime, 1003001)?;
    assert_eq!(s.accept_node_usage(&signed, 1003003)?, ack);
    c.lease_sequence = lease.lease_sequence;
    c.report_sequence = 2;
    c.opened_connections = 3;
    c.closed_connections = 1;
    c.admitted_bytes = 1024;
    c.sampled_at_unix_ms = 1003003;
    s.accept_node_usage(&key.sign_usage(&c)?, 1003003)?;
    assert!(s.accept_node_usage(&signed, 1003004).is_err());
    for change in 0..9 {
        let mut invalid = c.clone();
        invalid.report_sequence = 3;
        match change {
            0 => invalid.report_sequence = 4,
            1 => invalid.opened_connections = 2,
            2 => invalid.closed_connections = 0,
            3 => invalid.admitted_bytes = 1000,
            4 => invalid.opened_connections = 4,
            5 => invalid.sampled_at_unix_ms = 1003002,
            6 => invalid.sampled_at_unix_ms = 1005005,
            7 => invalid.admitted_bytes = 100000,
            _ => invalid.lease_sequence = 1,
        }
        assert!(
            s.accept_node_usage(&key.sign_usage(&invalid)?, 1003004)
                .is_err(),
            "case {change}"
        );
    }
    let mut huge = signed.clone();
    huge.claims = vec![0; 4097];
    assert!(s.accept_node_usage(&huge, 1003004).is_err());
    assert!(s.accept_node_usage(&key.sign_usage(&c)?, 1003002).is_err());
    let page = s.node_usage(&p, &id, query(&s, 0, 100)?, 1003004)?;
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].report_sequence, 2);
    assert_eq!(page.entries[0].admitted_bytes, 1024);
    assert!(page.entries[0].current);
    Ok(())
}
#[test]
fn sqlite_reopen_preserves_generation_tombstones_counters_and_exact_confirmation() -> Result {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("node-meter.sqlite3");
    let deployment = random_id();
    let (mut s, p, key, id) = setup(Store::open(&path, &deployment)?)?;
    let runtime = random_id();
    let first = issue(&mut s, &key, &id, &runtime, 1000000)?;
    let signed = key.sign_usage(&report(&first))?;
    let ack = s.accept_node_usage(&signed, 1000002)?;
    drop(s);
    let mut s = Store::open_existing(&path, &deployment)?;
    assert_eq!(s.accept_node_usage(&signed, 1000003)?, ack);
    let new_runtime = random_id();
    let second = issue(&mut s, &key, &id, &new_runtime, 1003001)?;
    assert_eq!(second.runtime_generation, first.runtime_generation + 1);
    assert!(!s.node_lease_current(&first)?);
    assert!(s.accept_node_usage(&signed, 1003003).is_err());
    assert!(issue(&mut s, &key, &id, &runtime, 1006002).is_err());
    assert!(s.node_lease_current(&second)?);
    let page = s.node_usage(&p, &id, query(&s, 0, 1)?, 1003003)?;
    assert!(page.more);
    assert_eq!(page.next_generation, 1);
    assert_eq!(page.entries[0].admitted_bytes, 512);
    assert!(!page.entries[0].current);
    let page = s.node_usage(&p, &id, query(&s, page.next_generation, 1)?, 1003003)?;
    assert!(!page.more);
    assert_eq!(page.entries[0].report_sequence, 0);
    // ACK replay has not extended the ten-second node lease.
    assert!(issue(&mut s, &key, &id, &new_runtime, 1013002).is_err());
    let third = issue(&mut s, &key, &id, &random_id(), 1013002)?;
    assert_eq!(third.runtime_generation, 3);
    let events = s
        .query_audit(
            &p,
            AuditQuery {
                security_epoch: s.security_epoch()?,
                after_sequence: 0,
                limit: 100,
            },
            1013,
        )?
        .entries;
    let started: Vec<_> = events
        .iter()
        .filter(|e| e.event == "node_runtime_started")
        .collect();
    assert_eq!(started.len(), 3);
    assert!(
        matches!(&started[0].actor,AuditActor::Node {node_id,runtime_id,runtime_generation:1} if node_id==&id && runtime_id==&runtime)
    );
    Ok(())
}
#[test]
fn restore_policy_revocation_and_admin_query_boundaries_cannot_reanimate_old_reports() -> Result {
    let (mut s, p, key, id) = setup(Store::in_memory(&random_id())?)?;
    let runtime = random_id();
    let first = issue(&mut s, &key, &id, &runtime, 1000000)?;
    let signed = key.sign_usage(&report(&first))?;
    s.accept_node_usage(&signed, 1000002)?;
    let mut member = p.clone();
    member.is_admin = false;
    assert!(
        s.node_usage(&member, &id, query(&s, 0, 1)?, 1001000)
            .is_err()
    );
    for limit in [0, 101, u16::MAX] {
        assert!(
            s.node_usage(&p, &id, query(&s, 0, limit)?, 1001000)
                .is_err()
        );
    }
    assert!(
        s.node_usage(&p, &id, query(&s, u64::MAX, 1)?, 1001000)
            .is_err()
    );
    assert!(s.accept_node_usage(&signed, 1010001).is_err());
    let bytes = s.snapshot()?;
    let mut restored = Store::from_snapshot(&bytes, &s.deployment_id()?)?;
    restored.invalidate_after_restore()?;
    assert!(restored.accept_node_usage(&signed, 1000003).is_err());
    assert!(issue(&mut restored, &key, &id, &runtime, 1003001).is_err());
    let fresh = issue(&mut restored, &key, &id, &random_id(), 1003001)?;
    assert_eq!(fresh.runtime_generation, 2);
    let mut no_data = report(&fresh);
    no_data.opened_connections = 0;
    no_data.admitted_bytes = 0;
    restored.accept_node_usage(&key.sign_usage(&no_data)?, 1003003)?;
    s.apply_policy(
        1,
        nestlink_policy::NetworkPolicy {
            server_forwarding: nestlink_policy::ServerForwarding::Allow,
            ..Default::default()
        },
    )?;
    assert!(s.accept_node_usage(&signed, 1003003).is_err());
    assert!(!s.node_usage(&p, &id, query(&s, 0, 1)?, 1003003)?.entries[0].current);
    let mut forged = report(&first);
    forged.policy_revision = 2;
    assert!(
        s.accept_node_usage(&key.sign_usage(&forged)?, 1003003)
            .is_err()
    );
    s.revoke_node(&p, &id)?;
    assert!(issue(&mut s, &key, &id, &random_id(), 1003003).is_err());
    Ok(())
}
