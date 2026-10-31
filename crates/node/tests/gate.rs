use nestlink_identity::{
    PermitSigner, digest,
    nodes::{NodeIdentity, verify_lease, verify_proof},
};
use nestlink_node::gate::NodeGate;
use nestlink_protocol::{NodeChallenge, NodeLeaseClaims, NodeRole, SCHEMA_VERSION};
use nestlink_session::ClockSample;
use prost::Message;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn clock(monotonic_ms: u64, unix_ms: u64) -> ClockSample {
    ClockSample {
        monotonic_ms,
        unix_ms,
    }
}
fn challenge(key: &[u8; 32], request: u8, expires: u64) -> NodeChallenge {
    NodeChallenge {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 77,
        node_id: id(2),
        node_key_sha256: digest(key).to_vec(),
        request_id: id(request),
        nonce: vec![request; 32],
        expires_at_unix_ms: expires,
    }
}
fn claims(c: &NodeChallenge, sequence: u64, issued: u64) -> NodeLeaseClaims {
    NodeLeaseClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        node_id: c.node_id.clone(),
        node_key_sha256: c.node_key_sha256.clone(),
        request_id: c.request_id.clone(),
        nonce: c.nonce.clone(),
        roles: vec![NodeRole::NodeRelay as i32],
        policy_revision: 1,
        lease_sequence: sequence,
        issued_at_unix_ms: issued,
        expires_at_unix_ms: issued + 10000,
        server_forwarding_allowed: true,
        public_ingress_allowed: false,
        max_connections: 128,
        bytes_per_second: 16777216,
        runtime_id: id(9),
        runtime_generation: 1,
    }
}
#[test]
fn policy_key_and_domains_are_distinct_and_challenges_require_the_enrolled_key() -> Result {
    let master = PermitSigner::generate();
    let issuer = master.node_policy_signer()?;
    assert_ne!(master.public_key(), issuer.public_key());
    let node = NodeIdentity::generate();
    let c = challenge(&node.public_key(), 3, 6000);
    let proof = node.prove(&c, &id(9))?;
    verify_proof(&proof, &node.public_key())?;
    assert!(NodeIdentity::generate().prove(&c, &id(9)).is_err());
    let mut changed = proof.clone();
    changed.runtime_id = id(10);
    assert!(verify_proof(&changed, &node.public_key()).is_err());
    let mut changed = proof.clone();
    changed.challenge.as_mut().ok_or("missing challenge")?.nonce[0] ^= 1;
    assert!(verify_proof(&changed, &node.public_key()).is_err());
    let bytes = issuer.sign(&claims(&c, 1, 1000))?.encode_to_vec();
    assert!(verify_lease(&bytes, &master.public_key()).is_err());
    let mut corrupt = bytes.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(verify_lease(&corrupt, &issuer.public_key()).is_err());
    Ok(())
}
#[test]
fn delayed_responses_keep_the_original_monotonic_budget_and_expiry_is_terminal() -> Result {
    let issuer = PermitSigner::generate().node_policy_signer()?;
    let node = NodeIdentity::generate();
    let mut gate = NodeGate::new(
        id(1),
        id(2),
        id(9),
        node.public_key(),
        issuer.public_key(),
        vec![NodeRole::NodeRelay],
    )?;
    let c = challenge(&node.public_key(), 3, 6000);
    assert!(
        gate.authorize_forwarding(NodeRole::NodeRelay, false, clock(0, 1000))
            .is_err()
    );
    gate.accept(
        &issuer.sign(&claims(&c, 1, 1000))?.encode_to_vec(),
        &c,
        0,
        clock(2000, 3000),
    )?;
    assert_eq!(gate.deadline_ms(), 10000);
    assert!(
        gate.authorize_forwarding(NodeRole::NodeRelay, false, clock(9999, 10999))
            .is_ok()
    );
    assert!(
        gate.authorize_forwarding(NodeRole::NodeRelay, false, clock(10000, 11000))
            .is_err()
    );
    let next = challenge(&node.public_key(), 4, 14000);
    assert!(
        gate.accept(
            &issuer.sign(&claims(&next, 2, 11000))?.encode_to_vec(),
            &next,
            10001,
            clock(10001, 11001)
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn signed_wall_expiry_stops_a_node_before_monotonic_rounding_can_create_an_empty_query() -> Result {
    let issuer = PermitSigner::generate().node_policy_signer()?;
    let node = NodeIdentity::generate();
    let mut gate = NodeGate::new(
        id(1),
        id(2),
        id(9),
        node.public_key(),
        issuer.public_key(),
        vec![NodeRole::NodeRelay],
    )?;
    let first = challenge(&node.public_key(), 3, 6000);
    gate.accept(
        &issuer.sign(&claims(&first, 1, 1000))?.encode_to_vec(),
        &first,
        0,
        clock(0, 1000),
    )?;
    assert!(gate.current(clock(9998, 10999)).is_ok());
    let failure = gate.current(clock(9999, 11000));
    assert!(
        matches!(failure, Err(error) if error.code == nestlink_protocol::ErrorCode::LeaseExpired && error.reason == "node local lease deadline expired")
    );
    let next = challenge(&node.public_key(), 4, 14000);
    assert!(
        gate.accept(
            &issuer.sign(&claims(&next, 2, 11000))?.encode_to_vec(),
            &next,
            10000,
            clock(10000, 11001)
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn signed_wall_expiry_and_request_lifetime_independently_bound_a_delayed_lease() -> Result {
    let issuer = PermitSigner::generate().node_policy_signer()?;
    let node = NodeIdentity::generate();
    let fresh = || {
        NodeGate::new(
            id(1),
            id(2),
            id(9),
            node.public_key(),
            issuer.public_key(),
            vec![NodeRole::NodeRelay],
        )
    };
    let c = challenge(&node.public_key(), 3, 6000);
    let signed = issuer.sign(&claims(&c, 1, 1000))?.encode_to_vec();
    for (now, expected) in [
        (clock(600, 1000), 10000), // A lagging wall clock cannot extend request lifetime.
        (clock(600, 1600), 10000),
        (clock(600, 1700), 9900), // An earlier signed wall expiry still wins.
    ] {
        let mut gate = fresh()?;
        gate.accept(&signed, &c, 0, now)?;
        assert_eq!(gate.deadline_ms(), expected);
    }
    let mut gate = fresh()?;
    assert!(gate.accept(&signed, &c, 601, clock(600, 1600)).is_err());
    let mut gate = fresh()?;
    assert!(
        gate.accept(&signed, &c, u64::MAX - 500, clock(u64::MAX - 499, 1000))
            .is_err()
    );
    Ok(())
}
#[test]
fn replay_wrong_nonce_policy_change_and_clock_rollback_cannot_revive_authority() -> Result {
    let issuer = PermitSigner::generate().node_policy_signer()?;
    let node = NodeIdentity::generate();
    let fresh = || {
        NodeGate::new(
            id(1),
            id(2),
            id(9),
            node.public_key(),
            issuer.public_key(),
            vec![NodeRole::NodeRelay],
        )
    };
    let c = challenge(&node.public_key(), 3, 6000);
    let first = issuer.sign(&claims(&c, 1, 1000))?.encode_to_vec();
    let mut gate = fresh()?;
    gate.accept(&first, &c, 0, clock(1, 1001))?;
    assert!(gate.accept(&first, &c, 3000, clock(3000, 4000)).is_err());
    let next = challenge(&node.public_key(), 4, 9000);
    let second = issuer.sign(&claims(&next, 2, 4000))?.encode_to_vec();
    assert!(gate.accept(&second, &c, 3001, clock(3001, 4001)).is_err());
    gate.accept(&second, &next, 3002, clock(3002, 4002))?;
    assert!(gate.check_live(clock(3003, 4001)).is_err());
    assert!(
        gate.accept(&second, &next, 3004, clock(3004, 4004))
            .is_err()
    );
    let mut gate = fresh()?;
    gate.accept(&first, &c, 0, clock(1, 1001))?;
    let mut changed = claims(&next, 2, 4000);
    changed.policy_revision = 2;
    assert!(
        gate.accept(
            &issuer.sign(&changed)?.encode_to_vec(),
            &next,
            3000,
            clock(3001, 4001)
        )
        .is_err()
    );
    assert!(gate.current(clock(3002, 4002)).is_err());
    let mut gate = fresh()?;
    gate.accept(&first, &c, 0, clock(1, 1001))?;
    assert!(gate.check_live(clock(2, 5000)).is_err());
    Ok(())
}
#[test]
fn default_deny_role_and_public_ingress_limits_remain_independent() -> Result {
    let issuer = PermitSigner::generate().node_policy_signer()?;
    let node = NodeIdentity::generate();
    let mut gate = NodeGate::new(
        id(1),
        id(2),
        id(9),
        node.public_key(),
        issuer.public_key(),
        vec![NodeRole::NodeRelay],
    )?;
    let c = challenge(&node.public_key(), 3, 6000);
    let mut lease = claims(&c, 1, 1000);
    lease.server_forwarding_allowed = false;
    gate.accept(&issuer.sign(&lease)?.encode_to_vec(), &c, 0, clock(1, 1001))?;
    assert!(gate.current(clock(2, 1002)).is_ok());
    assert!(
        gate.authorize_forwarding(NodeRole::NodeRelay, false, clock(3, 1003))
            .is_err()
    );
    assert!(
        gate.authorize_forwarding(NodeRole::NodeEdge, true, clock(4, 1004))
            .is_err()
    );
    let mut bad = claims(&c, 2, 1000);
    bad.roles = vec![99];
    assert!(issuer.sign(&bad).is_err());
    let mut bad = claims(&c, 2, 1000);
    bad.expires_at_unix_ms = 11001;
    assert!(issuer.sign(&bad).is_err());
    Ok(())
}
#[test]
fn node_runtime_binding_and_generation_changes_cannot_be_accepted_as_renewal() -> Result {
    let issuer = PermitSigner::generate().node_policy_signer()?;
    let node = NodeIdentity::generate();
    let mut gate = NodeGate::new(
        id(1),
        id(2),
        id(9),
        node.public_key(),
        issuer.public_key(),
        vec![NodeRole::NodeRelay],
    )?;
    let c = challenge(&node.public_key(), 3, 6000);
    let mut lease = claims(&c, 1, 1000);
    lease.runtime_id = id(10);
    assert!(
        gate.accept(&issuer.sign(&lease)?.encode_to_vec(), &c, 0, clock(1, 1001))
            .is_err()
    );
    gate.accept(
        &issuer.sign(&claims(&c, 1, 1000))?.encode_to_vec(),
        &c,
        0,
        clock(1, 1001),
    )?;
    let next = challenge(&node.public_key(), 4, 9000);
    let mut changed = claims(&next, 2, 4000);
    changed.runtime_generation = 2;
    assert!(
        gate.accept(
            &issuer.sign(&changed)?.encode_to_vec(),
            &next,
            3000,
            clock(3001, 4001)
        )
        .is_err()
    );
    assert!(gate.current(clock(3002, 4002)).is_err());
    Ok(())
}
#[test]
fn usage_report_and_confirmation_signatures_cannot_be_used_as_node_proofs_or_policy_leases()
-> Result {
    use nestlink_identity::nodes::{verify_usage, verify_usage_ack};
    use nestlink_protocol::{
        NodeUsageAckClaims, NodeUsageClaims, SignedNodeUsage, SignedNodeUsageAck,
    };
    let issuer = PermitSigner::generate().node_policy_signer()?;
    let node = NodeIdentity::generate();
    let challenge = challenge(&node.public_key(), 3, 6000);
    let proof = node.prove(&challenge, &id(9))?;
    let report = NodeUsageClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 77,
        node_id: id(2),
        runtime_id: id(9),
        runtime_generation: 1,
        policy_revision: 1,
        lease_sequence: 1,
        report_sequence: 1,
        opened_connections: 0,
        closed_connections: 0,
        admitted_bytes: 0,
        sampled_at_unix_ms: 1001,
    };
    let signed = node.sign_usage(&report)?;
    verify_usage(&signed, &node.public_key())?;
    let swapped = SignedNodeUsage {
        claims: signed.claims.clone(),
        signature: proof.signature.clone(),
    };
    assert!(verify_usage(&swapped, &node.public_key()).is_err());
    let mut swapped = proof;
    swapped.signature = signed.signature;
    assert!(verify_proof(&swapped, &node.public_key()).is_err());
    let ack = NodeUsageAckClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 77,
        node_id: id(2),
        runtime_id: id(9),
        runtime_generation: 1,
        report_sequence: 1,
        report_sha256: digest(&signed.claims).to_vec(),
        accepted_at_unix_ms: 1002,
    };
    let signed_ack = issuer.sign_usage_ack(&ack)?;
    assert_eq!(verify_usage_ack(&signed_ack, &issuer.public_key())?, ack);
    assert!(verify_lease(&signed_ack.encode_to_vec(), &issuer.public_key()).is_err());
    let lease = issuer.sign(&claims(&challenge, 1, 1000))?;
    assert!(
        verify_usage_ack(
            &SignedNodeUsageAck {
                claims: lease.claims,
                signature: lease.signature
            },
            &issuer.public_key()
        )
        .is_err()
    );
    Ok(())
}
