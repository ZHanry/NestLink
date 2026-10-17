use super::*;
use nestlink_identity::{
    node_closes::verify_relay_close_ack, nodes::NodePolicySigner, relay::allocation_binding,
};
use nestlink_protocol::{RelayCloseClaims, SignedRelayClose};
fn close(node: &NodeIdentity, c: &RelayAllocationClaims, now: u64) -> Result<SignedRelayClose> {
    Ok(node.sign_relay_close(&RelayCloseClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        node_id: c.node_id.clone(),
        runtime_id: c.runtime_id.clone(),
        runtime_generation: c.runtime_generation,
        allocation_id: c.allocation_id.clone(),
        allocation_binding_sha256: allocation_binding(c)?.to_vec(),
        observed_grant_sequence: c.grant_sequence,
        opened_connections: 2,
        closed_connections: 2,
        admitted_bytes: 42,
        closed_at_unix_ms: now,
    })?)
}
#[test]
fn close_releases_exact_capacity_once_and_preserves_signed_ack_and_node_audit() -> Result {
    let mut f = Fixture::new(false, 4)?;
    f.quota(1, 2)?;
    let grant = f.allocation()?;
    let signed = close(&f.node, &grant, NOW)?;
    assert!(f.allocation().is_err());
    let count = f.s.audit_count()?;
    let ack = f.s.accept_relay_close(&f.lifecycle, &signed, NOW)?;
    assert_eq!(ack.released_endpoint_slots, 2);
    assert_eq!(f.usage(NOW)?.held_allocations, 0);
    assert_eq!(f.s.audit_count()?, count + 1);
    let policy = NodePolicySigner::from_master_seed(&[8; 32])?;
    let original_ack = policy.sign_relay_close_ack(&ack)?;
    assert_eq!(
        verify_relay_close_ack(&original_ack, &policy.public_key(), &signed)?,
        ack
    );
    let retry = f.s.accept_relay_close(&f.lifecycle, &signed, NOW)?;
    assert_eq!(policy.sign_relay_close_ack(&retry)?, original_ack);
    assert_eq!(f.s.audit_count()?, count + 1);
    let actor: nestlink_protocol::api::AuditActor =
        serde_json::from_str(&f.s.connection.query_row(
            "SELECT actor_json FROM audit WHERE event='node_relay_closed'",
            [],
            |r| r.get::<_, String>(0),
        )?)?;
    assert_eq!(
        actor,
        nestlink_protocol::api::AuditActor::Node {
            node_id: grant.node_id.clone(),
            runtime_id: grant.runtime_id.clone(),
            runtime_generation: grant.runtime_generation
        }
    );
    let old_request = f.request(&grant.allocation_id)?;
    assert!(
        f.s.reserve_node_relay(
            &f.lifecycle,
            &f.admin,
            &f.permit.session_id,
            old_request,
            NOW
        )
        .is_err()
    );
    f.allocation()?; // Only a fresh UUID may reuse the now-released capacity.
    Ok(())
}
#[test]
fn close_rejects_wrong_node_binding_runtime_sequence_and_changed_retry_without_refund() -> Result {
    let mut f = Fixture::new(false, 8)?;
    let grant = f.allocation()?;
    let signed = close(&f.node, &grant, NOW)?;
    let original =
        nestlink_identity::node_closes::verify_relay_close(&signed, &f.node.public_key())?;
    let mut wrong = signed.clone();
    wrong.signature[0] ^= 1;
    assert!(f.s.accept_relay_close(&f.lifecycle, &wrong, NOW).is_err());
    for variant in 0..5 {
        let mut c = original.clone();
        match variant {
            0 => c.allocation_binding_sha256[0] ^= 1,
            1 => c.runtime_id = random_id(),
            2 => c.observed_grant_sequence += 1,
            3 => c.admitted_bytes = grant.bytes_per_allocation + 1,
            _ => c.allocation_id = random_id(),
        }
        assert!(
            f.s.accept_relay_close(&f.lifecycle, &f.node.sign_relay_close(&c)?, NOW)
                .is_err()
        );
        assert_eq!(f.usage(NOW)?.held_allocations, 1);
    }
    f.s.accept_relay_close(&f.lifecycle, &signed, NOW)?;
    let mut changed = original;
    changed.admitted_bytes += 1;
    assert!(matches!(
        f.s.accept_relay_close(&f.lifecycle, &f.node.sign_relay_close(&changed)?, NOW),
        Err(StorageError::Conflict)
    ));
    Ok(())
}
#[test]
fn revoked_node_and_session_may_report_their_retired_fact_without_new_authority() -> Result {
    let mut f = Fixture::new(false, 8)?;
    let grant = f.allocation()?;
    let signed = close(&f.node, &grant, NOW)?;
    f.s.revoke_remote(&f.admin, &f.permit.session_id)?;
    f.s.revoke_node(&f.admin, &f.node_id)?;
    assert_eq!(f.usage(NOW)?.held_allocations, 1);
    f.s.accept_relay_close(&f.lifecycle, &signed, NOW)?;
    assert_eq!(f.usage(NOW)?.held_allocations, 0);
    assert!(f.allocation().is_err());
    Ok(())
}
#[test]
fn retired_node_runtime_can_release_only_its_old_allocation_and_not_the_successor() -> Result {
    let mut f = Fixture::new(false, 8)?;
    let old = f.allocation()?;
    let challenge = f.s.node_challenge(&f.node_id, NOW)?;
    let successor = random_id();
    f.s.issue_node_lease(&f.node.prove(&challenge, &successor)?, NOW)?;
    f.node_runtime = successor;
    let current = f.allocation()?;
    assert!(current.runtime_generation > old.runtime_generation);
    f.s.accept_relay_close(&f.lifecycle, &close(&f.node, &old, NOW)?, NOW)?;
    assert_eq!(f.usage(NOW)?.held_allocations, 1);
    assert_eq!(f.resource_snapshot(NOW)?.allocations, vec![current]);
    Ok(())
}
#[test]
fn already_expired_promise_records_zero_released_slots_without_extending_any_authority() -> Result {
    let mut f = Fixture::new(false, 8)?;
    let grant = f.allocation()?;
    let later = grant.expires_at_unix_ms + HOLD_MARGIN_MS + 1;
    f.at(later);
    let ack =
        f.s.accept_relay_close(&f.lifecycle, &close(&f.node, &grant, later)?, later)?;
    assert_eq!(ack.released_endpoint_slots, 0);
    assert_eq!(f.usage(later)?.held_allocations, 0);
    let request = f.request(&random_id())?;
    assert!(matches!(
        f.s.reserve_node_relay(&f.lifecycle, &f.admin, &f.permit.session_id, request, later),
        Err(StorageError::Forbidden)
    ));
    f.lifecycle.check_clock(later)?;
    Ok(())
}
#[test]
fn old_observed_grant_can_close_latest_renewal_and_close_wins_the_other_order() -> Result {
    for close_first in [false, true] {
        let mut f = Fixture::new(false, 8)?;
        let old = f.allocation()?;
        let next = NOW + 6000;
        let signed = close(&f.node, &old, next)?;
        f.renew(next)?;
        let request = f.request(&old.allocation_id)?;
        if close_first {
            f.s.accept_relay_close(&f.lifecycle, &signed, next)?;
            assert!(
                f.s.reserve_node_relay(&f.lifecycle, &f.admin, &f.permit.session_id, request, next)
                    .is_err()
            );
        } else {
            let current = f.s.reserve_node_relay(
                &f.lifecycle,
                &f.admin,
                &f.permit.session_id,
                request,
                next,
            )?;
            assert!(current.grant_sequence > old.grant_sequence);
            assert_eq!(allocation_binding(&current)?, allocation_binding(&old)?);
            f.s.accept_relay_close(&f.lifecycle, &signed, next)?;
        }
        assert_eq!(f.usage(next)?.held_allocations, 0);
    }
    Ok(())
}
#[test]
fn audit_failure_rolls_back_close_capacity_and_receipt_together() -> Result {
    let mut f = Fixture::new(false, 8)?;
    let grant = f.allocation()?;
    let signed = close(&f.node, &grant, NOW)?;
    f.s.connection
        .execute("UPDATE audit_settings SET high_watermark=?1", [i64::MAX])?;
    assert!(f.s.accept_relay_close(&f.lifecycle, &signed, NOW).is_err());
    assert_eq!(f.usage(NOW)?.held_allocations, 1);
    assert_eq!(
        f.s.connection
            .query_row("SELECT count(*) FROM relay_close_receipts", [], |r| r
                .get::<_, u64>(0))?,
        0
    );
    f.s.connection
        .execute("UPDATE audit_settings SET high_watermark=10000", [])?;
    f.s.accept_relay_close(&f.lifecycle, &signed, NOW)?;
    assert_eq!(f.usage(NOW)?.held_allocations, 0);
    Ok(())
}
#[test]
fn restart_preserves_exact_ack_but_new_cleanup_cannot_bypass_unknown_promise_fence() -> Result {
    let mut f = Fixture::new(false, 8)?;
    let accepted = f.allocation()?;
    let pending = f.allocation()?;
    let signed = close(&f.node, &accepted, NOW)?;
    let ack = f.s.accept_relay_close(&f.lifecycle, &signed, NOW)?;
    let snapshot = f.s.snapshot()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("control.sqlite3");
    std::fs::write(&path, &snapshot[..])?;
    let mut reopened = Store::open_existing(&path, &f.s.deployment_id()?)?;
    let lifecycle = reopened.relay_lifecycle(NOW)?;
    assert_eq!(reopened.accept_relay_close(&lifecycle, &signed, NOW)?, ack);
    assert!(
        reopened
            .accept_relay_close(&lifecycle, &close(&f.node, &pending, NOW)?, NOW)
            .is_err()
    );
    assert_eq!(
        reopened
            .relay_reservation_usage(&f.admin, NOW)?
            .held_allocations,
        1
    );
    reopened.invalidate_after_restore()?;
    let restored = reopened.relay_lifecycle(NOW)?;
    assert!(
        reopened
            .accept_relay_close(&restored, &signed, NOW)
            .is_err()
    );
    assert_eq!(
        reopened
            .connection
            .query_row("SELECT count(*) FROM relay_close_receipts", [], |r| r
                .get::<_, u64>(0))?,
        1
    );
    Ok(())
}
