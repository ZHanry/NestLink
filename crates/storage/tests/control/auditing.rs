use super::*;
use nestlink_protocol::api::{AuditActor, AuditQuery, AuditRetentionUpdate};

fn query(s: &Store, after: u64, limit: u16) -> Result<AuditQuery> {
    Ok(AuditQuery {
        security_epoch: s.security_epoch()?,
        after_sequence: after,
        limit,
    })
}
pub(super) fn mutate(s: &Store, sql: &str) -> Result<Store> {
    let snapshot = s.snapshot()?;
    let mut db = rusqlite::Connection::open_in_memory()?;
    db.deserialize_read_exact(rusqlite::MAIN_DB, &snapshot[..], snapshot.len(), false)?;
    db.execute_batch(sql)?;
    let bytes = db.serialize(rusqlite::MAIN_DB)?;
    Ok(Store::from_snapshot(&bytes, &s.deployment_id()?)?)
}
#[test]
fn audit_visibility_uses_live_database_role_and_session_not_supplied_admin_flag() -> Result {
    let (mut s, vault, dummy, admin, mut member) = fixture()?;
    let count = s.audit_count()?;
    member.is_admin = true;
    assert!(
        s.create_member(&member, "forged-admin-member", PASSWORD)
            .is_err()
    );
    assert!(s.disable_account(&member, &admin.account_id).is_err());
    assert!(s.accounts(&member).is_err());
    assert!(s.nodes(&member).is_err());
    assert!(s.path_limits(&member).is_err());
    assert_eq!(s.audit_count()?, count);
    assert!(matches!(
        s.query_audit(&member, query(&s, 0, 100)?, 1001),
        Err(StorageError::Forbidden)
    ));
    assert!(s.audit_retention(&member, 1001).is_err());
    assert!(
        s.set_audit_retention(
            &member,
            AuditRetentionUpdate {
                expected_revision: 1,
                retention_seconds: 3600
            },
            1001
        )
        .is_err()
    );
    let demoted = mutate(&s, "UPDATE account_security SET is_admin=0;")?;
    assert!(
        demoted
            .query_audit(&admin, query(&demoted, 0, 100)?, 1001)
            .is_err()
    );
    assert!(s.query_audit(&admin, query(&s, 0, 100)?, 1300).is_err());
    let epoch = s.security_epoch()?;
    s.invalidate_after_restore()?;
    let refreshed = s
        .login("admin", PASSWORD, None, 1002, &vault, &dummy)?
        .principal;
    assert!(matches!(
        s.query_audit(
            &refreshed,
            AuditQuery {
                security_epoch: epoch,
                after_sequence: 0,
                limit: 100
            },
            1002
        ),
        Err(StorageError::Conflict)
    ));
    let current = query(&s, 0, 100)?;
    s.logout(&refreshed)?;
    assert!(s.query_audit(&refreshed, current, 1002).is_err());
    Ok(())
}
#[test]
fn audit_pages_are_bounded_ordered_and_retention_updates_are_transactional() -> Result {
    let (mut s, _, _, admin, _) = fixture()?;
    let (mut revision, policy) = s.policy()?;
    for _ in 0..8 {
        revision = s.apply_policy(revision, policy)?;
    }
    let first = s.query_audit(&admin, query(&s, 0, 2)?, 1001)?;
    assert_eq!(first.entries.len(), 2);
    assert!(first.more);
    let second = s.query_audit(&admin, query(&s, first.next_sequence, 2)?, 1001)?;
    assert!(
        second
            .entries
            .iter()
            .all(|e| e.sequence > first.next_sequence)
    );
    assert!(
        second
            .entries
            .windows(2)
            .all(|p| p[0].sequence < p[1].sequence)
    );
    let text = serde_json::to_string(&first)?;
    assert!(!text.contains(PASSWORD));
    assert!(!text.contains("argon2"));
    for limit in [0, 101, u16::MAX] {
        assert!(s.query_audit(&admin, query(&s, 0, limit)?, 1001).is_err());
    }
    assert!(
        s.query_audit(&admin, query(&s, u64::MAX, 1)?, 1001)
            .is_err()
    );
    assert!(
        s.query_audit(&admin, query(&s, first.high_watermark + 1, 1)?, 1001)
            .is_err()
    );
    let count = s.audit_count()?;
    assert!(matches!(
        s.set_audit_retention(
            &admin,
            AuditRetentionUpdate {
                expected_revision: 0,
                retention_seconds: 3600
            },
            1001
        ),
        Err(StorageError::Conflict)
    ));
    assert!(
        s.set_audit_retention(
            &admin,
            AuditRetentionUpdate {
                expected_revision: 1,
                retention_seconds: 3599
            },
            1001
        )
        .is_err()
    );
    assert!(
        s.set_audit_retention(
            &admin,
            AuditRetentionUpdate {
                expected_revision: 1,
                retention_seconds: 31_536_001
            },
            1001
        )
        .is_err()
    );
    assert_eq!(s.audit_count()?, count);
    let changed = s.set_audit_retention(
        &admin,
        AuditRetentionUpdate {
            expected_revision: 1,
            retention_seconds: 3600,
        },
        1001,
    )?;
    assert_eq!(changed.revision, 2);
    assert_eq!(changed.retention_seconds, 3600);
    assert_eq!(s.audit_count()?, count + 1);
    assert!(
        s.set_audit_retention(
            &admin,
            AuditRetentionUpdate {
                expected_revision: 1,
                retention_seconds: 7200
            },
            1001
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn bounded_retention_persists_cursor_and_does_not_reuse_sequence_after_emptying() -> Result {
    let (mut s, vault, dummy, admin, _) = fixture()?;
    let (mut revision, policy) = s.policy()?;
    for _ in 0..600 {
        revision = s.apply_policy(revision, policy)?;
    }
    s.set_audit_retention(
        &admin,
        AuditRetentionUpdate {
            expected_revision: 1,
            retention_seconds: 3600,
        },
        1001,
    )?;
    let high = s.audit_retention(&admin, 1001)?.high_watermark;
    s = mutate(&s, "UPDATE audit SET created_at=500;")?;
    assert_eq!(s.cleanup_audit(4099, 500)?, 0);
    assert_eq!(s.cleanup_audit(4100, 500)?, 500);
    assert_eq!(s.audit_count()?, high - 500);
    let gap = s.query_audit(&admin, query(&s, 0, 100)?, 1001)?;
    assert!(gap.history_pruned);
    assert_eq!(gap.pruned_through, 500);
    assert_eq!(gap.high_watermark, high);
    assert!(s.cleanup_audit(4099, 500).is_err());
    assert!(s.cleanup_audit(4100, 0).is_err());
    assert!(s.cleanup_audit(4100, 501).is_err());
    let deployment = s.deployment_id()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("audit.sqlite3");
    std::fs::write(&path, &*s.snapshot()?)?;
    s = Store::open_existing(&path, &deployment)?;
    assert_eq!(s.cleanup_audit(4100, 500)?, high - 500);
    assert_eq!(s.audit_count()?, 0);
    drop(s);
    s = Store::open_existing(&path, &deployment)?;
    let empty = s.query_audit(&admin, query(&s, 0, 100)?, 1001)?;
    assert_eq!(empty.next_sequence, high);
    assert_eq!(empty.high_watermark, high);
    assert!(empty.history_pruned);
    assert!(!empty.more);
    assert!(empty.entries.is_empty());
    let login = s.login("admin", PASSWORD, None, 4100, &vault, &dummy)?;
    let page = s.query_audit(&login.principal, query(&s, high, 100)?, 4100)?;
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].sequence, high + 1);
    assert!(!page.history_pruned);
    Ok(())
}
#[test]
fn audit_counter_exhaustion_rolls_back_the_business_transaction() -> Result {
    let (s, _, _, admin, _) = fixture()?;
    let (revision, policy) = s.policy()?;
    let mut s = mutate(
        &s,
        "UPDATE audit_settings SET high_watermark=9223372036854775807;",
    )?;
    let count = s.audit_count()?;
    assert!(matches!(
        s.apply_policy(revision, policy),
        Err(StorageError::Conflict)
    ));
    assert_eq!(s.policy()?.0, revision);
    assert_eq!(s.audit_count()?, count);
    assert_eq!(
        s.audit_retention(&admin, 1001)?.high_watermark,
        i64::MAX as u64
    );
    Ok(())
}

#[test]
fn actor_identity_distinguishes_login_attempts_sessions_and_local_operations() -> Result {
    let (mut s, vault, dummy, admin, member) = fixture()?;
    assert!(
        s.login("member", "wrong-test-password", None, 1001, &vault, &dummy)
            .is_err()
    );
    assert!(
        s.login("unknown-login-name", PASSWORD, None, 1001, &vault, &dummy)
            .is_err()
    );
    let login = s.login("admin", PASSWORD, None, 1001, &vault, &dummy)?;
    let refreshed = s.refresh_login(login.refresh_token.expose(), login.generation, 1002)?;
    s.logout(&refreshed.principal)?;
    let (revision, policy) = s.policy()?;
    s.apply_policy(revision, policy)?;
    let page = s.query_audit(&admin, query(&s, 0, 100)?, 1002)?;
    assert_eq!(page.entries[0].actor, AuditActor::LocalOperator);
    let failed: Vec<_> = page
        .entries
        .iter()
        .filter(|e| e.event == "login_failed")
        .collect();
    assert_eq!(failed.len(), 2);
    assert!(
        failed
            .iter()
            .all(|e| e.actor == AuditActor::Unauthenticated)
    );
    assert_eq!(failed[0].resource_id, member.account_id);
    assert_eq!(failed[1].resource_id, "login");
    let expected = AuditActor::Management {
        account_id: admin.account_id.clone(),
        session_id: login.principal.session_id.clone(),
    };
    for event in ["login_refreshed", "login_revoked"] {
        assert_eq!(
            page.entries
                .iter()
                .find(|e| e.event == event)
                .ok_or("missing login lifecycle event")?
                .actor,
            expected
        );
    }
    assert_eq!(
        page.entries.last().ok_or("empty page")?.actor,
        AuditActor::LocalOperator
    );
    let text = serde_json::to_string(&page)?;
    for secret in [
        PASSWORD,
        "unknown-login-name",
        "wrong-test-password",
        login.access_token.expose(),
        login.refresh_token.expose(),
    ] {
        assert!(!text.contains(secret));
    }
    Ok(())
}

#[test]
fn remote_audit_binds_verified_host_proof_and_retries_do_not_duplicate_events() -> Result {
    let (mut s, _, _, admin, owner) = fixture()?;
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let c = enroll(&mut s, &admin, &controller, "controller")?;
    let h = enroll(&mut s, &owner, &host, "host")?;
    let request = RemoteRequest {
        id: random_id(),
        controller_device_id: c.clone(),
        host_device_id: h.clone(),
        permissions: vec![Permission::View as i32],
        path_mode: "direct_only".into(),
    };
    s.create_remote(&admin, request.clone(), 1001)?;
    let count = s.audit_count()?;
    s.create_remote(&admin, request.clone(), 1001)?;
    assert_eq!(s.audit_count()?, count);
    let choice = ApprovalChoice {
        approved: true,
        permissions: vec![Permission::View as i32],
        paths: vec![1],
    };
    let proof = s.approval_transcript(&owner, &request.id, &choice, 1001)?;
    let signature = URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?);
    s.approve_remote(&owner, &request.id, choice, &signature, 1001)?;
    s.initial_permit(&admin, &request.id, 1001)?;
    let count = s.audit_count()?;
    s.initial_permit(&admin, &request.id, 1001)?;
    assert_eq!(s.audit_count()?, count);
    s.revoke_remote(&owner, &request.id)?;
    let count = s.audit_count()?;
    s.revoke_remote(&owner, &request.id)?;
    assert_eq!(s.audit_count()?, count);
    let page = s.query_audit(&admin, query(&s, 0, 100)?, 1001)?;
    let event = |name: &str| {
        page.entries
            .iter()
            .find(|e| e.event == name && e.resource_id == request.id)
            .ok_or("missing remote event")
    };
    assert_eq!(
        event("remote_requested")?.actor,
        AuditActor::Management {
            account_id: admin.account_id.clone(),
            session_id: admin.session_id.clone()
        }
    );
    assert_eq!(
        event("remote_approved")?.actor,
        AuditActor::Device {
            account_id: owner.account_id.clone(),
            session_id: owner.session_id.clone(),
            device_id: h.clone()
        }
    );
    assert_eq!(
        event("remote_permit_issued")?.actor,
        AuditActor::Management {
            account_id: admin.account_id.clone(),
            session_id: admin.session_id.clone()
        }
    );
    assert_eq!(
        event("remote_revoked")?.actor,
        AuditActor::Management {
            account_id: owner.account_id.clone(),
            session_id: owner.session_id.clone()
        }
    );
    let enrolled = page
        .entries
        .iter()
        .find(|e| e.event == "device_registered" && e.resource_id == c)
        .ok_or("missing enrollment")?;
    assert_eq!(
        enrolled.actor,
        AuditActor::Device {
            account_id: admin.account_id,
            session_id: admin.session_id,
            device_id: c
        }
    );
    assert!(!serde_json::to_string(&page)?.contains(&signature));
    Ok(())
}

#[test]
fn invalid_actor_association_rolls_back_and_management_policy_uses_live_role() -> Result {
    let (mut s, _, _, admin, mut member) = fixture()?;
    let mut mismatched = admin.clone();
    mismatched.account_id = member.account_id.clone();
    let count = s.audit_count()?;
    assert!(
        s.create_member(&mismatched, "should-not-exist", PASSWORD)
            .is_err()
    );
    assert_eq!(s.audit_count()?, count);
    assert!(
        !s.accounts(&admin)?
            .iter()
            .any(|a| a.name == "should-not-exist")
    );
    let (revision, policy) = s.policy()?;
    member.is_admin = true;
    assert!(matches!(
        s.apply_policy_as(&member, 1001, revision, policy),
        Err(StorageError::Forbidden)
    ));
    assert_eq!(s.policy()?.0, revision);
    s.apply_policy_as(&admin, 1001, revision, policy)?;
    let entry = s
        .query_audit(&admin, query(&s, 0, 100)?, 1001)?
        .entries
        .pop()
        .ok_or("missing policy event")?;
    assert_eq!(
        entry.actor,
        AuditActor::Management {
            account_id: admin.account_id.clone(),
            session_id: admin.session_id.clone()
        }
    );
    let key = InstallationIdentity::generate();
    let id = enroll(&mut s, &admin, &key, "managed")?;
    let request = random_id();
    s.revoke_device_as(&admin, &request, &id, 1001)?;
    let count = s.audit_count()?;
    s.revoke_device_as(&admin, &request, &id, 1001)?;
    assert_eq!(s.audit_count()?, count);
    let entry = s
        .query_audit(&admin, query(&s, 0, 100)?, 1001)?
        .entries
        .pop()
        .ok_or("missing revoke event")?;
    assert_eq!(
        entry.actor,
        AuditActor::Management {
            account_id: admin.account_id.clone(),
            session_id: admin.session_id.clone()
        }
    );
    s.logout(&admin)?;
    assert!(
        s.apply_policy_as(&admin, 1001, revision + 1, policy)
            .is_err()
    );
    Ok(())
}
