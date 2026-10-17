use super::*;
use nestlink_protocol::api::{AuditActor, AuditQuery, RelayQuotaUpdate};

#[test]
fn persistent_relay_quota_is_revision_checked_admin_only_and_audited_atomically() -> Result {
    let (mut s, _, _, admin, mut member) = fixture()?;
    let initial = s.relay_quota(&admin, 1001)?;
    assert_eq!(
        (
            initial.revision,
            initial.limits.max_allocations,
            initial.limits.max_account_endpoints,
            initial.limits.bytes_per_second,
            initial.limits.bytes_per_allocation
        ),
        (1, 128, 16, 16 * 1024 * 1024, 1024 * 1024 * 1024)
    );
    member.is_admin = true;
    assert!(s.relay_quota(&member, 1001).is_err());
    let update = || RelayQuotaUpdate {
        expected_revision: initial.revision,
        limits: initial.limits,
    };
    assert!(s.set_relay_quota(&member, update(), 1001).is_err());
    assert!(s.set_relay_quota(&admin, update(), 1300).is_err());
    let count = s.audit_count()?;
    let mut limits = initial.limits;
    limits.max_allocations = 0;
    limits.max_account_endpoints = 1;
    limits.bytes_per_second = 128;
    limits.bytes_per_allocation = 256;
    let changed = s.set_relay_quota(
        &admin,
        RelayQuotaUpdate {
            expected_revision: 1,
            limits,
        },
        1001,
    )?;
    assert_eq!(changed.revision, 2);
    assert_eq!(s.audit_count()?, count + 1);
    assert!(matches!(
        s.set_relay_quota(&admin, update(), 1001),
        Err(StorageError::Conflict)
    ));
    let page = s.query_audit(
        &admin,
        AuditQuery {
            security_epoch: s.security_epoch()?,
            after_sequence: 0,
            limit: 100,
        },
        1001,
    )?;
    let event = page.entries.last().ok_or("missing quota event")?;
    assert_eq!(event.event, "relay_quota_changed");
    assert_eq!(
        event.actor,
        AuditActor::Management {
            account_id: admin.account_id.clone(),
            session_id: admin.session_id.clone()
        }
    );
    let deployment = s.deployment_id()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("quotas.sqlite3");
    std::fs::write(&path, &*s.snapshot()?)?;
    let reopened = Store::open_existing(&path, &deployment)?;
    assert_eq!(reopened.relay_quota_current()?, changed);
    assert_eq!(
        Store::from_snapshot(&reopened.snapshot()?, &deployment)?.relay_quota_current()?,
        changed
    );
    assert_eq!(
        s.policy()?.1.server_forwarding,
        nestlink_policy::ServerForwarding::Deny
    );
    Ok(())
}
#[test]
fn invalid_or_unauditable_relay_quota_update_rolls_back() -> Result {
    let (mut s, _, _, admin, _) = fixture()?;
    let initial = s.relay_quota_current()?;
    let count = s.audit_count()?;
    let mut cases = Vec::new();
    let mut v = initial.limits;
    v.max_allocations = 129;
    cases.push(v);
    let mut v = initial.limits;
    v.max_account_endpoints = 257;
    cases.push(v);
    let mut v = initial.limits;
    v.bytes_per_second = 0;
    cases.push(v);
    let mut v = initial.limits;
    v.bytes_per_second = 1073741825;
    cases.push(v);
    let mut v = initial.limits;
    v.bytes_per_allocation = 0;
    cases.push(v);
    let mut v = initial.limits;
    v.bytes_per_allocation = 1099511627777;
    cases.push(v);
    for limits in cases {
        assert!(
            s.set_relay_quota(
                &admin,
                RelayQuotaUpdate {
                    expected_revision: 1,
                    limits
                },
                1001
            )
            .is_err()
        );
    }
    assert_eq!(s.audit_count()?, count);
    assert_eq!(s.relay_quota_current()?, initial);
    s = super::auditing::mutate(
        &s,
        "UPDATE audit_settings SET high_watermark=9223372036854775807;",
    )?;
    assert!(matches!(
        s.set_relay_quota(
            &admin,
            RelayQuotaUpdate {
                expected_revision: 1,
                limits: initial.limits
            },
            1001
        ),
        Err(StorageError::Conflict)
    ));
    assert_eq!(s.relay_quota_current()?, initial);
    Ok(())
}
