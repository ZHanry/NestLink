use super::*;

#[test]
fn login_devices_are_owned_sessions_and_revocation_preserves_registered_devices() -> Result {
    let (mut store, vault, dummy, admin, member) = fixture()?;
    let identity = InstallationIdentity::from_seed([47; 32]);
    let device = enroll(&mut store, &admin, &identity, "My workstation")?;
    let second = store.login("admin", PASSWORD, None, 1001, &vault, &dummy)?;
    store.record_login_metadata(
        &second.principal,
        "Studio-PC",
        "Windows desktop",
        "Windows",
        1001,
    )?;
    let sessions = store.login_sessions(&admin, 1002)?;
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .any(|s| s.current && s.session_id == admin.session_id)
    );
    assert!(
        sessions
            .iter()
            .any(|s| s.device_name.as_deref() == Some("Studio-PC") && !s.current)
    );
    let member_sessions = store.login_sessions(&member, 1002)?;
    assert_eq!(member_sessions.len(), 1);
    assert_eq!(member_sessions[0].session_id, member.session_id);
    assert!(matches!(
        store.revoke_login_session(&admin, &member.session_id, 1002),
        Err(StorageError::Forbidden)
    ));
    assert_eq!(store.login_sessions(&member, 1002)?.len(), 1);
    store.revoke_login_session(&admin, &second.principal.session_id, 1003)?;
    assert!(matches!(
        store.authenticate(second.access_token.expose(), 1003),
        Err(StorageError::Unauthorized)
    ));
    assert!(
        store
            .refresh_login(second.refresh_token.expose(), second.generation, 1003)
            .is_err()
    );
    assert_eq!(store.login_sessions(&admin, 1003)?.len(), 1);
    assert!(
        store
            .devices(&admin)?
            .iter()
            .any(|d| d.device.id == device && !d.revoked)
    );
    Ok(())
}

#[test]
fn legacy_logins_have_unknown_metadata_and_expired_or_revoked_logins_are_excluded() -> Result {
    let (mut store, vault, dummy, admin, _) = fixture()?;
    let original = store.login_sessions(&admin, 1000)?;
    assert_eq!(original.len(), 1);
    assert!(original[0].device_name.is_none());
    assert!(original[0].created_at.is_none());
    let second = store.login("admin", PASSWORD, None, 1001, &vault, &dummy)?;
    assert!(
        store
            .record_login_metadata(&second.principal, "bad\nname", "client", "Windows", 1001)
            .is_err()
    );
    store.record_login_metadata(
        &second.principal,
        "Laptop",
        "Windows desktop",
        "Windows",
        1001,
    )?;
    store.revoke_login_session(&admin, &second.principal.session_id, 1002)?;
    assert!(store.login_sessions(&second.principal, 1002).is_err());
    assert_eq!(store.login_sessions(&admin, 1002)?.len(), 1);
    Ok(())
}
