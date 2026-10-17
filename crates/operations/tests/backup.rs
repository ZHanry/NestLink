use nestlink_auth::{VaultKey, hash_password, random_bytes, random_id, totp};
use nestlink_operations::backup::{BackupError, DeploymentBackup};
use nestlink_platform_security::{load_key, read_private};
use nestlink_storage::Store;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const PASSWORD: &[u8] = b"archive-test-only-password";
const ACCOUNT_PASSWORD: &str = "account-test-only-password";

fn capture() -> Result<DeploymentBackup> {
    let store = Store::in_memory(&random_id())?;
    Ok(DeploymentBackup::capture(
        &store,
        b"test configuration",
        &random_bytes(),
        &random_bytes(),
    )?)
}

#[test]
fn authenticated_archive_randomizes_and_rejects_corruption_and_wrong_password() -> Result {
    let backup = capture()?;
    let archive = backup.encrypt(PASSWORD)?;
    let second = backup.encrypt(PASSWORD)?;
    assert_ne!(archive, second);
    assert!(!archive.windows(32).any(|window| window == backup.vault_key));
    let recovered = DeploymentBackup::decrypt(&archive, PASSWORD, &backup.deployment_id)?;
    assert_eq!(recovered.database, backup.database);
    assert_eq!(recovered.vault_key, backup.vault_key);
    assert_eq!(recovered.permit_seed, backup.permit_seed);
    assert!(matches!(
        DeploymentBackup::decrypt(&archive, b"incorrect-test-password", &backup.deployment_id),
        Err(BackupError::Authentication)
    ));
    for index in [20, 36, 64, archive.len() - 1] {
        let mut corrupt = archive.clone();
        corrupt[index] ^= 1;
        assert!(matches!(
            DeploymentBackup::decrypt(&corrupt, PASSWORD, &backup.deployment_id),
            Err(BackupError::Authentication)
        ));
    }
    assert!(matches!(
        DeploymentBackup::decrypt(&archive, PASSWORD, &random_id()),
        Err(BackupError::Deployment)
    ));
    Ok(())
}

#[test]
fn hostile_header_and_truncation_are_rejected_without_unbounded_kdf_work() -> Result {
    let backup = capture()?;
    let archive = backup.encrypt(PASSWORD)?;
    for length in [0, 7, 63, 64, 100, archive.len() - 1] {
        assert!(matches!(
            DeploymentBackup::decrypt(&archive[..length], PASSWORD, &backup.deployment_id),
            Err(BackupError::Format)
        ));
    }
    for index in [0, 8, 12, 16, 60] {
        let mut corrupt = archive.clone();
        corrupt[index] ^= 0xff;
        assert!(matches!(
            DeploymentBackup::decrypt(&corrupt, PASSWORD, &backup.deployment_id),
            Err(BackupError::Format)
        ));
    }
    assert!(backup.encrypt(b"short").is_err());
    Ok(())
}

#[test]
fn offline_restore_retains_identity_but_revokes_login_leases_and_all_old_recovery_codes() -> Result
{
    let deployment = random_id();
    let mut source = Store::in_memory(&deployment)?;
    let vault_bytes = random_bytes();
    let permit = random_bytes();
    let vault = VaultKey::from_bytes(vault_bytes);
    let dummy = hash_password("dummy-test-password")?;
    source.bootstrap_admin("administrator", ACCOUNT_PASSWORD)?;
    let login = source.login(
        "administrator",
        ACCOUNT_PASSWORD,
        None,
        1000,
        &vault,
        &dummy,
    )?;
    source.begin_totp(&login.principal, ACCOUNT_PASSWORD, None, 1000, &vault)?;
    // Read the real pending secret through a SQLite view to avoid a separate test implementation.
    let view = rusqlite_view(&source.snapshot()?)?;
    let pending: Vec<u8> =
        view.query_row("SELECT totp_pending FROM account_security", [], |row| {
            row.get(0)
        })?;
    let secret = vault.decrypt(&login.principal.account_id, &pending)?;
    let codes = source.confirm_totp(&login.principal, &totp(&secret, 1000 / 30)?, 1000, &vault)?;
    let host = random_id();
    let controller = random_id();
    source.add_device(&host, &login.principal.account_id, &[4; 32])?;
    source.add_device(&controller, &login.principal.account_id, &[5; 32])?;
    let session = random_id();
    let lease = random_id();
    source.register_approved_session(&session, &controller, &host)?;
    source.add_lease(&lease, &session)?;
    let backup = DeploymentBackup::capture(&source, b"test config", &vault_bytes, &permit)?;
    // Consume a code AFTER the snapshot; rollback must never resurrect it.
    source.login(
        "administrator",
        ACCOUNT_PASSWORD,
        Some(codes[0].expose()),
        1001,
        &vault,
        &dummy,
    )?;
    let parent = tempfile::tempdir()?;
    let target = parent.path().join("restored");
    let epoch = backup.restore_new(&target, b"sanitized config")?;
    assert_ne!(epoch, source.security_epoch()?);
    assert_eq!(*load_key(&target.join("vault.key"))?, vault_bytes);
    assert_eq!(*load_key(&target.join("permit.key"))?, permit);
    assert_eq!(
        &*read_private(&target.join("server.toml"), 100)?,
        b"sanitized config"
    );
    let mut restored = Store::open_existing(&target.join("control.sqlite3"), &deployment)?;
    assert_eq!(restored.security_epoch()?, epoch);
    assert!(
        restored
            .authenticate(login.access_token.expose(), 1001)
            .is_err()
    );
    assert!(
        restored
            .refresh_login(login.refresh_token.expose(), login.generation, 1001)
            .is_err()
    );
    assert!(!restored.session_is_active(&session)?);
    assert!(!restored.lease_is_active(&lease)?);
    for code in &codes[..2] {
        assert!(
            restored
                .login(
                    "administrator",
                    ACCOUNT_PASSWORD,
                    Some(code.expose()),
                    1001,
                    &vault,
                    &dummy
                )
                .is_err()
        );
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    assert!(
        restored
            .login(
                "administrator",
                ACCOUNT_PASSWORD,
                Some(&totp(&secret, now / 30)?),
                now,
                &vault,
                &dummy
            )
            .is_err()
    );
    let later = now + 90;
    assert!(
        restored
            .login(
                "administrator",
                ACCOUNT_PASSWORD,
                Some(&totp(&secret, later / 30)?),
                later,
                &vault,
                &dummy
            )
            .is_ok()
    );
    assert!(backup.restore_new(&target, b"replacement config").is_err());
    assert_eq!(
        &*read_private(&target.join("server.toml"), 100)?,
        b"sanitized config"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(target.metadata()?.mode() & 0o777, 0o700);
    }
    // The source deployment is still live, unchanged by restoring its snapshot.
    assert!(
        source
            .authenticate(login.access_token.expose(), 1001)
            .is_ok()
    );
    assert!(source.lease_is_active(&lease)?);
    Ok(())
}
fn rusqlite_view(bytes: &[u8]) -> Result<rusqlite::Connection> {
    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.deserialize_read_exact(rusqlite::MAIN_DB, bytes, bytes.len(), false)?;
    Ok(connection)
}
