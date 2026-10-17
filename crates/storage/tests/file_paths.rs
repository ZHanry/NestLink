use nestlink_auth::random_id;
use nestlink_storage::{SCHEMA_VERSION, Store};
use rusqlite::{Connection, MAIN_DB};
use std::path::PathBuf;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn deep_directory(temporary: &tempfile::TempDir) -> Result<PathBuf> {
    let mut directory = temporary.path().to_owned();
    for index in 0..5 {
        directory.push(format!("deployment-sibling-{index}-{}", "a".repeat(36)));
    }
    // Include the non-ASCII names used by actual installations as well as
    // exceeding the default Windows VFS buffer with short legal components.
    directory.push("部署迁移目录");
    std::fs::create_dir_all(&directory)?;
    assert!(directory.as_os_str().len() > 300);
    Ok(directory)
}

#[test]
fn long_deployment_path_keeps_wal_snapshot_reopen_and_identity() -> Result {
    let temporary = tempfile::tempdir()?;
    let path = deep_directory(&temporary)?.join("control.sqlite3");
    let deployment = random_id();
    let mut store = Store::open(&path, &deployment)?;
    let original_epoch = store.security_epoch()?;
    store.add_account(&random_id(), "before-snapshot")?;
    assert!(path.with_file_name("control.sqlite3-wal").metadata()?.len() > 0);
    assert_eq!(Store::existing_schema(&path, &deployment)?, SCHEMA_VERSION);
    let first = Store::snapshot_existing(&path, &deployment, SCHEMA_VERSION)?;
    store.add_account(&random_id(), "after-snapshot")?;
    let mut snapshot = Connection::open_in_memory()?;
    snapshot.deserialize_read_exact(MAIN_DB, first.as_slice(), first.len(), true)?;
    assert_eq!(
        snapshot.query_row("SELECT count(*) FROM accounts", [], |row| row
            .get::<_, u64>(0))?,
        1
    );
    drop(store);
    let reopened = Store::open_existing(&path, &deployment)?;
    assert_eq!(reopened.security_epoch()?, original_epoch);
    let current = reopened.snapshot()?;
    let mut snapshot = Connection::open_in_memory()?;
    snapshot.deserialize_read_exact(MAIN_DB, current.as_slice(), current.len(), true)?;
    assert_eq!(
        snapshot.query_row("SELECT count(*) FROM accounts", [], |row| row
            .get::<_, u64>(0))?,
        2
    );
    drop(reopened);
    // Rust's canonical Windows path has an explicit verbatim prefix. It must
    // name the same database and keep the same normal SQLite locking behavior.
    let canonical = path.canonicalize()?;
    assert_eq!(
        Store::open_existing(&canonical, &deployment)?.security_epoch()?,
        original_epoch
    );
    Ok(())
}

#[test]
fn long_existing_path_never_creates_missing_database_or_modifies_foreign_bytes() -> Result {
    let temporary = tempfile::tempdir()?;
    let path = deep_directory(&temporary)?.join("missing.sqlite3");
    let deployment = random_id();
    assert!(Store::open_existing(&path, &deployment).is_err());
    assert!(Store::existing_schema(&path, &deployment).is_err());
    assert!(Store::snapshot_existing(&path, &deployment, SCHEMA_VERSION).is_err());
    assert!(!path.exists());
    let foreign = b"foreign deployment: never initialize or overwrite";
    std::fs::write(&path, foreign)?;
    assert!(Store::open_existing(&path, &deployment).is_err());
    assert!(Store::existing_schema(&path, &deployment).is_err());
    assert!(Store::snapshot_existing(&path, &deployment, SCHEMA_VERSION).is_err());
    assert_eq!(std::fs::read(&path)?, foreign);
    assert!(!path.with_file_name("missing.sqlite3-wal").exists());
    Ok(())
}
