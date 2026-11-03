//! Actual installed files at the same read-only boundary used by the CLI.
use super::Result;
use nestlink_platform_security::{
    create_private, load_key, new_private_directory, read_private, replace_private_metadata,
};
use std::path::{Path, PathBuf};

fn private(temporary: &tempfile::TempDir, name: &str) -> Result<PathBuf> {
    let directory = temporary.path().join(name);
    new_private_directory(&directory)?;
    Ok(directory)
}

fn digest(path: &Path) -> Result<[u8; 32]> {
    Ok(crate::sha256(&read_private(path, 16384)?))
}

#[test]
fn read_only_entry_requires_existing_identity_while_initial_install_can_create() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let directory = private(&temporary, "installation")?;
    assert!(crate::read_existing_identity(&directory).is_err());
    assert_eq!(std::fs::read_dir(&directory)?.count(), 0);
    let created = crate::identity(&directory)?;
    let loaded = crate::read_existing_identity(&directory)?;
    assert_eq!(loaded.device_id, created.device_id);
    assert_eq!(loaded.identity.public_key(), created.identity.public_key());
    let reloaded = crate::identity(&directory)?;
    assert_eq!(reloaded.device_id, created.device_id);
    assert_eq!(
        reloaded.identity.public_key(),
        created.identity.public_key()
    );
    Ok(())
}

#[test]
fn read_only_entry_does_not_recreate_record_deleted_after_original_existence_observation()
-> Result<()> {
    let temporary = tempfile::tempdir()?;
    let directory = private(&temporary, "installation")?;
    let _original = crate::identity(&directory)?;
    let manifest = directory.join("installation-device.json");
    let key = directory.join("installation-device.key");
    let original_key = digest(&key)?;
    assert!(manifest.try_exists()?);
    std::fs::remove_file(&manifest)?;
    let error = crate::read_existing_identity(&directory)
        .err()
        .ok_or("deleted original manifest was accepted")?;
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(|error| error.kind()),
        Some(std::io::ErrorKind::NotFound)
    );
    assert!(!manifest.try_exists()?);
    assert_eq!(digest(&key)?, original_key);
    Ok(())
}

#[test]
fn read_only_entry_does_not_recreate_key_deleted_after_original_existence_observation() -> Result<()>
{
    let temporary = tempfile::tempdir()?;
    let directory = private(&temporary, "installation")?;
    let _original = crate::identity(&directory)?;
    let manifest = directory.join("installation-device.json");
    let key = directory.join("installation-device.key");
    let original_manifest = digest(&manifest)?;
    assert!(manifest.try_exists()? && key.try_exists()?);
    std::fs::remove_file(&key)?;
    let error = crate::read_existing_identity(&directory)
        .err()
        .ok_or("deleted original key was accepted")?;
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(|error| error.kind()),
        Some(std::io::ErrorKind::NotFound)
    );
    assert!(!key.try_exists()?);
    assert_eq!(digest(&manifest)?, original_manifest);
    Ok(())
}

#[test]
fn read_only_entry_rejects_replaced_manifest_without_rewriting_original_key() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let original = private(&temporary, "original")?;
    let replacement = private(&temporary, "replacement")?;
    let _first = crate::identity(&original)?;
    let _second = crate::identity(&replacement)?;
    let manifest = original.join("installation-device.json");
    let key = original.join("installation-device.key");
    let original_key = digest(&key)?;
    let changed = read_private(&replacement.join("installation-device.json"), 1024)?;
    replace_private_metadata(&manifest, &changed)?;
    assert!(crate::read_existing_identity(&original).is_err());
    assert_eq!(digest(&key)?, original_key);
    assert_eq!(digest(&manifest)?, crate::sha256(&changed));
    Ok(())
}

#[test]
fn read_only_entry_rejects_valid_replacement_key_without_rewriting_original_manifest() -> Result<()>
{
    let temporary = tempfile::tempdir()?;
    let original = private(&temporary, "original")?;
    let replacement = private(&temporary, "replacement")?;
    let _first = crate::identity(&original)?;
    let _second = crate::identity(&replacement)?;
    let manifest = original.join("installation-device.json");
    let key = original.join("installation-device.key");
    let original_manifest = digest(&manifest)?;
    let changed = read_private(&replacement.join("installation-device.key"), 16384)?;
    std::fs::remove_file(&key)?;
    create_private(&key, &changed)?;
    // The replacement is a real key protected for this OS account, not an
    // invalid encoding. Its temporary plaintext remains zeroizing.
    drop(load_key(&key)?);
    assert!(crate::read_existing_identity(&original).is_err());
    assert_eq!(digest(&manifest)?, original_manifest);
    assert_eq!(digest(&key)?, crate::sha256(&changed));
    Ok(())
}
