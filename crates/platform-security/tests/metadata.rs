use nestlink_platform_security::{new_private_directory, read_private, replace_private_metadata};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn atomic_private_metadata_replaces_own_file_without_touching_other_bytes() -> Result {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("private-metadata");
    new_private_directory(&directory)?;
    let path = directory.join("journal.json");
    replace_private_metadata(&path, b"first exact metadata")?;
    let untouched = directory.join("untouched");
    std::fs::write(&untouched, b"preserved")?;
    replace_private_metadata(&path, b"second exact metadata")?;
    assert_eq!(
        read_private(&path, 1024)?.as_slice(),
        b"second exact metadata"
    );
    assert_eq!(std::fs::read(&untouched)?, b"preserved");
    assert!(replace_private_metadata(&path, &[]).is_err());
    assert!(replace_private_metadata(&path, &vec![0; 1024 * 1024 + 1]).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn linked_metadata_is_rejected_without_writing_its_target() -> Result {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("private-metadata");
    new_private_directory(&directory)?;
    let outside = directory.join("outside");
    std::fs::write(&outside, b"untouched target")?;
    let linked = directory.join("journal.json");
    std::os::unix::fs::symlink(&outside, &linked)?;
    assert!(replace_private_metadata(&linked, b"must refuse").is_err());
    assert_eq!(std::fs::read(&outside)?, b"untouched target");
    Ok(())
}
