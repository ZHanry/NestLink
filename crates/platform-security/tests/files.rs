use nestlink_platform_security::{check_private_directory, new_private_directory};
use nestlink_platform_security::{create_key, create_private, load_key, read_private};
use std::io;

#[test]
fn private_handles_enforce_size_and_round_trip_protected_keys() -> io::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("secret");
    create_private(&path, b"private-value")?;
    assert_eq!(&**read_private(&path, 32)?, b"private-value");
    assert!(read_private(&path, 1).is_err());
    assert!(read_private(&path, u64::MAX).is_err());
    assert!(create_private(&path, b"replace").is_err());
    let key = directory.path().join("install.key");
    create_key(&key, &[9; 32])?;
    assert_eq!(*load_key(&key)?, [9; 32]);
    #[cfg(unix)]
    {
        use std::{
            fs,
            os::unix::fs::{PermissionsExt, symlink},
        };
        let link = directory.path().join("link");
        symlink(&path, &link)?;
        assert!(read_private(&link, 32).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(read_private(&path, 32).is_err());
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_private_directory_requires_the_protected_owner_and_system_acl() -> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let private = temporary.path().join("private");
    new_private_directory(&private)?;
    check_private_directory(&private)?;

    // An ordinary inherited directory is deliberately rejected even when it
    // happens to be owned by the current account.
    let inherited = temporary.path().join("inherited");
    std::fs::create_dir(&inherited)?;
    assert!(check_private_directory(&inherited).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn private_directory_requires_owner_only_permissions() -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir()?;
    let private = temporary.path().join("private");
    new_private_directory(&private)?;
    check_private_directory(&private)?;
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755))?;
    assert!(check_private_directory(&private).is_err());
    Ok(())
}
