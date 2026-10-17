use nestlink_auth::random_id;
use nestlink_platform_files::{ApprovedReadRoot, FileRoots};
use nestlink_protocol::{FILE_PAYLOAD_BYTES, FILE_SIZE_BYTES};
use nestlink_remote::files::FileReadDevice;
use std::{fs, io, path::Path};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[cfg(unix)]
fn directory_link(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}
#[cfg(windows)]
fn directory_link(target: &Path, link: &Path) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    // Test-owned temporary paths are passed as data, never interpolated into
    // shell code. A junction needs no developer-mode or administrator switch.
    let result = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", "New-Item -ItemType Junction -Path $env:NESTLINK_TEST_LINK -Value $env:NESTLINK_TEST_TARGET -ErrorAction Stop | Out-Null"])
        .env("NESTLINK_TEST_LINK", link).env("NESTLINK_TEST_TARGET", target)
        .creation_flags(0x0800_0000).output()?;
    if !result.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&result.stderr).into_owned(),
        ));
    }
    Ok(())
}
#[test]
fn real_file_reads_use_portable_paths_and_local_root_and_size_consent() -> Result {
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("中文"))?;
    fs::write(dir.path().join("中文/文件.txt"), b"approved data")?;
    fs::write(dir.path().join("empty"), b"")?;
    let id = random_id();
    let (root, _consent) = ApprovedReadRoot::open(&id, dir.path(), 20)?;
    let mut roots = FileRoots::new(vec![root])?;
    let mut source = roots.open(&id, "中文/文件.txt")?;
    let manifest = source.describe(&mut || Ok(()))?;
    assert_eq!(manifest.size, 13);
    assert_eq!(source.read_chunk(0, 13, &mut || Ok(()))?, b"approved data");
    source.verify(&manifest, &mut || Ok(()))?;
    for path in [
        "../secret",
        "中文/../../secret",
        "/etc/passwd",
        "C:/Windows/file",
        "file:stream",
        "NUL",
        "中文/.",
        "中文//文件.txt",
    ] {
        assert!(roots.open(&id, path).is_err(), "{path}");
    }
    assert!(roots.open(&random_id(), "中文/文件.txt").is_err());
    assert!(roots.open(&id, "中文").is_err());
    assert!(
        source
            .read_chunk(0, FILE_PAYLOAD_BYTES as usize + 1, &mut || Ok(()))
            .is_err()
    );
    let (root, _zero_consent) = ApprovedReadRoot::open(&random_id(), dir.path(), 0)?;
    let root_id = root.id().to_owned();
    let mut zero = FileRoots::new(vec![root])?;
    assert!(zero.open(&root_id, "中文/文件.txt").is_err());
    assert_eq!(
        zero.open(&root_id, "empty")?.describe(&mut || Ok(()))?.size,
        0
    );
    assert!(ApprovedReadRoot::open(&random_id(), dir.path(), FILE_SIZE_BYTES + 1).is_err());
    Ok(())
}
#[test]
fn symlinks_junctions_and_hardlinks_cannot_expose_outside_files() -> Result {
    let dir = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    fs::write(outside.path().join("secret"), b"must not escape")?;
    directory_link(outside.path(), &dir.path().join("linked"))?;
    fs::hard_link(outside.path().join("secret"), dir.path().join("hardlinked"))?;
    let id = random_id();
    let (root, _consent) = ApprovedReadRoot::open(&id, dir.path(), 100)?;
    let mut roots = FileRoots::new(vec![root])?;
    assert!(roots.open(&id, "linked/secret").is_err());
    assert!(roots.open(&id, "hardlinked").is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            outside.path().join("secret"),
            dir.path().join("linked-file"),
        )?;
        assert!(roots.open(&id, "linked-file").is_err());
    }
    assert_eq!(fs::read(outside.path().join("secret"))?, b"must not escape");
    Ok(())
}
#[test]
fn replacing_the_approved_path_cannot_replace_its_root_handle() -> Result {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("root");
    fs::create_dir(&path)?;
    fs::write(path.join("file"), b"original approved object")?;
    let id = random_id();
    let (root, _consent) = ApprovedReadRoot::open(&id, &path, 100)?;
    let mut roots = FileRoots::new(vec![root])?;
    #[cfg(unix)]
    {
        fs::rename(&path, dir.path().join("moved"))?;
        fs::create_dir(&path)?;
        fs::write(path.join("file"), b"ambient replacement")?;
    }
    #[cfg(windows)]
    {
        let error = fs::rename(&path, dir.path().join("moved"))
            .err()
            .ok_or("approved directory was movable despite the pinned handle")?;
        assert_eq!(error.raw_os_error(), Some(32));
    }
    let mut source = roots.open(&id, "file")?;
    let m = source.describe(&mut || Ok(()))?;
    assert_eq!(
        source.read_chunk(0, m.size as usize, &mut || Ok(()))?,
        b"original approved object"
    );
    Ok(())
}
#[test]
fn root_revocation_invalidates_idle_existing_handles_and_future_opens() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("file"), b"test")?;
    let id = random_id();
    let (root, consent) = ApprovedReadRoot::open(&id, dir.path(), 100)?;
    let mut roots = FileRoots::new(vec![root])?;
    let mut source = roots.open(&id, "file")?;
    let manifest = source.describe(&mut || Ok(()))?;
    consent.revoke();
    assert!(source.describe(&mut || Ok(())).is_err());
    assert!(source.read_chunk(0, 4, &mut || Ok(())).is_err());
    assert!(source.verify(&manifest, &mut || Ok(())).is_err());
    assert!(roots.open(&id, "file").is_err());
    Ok(())
}
#[test]
fn hashing_checks_authorization_between_blocks_and_final_checksum_checks_content() -> Result {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("file");
    fs::write(&path, vec![5; FILE_PAYLOAD_BYTES as usize * 3])?;
    let id = random_id();
    let (root, _consent) = ApprovedReadRoot::open(&id, dir.path(), FILE_SIZE_BYTES)?;
    let mut roots = FileRoots::new(vec![root])?;
    let mut source = roots.open(&id, "file")?;
    let mut calls = 0;
    assert!(
        source
            .describe(&mut || {
                calls += 1;
                if calls >= 3 {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "test cancellation",
                    ))
                } else {
                    Ok(())
                }
            })
            .is_err()
    );
    assert_eq!(calls, 3);
    let manifest = source.describe(&mut || Ok(()))?;
    #[cfg(unix)]
    {
        let modified = fs::metadata(&path)?.modified()?;
        fs::write(&path, vec![6; manifest.size as usize])?;
        fs::File::options()
            .write(true)
            .open(&path)?
            .set_times(fs::FileTimes::new().set_modified(modified))?;
        assert!(source.verify(&manifest, &mut || Ok(())).is_err());
    }
    #[cfg(windows)]
    {
        assert!(fs::write(&path, vec![6; manifest.size as usize]).is_err());
        assert!(fs::rename(&path, dir.path().join("renamed")).is_err());
        source.verify(&manifest, &mut || Ok(()))?;
    }
    Ok(())
}
#[cfg(unix)]
#[test]
fn fifo_is_rejected_without_waiting_for_a_writer() -> Result {
    let dir = tempfile::tempdir()?;
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        dir.path().join("fifo"),
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    let id = random_id();
    let (root, _consent) = ApprovedReadRoot::open(&id, dir.path(), 100)?;
    let mut roots = FileRoots::new(vec![root])?;
    let started = std::time::Instant::now();
    assert!(roots.open(&id, "fifo").is_err());
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
    Ok(())
}
