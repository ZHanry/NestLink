//! Stable deployment admission outside a directory that migration may rename.
use crate::upgrade::{UpgradeError, UpgradeResult};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions, TryLockError},
    io,
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub(crate) struct Locations {
    pub parent: PathBuf,
    pub name: String,
    pub prefix: String,
}
impl Locations {
    pub fn new(directory: &Path) -> UpgradeResult<Self> {
        if !directory.is_absolute()
            || directory
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(UpgradeError::Invalid(
                "deployment directory must be absolute without parent traversal",
            ));
        }
        let parent = directory
            .parent()
            .ok_or(UpgradeError::Invalid("deployment has no parent"))?;
        nestlink_platform_security::check_private_directory(parent)?;
        let name = directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(UpgradeError::Invalid("deployment leaf must be Unicode"))?;
        if name.is_empty()
            || name.len() > 255
            || name == "."
            || name == ".."
            || name
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, '/' | '\\' | ':'))
        {
            return Err(UpgradeError::Invalid("invalid deployment leaf"));
        }
        let hash = Sha256::digest(name.as_bytes());
        let prefix = format!(
            ".nestlink-deployment-{}",
            hash.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        Ok(Self {
            parent: parent.to_owned(),
            name: name.to_owned(),
            prefix,
        })
    }
    pub fn admission(&self) -> PathBuf {
        self.parent.join(format!("{}.lock", self.prefix))
    }
    pub fn runtime(&self) -> PathBuf {
        self.parent.join(format!("{}.runtime.lock", self.prefix))
    }
    pub fn journal(&self) -> PathBuf {
        self.parent.join(format!("{}.migration.json", self.prefix))
    }
    pub fn active(&self) -> PathBuf {
        self.parent.join(&self.name)
    }
}

fn open_stable(path: &Path) -> UpgradeResult<File> {
    match nestlink_platform_security::create_private(path, &[]) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 0 {
        return Err(UpgradeError::Invalid(
            "deployment lock must be an empty regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(UpgradeError::Invalid(
                "deployment lock owner or permissions are invalid",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(UpgradeError::Invalid(
                "deployment lock cannot be a reparse point",
            ));
        }
    }
    Ok(file)
}
fn lock_error(error: TryLockError) -> UpgradeError {
    match error {
        TryLockError::WouldBlock => UpgradeError::Busy,
        TryLockError::Error(error) => UpgradeError::Io(error),
    }
}

/// Shared admission for every operation that could open the database or keys.
/// A control runtime additionally holds a distinct exclusive singleton lock.
pub struct DeploymentLease {
    _admission: File,
    _runtime: Option<File>,
}
impl DeploymentLease {
    pub fn operation(directory: &Path) -> UpgradeResult<Self> {
        Self::acquire(directory, false)
    }
    pub fn runtime(directory: &Path) -> UpgradeResult<Self> {
        Self::acquire(directory, true)
    }
    fn acquire(directory: &Path, runtime: bool) -> UpgradeResult<Self> {
        let locations = Locations::new(directory)?;
        let admission = open_stable(&locations.admission())?;
        admission.try_lock_shared().map_err(lock_error)?;
        match std::fs::symlink_metadata(locations.journal()) {
            Ok(_) => return Err(UpgradeError::Incomplete),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        nestlink_platform_security::check_private_directory(directory)?;
        let runtime = if runtime {
            let file = open_stable(&locations.runtime())?;
            file.try_lock().map_err(lock_error)?;
            Some(file)
        } else {
            None
        };
        Ok(Self {
            _admission: admission,
            _runtime: runtime,
        })
    }
}

pub(crate) struct MigrationOwner {
    pub locations: Locations,
    _admission: File,
    _runtime: File,
}
impl MigrationOwner {
    pub fn acquire(directory: &Path, recover: bool) -> UpgradeResult<Self> {
        let locations = Locations::new(directory)?;
        let admission = open_stable(&locations.admission())?;
        admission.try_lock().map_err(lock_error)?;
        let runtime = open_stable(&locations.runtime())?;
        runtime.try_lock().map_err(lock_error)?;
        match std::fs::symlink_metadata(locations.journal()) {
            Ok(_) if !recover => return Err(UpgradeError::Incomplete),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Self {
            locations,
            _admission: admission,
            _runtime: runtime,
        })
    }
}
