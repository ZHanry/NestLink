//! Stable OS locks for normal-user installation maintenance.
//!
//! Locks are never deleted. A missing endpoint is not proof of quiescence.
//! The exclusive admission owner can stop the current authenticated runtime
//! while preventing another desktop or daemon from entering its state.
use crate::{Error, Result};
use std::{
    fs::{File, OpenOptions, TryLockError},
    io,
    path::{Path, PathBuf},
};

const ADMISSION: &str = "maintenance.lock";
const DESKTOP: &str = "desktop-lifetime.lock";
const DAEMON: &str = "daemon.lock";
const JOURNAL: &str = "maintenance-incomplete.json";

/// Installed payloads live below one stable installation root. An installer
/// owns its global lock before discovering user daemons, so a different user
/// cannot race a DEB upgrade by starting a new state namespace. Development
/// binaries outside such a marked root do not acquire a system install lock.
pub struct InstallationStartup {
    _admission: Option<File>,
    directory: Option<PathBuf>,
}
impl InstallationStartup {
    pub fn acquire(executable: &Path) -> Result<Self> {
        let executable = executable.canonicalize()?;
        for directory in executable.ancestors().skip(1).take(5) {
            let marker = directory.join("installation-v15.json");
            let marker_metadata = match std::fs::symlink_metadata(&marker) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if !marker_metadata.is_file()
                || marker_metadata.file_type().is_symlink()
                || marker_metadata.len() > 256
            {
                return Err(Error::Protocol);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if marker_metadata.file_attributes() & 0x400 != 0 {
                    return Err(Error::Protocol);
                }
            }
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Marker {
                schema_version: u16,
                namespace: String,
            }
            let marker: Marker =
                serde_json::from_slice(&std::fs::read(&marker)?).map_err(|_| Error::Protocol)?;
            if marker.schema_version != 1 || marker.namespace != "NestLink-v15" {
                return Err(Error::Protocol);
            }
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.custom_flags(0x0020_0000);
            }
            let admission = options.open(directory.join("installation-admission.lock"))?;
            let metadata = admission.metadata()?;
            if !metadata.is_file() || metadata.len() != 0 {
                return Err(Error::Protocol);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(Error::Protocol);
                }
            }
            admission.try_lock_shared().map_err(busy)?;
            match std::fs::symlink_metadata(directory.join("installation-incomplete.json")) {
                Ok(_) => return Err(Error::Maintenance),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            return Ok(Self {
                _admission: Some(admission),
                directory: Some(directory.to_owned()),
            });
        }
        Ok(Self {
            _admission: None,
            directory: None,
        })
    }

    /// Resolve while shared installation admission is held. The caller must
    /// acquire its real UI/daemon lifetime before dropping this guard.
    pub fn state_directory(&self, base: &Path) -> Result<PathBuf> {
        crate::instance::resolve_state(self.directory.as_deref(), base)
    }

    pub fn active_instance_id(&self) -> Result<Option<String>> {
        let Some(root) = &self.directory else {
            return Ok(None);
        };
        let instance = crate::instance::read_instance(root)?;
        Ok(instance.active.then_some(instance.instance_id))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u16,
    owner_id: String,
}

fn read_journal(directory: &Path) -> Result<Option<Journal>> {
    let bytes = match nestlink_platform_security::read_private(&directory.join(JOURNAL), 512) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| Error::Protocol)?;
    if journal.schema_version != 1 || !crate::valid_runtime_id(&journal.owner_id) {
        return Err(Error::Protocol);
    }
    Ok(Some(journal))
}

fn busy(error: TryLockError) -> Error {
    match error {
        TryLockError::WouldBlock => Error::Maintenance,
        TryLockError::Error(error) => Error::Io(error),
    }
}

/// Same safety rules as the daemon's original singleton file, without reading
/// bytes which Windows range locking deliberately makes unavailable.
pub(crate) fn open_lock(directory: &Path, name: &str) -> Result<File> {
    nestlink_platform_security::check_private_directory(directory)?;
    let path = directory.join(name);
    match nestlink_platform_security::create_private(&path, &[]) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 0 {
        return Err(Error::Protocol);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(Error::Protocol);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(Error::Protocol);
        }
    }
    Ok(file)
}

/// Retain until the real desktop lifetime or daemon singleton lock is held.
pub struct StartupPermit {
    _admission: File,
}
impl StartupPermit {
    pub fn acquire(directory: &Path) -> Result<Self> {
        crate::initialize_directory(directory)?;
        let admission = open_lock(directory, ADMISSION)?;
        admission.try_lock_shared().map_err(busy)?;
        if read_journal(directory)?.is_some() {
            return Err(Error::Maintenance);
        }
        Ok(Self {
            _admission: admission,
        })
    }
}

/// Shared across every desktop window process for this exact state directory.
/// The lifetime owner must outlive its UI workers, chooser children and bridge.
pub struct DesktopLease {
    _lifetime: File,
}

/// One workspace window per private state directory. A repeated launch only
/// posts an activation request; it never reads or changes management sessions.
pub struct DesktopInstance {
    _owner: File,
}
impl DesktopInstance {
    pub fn acquire_or_activate(directory: &Path) -> Result<Option<Self>> {
        let owner = open_lock(directory, "desktop-instance.lock")?;
        match owner.try_lock() {
            Ok(()) => {
                let _ = std::fs::remove_file(directory.join("desktop-activate"));
                Ok(Some(Self { _owner: owner }))
            }
            Err(TryLockError::WouldBlock) => {
                nestlink_platform_security::replace_private_metadata(
                    &directory.join("desktop-activate"),
                    b"open",
                )?;
                Ok(None)
            }
            Err(error) => Err(busy(error)),
        }
    }
    pub fn take_activation(directory: &Path) -> bool {
        let path = directory.join("desktop-activate");
        match nestlink_platform_security::read_private(&path, 4) {
            Ok(bytes) if bytes.as_slice() == b"open" => std::fs::remove_file(path).is_ok(),
            _ => false,
        }
    }
}
impl DesktopLease {
    pub fn acquire(directory: &Path) -> Result<Self> {
        let _startup = StartupPermit::acquire(directory)?;
        let lifetime = open_lock(directory, DESKTOP)?;
        lifetime.try_lock_shared().map_err(busy)?;
        Ok(Self {
            _lifetime: lifetime,
        })
    }
}

/// A held exclusive admission is a maintenance request to existing UIs.
/// Invalid directories/locks remain errors, never an implicit permission.
pub fn requested(directory: &Path) -> Result<bool> {
    match StartupPermit::acquire(directory) {
        Ok(_permit) => Ok(false),
        Err(Error::Maintenance) => Ok(true),
        Err(error) => Err(error),
    }
}

pub struct MaintenanceGuard {
    directory: PathBuf,
    _admission: File,
    daemon: Option<File>,
    desktop: Option<File>,
    journal_id: String,
}

/// Per-user Windows install root owner. Ubuntu's privileged package owner
/// holds this same stable global lock with flock before discovering users.
pub struct InstallationMaintenance {
    directory: PathBuf,
    _admission: File,
    recovering: bool,
}
impl InstallationMaintenance {
    pub fn acquire(directory: &Path) -> Result<Self> {
        crate::initialize_directory(directory)?;
        let admission = open_lock(directory, "installation-admission.lock")?;
        admission.try_lock().map_err(busy)?;
        let marker = directory.join("installation-v15.json");
        let expected = b"{\"schema_version\":1,\"namespace\":\"NestLink-v15\"}";
        match nestlink_platform_security::read_private(&marker, 256) {
            Ok(bytes) if bytes.as_slice() == expected => {}
            Ok(_) => return Err(Error::Protocol),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                nestlink_platform_security::create_private(&marker, expected)?;
            }
            Err(error) => return Err(error.into()),
        }
        let journal = directory.join("installation-incomplete.json");
        let recovering = match nestlink_platform_security::read_private(&journal, 256) {
            Ok(bytes)
                if bytes.as_slice() == b"{\"schema_version\":1,\"namespace\":\"NestLink-v15\"}" =>
            {
                true
            }
            Ok(_) => return Err(Error::Protocol),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                nestlink_platform_security::create_private(&journal, expected)?;
                false
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            directory: directory.to_owned(),
            _admission: admission,
            recovering,
        })
    }

    /// Determined only while this owner holds exclusive installation admission.
    pub fn recovering(&self) -> bool {
        self.recovering
    }

    pub fn release(self) -> Result<()> {
        let path = self.directory.join("installation-incomplete.json");
        let bytes = nestlink_platform_security::read_private(&path, 256)?;
        if bytes.as_slice() != b"{\"schema_version\":1,\"namespace\":\"NestLink-v15\"}" {
            return Err(Error::Protocol);
        }
        std::fs::remove_file(path)?;
        #[cfg(unix)]
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}
impl MaintenanceGuard {
    pub fn acquire(directory: &Path) -> Result<Self> {
        crate::initialize_directory(directory)?;
        let admission = open_lock(directory, ADMISSION)?;
        admission.try_lock().map_err(busy)?;
        // A crash/expired controller must not reopen user business while an
        // installer may be partway through activation. Only explicit release
        // under a new exclusive maintenance owner clears this stable journal.
        let journal = match read_journal(directory)? {
            Some(journal) => journal,
            None => {
                let journal = Journal {
                    schema_version: 1,
                    owner_id: nestlink_auth::random_id(),
                };
                nestlink_platform_security::create_private(
                    &directory.join(JOURNAL),
                    &serde_json::to_vec(&journal).map_err(|_| Error::Protocol)?,
                )?;
                journal
            }
        };
        Ok(Self {
            directory: directory.to_owned(),
            _admission: admission,
            daemon: None,
            desktop: None,
            journal_id: journal.owner_id,
        })
    }

    /// Successful package completion/cancellation explicitly releases the
    /// journal while admission is still held. Drop/error preserves the fence.
    pub fn release(self) -> Result<()> {
        let journal = read_journal(&self.directory)?.ok_or(Error::Protocol)?;
        if journal.owner_id != self.journal_id {
            return Err(Error::Protocol);
        }
        std::fs::remove_file(self.directory.join(JOURNAL))?;
        #[cfg(unix)]
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    /// Once true, the exact daemon singleton is retained by maintenance.
    /// No second runtime can enter until the maintenance owner is dropped.
    pub fn daemon_stopped(&mut self) -> Result<bool> {
        if self.daemon.is_some() {
            return Ok(true);
        }
        let daemon = open_lock(&self.directory, DAEMON)?;
        match daemon.try_lock() {
            Ok(()) => {
                self.daemon = Some(daemon);
                Ok(true)
            }
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
    }

    /// Both the daemon owner and all registered desktop lifetime owners ended.
    /// The caller retains all three exclusive locks throughout package changes.
    pub fn quiescent(&mut self) -> Result<bool> {
        if !self.daemon_stopped()? {
            return Ok(false);
        }
        if self.desktop.is_some() {
            return Ok(true);
        }
        let desktop = open_lock(&self.directory, DESKTOP)?;
        match desktop.try_lock() {
            Ok(()) => {
                self.desktop = Some(desktop);
                Ok(true)
            }
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn installation_recovery_is_observed_only_under_exclusive_ownership() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("installation");
        let first = InstallationMaintenance::acquire(&directory)?;
        assert!(!first.recovering());
        assert!(matches!(
            InstallationMaintenance::acquire(&directory),
            Err(Error::Maintenance)
        ));
        drop(first);
        assert!(directory.join("installation-incomplete.json").is_file());
        let recovery = InstallationMaintenance::acquire(&directory)?;
        assert!(recovery.recovering());
        recovery.release()?;
        let fresh = InstallationMaintenance::acquire(&directory)?;
        assert!(!fresh.recovering());
        fresh.release()?;
        Ok(())
    }

    #[tokio::test]
    async fn maintenance_fences_startup_and_waits_for_original_runtime_and_desktops() -> TestResult
    {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let first_ui = DesktopLease::acquire(&directory)?;
        let second_ui = DesktopLease::acquire(&directory)?;
        let daemon = crate::LocalServer::bind(&directory).await?;
        let mut maintenance = MaintenanceGuard::acquire(&directory)?;
        assert!(requested(&directory)?);
        assert!(!maintenance.quiescent()?);
        assert!(matches!(
            DesktopLease::acquire(&directory),
            Err(Error::Maintenance)
        ));
        assert!(matches!(
            crate::LocalServer::bind(&directory).await,
            Err(Error::Maintenance)
        ));
        drop(daemon);
        assert!(maintenance.daemon_stopped()?);
        assert!(!maintenance.quiescent()?);
        drop(first_ui);
        assert!(!maintenance.quiescent()?);
        drop(second_ui);
        assert!(maintenance.quiescent()?);
        maintenance.release()?;
        assert!(!requested(&directory)?);
        let _replacement = crate::LocalServer::bind(&directory).await?;
        Ok(())
    }

    #[test]
    fn startup_handoff_is_atomic_and_stable_lock_bytes_are_never_reset() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let startup = StartupPermit::acquire(&directory)?;
        assert!(matches!(
            MaintenanceGuard::acquire(&directory),
            Err(Error::Maintenance)
        ));
        drop(startup);
        let maintenance = MaintenanceGuard::acquire(&directory)?;
        assert!(matches!(
            MaintenanceGuard::acquire(&directory),
            Err(Error::Maintenance)
        ));
        drop(maintenance);
        assert!(requested(&directory)?);
        let mut recovery = MaintenanceGuard::acquire(&directory)?;
        assert!(recovery.quiescent()?);
        recovery.release()?;
        assert!(!requested(&directory)?);
        std::fs::write(directory.join(ADMISSION), b"not an empty stable lock")?;
        assert!(matches!(
            StartupPermit::acquire(&directory),
            Err(Error::Protocol)
        ));
        assert_eq!(
            std::fs::read(directory.join(ADMISSION))?,
            b"not an empty stable lock"
        );
        Ok(())
    }

    #[test]
    fn repeated_desktop_start_activates_exact_state_directory() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let _startup = StartupPermit::acquire(&directory)?;
        let first = DesktopInstance::acquire_or_activate(&directory)?.ok_or("missing owner")?;
        assert!(DesktopInstance::acquire_or_activate(&directory)?.is_none());
        assert!(DesktopInstance::take_activation(&directory));
        assert!(!DesktopInstance::take_activation(&directory));
        let other = temporary.path().join("other");
        let _other_startup = StartupPermit::acquire(&other)?;
        assert!(DesktopInstance::acquire_or_activate(&other)?.is_some());
        drop(first);
        assert!(DesktopInstance::acquire_or_activate(&directory)?.is_some());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn maintenance_rejects_a_link_without_touching_its_target() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        crate::initialize_directory(&directory)?;
        let outside = temporary.path().join("outside");
        std::fs::write(&outside, b"preserve")?;
        std::os::unix::fs::symlink(&outside, directory.join(ADMISSION))?;
        assert!(MaintenanceGuard::acquire(&directory).is_err());
        assert_eq!(std::fs::read(outside)?, b"preserve");
        Ok(())
    }
}
