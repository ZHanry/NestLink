//! Reuses the existing protected metadata primitives and OS file lock. A failed
//! durable commit always retains the fixed recovery journal.
use super::*;
use nestlink_platform_security::{
    MetadataCommit, check_private_directory, create_private, read_private, replace_private_metadata,
};
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

const JOURNAL: &str = "network-tun-owner.json";
pub(super) struct JournalStore {
    directory: PathBuf,
    _lock: File,
}
impl JournalStore {
    pub fn open(directory: &Path) -> Result<Self> {
        if !directory.is_absolute() {
            return Err(
                io::Error::other("absolute root-private TUN journal directory required").into(),
            );
        }
        check_private_directory(directory)?;
        let directory = directory.canonicalize()?;
        let path = directory.join("network-tun-owner.lock");
        match create_private(&path, &[]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let _ = read_private(&path, 1)?;
            }
            Err(error) => return Err(error.into()),
        }
        let lock = OpenOptions::new().read(true).write(true).open(path)?;
        if !lock.metadata()?.is_file() || lock.metadata()?.len() != 0 {
            return Err(io::Error::other("invalid TUN journal lock").into());
        }
        lock.try_lock()
            .map_err(|_| io::Error::other("another TUN helper owns this recovery journal"))?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }
    pub fn read(&self) -> Result<Option<Journal>> {
        let bytes = match read_private(&self.directory.join(JOURNAL), plan::MAX_JSON) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let journal: Journal = serde_json::from_slice(&bytes)?;
        if journal.schema_version != 1 {
            return Err(io::Error::other("unsupported TUN recovery journal").into());
        }
        journal.plan.validate(false)?;
        let uid = journal.plan.linux_uid()?;
        if journal.identity.as_ref().is_some_and(|id| {
            id.name != journal.plan.link()
                || id.marker != journal.plan.marker()
                || id.uid != uid
                || id.index == 0
        }) || journal
            .installed
            .as_ref()
            .is_some_and(|state| Some(&state.identity) != journal.identity.as_ref())
        {
            return Err(io::Error::other(
                "TUN recovery identity differs from its exact original plan",
            )
            .into());
        }
        Ok(Some(journal))
    }
    pub fn save(&self, journal: &Journal) -> Result {
        let bytes = serde_json::to_vec(journal)?;
        if bytes.len() > plan::MAX_JSON as usize {
            return Err(io::Error::other("TUN recovery journal exceeds bound").into());
        }
        if replace_private_metadata(&self.directory.join(JOURNAL), &bytes)?
            != MetadataCommit::Durable
        {
            return Err(io::Error::other(
                "TUN journal is visible but not confirmed durable; recovery required",
            )
            .into());
        }
        Ok(())
    }
    pub fn clear(&self) -> Result {
        let _ = self
            .read()?
            .ok_or_else(|| io::Error::other("TUN journal disappeared before confirmed cleanup"))?;
        std::fs::remove_file(self.directory.join(JOURNAL))?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}
