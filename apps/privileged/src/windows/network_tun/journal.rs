//! The TUN journal reuses the existing protected local-file implementation.
//! Its independent names prevent confusing a WFP recovery record with a TUN.
use super::super::{local_port_gate::store, security};
use std::{ffi::OsStr, fs::{File, OpenOptions}, io, os::windows::{fs::{OpenOptionsExt,MetadataExt}, io::AsRawHandle}, path::Path};

const RECORD: &str = "network-tun-owner.json";
pub struct AdminJournal {
    parents: store::Parents,
    _lock: File,
}
impl AdminJournal {
    pub fn initialize(path: &Path) -> io::Result<()> { store::initialize(path) }
    pub fn open(path: &Path) -> io::Result<Self> {
        super::super::require_administrator_process()?;
        // initialize also checks an existing leaf is administrator-private.
        store::initialize(path)?;
        let parents = store::Parents::open(path)?;
        let lock_path = path.join("network-tun-owner.lock");
        match parents.write(OsStr::new("network-tun-owner.lock"), b"NestLink TUN lock\n", None, false) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(error) => return Err(error),
        }
        let lock = OpenOptions::new().read(true).write(true).share_mode(0)
            .custom_flags(0x0020_0000).open(lock_path)?;
        let metadata=lock.metadata()?;
        if !metadata.is_file() || metadata.file_attributes()&0x400!=0 { return Err(security::denied()); }
        security::private_administrator_acl(lock.as_raw_handle().cast())?;
        Ok(Self { parents, _lock:lock })
    }
    pub fn read(&self) -> io::Result<Option<Vec<u8>>> {
        match self.parents.read(OsStr::new(RECORD), true) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    pub fn save(&self, bytes: &[u8]) -> io::Result<()> {
        self.parents.write(OsStr::new(RECORD), bytes, None, true)
    }
    pub fn clear(&self, expected: &[u8]) -> io::Result<()> {
        if self.read()?.as_deref() != Some(expected) { return Err(security::denied()); }
        std::fs::remove_file(self.parents.directory.join(RECORD))
    }
}

/// Remove only the unchanged protected receipt after kernel absence was read.
pub fn clear_receipt(path: &Path, expected: &[u8]) -> io::Result<()> {
    super::super::require_administrator_process()?;
    let parents = store::Parents::open(path.parent().ok_or_else(security::denied)?)?;
    let name = path.file_name().ok_or_else(security::denied)?;
    match parents.read(name,false) {
        Ok(bytes) if bytes==expected=>{},
        Err(error) if error.kind()==io::ErrorKind::NotFound=>return Ok(()),
        Err(error)=>return Err(error),
        _=>return Err(security::denied()),
    }
    std::fs::remove_file(path)
}

pub fn validate_receipt_destination(path:&Path)->io::Result<()> {
    super::super::require_administrator_process()?;
    let parents=store::Parents::open(path.parent().ok_or_else(security::denied)?)?;
    match parents.read(path.file_name().ok_or_else(security::denied)?,false) {
        Err(error) if error.kind()==io::ErrorKind::NotFound=>Ok(()),
        Err(error)=>Err(error),
        Ok(_)=>Err(io::Error::other("fresh administrator-owned TUN receipt destination required")),
    }
}
