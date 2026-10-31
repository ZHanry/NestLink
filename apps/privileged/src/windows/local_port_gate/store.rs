//! Protected native files reuse the broker ACL parser and open-handle policy.
#![allow(unsafe_code)]
use super::*;
use std::{
    ffi::OsStr,
    fs::OpenOptions,
    io::{Read, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Prefix},
    ptr::null_mut,
    sync::atomic::{AtomicU64, Ordering},
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetDriveTypeW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        MoveFileExW, READ_CONTROL,
    },
};

const JOURNAL: &str = "local-port-owner.json";
pub(in crate::windows) struct Parents {
    pub directory: PathBuf,
    _handles: Vec<File>,
}
impl Parents {
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("absolute local protected directory required"));
        }
        let mut directory = PathBuf::new();
        let mut handles = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix)
                    if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
                {
                    directory.push(prefix.as_os_str())
                }
                Component::RootDir => {
                    directory.push(component.as_os_str());
                    let root = security::wide(directory.as_os_str())?;
                    // DRIVE_FIXED is 3 in the native GetDriveType contract.
                    // A mapped SMB drive also has a Disk prefix, but its
                    // remote server's ACL assertions are not a trust anchor.
                    if unsafe { GetDriveTypeW(root.as_ptr()) } != 3 {
                        return Err(invalid("gate trust anchor requires a fixed local volume"));
                    }
                }
                Component::Normal(name) => directory.push(name),
                _ => {
                    return Err(invalid(
                        "local gate path must not use network shares or relative components",
                    ));
                }
            }
            if !directory.is_absolute() {
                continue;
            }
            let file = open(&directory, true, false)?;
            security::protected_ancestor_acl(file.as_raw_handle().cast())?;
            handles.push(file);
        }
        let leaf = handles
            .last()
            .ok_or_else(|| invalid("protected directory missing"))?;
        security::protected_acl(leaf.as_raw_handle().cast())?;
        Ok(Self {
            directory,
            _handles: handles,
        })
    }
    fn path(&self, name: &OsStr) -> io::Result<PathBuf> {
        let name = Path::new(name);
        if name.components().count() != 1
            || !matches!(name.components().next(), Some(Component::Normal(_)))
        {
            return Err(invalid("gate metadata must have one regular filename"));
        }
        Ok(self.directory.join(name))
    }
    pub fn write(
        &self,
        name: &OsStr,
        bytes: &[u8],
        user: Option<&str>,
        replace: bool,
    ) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_JSON as usize {
            return Err(invalid("gate metadata size rejected"));
        }
        let destination = self.path(name)?;
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let temporary = self.directory.join(format!(
            ".nestlink-gate-{}-{}.tmp",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| -> io::Result<()> {
            let mut file = create(&temporary, user)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            let source = security::wide(temporary.as_os_str())?;
            let target = security::wide(destination.as_os_str())?;
            let flags = MOVEFILE_WRITE_THROUGH
                | if replace {
                    MOVEFILE_REPLACE_EXISTING
                } else {
                    0
                };
            // SAFETY: both names are beneath the same retained no-reparse,
            // admin-controlled parent. Only this operation created the source.
            if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), flags) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
    pub fn read(&self, name: &OsStr, private: bool) -> io::Result<Vec<u8>> {
        let file = open(&self.path(name)?, false, false)?;
        if private {
            security::private_administrator_acl(file.as_raw_handle().cast())?;
        } else {
            security::protected_acl(file.as_raw_handle().cast())?;
        }
        bounded(file)
    }
}
pub(in crate::windows) fn open(path: &Path, directory: bool, write: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .access_mode(0x80000000 | READ_CONTROL | if write { 0x40000000 } else { 0 })
        .share_mode(FILE_SHARE_READ | if directory { FILE_SHARE_WRITE } else { 0 })
        .custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        );
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & 0x400 != 0
        || metadata.is_dir() != directory
        || !directory && !metadata.is_file()
    {
        return Err(invalid(
            "gate metadata must not be a reparse point or device",
        ));
    }
    Ok(file)
}
pub(in crate::windows) fn bounded(file: File) -> io::Result<Vec<u8>> {
    if file.metadata()?.len() > MAXIMUM_JSON {
        return Err(invalid("gate metadata exceeds its bound"));
    }
    let mut bytes = Vec::new();
    file.take(MAXIMUM_JSON + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAXIMUM_JSON as usize {
        return Err(invalid("gate metadata exceeds its bound"));
    }
    Ok(bytes)
}
pub(super) fn descriptor(user: Option<&str>, directory: bool) -> io::Result<security::Local> {
    if user.is_some_and(|sid| !valid_sid(sid)) {
        return Err(invalid("invalid local owner SID"));
    }
    let inheritance = if directory { "OICI" } else { "" };
    let text = format!(
        "O:BAG:BAD:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA){}",
        user.map(|sid| format!("(A;;FR;;;{sid})"))
            .unwrap_or_default()
    );
    let text = security::text(&text)?;
    let mut raw = null_mut();
    // SAFETY: bounded validated SID and fixed SDDL, allocation owned by Local.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            null_mut(),
        )
    } == 0
        || raw.is_null()
    {
        return Err(io::Error::last_os_error());
    }
    Ok(security::Local(raw))
}
fn create(path: &Path, user: Option<&str>) -> io::Result<File> {
    let descriptor = descriptor(user, false)?;
    let file = create_with_descriptor(path, &descriptor)?;
    security::protected_acl(file.as_raw_handle().cast())?;
    Ok(file)
}
fn create_with_descriptor(path: &Path, descriptor: &security::Local) -> io::Result<File> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let name = security::wide(path.as_os_str())?;
    // SAFETY: CREATE_NEW never adopts an existing object. The descriptor and
    // terminated path live through this synchronous call; ownership transfers.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x40000000 | READ_CONTROL,
            FILE_SHARE_READ,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful non-pseudo CreateFileW handle transfers exactly
    // once into this File and is closed when the File is dropped.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}
pub(super) fn save_plan(path: &Path, plan: &GatePlan) -> io::Result<()> {
    save_owner_plan(path, &serde_json::to_vec_pretty(plan)?, &plan.process.sid)
}
pub(in crate::windows) fn save_owner_plan(path: &Path, bytes: &[u8], sid: &str) -> io::Result<()> {
    if !valid_sid(sid) || bytes.is_empty() || bytes.len() > MAXIMUM_JSON as usize {
        return Err(invalid("bounded original-owner public plan required"));
    }
    // Explicit administrator read admission allows an administrator using a
    // different SID to consume the selected plan without changing its owner
    // or ACL. The ordinary owner's already-private parent remains private.
    let sddl = security::text(&format!(
        "O:{}D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FR;;;BA)",
        sid, sid
    ))?;
    let mut raw = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            null_mut(),
        )
    } == 0
        || raw.is_null()
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = security::Local(raw);
    let mut file = create_with_descriptor(path, &descriptor)?;
    security::private_owner_acl(file.as_raw_handle().cast(), sid)?;
    file.write_all(bytes)?;
    file.sync_all()
}
pub(super) fn initialize(directory: &Path) -> io::Result<()> {
    require_admin()?;
    let _parent = Parents::open(
        directory
            .parent()
            .ok_or_else(|| invalid("journal parent missing"))?,
    )?;
    let name = security::wide(directory.as_os_str())?;
    let descriptor = descriptor(None, true)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: one explicit child under retained protected ancestors, fixed ACL.
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    let directory = Parents::open(directory)?;
    let leaf = directory
        ._handles
        .last()
        .ok_or_else(|| invalid("journal directory missing"))?;
    security::private_administrator_acl(leaf.as_raw_handle().cast())
}
pub(super) struct Store {
    parent: Parents,
    _lock: File,
}
impl Store {
    pub fn open(directory: &Path) -> io::Result<Self> {
        require_admin()?;
        let parent = Parents::open(directory)?;
        let leaf = parent
            ._handles
            .last()
            .ok_or_else(|| invalid("journal directory missing"))?;
        security::private_administrator_acl(leaf.as_raw_handle().cast())?;
        let path = parent.directory.join("local-port-owner.lock");
        match create(&path, None) {
            Ok(file) => drop(file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(0xc0000000 | READ_CONTROL)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        if !lock.metadata()?.is_file()
            || lock.metadata()?.file_attributes() & 0x400 != 0
            || lock.metadata()?.len() != 0
        {
            return Err(invalid("invalid gate journal lock"));
        }
        security::private_administrator_acl(lock.as_raw_handle().cast())?;
        Ok(Self {
            parent,
            _lock: lock,
        })
    }
    pub fn read(&self) -> io::Result<Option<Journal>> {
        let bytes = match self.parent.read(OsStr::new(JOURNAL), true) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let journal: Journal = serde_json::from_slice(&bytes)?;
        if journal.schema_version != 1 {
            return Err(invalid("unsupported WFP journal"));
        }
        journal.plan.validate(false)?;
        Ok(Some(journal))
    }
    pub fn save(&self, journal: &Journal) -> io::Result<()> {
        self.parent.write(
            OsStr::new(JOURNAL),
            &serde_json::to_vec(journal)?,
            None,
            true,
        )
    }
    pub fn clear(&self) -> io::Result<()> {
        if self.read()?.is_none() {
            return Err(invalid("original WFP journal disappeared"));
        }
        std::fs::remove_file(self.parent.directory.join(JOURNAL))
    }
}
pub(super) fn read_plan(path: &Path) -> io::Result<GatePlan> {
    if !path.is_absolute() {
        return Err(invalid("absolute plan path required"));
    }
    let file = open(path, false, false)?;
    let plan: GatePlan = serde_json::from_slice(&bounded(file.try_clone()?)?)?;
    plan.validate(false)?;
    security::private_owner_acl(file.as_raw_handle().cast(), &plan.process.sid)?;
    // This is selected untrusted input, not the administrator trust anchor.
    // Validate its retained file/owner and later the live captured process;
    // no parent ACL is adopted as authority. Requiring directory read access
    // here would defeat the explicit BA file read grant for another admin SID.
    Ok(plan)
}
pub(super) fn image(path: &Path) -> io::Result<(u32, u64)> {
    image_identity(&open(path, false, false)?)
}
fn image_identity(file: &File) -> io::Result<(u32, u64)> {
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: live regular-file handle and complete writable fixed-size output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        info.dwVolumeSerialNumber,
        u64::from(info.nFileIndexLow) | u64::from(info.nFileIndexHigh) << 32,
    ))
}
pub(in crate::windows) struct ImageLock {
    pub identity: (u32, u64),
    _file: File,
    _parents: Parents,
}
pub(in crate::windows) fn lock_image(path: &Path) -> io::Result<ImageLock> {
    let parents = Parents::open(
        path.parent()
            .ok_or_else(|| invalid("protected executable parent missing"))?,
    )?;
    let file = open(path, false, false)?;
    security::protected_acl(file.as_raw_handle().cast())?;
    Ok(ImageLock {
        identity: image_identity(&file)?,
        _file: file,
        _parents: parents,
    })
}
