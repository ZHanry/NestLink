//! Small OS boundary for installation keys. No network or business authorization.
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
#[cfg(target_os = "linux")]
pub mod local_port_gate;
#[cfg(any(unix, windows))]
pub mod local_stream;

pub fn private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    check_regular(path, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        check_owner(path)?;
    }
    Ok(())
}
/// Atomically creates one fresh private directory. Never accepts an existing path.
/// The caller selects a trusted parent directory; parents are not created here.
pub fn new_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    #[cfg(windows)]
    private_acl::create_directory(path)?;
    check_private_directory(path)
}

/// Fails closed unless `path` is a real private directory owned by this user.
/// On Windows the directory must have the protected owner/SYSTEM-only ACL that
/// `new_private_directory` installs; inherited or otherwise widened ACLs fail.
pub fn check_private_directory(path: &Path) -> io::Result<()> {
    check_regular(path, true)?;
    #[cfg(unix)]
    check_owner(path)?;
    #[cfg(windows)]
    private_acl::check_directory(path)?;
    Ok(())
}
pub fn create_key(path: &Path, key: &[u8; 32]) -> io::Result<()> {
    create_private(path, &protect(key)?)
}
pub fn load_key(path: &Path) -> io::Result<Zeroizing<[u8; 32]>> {
    let data = read_private(path, 16_384)?;
    let plain = unprotect(&data)?;
    let key: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| io::Error::other("invalid installation key length"))?;
    Ok(Zeroizing::new(key))
}
pub fn create_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()
}
/// A replacement may already be visible when flushing its parent fails. Such
/// a commit must not be reported as though the previous file were unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataCommit {
    Durable,
    Visible,
}

struct MetadataTemporary(PathBuf);

impl Drop for MetadataTemporary {
    fn drop(&mut self) {
        // This path was created exclusively by this operation. After commit
        // it no longer exists; an unsuccessful operation removes its own file.
        let _ = fs::remove_file(&self.0);
    }
}

fn metadata_temporary(path: PathBuf, bytes: &[u8]) -> io::Result<MetadataTemporary> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    let temporary = MetadataTemporary(path);
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    // Windows must close the handle before either rename or cleanup.
    drop(file);
    written?;
    Ok(temporary)
}

fn commit_metadata(
    temporary: MetadataTemporary,
    path: &Path,
    replace: impl FnOnce(&Path, &Path) -> io::Result<()>,
    synchronize: impl FnOnce() -> io::Result<()>,
) -> io::Result<MetadataCommit> {
    replace(&temporary.0, path)?;
    Ok(if synchronize().is_ok() {
        MetadataCommit::Durable
    } else {
        MetadataCommit::Visible
    })
}

/// Atomically replace one bounded metadata file below a checked private
/// parent. The caller must retain its stable admission lock through the write.
/// Keys and databases are never replaced through this small-metadata API.
/// `Err` means the replacement did not commit; `Visible` means new bytes are
/// effective, but persistence across sudden power loss could not be confirmed.
pub fn replace_private_metadata(path: &Path, bytes: &[u8]) -> io::Result<MetadataCommit> {
    const MAXIMUM: usize = 1024 * 1024;
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if !path.is_absolute() || bytes.is_empty() || bytes.len() > MAXIMUM {
        return Err(io::Error::other("invalid atomic private metadata request"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("metadata parent missing"))?;
    check_private_directory(parent)?;
    match read_private(path, MAXIMUM as u64) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let leaf = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("metadata leaf is not Unicode"))?;
    let mut selected = None;
    for _ in 0..16 {
        let value = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = parent.join(format!("{leaf}.replace-{}-{value}", std::process::id()));
        match metadata_temporary(temporary, bytes) {
            Ok(temporary) => {
                selected = Some(temporary);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    let temporary =
        selected.ok_or_else(|| io::Error::other("metadata temporary-file budget exhausted"))?;
    commit_metadata(
        temporary,
        path,
        |source, destination| {
            #[cfg(windows)]
            return atomic_metadata::replace(source, destination);
            #[cfg(not(windows))]
            fs::rename(source, destination)
        },
        || {
            #[cfg(unix)]
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        },
    )
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod atomic_metadata {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    pub(super) fn replace(source: &Path, destination: &Path) -> io::Result<()> {
        let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: NUL-terminated paths name this caller's create-new temporary
        // file and checked destination below one protected private parent.
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub fn read_private(path: &Path, maximum: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    let limit = maximum
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid private file limit"))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
        options.custom_flags(flags.bits() as i32);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT opens the link itself, then rejects it below.
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("private handle must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "private file handle has an invalid owner or permissions",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other(
                "private file handle must not be a reparse point",
            ));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(io::Error::other("private file exceeds size limit"));
    }
    Ok(bytes)
}
fn check_regular(path: &Path, directory: bool) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other(
                "reparse points are not allowed for private files",
            ));
        }
    }
    if m.file_type().is_symlink() || (directory && !m.is_dir()) || (!directory && !m.is_file()) {
        return Err(io::Error::other(
            "private path must be a regular file or directory",
        ));
    }
    Ok(())
}
#[cfg(unix)]
fn check_owner(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path)?;
    if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
        return Err(io::Error::other(
            "private files must be owned by the service user and deny group/other access",
        ));
    }
    Ok(())
}
#[cfg(unix)]
fn protect(key: &[u8; 32]) -> io::Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(key.to_vec()))
}
#[cfg(unix)]
fn unprotect(data: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(data.to_vec()))
}
#[cfg(windows)]
fn protect(key: &[u8; 32]) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(b"NL15DP01".to_vec());
    data.extend_from_slice(&dpapi::transform(key, true)?);
    Ok(data)
}
#[cfg(windows)]
fn unprotect(data: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let body = data
        .strip_prefix(b"NL15DP01")
        .ok_or_else(|| io::Error::other("expected a NestLink DPAPI key"))?;
    dpapi::transform(body, false)
}
// Synchronous Win32 boundaries are kept in these two narrowly scoped modules.
#[cfg(windows)]
#[allow(unsafe_code)]
mod private_acl {
    use super::*;
    use std::{
        mem::offset_of,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        },
        ptr::{null, null_mut},
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
            LocalFree,
        },
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
            GetAclInformation, GetLengthSid, GetSecurityDescriptorControl,
            GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, IsValidAcl,
            IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
            SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser, WinCreatorOwnerRightsSid,
            WinLocalSystemSid,
        },
        Storage::FileSystem::{
            CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            OPEN_EXISTING, READ_CONTROL,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: this wrapper owns a valid handle returned by a Win32 open call.
            unsafe { CloseHandle(self.0) };
        }
    }

    struct OwnedSecurityDescriptor(*mut core::ffi::c_void);
    impl Drop for OwnedSecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo allocates this descriptor with LocalAlloc.
            unsafe { LocalFree(self.0) };
        }
    }

    fn denied() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private directory owner or ACL is unsafe",
        )
    }

    fn sid(kind: i32) -> io::Result<[u8; 68]> {
        let mut bytes = [0_u8; 68];
        let mut length = bytes.len() as u32;
        // SAFETY: the output buffer has SECURITY_MAX_SID_SIZE bytes and remains
        // alive for the synchronous API call.
        if unsafe { CreateWellKnownSid(kind, null_mut(), bytes.as_mut_ptr().cast(), &mut length) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes)
    }

    fn current_user_sid() -> io::Result<(Vec<u64>, *mut core::ffi::c_void)> {
        let mut raw_token = null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle; OpenProcessToken
        // initializes `raw_token` on success.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(raw_token);
        let mut length = 0_u32;
        // SAFETY: null is the documented size-query form for GetTokenInformation.
        let first = unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut length) };
        if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || length == 0 {
            return Err(io::Error::last_os_error());
        }
        let words = (length as usize).div_ceil(std::mem::size_of::<u64>());
        let mut storage = vec![0_u64; words];
        let capacity = u32::try_from(storage.len() * std::mem::size_of::<u64>())
            .map_err(|_| io::Error::other("token information is too large"))?;
        // SAFETY: aligned writable storage is at least `length` bytes and the
        // token remains open for the duration of the call.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                storage.as_mut_ptr().cast(),
                capacity,
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: TokenUser returns a TOKEN_USER at the beginning of this
        // correctly aligned buffer, and the buffer stays owned by the caller.
        let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
        Ok((storage, user.User.Sid))
    }

    fn allowed_ace(
        acl: *mut ACL,
        index: u32,
        expected_sid: *mut core::ffi::c_void,
    ) -> io::Result<bool> {
        let mut raw = null_mut();
        // SAFETY: the ACL is owned by the valid security descriptor; GetAce
        // bounds-checks the requested index.
        if unsafe { GetAce(acl, index, &mut raw) } == 0 || raw.is_null() {
            return Err(denied());
        }
        // SAFETY: every ACE has a common ACE_HEADER prefix.
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE
            || u32::from(header.AceFlags) != OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            || usize::from(header.AceSize) < offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
        {
            return Ok(false);
        }
        // SAFETY: type and minimum size were validated above; the pointer is
        // aligned by the ACL's ACE layout.
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Mask != FILE_ALL_ACCESS {
            return Ok(false);
        }
        let ace_sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
        // SAFETY: the ACE includes the minimum SID bytes and originates in the
        // OS-validated ACL returned by GetSecurityInfo.
        if unsafe { IsValidSid(ace_sid) } == 0 {
            return Err(denied());
        }
        // SAFETY: IsValidSid confirmed this SID header is readable; keep the
        // complete variable-length SID inside this single ACE.
        let sid_length = unsafe { GetLengthSid(ace_sid) } as usize;
        if sid_length == 0
            || offset_of!(ACCESS_ALLOWED_ACE, SidStart) + sid_length != usize::from(header.AceSize)
        {
            return Err(denied());
        }
        // SAFETY: both values are valid SIDs and remain live through comparison.
        Ok(unsafe { EqualSid(ace_sid, expected_sid) } != 0)
    }

    pub(super) fn check_directory(path: &Path) -> io::Result<()> {
        let mut name: Vec<u16> = path.as_os_str().encode_wide().collect();
        if name.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory contains NUL",
            ));
        }
        name.push(0);
        // Open the directory itself, including a reparse point if one raced
        // path validation. The handle metadata below rejects that case.
        // SAFETY: `name` is terminated UTF-16 and remains live for the call.
        let raw_handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw_handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileW succeeded and ownership transfers to this File.
        let file = unsafe { std::fs::File::from_raw_handle(raw_handle.cast()) };
        let metadata = file.metadata()?;
        use std::os::windows::fs::MetadataExt;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(denied());
        }

        let mut descriptor = null_mut();
        // SAFETY: output pointers are valid; descriptor is freed below.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let descriptor = OwnedSecurityDescriptor(descriptor);
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: descriptor is a valid security descriptor returned by Win32.
        if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(denied());
        }
        let mut dacl_present = 0;
        let mut dacl = null_mut();
        let mut dacl_defaulted = 0;
        // SAFETY: all output pointers are valid and descriptor is still alive.
        if unsafe {
            GetSecurityDescriptorDacl(
                descriptor.0,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
        } == 0
            || dacl_present == 0
            || dacl.is_null()
            || unsafe { IsValidAcl(dacl) } == 0
        {
            return Err(denied());
        }
        let mut owner = null_mut();
        let mut owner_defaulted = 0;
        // SAFETY: the owner pointer is an output into the live descriptor.
        if unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut owner_defaulted) }
            == 0
            || owner.is_null()
            || unsafe { IsValidSid(owner) } == 0
        {
            return Err(denied());
        }
        let (user_storage, user_sid) = current_user_sid()?;
        let _keep_user_storage_alive = user_storage;
        // SAFETY: both SIDs are validated, and their backing storage remains live.
        if unsafe { EqualSid(owner, user_sid) } == 0 {
            return Err(denied());
        }

        let mut size = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` is valid and size receives a fixed-size record.
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
            || size.AceCount != 2
        {
            return Err(denied());
        }
        let owner_rights = sid(WinCreatorOwnerRightsSid)?;
        let system = sid(WinLocalSystemSid)?;
        let owner_rights = owner_rights.as_ptr().cast_mut().cast();
        let system = system.as_ptr().cast_mut().cast();
        let mut found_owner_rights = false;
        let mut found_system = false;
        for index in 0..size.AceCount {
            if allowed_ace(dacl, index, owner_rights)? {
                if found_owner_rights {
                    return Err(denied());
                }
                found_owner_rights = true;
            } else if allowed_ace(dacl, index, system)? {
                if found_system {
                    return Err(denied());
                }
                found_system = true;
            } else {
                return Err(denied());
            }
        }
        if !found_owner_rights || !found_system {
            return Err(denied());
        }
        Ok(())
    }

    pub(super) fn create_directory(path: &Path) -> io::Result<()> {
        let mut name: Vec<u16> = path.as_os_str().encode_wide().collect();
        if name.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory contains NUL",
            ));
        }
        name.push(0);
        // Elevated tokens may default to Administrators as their object owner.
        // Bind the fresh directory to this exact TokenUser, as required by the
        // existing readback check, without relaxing its protected DACL.
        let (_user_storage, user) = current_user_sid()?;
        let mut user_text = std::ptr::null_mut();
        // SAFETY: the live token buffer contains a valid SID; the API allocates
        // its terminated text and the allocation is released by this frame.
        if unsafe { ConvertSidToStringSidW(user, &mut user_text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _user_text = OwnedSecurityDescriptor(user_text.cast());
        let mut length = 0usize;
        while length < 256 && unsafe { *user_text.add(length) } != 0 { length += 1; }
        if length == 256 { return Err(denied()); }
        // SAFETY: ConvertSidToStringSidW owns this valid terminated text for
        // the complete bounded copy; no pointer is retained in the SDDL.
        let user = String::from_utf16(unsafe { std::slice::from_raw_parts(user_text,length) })
            .map_err(|_| denied())?;
        let descriptor_text: Vec<u16> = format!("O:{user}D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)\0")
            .encode_utf16().collect();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: terminated UTF-16 input is alive; Win32 initializes the output allocation.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor_text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        // SAFETY: both input allocations outlive this synchronous call. No existing
        // directory is opened. Capture the error before freeing the descriptor.
        let result = if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        };
        // SAFETY: the conversion returned a LocalAlloc-owned descriptor, freed once.
        unsafe {
            LocalFree(descriptor);
        }
        result
    }
}
#[cfg(windows)]
#[allow(unsafe_code)]
mod dpapi {
    use super::*;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    };
    pub(super) fn transform(input: &[u8], encrypt: bool) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut source = Zeroizing::new(input.to_vec());
        let blob = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(source.len()).map_err(|_| io::Error::other("key too large"))?,
            pbData: source.as_mut_ptr(),
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: input remains alive, outputs are initialized, no optional pointers are used.
        let success = unsafe {
            if encrypt {
                CryptProtectData(
                    &blob,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut output,
                )
            } else {
                CryptUnprotectData(
                    &blob,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut output,
                )
            }
        };
        if success == 0 {
            return Err(io::Error::last_os_error());
        }
        if output.pbData.is_null() {
            return Err(io::Error::other("DPAPI returned no data"));
        }
        // SAFETY: DPAPI owns a cbData-sized allocation released exactly once with LocalFree.
        let result = unsafe {
            let slice = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
            let bytes = Zeroizing::new(slice.to_vec());
            use zeroize::Zeroize;
            slice.zeroize();
            LocalFree(output.pbData.cast());
            bytes
        };
        Ok(result)
    }
}

#[cfg(test)]
mod metadata_commit_tests {
    use super::*;

    #[test]
    fn failed_rename_preserves_previous_bytes_and_removes_owned_temporary()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("metadata");
        fs::write(&path, b"previous")?;
        let temporary_path = directory.path().join("owned-temporary");
        let temporary = metadata_temporary(temporary_path.clone(), b"replacement")?;
        assert!(
            commit_metadata(
                temporary,
                &path,
                |_, _| Err(io::Error::other("rename refused")),
                || Ok(())
            )
            .is_err()
        );
        assert_eq!(fs::read(path)?, b"previous");
        assert!(!temporary_path.exists());
        Ok(())
    }

    #[test]
    fn failed_directory_flush_reports_the_replacement_that_already_committed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("metadata");
        fs::write(&path, b"previous")?;
        let temporary_path = directory.path().join("owned-temporary");
        let temporary = metadata_temporary(temporary_path.clone(), b"replacement")?;
        let result = commit_metadata(
            temporary,
            &path,
            |source, destination| {
                #[cfg(windows)]
                return atomic_metadata::replace(source, destination);
                #[cfg(not(windows))]
                fs::rename(source, destination)
            },
            || Err(io::Error::other("directory flush failed")),
        )?;
        assert_eq!(result, MetadataCommit::Visible);
        assert_eq!(fs::read(path)?, b"replacement");
        assert!(!temporary_path.exists());
        Ok(())
    }
}
