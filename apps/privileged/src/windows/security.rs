#![allow(unsafe_code)]
use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_BAD_LENGTH, ERROR_INSUFFICIENT_BUFFER, FILETIME, GetLastError, HANDLE,
        LocalFree, WAIT_TIMEOUT,
    },
    Security::{Authorization::*, *},
    System::{Pipes::*, Threading::*},
};

pub(super) fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "privileged broker OS identity or ACL rejected",
    )
}
pub(super) fn wide(value: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
    let mut result: Vec<_> = value.encode_wide().collect();
    if result.contains(&0) || result.len() > 32760 {
        return Err(denied());
    }
    result.push(0);
    Ok(result)
}
pub(super) fn text(value: &str) -> io::Result<Vec<u16>> {
    wide(std::ffi::OsStr::new(value))
}
pub(super) struct Handle(pub HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: each Handle owns one successfully opened non-pseudo OS handle.
        unsafe { CloseHandle(self.0) };
    }
}
pub(super) struct Local(pub *mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: every constructor of Local wraps an allocation documented for LocalFree.
        unsafe { LocalFree(self.0) };
    }
}

fn token_blob(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut length = 0;
    // SAFETY: null buffer is the documented size query; the token remains open.
    let first = unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut length) };
    let size_error = if first == 0 {
        // SAFETY: GetLastError immediately follows the failed size query.
        unsafe { GetLastError() }
    } else {
        0
    };
    if first != 0
        || !matches!(size_error, ERROR_INSUFFICIENT_BUFFER | ERROR_BAD_LENGTH)
        || length == 0
        || length > 65536
    {
        return Err(denied());
    }
    // Some token classes, including TokenElevation, require this exact byte
    // length even though the allocation is padded for pointer alignment.
    let required = length;
    let mut storage = vec![0u64; (length as usize).div_ceil(size_of::<u64>())];
    let capacity = (storage.len() * size_of::<u64>()) as u32;
    let mut returned_length = required;
    // SAFETY: aligned writable capacity covers the size returned above.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            storage.as_mut_ptr().cast(),
            required,
            &mut returned_length,
        )
    } == 0
        || returned_length > capacity
    {
        return Err(denied());
    }
    Ok(storage)
}
fn in_blob_sid(storage: &[u64], sid: PSID) -> io::Result<()> {
    let first = storage.as_ptr() as usize;
    let last = first.checked_add(size_of_val(storage)).ok_or_else(denied)?;
    let address = sid as usize;
    if address < first || address.checked_add(8).is_none_or(|end| end > last) {
        return Err(denied());
    }
    // SAFETY: a complete SID header is inside the live OS token buffer.
    let length = unsafe { GetLengthSid(sid) } as usize;
    if length < 8
        || address.checked_add(length).is_none_or(|end| end > last)
        || unsafe { IsValidSid(sid) } == 0
    {
        return Err(denied());
    }
    Ok(())
}
fn sid_string(sid: PSID) -> io::Result<String> {
    let mut value = null_mut();
    // SAFETY: caller supplies an OS-validated live SID; output is freed by Local.
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 || value.is_null() {
        return Err(denied());
    }
    let memory = Local(value.cast());
    let mut length = 0;
    // SAFETY: Windows SID strings are bounded by documented SID sizes. The
    // returned allocation is terminated; stop before that terminator.
    while length < 256 && unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(denied());
    }
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
        .map_err(|_| denied());
    drop(memory);
    result
}

pub(super) struct Peer {
    pub handle: Handle,
    pub pid: u32,
    pub sid: String,
    pub session: u32,
    pub integrity: u32,
    pub elevated: bool,
    pub image: PathBuf,
    pub creation: u64,
}
impl Peer {
    pub fn open(pid: u32) -> io::Result<Self> {
        if pid == 0 {
            return Err(denied());
        }
        // SAFETY: read/synchronization-only access to a concrete local PID.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return Err(denied());
        }
        Self::from_handle(Handle(handle), pid)
    }
    pub fn from_handle(handle: Handle, pid: u32) -> io::Result<Self> {
        // SAFETY: the caller transfers an owned process handle; GetProcessId is read-only.
        if unsafe { GetProcessId(handle.0) } != pid {
            return Err(denied());
        }
        let mut token = null_mut();
        // SAFETY: owned process handle and writable token output; no impersonation.
        if unsafe { OpenProcessToken(handle.0, TOKEN_QUERY, &mut token) } == 0 {
            return Err(denied());
        }
        let token = Handle(token);
        let user = token_blob(token.0, TokenUser)?;
        if size_of_val(user.as_slice()) < size_of::<TOKEN_USER>() {
            return Err(denied());
        }
        // SAFETY: TokenUser returned the required aligned structure prefix.
        let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        in_blob_sid(&user, sid)?;
        let sid = sid_string(sid)?;
        let session = token_blob(token.0, TokenSessionId)?;
        let session = session.first().copied().ok_or_else(denied)? as u32;
        if session == 0 {
            return Err(denied());
        }
        let elevated = token_blob(token.0, TokenElevation)?;
        let elevated = elevated.first().copied().ok_or_else(denied)? as u32 != 0;
        let app_container = token_blob(token.0, TokenIsAppContainer)?;
        if app_container.first().copied().ok_or_else(denied)? as u32 != 0 {
            return Err(denied());
        }
        let integrity = token_blob(token.0, TokenIntegrityLevel)?;
        if size_of_val(integrity.as_slice()) < size_of::<TOKEN_MANDATORY_LABEL>() {
            return Err(denied());
        }
        // SAFETY: exact token class and prefix size select this structure.
        let label = unsafe {
            (*integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>())
                .Label
                .Sid
        };
        in_blob_sid(&integrity, label)?;
        // SAFETY: the complete variable SID was checked against its token allocation.
        let count = unsafe { *GetSidSubAuthorityCount(label) };
        if count == 0 {
            return Err(denied());
        }
        let integrity = unsafe { *GetSidSubAuthority(label, u32::from(count - 1)) };
        let mut image = vec![0u16; 32768];
        let mut length = image.len() as u32;
        // SAFETY: writable UTF-16 output buffer and read-only process handle.
        if unsafe { QueryFullProcessImageNameW(handle.0, 0, image.as_mut_ptr(), &mut length) } == 0
            || length == 0
            || length as usize > image.len()
        {
            return Err(denied());
        }
        let image =
            PathBuf::from(String::from_utf16(&image[..length as usize]).map_err(|_| denied())?);
        let (mut creation, mut exit, mut kernel, mut user_time) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: valid process handle and four writable FILETIME outputs.
        if unsafe {
            GetProcessTimes(
                handle.0,
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user_time,
            )
        } == 0
        {
            return Err(denied());
        }
        let result = Self {
            handle,
            pid,
            sid,
            session,
            integrity,
            elevated,
            image,
            creation: u64::from(creation.dwLowDateTime)
                | (u64::from(creation.dwHighDateTime) << 32),
        };
        result.alive()?;
        Ok(result)
    }
    pub fn alive(&self) -> io::Result<()> {
        // SAFETY: zero-time read-only wait on the retained process handle. Keeping
        // this handle and creation stamp prevents authentication by a reused PID.
        if unsafe { WaitForSingleObject(self.handle.0, 0) } != WAIT_TIMEOUT {
            return Err(denied());
        }
        Ok(())
    }
    pub fn is_normal(&self) -> bool {
        !self.elevated && (0x2000..0x3000).contains(&self.integrity)
    }
    pub fn is_broker(&self) -> bool {
        self.elevated && self.integrity == 0x3000
    }
    pub fn same_login(&self, other: &Self) -> bool {
        self.sid == other.sid && self.session == other.session
    }
}
pub(super) fn same_image(actual: &Path, expected: &Path) -> bool {
    let clean = |path: &Path| {
        path.to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_owned()
    };
    clean(actual).eq_ignore_ascii_case(&clean(expected))
}
pub(super) fn pipe_peer(pipe: HANDLE, server_side: bool) -> io::Result<Peer> {
    let mut pid = 0;
    // SAFETY: live named-pipe handle and writable PID. The OS supplies the actual
    // connected endpoint identity, independent of any request fields.
    let okay = unsafe {
        if server_side {
            GetNamedPipeClientProcessId(pipe, &mut pid)
        } else {
            GetNamedPipeServerProcessId(pipe, &mut pid)
        }
    };
    if okay == 0 {
        return Err(denied());
    }
    Peer::open(pid)
}

pub(super) fn pipe_security(user_sid: &str) -> io::Result<Local> {
    if !user_sid.starts_with("S-1-")
        || user_sid.len() > 184
        || !user_sid
            .bytes()
            .all(|value| value.is_ascii_digit() || value == b'S' || value == b'-')
    {
        return Err(denied());
    }
    let sddl = text(&format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{user_sid})S:(ML;;NW;;;ME)"
    ))?;
    let mut descriptor = null_mut();
    // SAFETY: fixed protected DACL plus an OS-derived bounded SID; Windows owns
    // the returned descriptor allocation and Local frees it after pipe creation.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(denied());
    }
    Ok(Local(descriptor))
}

const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
fn administrative(sid: PSID) -> io::Result<bool> {
    Ok(
        matches!(sid_string(sid)?.as_str(), "S-1-5-18" | "S-1-5-32-544")
            || sid_string(sid)? == TRUSTED_INSTALLER,
    )
}
/// Check an already-opened file/directory, so a reparse or rename cannot swap
/// the security descriptor between metadata and ACL validation.
pub(super) fn protected_acl(handle: HANDLE) -> io::Result<()> {
    checked_acl(handle, None, PROTECTED_WRITE)
}
/// A parent may allow creation of a new child without allowing replacement of
/// an existing protected child. Generic write, delete-child and ACL/owner
/// changes remain forbidden; callers retain each no-reparse directory handle.
pub(super) fn protected_ancestor_acl(handle: HANDLE) -> io::Result<()> {
    checked_acl(handle, None, PROTECTED_WRITE & !0x00000006)
}
/// Administrative readers authenticate the captured ordinary owner's private
/// plan without impersonation or assuming that the administrator has its SID.
pub(super) fn private_owner_acl(handle: HANDLE, owner: &str) -> io::Result<()> {
    checked_acl(handle, Some(owner), u32::MAX)
}
pub(super) fn private_administrator_acl(handle: HANDLE) -> io::Result<()> {
    checked_acl(handle, None, u32::MAX)
}
const PROTECTED_WRITE: u32 = 0x40000000 | 0x10000000 | 0x00010000 | 0x00040000
    | 0x00080000 | 0x00000002 | 0x00000004 | 0x00000010 | 0x00000040 | 0x00000100;
fn checked_acl(handle: HANDLE, private_owner: Option<&str>, forbidden: u32) -> io::Result<()> {
    let mut descriptor = null_mut();
    // SAFETY: live file handle, documented read-only security information query.
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 || descriptor.is_null() {
        return Err(denied());
    }
    let descriptor = Local(descriptor);
    checked_descriptor(descriptor.0, private_owner, forbidden)
}
fn checked_descriptor(descriptor: *mut c_void, private_owner: Option<&str>, forbidden: u32) -> io::Result<()> {
    // SAFETY: the caller retains an OS-returned or SDDL-created allocation.
    if descriptor.is_null() || unsafe { IsValidSecurityDescriptor(descriptor) } == 0 { return Err(denied()); }
    let mut owner = null_mut();
    let mut defaulted = 0;
    // SAFETY: descriptor and returned SID remain live until Local drops.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } == 0
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || match private_owner { Some(expected) => sid_string(owner)? != expected, None => !administrative(owner)? }
    {
        return Err(denied());
    }
    let mut present = 0;
    let mut acl = null_mut();
    // SAFETY: writable outputs for a live, OS-validated security descriptor.
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
        == 0
        || present == 0
        || acl.is_null()
        || unsafe { IsValidAcl(acl) } == 0
    {
        return Err(denied());
    }
    // SAFETY: IsValidAcl established a complete ACL header in the descriptor.
    let count = unsafe { (*acl).AceCount };
    for index in 0..u32::from(count) {
        let mut raw = null_mut();
        // SAFETY: GetAce bounds-checks this OS ACL index and returns a live ACE.
        if unsafe { GetAce(acl, index, &mut raw) } == 0 || raw.is_null() {
            return Err(denied());
        }
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
            continue;
        }
        if header.AceType == 1 {
            continue;
        } // An access-denied ACE cannot grant write access.
        if header.AceType != 0
            || (header.AceSize as usize) < std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
        {
            return Err(denied());
        }
        // SAFETY: common allow-ACE type and complete minimum size checked above.
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Mask & forbidden == 0 {
            continue;
        }
        let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
        if unsafe { IsValidSid(sid) } == 0
            || std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart)
                + unsafe { GetLengthSid(sid) } as usize
                > header.AceSize as usize
            || !(administrative(sid)? || match private_owner {
                Some(expected) => { let actual = sid_string(sid)?; actual == expected || actual == "S-1-3-4" },
                None => false,
            })
        {
            return Err(denied());
        }
    }
    Ok(())
}

#[cfg(test)]
mod acl_tests {
    use super::*;
    fn check(sddl: &str, owner: Option<&str>, forbidden: u32) -> io::Result<()> {
        let text = text(sddl)?; let mut descriptor = null_mut();
        // These are real self-relative Windows security descriptors, parsed
        // and validated by the same APIs used for opened production objects.
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), SDDL_REVISION_1, &mut descriptor, null_mut()) } == 0 { return Err(io::Error::last_os_error()); }
        let descriptor = Local(descriptor);
        checked_descriptor(descriptor.0, owner, forbidden)
    }
    #[test]
    fn ancestors_allow_only_explicit_child_creation_without_replacement() {
        let descriptor = "O:BAG:BAD:P(A;;FA;;;BA)(A;;0x00000006;;;AU)(A;;FR;;;BU)";
        assert!(check(descriptor, None, PROTECTED_WRITE & !0x6).is_ok());
        assert!(check(descriptor, None, PROTECTED_WRITE).is_err());
        for rights in ["GW", "GA", "WD", "WO", "SD", "0x40", "0x10", "0x100"] {
            assert!(check(&format!("O:BAG:BAD:P(A;;FA;;;BA)(A;;{rights};;;AU)"), None, PROTECTED_WRITE & !0x6).is_err(), "unsafe ancestor rights {rights}");
        }
    }
    #[test]
    fn original_strict_policy_and_private_modes_reject_widened_access() {
        assert!(check("O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)", None, PROTECTED_WRITE).is_ok());
        assert!(check("O:BAG:BAD:P(A;;FA;;;BA)(A;;FR;;;BU)", None, u32::MAX).is_err());
        assert!(check("O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)", None, u32::MAX).is_ok());
        let owner = "S-1-5-21-1-2-3-1001";
        let descriptor = format!("O:{owner}G:{owner}D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FR;;;BA)");
        assert!(check(&descriptor, Some(owner), u32::MAX).is_ok());
        assert!(check(&descriptor, Some("S-1-5-21-1-2-3-1002"), u32::MAX).is_err());
        assert!(check(&format!("{descriptor}(A;;FR;;;BU)"), Some(owner), u32::MAX).is_err());
        assert!(check(&descriptor, None, PROTECTED_WRITE).is_err());
    }
}
