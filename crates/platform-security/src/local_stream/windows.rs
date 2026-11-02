//! Thin reuse of the existing Windows broker's Tokio pipe, protected DACL and
//! OS-reported peer token policy. No broker input capability or elevation.
#![allow(unsafe_code)]
use super::*;
use std::{
    ffi::c_void,
    mem::size_of,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr::null_mut,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_BUSY, GetLastError, HANDLE, LocalFree,
        WAIT_TIMEOUT,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        GetTokenInformation, IsValidSid, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_STATISTICS,
        TOKEN_USER, TokenSessionId, TokenStatistics, TokenUser,
    },
    System::{
        Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
        Threading::{
            GetCurrentProcess, GetProcessId, OpenProcess, OpenProcessToken, PROCESS_DUP_HANDLE,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        },
    },
};

const PREFIX: &str = r"\\.\pipe\NestLink.PrivateService.";
// SECURITY_IDENTIFICATION file-open SQOS flag from WinBase.h (not the token
// impersonation-level enum, whose similarly named value is 1).
const IDENTIFICATION_SQOS: u32 = 0x0001_0000;
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Descriptor(*mut c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
#[derive(PartialEq, Eq)]
struct Owner {
    sid: String,
    session: u32,
    authentication_id: (u32, i32),
}
struct PeerState {
    process: OwnedHandle,
    pid: u32,
    owner: Owner,
    active: AtomicBool,
}
/// An OS-reported named-pipe peer with a retained original process handle.
/// Clones share the original pipe's revocation; no PID or JSON constructor exists.
#[derive(Clone)]
pub struct VerifiedPeerProcess(Arc<PeerState>);
/// Export destination for the original pipe peer, never a reopened PID. The
/// handle stays private and every synchronous use checks its original fence.
#[derive(Clone)]
pub struct VerifiedProcessExportTarget(VerifiedPeerProcess);
impl VerifiedProcessExportTarget {
    pub fn check_current(&self) -> io::Result<()> {
        self.0.check_current()
    }
    pub fn with_process_handle<T>(
        &self,
        operation: impl FnOnce(BorrowedHandle<'_>) -> io::Result<T>,
    ) -> io::Result<T> {
        self.check_current()?;
        let result = operation(self.0.0.process.as_handle())?;
        self.check_current()?;
        Ok(result)
    }
}
impl VerifiedPeerProcess {
    pub fn process_id(&self) -> u32 {
        self.0.pid
    }
    pub fn export_target(&self) -> io::Result<VerifiedProcessExportTarget> {
        self.check_current()?;
        Ok(VerifiedProcessExportTarget(self.clone()))
    }
    pub fn check_current(&self) -> io::Result<()> {
        if !self.0.active.load(Ordering::Acquire)
            || unsafe { WaitForSingleObject(self.0.process.as_raw_handle().cast(), 0) }
                != WAIT_TIMEOUT
            || process_owner(self.0.process.as_raw_handle().cast())? != self.0.owner
        {
            return Err(denied());
        }
        Ok(())
    }
    /// Retire this original pipe proof and every clone. This cannot create or
    /// extend process authority; TLS framing owners use it on cancellation.
    pub fn fence(&self) {
        self.0.active.store(false, Ordering::Release);
    }
}
fn current_owner() -> io::Result<Owner> {
    // SAFETY: GetCurrentProcess is a borrowed pseudo-handle; only the token
    // opened below is closed by this function.
    process_owner(unsafe { GetCurrentProcess() })
}
fn process_owner(process: HANDLE) -> io::Result<Owner> {
    let mut raw_token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Handle(raw_token);
    let mut required = 0;
    if unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required) } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || required == 0
    {
        return Err(denied());
    }
    let mut storage = vec![0_u64; (required as usize).div_ceil(size_of::<u64>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
        || required as usize > storage.len() * size_of::<u64>()
        || (required as usize) < size_of::<TOKEN_USER>()
    {
        return Err(denied());
    }
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let start = storage.as_ptr() as usize;
    let end = start + storage.len() * size_of::<u64>();
    let sid = user.User.Sid as usize;
    if sid < start || sid.checked_add(8).is_none_or(|limit| limit > end) {
        return Err(denied());
    }
    let count = unsafe { *((sid as *const u8).add(1)) } as usize;
    if sid
        .checked_add(8 + count * 4)
        .is_none_or(|limit| limit > end)
        || unsafe { IsValidSid(user.User.Sid) } == 0
    {
        return Err(denied());
    }
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 || text.is_null() {
        return Err(denied());
    }
    let allocated = Descriptor(text.cast());
    let mut length = 0;
    while length < 184 && unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    if length == 184 {
        return Err(denied());
    }
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| denied())?;
    drop(allocated);
    let mut session = 0_u32;
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenSessionId,
            (&mut session as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut length,
        )
    } == 0
        || length as usize != size_of::<u32>()
    {
        return Err(denied());
    }
    let mut statistics = TOKEN_STATISTICS::default();
    let mut length = 0;
    // The authentication LUID distinguishes another logon by the same SID in
    // the same desktop session. It is read from the original process token.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenStatistics,
            (&mut statistics as *mut TOKEN_STATISTICS).cast(),
            size_of::<TOKEN_STATISTICS>() as u32,
            &mut length,
        )
    } == 0
        || length as usize != size_of::<TOKEN_STATISTICS>()
    {
        return Err(denied());
    }
    Ok(Owner {
        sid,
        session,
        authentication_id: (
            statistics.AuthenticationId.LowPart,
            statistics.AuthenticationId.HighPart,
        ),
    })
}
fn peer_pid(pipe: HANDLE, server: bool) -> io::Result<u32> {
    let mut pid = 0;
    let read = unsafe {
        if server {
            GetNamedPipeClientProcessId(pipe, &mut pid)
        } else {
            GetNamedPipeServerProcessId(pipe, &mut pid)
        }
    };
    if read == 0 || pid == 0 {
        return Err(denied());
    }
    Ok(pid)
}
fn peer_process(pipe: HANDLE, server: bool, expected: &Owner) -> io::Result<VerifiedPeerProcess> {
    let pid = peer_pid(pipe, server)?;
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_DUP_HANDLE,
            0,
            pid,
        )
    };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcess succeeded, and this is the sole owned handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process.cast()) };
    let owner = process_owner(process.as_raw_handle().cast())?;
    if owner != *expected
        || peer_pid(pipe, server)? != pid
        || unsafe { GetProcessId(process.as_raw_handle().cast()) } != pid
    {
        return Err(denied());
    }
    let proof = VerifiedPeerProcess(Arc::new(PeerState {
        process,
        pid,
        owner,
        active: AtomicBool::new(true),
    }));
    proof.check_current()?;
    Ok(proof)
}
fn descriptor(owner: &Owner) -> io::Result<Descriptor> {
    if !owner.sid.starts_with("S-1-")
        || owner.sid.len() > 184
        || !owner
            .sid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'S' || byte == b'-')
    {
        return Err(denied());
    }
    // The normal-user stream grants the actual owner and SYSTEM only. The
    // existing broker additionally grants administrators because it elevates.
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{})S:(ML;;NW;;;ME)\0", owner.sid)
        .encode_utf16()
        .collect();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(Descriptor(descriptor))
}
fn create(endpoint: &Path, owner: &Owner, first: bool) -> io::Result<NamedPipeServer> {
    let descriptor = descriptor(owner)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // Tokio owns overlapped I/O and copies the descriptor into the kernel.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(10)
            .in_buffer_size(16_384)
            .out_buffer_size(16_384)
            .create_with_security_attributes_raw(
                endpoint,
                (&attributes as *const SECURITY_ATTRIBUTES)
                    .cast_mut()
                    .cast(),
            )
    }
}
pub struct Listener {
    pending: Option<NamedPipeServer>,
    endpoint: PathBuf,
    owner: Owner,
}
/// Derive the existing protected-pipe namespace without accepting arbitrary paths.
pub fn endpoint_for(owner_id: &str) -> io::Result<PathBuf> {
    if !valid_owner_id(owner_id) {
        return Err(denied());
    }
    Ok(PathBuf::from(format!("{PREFIX}{owner_id}")))
}
impl Listener {
    pub fn bind(directory: &Path, owner_id: &str) -> io::Result<Self> {
        if !valid_owner_id(owner_id) {
            return Err(denied());
        }
        crate::check_private_directory(directory)?;
        let endpoint = endpoint_for(owner_id)?;
        let owner = current_owner()?;
        let pending = create(&endpoint, &owner, true)?;
        Ok(Self {
            pending: Some(pending),
            endpoint,
            owner,
        })
    }
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }
    pub async fn accept(&mut self) -> io::Result<LocalStream> {
        let pending = self.pending.as_ref().ok_or_else(denied)?;
        pending.connect().await?;
        let peer = match peer_process(pending.as_raw_handle().cast(), true, &self.owner) {
            Ok(peer) => peer,
            Err(error) => {
                pending.disconnect()?;
                return Err(error);
            }
        };
        // Keep one server instance alive across accepts: another process cannot
        // insert a replacement pipe server between two authenticated clients.
        let next = create(&self.endpoint, &self.owner, false)?;
        let connected = self.pending.replace(next).ok_or_else(denied)?;
        Ok(LocalStream::with_peer(connected, peer))
    }
    pub fn stop_accepting(&mut self) {
        self.pending.take();
    }
    pub fn cleanup(mut self) -> io::Result<()> {
        self.stop_accepting();
        Ok(())
    }
}
pub async fn connect(endpoint: &Path) -> io::Result<LocalStream> {
    let name = endpoint.to_str().ok_or_else(denied)?;
    if !name.starts_with(PREFIX) || !valid_owner_id(&name[PREFIX.len()..]) {
        return Err(denied());
    }
    let owner = current_owner()?;
    let attempt = async {
        loop {
            match ClientOptions::new()
                .security_qos_flags(IDENTIFICATION_SQOS)
                .open(endpoint)
            {
                Ok(pipe) => {
                    let peer = peer_process(pipe.as_raw_handle().cast(), false, &owner)?;
                    return Ok(LocalStream::with_peer(pipe, peer));
                }
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    tokio::time::sleep(Duration::from_millis(10)).await
                }
                Err(error) => return Err(error),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(2), attempt)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local pipe connect timed out"))?
}
