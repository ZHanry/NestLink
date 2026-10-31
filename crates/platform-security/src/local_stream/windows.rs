//! Thin reuse of the existing Windows broker's Tokio pipe, protected DACL and
//! OS-reported peer token policy. No broker input capability or elevation.
#![allow(unsafe_code)]
use super::*;
use std::{ffi::c_void, mem::size_of, os::windows::io::AsRawHandle, ptr::null_mut, time::Duration};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_BUSY, GetLastError, HANDLE, LocalFree},
    Security::{Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        GetTokenInformation, IsValidSid, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenSessionId, TokenUser},
    System::{Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
        Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION}},
};

const PREFIX: &str = r"\\.\pipe\NestLink.PrivateService.";
// SECURITY_IDENTIFICATION file-open SQOS flag from WinBase.h (not the token
// impersonation-level enum, whose similarly named value is 1).
const IDENTIFICATION_SQOS: u32 = 0x0001_0000;
struct Handle(HANDLE);
impl Drop for Handle { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }
struct Descriptor(*mut c_void);
impl Drop for Descriptor { fn drop(&mut self) { unsafe { LocalFree(self.0); } } }
#[derive(PartialEq, Eq)]
struct Owner { sid: String, session: u32 }
fn current_owner() -> io::Result<Owner> {
    // SAFETY: GetCurrentProcess is a borrowed pseudo-handle; only the token
    // opened below is closed by this function.
    process_owner(unsafe { GetCurrentProcess() })
}
fn process_owner(process: HANDLE) -> io::Result<Owner> {
    let mut raw_token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw_token) } == 0 { return Err(io::Error::last_os_error()); }
    let token = Handle(raw_token);
    let mut required = 0;
    if unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required) } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || required == 0 { return Err(denied()); }
    let mut storage = vec![0_u64; (required as usize).div_ceil(size_of::<u64>())];
    if unsafe { GetTokenInformation(token.0, TokenUser, storage.as_mut_ptr().cast(), required, &mut required) } == 0
        || required as usize > storage.len() * size_of::<u64>() || (required as usize) < size_of::<TOKEN_USER>() { return Err(denied()); }
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let start = storage.as_ptr() as usize;
    let end = start + storage.len() * size_of::<u64>();
    let sid = user.User.Sid as usize;
    if sid < start || sid.checked_add(8).is_none_or(|limit| limit > end)
        { return Err(denied()); }
    let count = unsafe { *((sid as *const u8).add(1)) } as usize;
    if sid.checked_add(8 + count * 4).is_none_or(|limit| limit > end)
        || unsafe { IsValidSid(user.User.Sid) } == 0 { return Err(denied()); }
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 || text.is_null() { return Err(denied()); }
    let allocated = Descriptor(text.cast());
    let mut length = 0;
    while length < 184 && unsafe { *text.add(length) } != 0 { length += 1; }
    if length == 184 { return Err(denied()); }
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).map_err(|_| denied())?;
    drop(allocated);
    let mut session = 0_u32;
    let mut length = 0;
    if unsafe { GetTokenInformation(token.0, TokenSessionId, (&mut session as *mut u32).cast(),
        size_of::<u32>() as u32, &mut length) } == 0 || length as usize != size_of::<u32>() { return Err(denied()); }
    Ok(Owner { sid, session })
}
fn peer_owner(pipe: HANDLE, server: bool) -> io::Result<Owner> {
    let mut pid = 0;
    let read = unsafe { if server { GetNamedPipeClientProcessId(pipe, &mut pid) }
        else { GetNamedPipeServerProcessId(pipe, &mut pid) } };
    if read == 0 || pid == 0 { return Err(denied()); }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() { return Err(io::Error::last_os_error()); }
    let process = Handle(process);
    process_owner(process.0)
}
fn descriptor(owner: &Owner) -> io::Result<Descriptor> {
    if !owner.sid.starts_with("S-1-") || owner.sid.len() > 184
        || !owner.sid.bytes().all(|byte| byte.is_ascii_digit() || byte == b'S' || byte == b'-') { return Err(denied()); }
    // The normal-user stream grants the actual owner and SYSTEM only. The
    // existing broker additionally grants administrators because it elevates.
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{})S:(ML;;NW;;;ME)\0", owner.sid).encode_utf16().collect();
    let mut descriptor = null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1,
        &mut descriptor, null_mut()) } == 0 { return Err(io::Error::last_os_error()); }
    Ok(Descriptor(descriptor))
}
fn create(endpoint: &Path, owner: &Owner, first: bool) -> io::Result<NamedPipeServer> {
    let descriptor = descriptor(owner)?;
    let attributes = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0, bInheritHandle: 0 };
    // Tokio owns overlapped I/O and copies the descriptor into the kernel.
    unsafe { ServerOptions::new().first_pipe_instance(first).reject_remote_clients(true)
        .max_instances(10).in_buffer_size(16_384).out_buffer_size(16_384)
        .create_with_security_attributes_raw(endpoint,
            (&attributes as *const SECURITY_ATTRIBUTES).cast_mut().cast()) }
}
pub struct Listener { pending: Option<NamedPipeServer>, endpoint: PathBuf, owner: Owner }
impl Listener {
    pub fn bind(directory: &Path, owner_id: &str) -> io::Result<Self> {
        if !valid_owner_id(owner_id) { return Err(denied()); }
        crate::check_private_directory(directory)?;
        let endpoint = PathBuf::from(format!("{PREFIX}{owner_id}"));
        let owner = current_owner()?;
        let pending = create(&endpoint, &owner, true)?;
        Ok(Self { pending: Some(pending), endpoint, owner })
    }
    pub fn endpoint(&self) -> &Path { &self.endpoint }
    pub async fn accept(&mut self) -> io::Result<LocalStream> {
        let pending = self.pending.as_ref().ok_or_else(denied)?;
        pending.connect().await?;
        let peer = peer_owner(pending.as_raw_handle().cast(), true);
        if peer.as_ref().is_err() || peer.as_ref().is_ok_and(|peer| *peer != self.owner) {
            pending.disconnect()?;
            return Err(denied());
        }
        // Keep one server instance alive across accepts: another process cannot
        // insert a replacement pipe server between two authenticated clients.
        let next = create(&self.endpoint, &self.owner, false)?;
        let connected = self.pending.replace(next).ok_or_else(denied)?;
        Ok(LocalStream::new(connected))
    }
    pub fn stop_accepting(&mut self) { self.pending.take(); }
    pub fn cleanup(mut self) -> io::Result<()> { self.stop_accepting(); Ok(()) }
}
pub async fn connect(endpoint: &Path) -> io::Result<LocalStream> {
    let name = endpoint.to_str().ok_or_else(denied)?;
    if !name.starts_with(PREFIX) || !valid_owner_id(&name[PREFIX.len()..]) { return Err(denied()); }
    let owner = current_owner()?;
    let attempt = async {
        loop {
            match ClientOptions::new().security_qos_flags(IDENTIFICATION_SQOS).open(endpoint) {
                Ok(pipe) => {
                    if peer_owner(pipe.as_raw_handle().cast(), false)? != owner { return Err(denied()); }
                    return Ok(LocalStream::new(pipe));
                }
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(error) => return Err(error),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(2), attempt).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local pipe connect timed out"))?
}
