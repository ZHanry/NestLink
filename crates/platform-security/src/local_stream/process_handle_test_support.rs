//! Explicit test support for the original local TLS process-export experiment.
//! Absent from default product builds. All Win32 handle operations remain in
//! the existing OS boundary; the IPC crate continues to forbid unsafe Rust.
use super::VerifiedProcessExportTarget;
use std::{
    collections::HashSet,
    fs::File,
    io,
    os::windows::io::AsRawHandle,
    sync::{Mutex, OnceLock},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE},
    Storage::FileSystem::{FILE_TYPE_DISK, GetFileSizeEx, GetFileType, ReadFile},
    System::Threading::GetCurrentProcess,
};

/// The real child must consume this fresh destination handle through its
/// authenticated original parent channel. No PID lookup or remote close occurs.
pub fn duplicate_file(file: &File, target: &VerifiedProcessExportTarget) -> io::Result<u64> {
    target.with_process_handle(|process| {
        let mut duplicate = std::ptr::null_mut();
        // SAFETY: the file and verified original process handle are borrowed
        // for this synchronous operation. The child receives the new handle.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                file.as_raw_handle(),
                process.as_raw_handle(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(duplicate as usize as u64)
    })
}

/// Read a tiny fixture file transferred by the already authenticated parent.
/// A child process may consume at most sixteen handle values, each once. The
/// tombstones survive closure, so a repeated integer cannot adopt an ABA reuse.
/// This never creates a Rust File from caller-supplied raw ownership.
pub fn read_file_once(handle: u64) -> io::Result<String> {
    static CONSUMED: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();
    if handle == 0 || handle > isize::MAX as u64 {
        return Err(io::Error::other("invalid fixture handle"));
    }
    let raw = handle as usize as HANDLE;
    // SAFETY: GetFileType treats this integer as an opaque kernel handle; it
    // neither dereferences it nor assumes ownership.
    if unsafe { GetFileType(raw) } != FILE_TYPE_DISK {
        return Err(io::Error::other("fixture export is not a disk file"));
    }
    {
        let mut consumed = CONSUMED
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .map_err(|_| io::Error::other("fixture ownership poisoned"))?;
        if consumed.len() >= 16 || !consumed.insert(handle) {
            return Err(io::Error::other("fixture handle already consumed or full"));
        }
    }
    struct Original(HANDLE);
    impl Drop for Original {
        fn drop(&mut self) {
            // SAFETY: this once-claimed original export belongs to this child.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let original = Original(raw);
    let mut size = 0i64;
    // SAFETY: size points to a live output scalar; the original remains open.
    if unsafe { GetFileSizeEx(original.0, &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if !(1..=4096).contains(&size) {
        return Err(io::Error::other("fixture file exceeds finite read budget"));
    }
    let mut bytes = vec![0; size as usize];
    let mut read = 0;
    // SAFETY: bytes is a live initialized allocation of the exact bounded
    // requested size. Synchronous ReadFile receives no OVERLAPPED pointer.
    if unsafe {
        ReadFile(
            original.0,
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            &mut read,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if read as usize != bytes.len() {
        return Err(io::Error::other("fixture export was truncated"));
    }
    String::from_utf8(bytes).map_err(|_| io::Error::other("fixture export is not UTF-8"))
}
