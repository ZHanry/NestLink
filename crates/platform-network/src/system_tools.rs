//! Trusted OS program location; never resolves privileged tools through PATH.
#![allow(unsafe_code)]
use std::{io, path::PathBuf};

fn windows_system_directory() -> io::Result<PathBuf> {
    let mut buffer = vec![0_u16; 32768];
    // SAFETY: the buffer is writable for the exact number of supplied UTF-16
    // units, and the returned length is checked before constructing a path.
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    let directory = String::from_utf16(&buffer[..length]).map_err(io::Error::other)?;
    Ok(PathBuf::from(directory))
}

pub fn windows_powershell() -> io::Result<PathBuf> {
    Ok(windows_system_directory()?
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe"))
}

/// The OS-provided network configuration tool; never uses PATH or a caller
/// selected executable. Callers still supply fixed argument names and bind
/// every mutation to the fresh original adapter's observed index.
pub fn windows_netsh() -> io::Result<PathBuf> {
    Ok(windows_system_directory()?.join("netsh.exe"))
}
