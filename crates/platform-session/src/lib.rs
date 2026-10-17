//! Read-only OS session facts. These never grant application authorization.
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{WindowsSessionMonitor, WindowsSessionObserver, WindowsSessionSnapshot};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{LinuxDesktopSession, LinuxSessionState};
