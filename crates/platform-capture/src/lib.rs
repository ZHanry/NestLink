//! First-party platform capture. No codec or application authorization here.
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{WindowsCapture, WindowsCaptureSource};
#[cfg(target_os = "linux")]
mod pipewire;
#[cfg(target_os = "linux")]
pub use pipewire::PortalCapture;
#[cfg(target_os = "linux")]
mod x11;
#[cfg(target_os = "linux")]
pub use x11::X11Capture;
