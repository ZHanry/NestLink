//! First-party capture and Windows owner-thread capture/encode. No grants originate here.
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    WindowsCapture, WindowsCaptureSource, WindowsHostCapture, probe_windows_gpu_h264,
};
#[cfg(target_os = "linux")]
mod pipewire;
#[cfg(target_os = "linux")]
pub use pipewire::PortalCapture;
#[cfg(target_os = "linux")]
mod x11;
#[cfg(target_os = "linux")]
pub use x11::X11Capture;
