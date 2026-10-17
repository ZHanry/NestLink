//! Native OS input adapters. Application authorization is owned by remote.
use nestlink_remote::input::{InputDevice, InputLayout};
use std::io;
mod keys;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::WindowsInput;
#[cfg(target_os = "linux")]
mod x11;
#[cfg(target_os = "linux")]
mod x11_image;
#[cfg(target_os = "linux")]
mod x11_transport;
#[cfg(target_os = "linux")]
pub use x11_image::{X11CaptureControl, X11CaptureSource};
#[cfg(target_os = "linux")]
mod x11_session;
#[cfg(target_os = "linux")]
mod x11_text;
#[cfg(target_os = "linux")]
pub use x11::X11Input;
#[cfg(target_os = "linux")]
pub mod portal;

pub struct InputCapabilities {
    pub physical_keys: bool,
    pub pointer_buttons: bool,
    pub text_commit: bool,
}
pub trait NativeInput: InputDevice {
    fn layout(&self) -> InputLayout;
    fn capabilities(&self) -> InputCapabilities;
}
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
