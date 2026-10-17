//! First-party bounded system audio adapters. No application authorization here.
#[cfg(any(windows, target_os = "linux", test))]
mod pcm;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{WindowsAudioCapture, WindowsAudioEndpoint, WindowsAudioPlayback};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{LinuxAudioCapture, LinuxAudioEndpoint, LinuxAudioPlayback};
