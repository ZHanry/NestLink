#[cfg(any(target_os = "android", test))]
mod handle_registry;

#[cfg(any(target_os = "android", test))]
mod management;

#[cfg(any(target_os = "android", test))]
mod jni_bridge;

#[cfg(any(target_os = "android", test))]
mod platform_input;

#[cfg(any(target_os = "android", test))]
mod platform_audio;

#[cfg(any(target_os = "android", test))]
mod platform_clipboard;

#[cfg(any(target_os = "android", test))]
mod file_transfer;

#[cfg(any(target_os = "android", test))]
mod host_files;

#[cfg(any(target_os = "android", test))]
mod browser_data;

#[cfg(any(target_os = "android", test))]
mod browser_host;

#[cfg(any(target_os = "android", test))]
mod browser_capture;

#[cfg(target_os = "android")]
pub use jni_bridge::*;
