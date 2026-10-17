//! Browser runtime components shared by the static web application.
#[cfg(target_arch = "wasm32")]
pub mod browser_clipboard;
#[cfg(target_arch = "wasm32")]
pub mod browser_data;
#[cfg(any(target_arch = "wasm32", test))]
mod browser_displays;
#[cfg(target_arch = "wasm32")]
pub mod browser_files;
#[cfg(target_arch = "wasm32")]
pub mod browser_identity;
#[cfg(target_arch = "wasm32")]
pub mod browser_input;
pub mod browser_peer;
#[cfg(target_arch = "wasm32")]
pub mod browser_rpc;
#[cfg(target_arch = "wasm32")]
mod browser_sdp;
#[cfg(target_arch = "wasm32")]
mod browser_storage;
pub mod i18n;
