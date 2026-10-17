#![allow(dead_code)]

#[cfg(target_arch = "wasm32")]
use nestlink_web::i18n;

#[path = "../browser_clipboard.rs"]
#[cfg(target_arch = "wasm32")]
mod browser_clipboard;
#[path = "../browser_data.rs"]
#[cfg(target_arch = "wasm32")]
mod browser_data;
#[path = "../browser_identity.rs"]
#[cfg(target_arch = "wasm32")]
mod browser_identity;
#[path = "../browser_rpc.rs"]
#[cfg(target_arch = "wasm32")]
mod browser_rpc;
#[path = "../browser_sdp.rs"]
#[cfg(target_arch = "wasm32")]
mod browser_sdp;
#[path = "../browser_storage.rs"]
#[cfg(target_arch = "wasm32")]
mod browser_storage;
#[path = "../browser_verification.rs"]
#[cfg(target_arch = "wasm32")]
mod browser_verification;

fn main() {}
