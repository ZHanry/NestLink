//! Rust-owned product state. UI bindings send actions and observe immutable views.
//! Credentials and installation keys never enter the view or operation history.
mod action;
mod model;
mod native_network;
pub use action::*;
pub use model::*;
pub use native_network::*;

#[cfg(not(target_arch = "wasm32"))]
mod browser_host;
#[cfg(not(target_arch = "wasm32"))]
mod native_session;
#[cfg(not(target_arch = "wasm32"))]
mod runtime;
#[cfg(not(target_arch = "wasm32"))]
mod sdk_call;
mod session_displays;
#[cfg(not(target_arch = "wasm32"))]
pub use browser_host::*;
#[cfg(not(target_arch = "wasm32"))]
pub use native_session::*;
#[cfg(not(target_arch = "wasm32"))]
pub use nestlink_media_session::{DecodedVideo, VideoLayout};
#[cfg(not(target_arch = "wasm32"))]
pub use runtime::*;

#[cfg(not(target_arch = "wasm32"))]
pub use nestlink_media_session::native_video_qpc;

#[cfg(not(target_arch = "wasm32"))]
mod native_media_provider;
#[cfg(not(target_arch = "wasm32"))]
pub use native_media_provider::NativeMediaProvider;
