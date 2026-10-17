//! Optional Windows input broker. This crate owns no network/media business.
//! The only elevated entry point accepts a fixed local named-pipe protocol.
mod gate;
#[cfg(windows)]
pub mod windows;
pub mod wire;
pub use gate::{BrokerGate, ConsentFacts, TrustPins};
pub use wire::{BrokerError, Grant, GrantBinding, Layout, Stamp};
