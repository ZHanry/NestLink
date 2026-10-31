//! Optional Windows privilege boundaries. The input broker accepts its fixed
//! local pipe protocol; a separate WFP helper owns exact local socket admission.
//! Neither helper owns remote network/media business or service authority.
mod gate;
#[cfg(windows)]
pub mod windows;
pub mod wire;
pub use gate::{BrokerGate, ConsentFacts, TrustPins};
pub use wire::{BrokerError, Grant, GrantBinding, Layout, Stamp};
