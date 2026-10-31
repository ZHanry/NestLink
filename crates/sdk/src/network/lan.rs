//! Explicit LAN discovery adapters for the original authenticated packet owner.
//! These sockets cannot claim, renew or replace a NetworkAccess budget. Callers
//! must use the original packet admission before either encrypted transmission
//! or `receive_admitted`, and stop this adapter when that owner stops.
mod mdns;
mod policy;
mod runtime;
#[cfg(test)]
mod tests;
mod wire;

pub use policy::{LanPolicy, MdnsRule, UdpRule};
pub use runtime::LanBridge;

use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

fn denied(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_string())
}
fn wall_ms() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}
