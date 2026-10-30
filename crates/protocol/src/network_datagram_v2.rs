//! Independently negotiated opaque packets for one or two authorized relays.
//! The verified chain manifest, authenticated adjacency and transit grant decide
//! the next neighbor and expected hop position. Decoding confers no authority.
use crate::{ContractError, ErrorCode};

use super::network_datagram::{decode_for, encode_for};
pub use super::network_datagram::{
    Direction, FRAGMENT_BYTES, Fragment, HEADER, PACKET_AGE_MS, PACKET_BYTES, PENDING_PACKETS,
    REPLAY_WINDOW,
};

pub const ALPN: &[u8] = b"nestlink/network-datagram/2";

fn invalid() -> ContractError {
    ContractError::new(
        ErrorCode::ProtocolMismatch,
        "invalid network datagram fragment",
    )
}

pub fn decode(bytes: &[u8]) -> Result<Fragment<'_>, ContractError> {
    decode_for(bytes, b"NRD2", 2)
}

/// Encode a complete inner packet with the same initial hop count in either
/// direction. The caller must obtain the relay count from the verified chain.
pub fn encode(
    binding: [u8; 32],
    direction: Direction,
    relay_count: u8,
    packet: u64,
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>, ContractError> {
    if !(1..=2).contains(&relay_count) {
        return Err(invalid());
    }
    encode_for(binding, direction, packet, bytes, b"NRD2", relay_count)
}

/// Validate the entire incoming fragment before consuming the authorized hop.
/// `expected_remaining_hops` must come from this relay's position in the
/// verified chain manifest, never from the incoming packet. A packet cannot
/// select a neighbor, authorize a relay or move itself to another hop position.
pub fn forward(
    bytes: &mut [u8],
    binding: [u8; 32],
    direction: Direction,
    expected_remaining_hops: u8,
) -> Result<(), ContractError> {
    if !(1..=2).contains(&expected_remaining_hops) {
        return Err(invalid());
    }
    let fragment = decode(bytes)?;
    if fragment.binding != binding
        || fragment.direction != direction
        || fragment.remaining_hops != expected_remaining_hops
    {
        return Err(invalid());
    }
    bytes[5] = expected_remaining_hops - 1;
    Ok(())
}
