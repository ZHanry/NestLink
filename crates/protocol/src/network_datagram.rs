//! Independently negotiated opaque network packets. Decoding is not authority.
//! Every header byte is carried by a pinned, mutually authenticated QUIC
//! adjacency; the binding digest must match a verified path and transit grant.
use crate::{ContractError, ErrorCode};

pub const ALPN: &[u8] = b"nestlink/network-datagram/1";
pub const HEADER: usize = 52;
pub const PACKET_BYTES: usize = 1400;
pub const FRAGMENT_BYTES: usize = 900;
pub const PENDING_PACKETS: usize = 32;
pub const PACKET_AGE_MS: u64 = 250;
pub const REPLAY_WINDOW: u64 = 64;
pub const PATH_EPOCH: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    FirstToSecond,
    SecondToFirst,
}
impl Direction {
    pub fn reverse(self) -> Self {
        match self {
            Self::FirstToSecond => Self::SecondToFirst,
            Self::SecondToFirst => Self::FirstToSecond,
        }
    }
    fn byte(self) -> u8 {
        match self {
            Self::FirstToSecond => 0,
            Self::SecondToFirst => 1,
        }
    }
}

pub struct Fragment<'a> {
    pub binding: [u8; 32],
    pub direction: Direction,
    pub remaining_hops: u8,
    pub packet: u64,
    pub length: usize,
    pub index: usize,
    pub payload: &'a [u8],
}
fn invalid() -> ContractError {
    ContractError::new(
        ErrorCode::ProtocolMismatch,
        "invalid network datagram fragment",
    )
}
pub fn decode(bytes: &[u8]) -> Result<Fragment<'_>, ContractError> {
    if bytes.len() <= HEADER || &bytes[..4] != b"NRD1" || bytes[17..20] != [0; 3] {
        return Err(invalid());
    }
    let direction = match bytes[4] {
        0 => Direction::FirstToSecond,
        1 => Direction::SecondToFirst,
        _ => return Err(invalid()),
    };
    let remaining_hops = bytes[5];
    let length = usize::from(u16::from_be_bytes(
        bytes[6..8].try_into().map_err(|_| invalid())?,
    ));
    let packet = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| invalid())?);
    let index = usize::from(bytes[16]);
    let binding = bytes[20..HEADER].try_into().map_err(|_| invalid())?;
    if remaining_hops > 1
        || binding == [0; 32]
        || packet == 0
        || length == 0
        || length > PACKET_BYTES
        || index >= length.div_ceil(FRAGMENT_BYTES)
        || bytes.len() - HEADER != (length - index * FRAGMENT_BYTES).min(FRAGMENT_BYTES)
    {
        return Err(invalid());
    }
    Ok(Fragment {
        binding,
        direction,
        remaining_hops,
        packet,
        length,
        index,
        payload: &bytes[HEADER..],
    })
}
pub fn encode(
    binding: [u8; 32],
    direction: Direction,
    packet: u64,
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>, ContractError> {
    if binding == [0; 32] || packet == 0 || bytes.is_empty() || bytes.len() > PACKET_BYTES {
        return Err(invalid());
    }
    let length = u16::try_from(bytes.len())
        .map_err(|_| invalid())?
        .to_be_bytes();
    Ok(bytes
        .chunks(FRAGMENT_BYTES)
        .enumerate()
        .map(|(index, payload)| {
            let mut fragment = Vec::with_capacity(HEADER + payload.len());
            fragment.extend_from_slice(b"NRD1");
            fragment.extend_from_slice(&[direction.byte(), 1]);
            fragment.extend_from_slice(&length);
            fragment.extend_from_slice(&packet.to_be_bytes());
            fragment.extend_from_slice(&[index as u8, 0, 0, 0]);
            fragment.extend_from_slice(&binding);
            fragment.extend_from_slice(payload);
            fragment
        })
        .collect())
}

/// Validate the complete incoming envelope before consuming the sole hop. No
/// network destination can be selected by a packet supplied to this function.
pub fn forward(
    bytes: &mut [u8],
    binding: [u8; 32],
    direction: Direction,
) -> Result<(), ContractError> {
    let fragment = decode(bytes)?;
    if fragment.binding != binding
        || fragment.direction != direction
        || fragment.remaining_hops != 1
    {
        return Err(invalid());
    }
    bytes[5] = 0;
    Ok(())
}
