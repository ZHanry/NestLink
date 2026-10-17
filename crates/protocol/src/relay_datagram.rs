//! Unreliable, bounded fragments of an opaque inner QUIC UDP packet.
use crate::{ContractError, ErrorCode, RELAY_UDP_FRAGMENT_BYTES, RELAY_UDP_PACKET_BYTES};

pub const ALPN: &[u8] = b"nestlink/relay-datagram/1";
pub const HEADER: usize = 12;
pub struct Fragment<'a> {
    pub packet: u64,
    pub length: usize,
    pub index: usize,
    pub payload: &'a [u8],
}
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::ProtocolMismatch, "invalid relay UDP fragment")
}
pub fn decode(bytes: &[u8]) -> Result<Fragment<'_>, ContractError> {
    if bytes.len() <= HEADER || bytes[0] != 1 {
        return Err(invalid());
    }
    let index = usize::from(bytes[1]);
    let length = usize::from(u16::from_be_bytes(
        bytes[2..4].try_into().map_err(|_| invalid())?,
    ));
    let packet = u64::from_be_bytes(bytes[4..12].try_into().map_err(|_| invalid())?);
    let size = RELAY_UDP_FRAGMENT_BYTES as usize;
    if packet == 0
        || length == 0
        || length > RELAY_UDP_PACKET_BYTES as usize
        || index >= length.div_ceil(size)
        || bytes.len() - HEADER != (length - index * size).min(size)
    {
        return Err(invalid());
    }
    Ok(Fragment {
        packet,
        length,
        index,
        payload: &bytes[HEADER..],
    })
}
pub fn encode(packet: u64, bytes: &[u8]) -> Result<Vec<Vec<u8>>, ContractError> {
    if packet == 0 || bytes.is_empty() || bytes.len() > RELAY_UDP_PACKET_BYTES as usize {
        return Err(invalid());
    }
    let length = u16::try_from(bytes.len())
        .map_err(|_| invalid())?
        .to_be_bytes();
    Ok(bytes
        .chunks(RELAY_UDP_FRAGMENT_BYTES as usize)
        .enumerate()
        .map(|(i, data)| {
            let mut fragment = Vec::with_capacity(HEADER + data.len());
            fragment.extend_from_slice(&[1, i as u8]);
            fragment.extend_from_slice(&length);
            fragment.extend_from_slice(&packet.to_be_bytes());
            fragment.extend_from_slice(data);
            fragment
        })
        .collect())
}
