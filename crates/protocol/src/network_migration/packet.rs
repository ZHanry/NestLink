//! Endpoint-only demultiplexing within the existing opaque routed packet.
//! Control and business use distinct queues/QUIC endpoint drivers; a peer
//! switching first cannot cause the control endpoint to reset the old business
//! connection's unknown CID. Relay forwarding and quota count all these bytes.
use crate::{ContractError, ErrorCode, network_datagram};

pub const HEADER: usize = 16;
pub const MAX_INNER_PACKET: usize = network_datagram::PACKET_BYTES - HEADER;
/// Every migratable original connection starts with this conservative budget.
/// It does not depend on shrinking a live fixed-MTU connection after rebind.
pub const INNER_MTU: u16 = 1200;
pub const REMOTE_ALPN: &[u8] = b"nestlink/network-remote-migration/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Control,
    Business(u64),
}

fn invalid() -> ContractError {
    ContractError::new(
        ErrorCode::InvalidMessage,
        "invalid migration packet demultiplexing envelope",
    )
}
pub fn encode(mode: Mode, payload: &[u8]) -> Result<Vec<u8>, ContractError> {
    if payload.is_empty() || payload.len() > MAX_INNER_PACKET {
        return Err(invalid());
    }
    let (tag, epoch) = match mode {
        Mode::Control => (1, 0),
        Mode::Business(epoch) if epoch != 0 => (2, epoch),
        _ => return Err(invalid()),
    };
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.extend_from_slice(b"NLM1");
    bytes.extend_from_slice(&[tag, 0, 0, 0]);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}
pub fn decode(bytes: &[u8]) -> Result<(Mode, &[u8]), ContractError> {
    if bytes.len() <= HEADER
        || bytes.len() > network_datagram::PACKET_BYTES
        || &bytes[..4] != b"NLM1"
        || bytes[5..8] != [0; 3]
    {
        return Err(invalid());
    }
    let epoch = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| invalid())?);
    let mode = match (bytes[4], epoch) {
        (1, 0) => Mode::Control,
        (2, epoch) if epoch != 0 => Mode::Business(epoch),
        _ => return Err(invalid()),
    };
    Ok((mode, &bytes[HEADER..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_header_keeps_control_and_epochs_separate_inside_original_packet_budget()
    -> Result<(), ContractError> {
        for mode in [Mode::Control, Mode::Business(1), Mode::Business(u64::MAX)] {
            let bytes = encode(mode, &[7; MAX_INNER_PACKET])?;
            let (parsed, payload) = decode(&bytes)?;
            assert_eq!(parsed, mode);
            assert_eq!(payload, &[7; MAX_INNER_PACKET]);
            assert_eq!(bytes.len(), network_datagram::PACKET_BYTES);
            for length in 0..=HEADER {
                assert!(decode(&bytes[..length]).is_err());
            }
            for offset in 4..8 {
                let mut wrong = bytes.clone();
                wrong[offset] = 255;
                assert!(decode(&wrong).is_err());
            }
        }
        assert!(encode(Mode::Business(0), b"payload").is_err());
        assert!(encode(Mode::Control, &[]).is_err());
        assert!(encode(Mode::Control, &[1; MAX_INNER_PACKET + 1]).is_err());
        let mut wrong = encode(Mode::Control, b"payload")?;
        wrong[15] = 1;
        assert!(decode(&wrong).is_err());
        Ok(())
    }
}
