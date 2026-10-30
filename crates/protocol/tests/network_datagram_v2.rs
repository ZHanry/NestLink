use nestlink_protocol::{
    ContractError, ErrorCode, network_datagram as v1, network_datagram_v2 as v2,
};

const BINDING: [u8; 32] = [7; 32];
const DIRECTIONS: [v2::Direction; 2] = [v2::Direction::FirstToSecond, v2::Direction::SecondToFirst];

fn assert_decode_rejected(bytes: &[u8]) {
    assert_eq!(
        v2::decode(bytes).err().map(|error| error.code),
        Some(ErrorCode::ProtocolMismatch)
    );
}

fn assert_forward_rejected(
    bytes: &[u8],
    binding: [u8; 32],
    direction: v2::Direction,
    expected_remaining_hops: u8,
) {
    let mut unchanged = bytes.to_vec();
    assert_eq!(
        v2::forward(&mut unchanged, binding, direction, expected_remaining_hops)
            .err()
            .map(|error| error.code),
        Some(ErrorCode::ProtocolMismatch)
    );
    assert_eq!(unchanged, bytes);
}

#[test]
fn versions_have_distinct_alpn_and_reject_each_others_wire_magic() -> Result<(), ContractError> {
    assert_eq!(v1::ALPN, b"nestlink/network-datagram/1");
    assert_eq!(v2::ALPN, b"nestlink/network-datagram/2");
    assert_eq!(v2::HEADER, v1::HEADER);
    assert_eq!(v2::FRAGMENT_BYTES, v1::FRAGMENT_BYTES);
    assert_eq!(v2::PACKET_BYTES, v1::PACKET_BYTES);
    assert_eq!(v2::PENDING_PACKETS, v1::PENDING_PACKETS);
    assert_eq!(v2::PACKET_AGE_MS, v1::PACKET_AGE_MS);
    assert_eq!(v2::REPLAY_WINDOW, v1::REPLAY_WINDOW);
    for direction in DIRECTIONS {
        let old = v1::encode(BINDING, direction, 1, &[9])?[0].clone();
        let new = v2::encode(BINDING, direction, 1, 1, &[9])?[0].clone();
        assert_eq!(&old[..4], b"NRD1");
        assert_eq!(&new[..4], b"NRD2");
        assert_eq!(&old[4..], &new[4..]);
        assert_decode_rejected(&old);
        assert_forward_rejected(&old, BINDING, direction, 1);
        assert!(v1::decode(&new).is_err());
        let mut unchanged = new.clone();
        assert!(v1::forward(&mut unchanged, BINDING, direction).is_err());
        assert_eq!(unchanged, new);
        let shared: v1::Fragment<'_> = v2::decode(&new)?;
        assert_eq!(shared.direction, direction);
    }
    Ok(())
}

#[test]
fn legacy_encoder_and_forwarder_preserve_the_single_hop_contract() -> Result<(), ContractError> {
    for direction in DIRECTIONS {
        let mut fragment = v1::encode(BINDING, direction, u64::MAX, &[9])?[0].clone();
        assert_eq!(v1::decode(&fragment)?.remaining_hops, 1);
        v1::forward(&mut fragment, BINDING, direction)?;
        assert_eq!(v1::decode(&fragment)?.remaining_hops, 0);
        let consumed = fragment.clone();
        assert!(v1::forward(&mut fragment, BINDING, direction).is_err());
        assert_eq!(fragment, consumed);
        fragment[5] = 2;
        let over_hop = fragment.clone();
        assert!(v1::decode(&fragment).is_err());
        assert!(v1::forward(&mut fragment, BINDING, direction).is_err());
        assert_eq!(fragment, over_hop);
    }
    Ok(())
}

#[test]
fn both_directions_consume_two_hops_once_without_changing_inner_bytes() -> Result<(), ContractError>
{
    let packet = vec![23; v2::PACKET_BYTES];
    for direction in DIRECTIONS {
        let mut fragments = v2::encode(BINDING, direction, 2, u64::MAX, &packet)?;
        let mut reassembled = Vec::new();
        for bytes in &mut fragments {
            assert_eq!(v2::decode(bytes)?.remaining_hops, 2);
            assert_forward_rejected(bytes, BINDING, direction, 1);
            let mut expected = bytes.clone();
            v2::forward(bytes, BINDING, direction, 2)?;
            expected[5] = 1;
            assert_eq!(*bytes, expected);
            assert_eq!(v2::decode(bytes)?.remaining_hops, 1);
            assert_forward_rejected(bytes, BINDING, direction, 2);
            v2::forward(bytes, BINDING, direction, 1)?;
            expected[5] = 0;
            assert_eq!(*bytes, expected);
            let fragment = v2::decode(bytes)?;
            assert_eq!(fragment.remaining_hops, 0);
            assert_eq!(fragment.direction, direction);
            assert_eq!(fragment.binding, BINDING);
            assert_eq!(fragment.packet, u64::MAX);
            reassembled.extend_from_slice(fragment.payload);
            assert_forward_rejected(bytes, BINDING, direction, 1);
            assert_forward_rejected(bytes, BINDING, direction, 2);
        }
        assert_eq!(reassembled, packet);
    }
    Ok(())
}

#[test]
fn both_directions_can_encode_a_single_relay_chain() -> Result<(), ContractError> {
    for direction in DIRECTIONS {
        let mut bytes = v2::encode(BINDING, direction, 1, 1, &[8])?[0].clone();
        assert_eq!(v2::decode(&bytes)?.remaining_hops, 1);
        assert_forward_rejected(&bytes, BINDING, direction, 2);
        v2::forward(&mut bytes, BINDING, direction, 1)?;
        assert_eq!(v2::decode(&bytes)?.remaining_hops, 0);
        assert_forward_rejected(&bytes, BINDING, direction, 1);
    }
    Ok(())
}

#[test]
fn forward_rejects_wrong_position_direction_or_binding_before_any_mutation()
-> Result<(), ContractError> {
    for direction in DIRECTIONS {
        for relay_count in 1..=2 {
            let bytes = v2::encode(BINDING, direction, relay_count, 1, &[8])?[0].clone();
            assert_forward_rejected(&bytes, [0; 32], direction, relay_count);
            assert_forward_rejected(&bytes, [8; 32], direction, relay_count);
            assert_forward_rejected(&bytes, BINDING, direction.reverse(), relay_count);
            for position in [0, 3, u8::MAX] {
                assert_forward_rejected(&bytes, BINDING, direction, position);
            }
        }
    }
    Ok(())
}

#[test]
fn encode_rejects_invalid_relay_counts_packet_ids_bindings_and_lengths() {
    for direction in DIRECTIONS {
        for relay_count in [0, 3, u8::MAX] {
            assert!(v2::encode(BINDING, direction, relay_count, 1, &[8]).is_err());
        }
        for relay_count in 1..=2 {
            assert!(v2::encode([0; 32], direction, relay_count, 1, &[8]).is_err());
            assert!(v2::encode(BINDING, direction, relay_count, 0, &[8]).is_err());
            assert!(v2::encode(BINDING, direction, relay_count, 1, &[]).is_err());
            assert!(
                v2::encode(
                    BINDING,
                    direction,
                    relay_count,
                    1,
                    &vec![8; v2::PACKET_BYTES + 1],
                )
                .is_err()
            );
        }
    }
}

#[test]
fn complete_packet_and_fragment_boundaries_round_trip_in_both_directions()
-> Result<(), ContractError> {
    for direction in DIRECTIONS {
        for relay_count in 1..=2 {
            for length in [1_usize, 899, 900, 901, 1399, 1400] {
                let packet: Vec<_> = (0..length).map(|index| (index % 251) as u8).collect();
                let fragments = v2::encode(BINDING, direction, relay_count, 42, &packet)?;
                assert_eq!(fragments.len(), length.div_ceil(v2::FRAGMENT_BYTES));
                let mut reassembled = Vec::new();
                for (index, bytes) in fragments.iter().enumerate() {
                    let fragment = v2::decode(bytes)?;
                    assert_eq!(fragment.binding, BINDING);
                    assert_eq!(fragment.direction, direction);
                    assert_eq!(fragment.remaining_hops, relay_count);
                    assert_eq!(fragment.packet, 42);
                    assert_eq!(fragment.length, length);
                    assert_eq!(fragment.index, index);
                    assert_eq!(
                        fragment.payload.len(),
                        (length - index * v2::FRAGMENT_BYTES).min(v2::FRAGMENT_BYTES)
                    );
                    assert_eq!(bytes.len(), v2::HEADER + fragment.payload.len());
                    reassembled.extend_from_slice(fragment.payload);
                }
                assert_eq!(reassembled, packet);
            }
        }
    }
    Ok(())
}

#[test]
fn decode_and_forward_reject_truncated_headers_and_missing_payloads() -> Result<(), ContractError> {
    let bytes = v2::encode(BINDING, v2::Direction::FirstToSecond, 2, 1, &[8])?[0].clone();
    for length in 0..=v2::HEADER {
        assert_decode_rejected(&bytes[..length]);
        assert_forward_rejected(&bytes[..length], BINDING, v2::Direction::FirstToSecond, 2);
    }
    Ok(())
}

#[test]
fn decode_and_forward_reject_reserved_bytes_invalid_fields_and_over_hop_counts()
-> Result<(), ContractError> {
    for direction in DIRECTIONS {
        let original = v2::encode(BINDING, direction, 2, 1, &[8])?[0].clone();
        for (offset, value) in [
            (0, 0),
            (4, 2),
            (5, 3),
            (5, u8::MAX),
            (17, 1),
            (18, 1),
            (19, 1),
        ] {
            let mut malformed = original.clone();
            malformed[offset] = value;
            assert_decode_rejected(&malformed);
            assert_forward_rejected(&malformed, BINDING, direction, 2);
        }
        for range in [6..8, 8..16, 20..v2::HEADER] {
            let mut malformed = original.clone();
            malformed[range].fill(0);
            assert_decode_rejected(&malformed);
            assert_forward_rejected(&malformed, BINDING, direction, 2);
        }
    }
    Ok(())
}

#[test]
fn decode_and_forward_enforce_exact_fragment_size_index_and_total_budget()
-> Result<(), ContractError> {
    for direction in DIRECTIONS {
        let fragments = v2::encode(BINDING, direction, 2, 1, &vec![8; v2::PACKET_BYTES])?;
        for bytes in &fragments {
            let mut wrong_index = bytes.clone();
            wrong_index[16] = 1 - wrong_index[16];
            assert_decode_rejected(&wrong_index);
            assert_forward_rejected(&wrong_index, BINDING, direction, 2);
            let mut truncated = bytes.clone();
            truncated.pop();
            assert_decode_rejected(&truncated);
            assert_forward_rejected(&truncated, BINDING, direction, 2);
            let mut oversized = bytes.clone();
            oversized.push(8);
            assert_decode_rejected(&oversized);
            assert_forward_rejected(&oversized, BINDING, direction, 2);
            for index in [2, u8::MAX] {
                let mut malformed = bytes.clone();
                malformed[16] = index;
                assert_decode_rejected(&malformed);
                assert_forward_rejected(&malformed, BINDING, direction, 2);
            }
            for length in [0_u16, 1401, u16::MAX] {
                let mut malformed = bytes.clone();
                malformed[6..8].copy_from_slice(&length.to_be_bytes());
                assert_decode_rejected(&malformed);
                assert_forward_rejected(&malformed, BINDING, direction, 2);
            }
        }
        let mut nonexistent_second = v2::encode(BINDING, direction, 2, 1, &[8])?[0].clone();
        nonexistent_second[16] = 1;
        assert_decode_rejected(&nonexistent_second);
        assert_forward_rejected(&nonexistent_second, BINDING, direction, 2);
    }
    Ok(())
}
