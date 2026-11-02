#![no_main]
use libfuzzer_sys::fuzz_target;
use nestlink_protocol::{
    NativeVideo,
    media_format::VideoFormat,
    native_displays::DisplayEnvelope,
    native_media_format::FormatEnvelope,
    native_renewal::Envelope,
    network::GrantClaims,
    network_datagram::{self as v1, Direction},
    network_datagram_v2 as v2,
    offline::OfflineGrantBundleClaims,
};

fuzz_target!(|input: &[u8]| {
    let Some((&selector, bytes)) = input.split_first() else { return; };
    if bytes.len() > 65_536 { return; }
    match selector % 8 {
        0 => {
            if let Ok(fragment) = v1::decode(bytes) {
                assert!(v2::decode(bytes).is_err());
                assert!(!fragment.payload.is_empty());
                assert!(fragment.length <= v1::PACKET_BYTES);
                assert!(fragment.index < fragment.length.div_ceil(v1::FRAGMENT_BYTES));
            }
        }
        1 => {
            if let Ok(fragment) = v2::decode(bytes) {
                assert!(v1::decode(bytes).is_err());
                let binding = fragment.binding;
                let direction = fragment.direction;
                let hops = fragment.remaining_hops;
                let mut rejected = bytes.to_vec();
                assert!(v2::forward(&mut rejected, [0; 32], direction, hops).is_err());
                assert_eq!(rejected, bytes, "rejected forwarding changed the input");
                let mut forwarded = bytes.to_vec();
                let result = v2::forward(&mut forwarded, binding, direction, hops);
                if hops == 0 {
                    assert!(result.is_err());
                    assert_eq!(forwarded, bytes);
                } else {
                    result.expect("valid authorized hop position");
                    let next = v2::decode(&forwarded).expect("forwarded fragment must decode");
                    assert_eq!(next.remaining_hops, hops - 1);
                    assert_eq!(next.binding, binding);
                    assert_eq!(next.direction, direction);
                    assert_eq!(next.packet, fragment.packet);
                    assert_eq!(next.payload, fragment.payload);
                    let mut expected = bytes.to_vec();
                    expected[5] -= 1;
                    assert_eq!(forwarded, expected, "forwarding changed more than the hop byte");
                }
                let reverse = match direction { Direction::FirstToSecond => Direction::SecondToFirst, Direction::SecondToFirst => Direction::FirstToSecond };
                let mut rejected = bytes.to_vec();
                assert!(v2::forward(&mut rejected, binding, reverse, hops).is_err());
                assert_eq!(rejected, bytes);
            }
        }
        2 => {
            if let Ok(value) = VideoFormat::decode(bytes) {
                assert_eq!(value.encode().expect("accepted format must encode"), bytes);
                value.digest().expect("accepted format has a canonical digest");
            }
        }
        3 => {
            if let Ok(value) = FormatEnvelope::decode(bytes) {
                assert_eq!(value.encode().expect("accepted NLMF must encode"), bytes);
            }
        }
        4 => {
            if let Ok(value) = GrantClaims::decode_canonical(bytes) {
                assert_eq!(value.canonical_bytes().expect("accepted grant must encode"), bytes);
            }
        }
        5 => {
            if let Ok(value) = OfflineGrantBundleClaims::decode_canonical(bytes) {
                assert_eq!(value.canonical_bytes().expect("accepted offline claims must encode"), bytes);
            }
        }
        6 => {
            if let Ok(value) = Envelope::decode(bytes) {
                assert_eq!(value.encode().expect("accepted renewal must encode"), bytes);
            }
            if let Ok(value) = DisplayEnvelope::decode(bytes) {
                assert_eq!(value.encode().expect("accepted display must encode"), bytes);
            }
        }
        _ => {
            if let Ok(value) = NativeVideo::decode_validated(bytes) {
                let encoded = value.encode_validated().expect("accepted video must encode");
                assert_eq!(NativeVideo::decode_validated(&encoded).expect("re-encoded video"), value);
            }
        }
    }
});
