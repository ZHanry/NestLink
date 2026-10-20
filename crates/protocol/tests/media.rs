use nestlink_protocol::{
    AUDIO_FRAME_BYTES, ErrorCode, FRAME_BYTES, NativeAudio, NativeVideo, OPUS_PACKET_BYTES,
};
use prost::Message;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn video() -> NativeVideo {
    NativeVideo {
        codec: 0,
        schema_version: 1,
        connection_generation: 9,
        layout_epoch: 7,
        source: 3,
        sequence: 1,
        pts_90khz: 90_000,
        width: 32,
        height: 24,
        keyframe: true,
        repeated_source: false,
        // Independent structural fixture, not claimed to have valid entropy.
        payload: vec![0x30, 0, 0, 0x9d, 1, 0x2a, 32, 0, 24, 0, 0, 0],
    }
}
fn audio() -> NativeAudio {
    NativeAudio {
        schema_version: 1,
        connection_generation: 9,
        source: 3,
        sequence: 2,
        pts_48khz: 960,
        channels: 1,
        payload: vec![0xf8, 0xff, 0xfe],
    }
}
fn unhex(value: &str) -> Result<Vec<u8>> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(Into::into))
        .collect()
}
#[test]
fn independent_native_wire_vectors_fix_field_numbers_and_clocks() -> Result {
    let video_bytes =
        unhex("080110091807200328013090bf05382040184801520c3000009d012a200018000000")?;
    let audio_bytes = unhex("080110091803200228c00730013a03f8fffe")?;
    assert_eq!(video().encode_validated()?, video_bytes);
    assert_eq!(audio().encode_validated()?, audio_bytes);
    assert_eq!(NativeVideo::decode_validated(&video_bytes)?, video());
    assert_eq!(NativeAudio::decode_validated(&audio_bytes)?, audio());
    // Unknown optional fields are skipped, not interpreted as authorization.
    let mut future = video_bytes;
    future.extend([0x78, 1]);
    assert_eq!(NativeVideo::decode_validated(&future)?, video());
    Ok(())
}

#[test]
fn video_feedback_wire_budget_and_required_domains_are_bounded() -> Result {
    use nestlink_protocol::{NativeVideoFeedback, VIDEO_FEEDBACK_BYTES, VideoRecoveryReason};
    let message = NativeVideoFeedback {
        schema_version: 1,
        connection_generation: 9,
        layout_epoch: 7,
        source: 3,
        request_sequence: 2,
        last_sequence: 8,
        reason: VideoRecoveryReason::ReferenceGap as i32,
    };
    // Independently assembled protobuf varints: tags 1..7 and their values.
    let wire = unhex("0801100918072003280230083802")?;
    assert_eq!(message.encode_validated()?, wire);
    assert_eq!(NativeVideoFeedback::decode_validated(&wire)?, message);
    for case in 0..7 {
        let mut invalid = message;
        match case {
            0 => invalid.schema_version = 2,
            1 => invalid.connection_generation = 0,
            2 => invalid.layout_epoch = 0,
            3 => invalid.request_sequence = 0,
            4 => invalid.last_sequence = u64::MAX,
            5 => invalid.reason = 0,
            _ => invalid.reason = 99,
        }
        assert!(invalid.encode_validated().is_err());
    }
    assert!(
        NativeVideoFeedback::decode_validated(&vec![0; VIDEO_FEEDBACK_BYTES as usize + 1]).is_err()
    );
    let mut repeated = video();
    repeated.repeated_source = true;
    repeated.validate()?;
    repeated.keyframe = false;
    assert!(repeated.validate().is_err());
    Ok(())
}
#[test]
fn metadata_domains_reject_invalid_epochs_sequences_and_timestamps() -> Result {
    for value in [0, i64::MAX as u64 + 1, u64::MAX] {
        let mut frame = video();
        frame.connection_generation = value;
        assert!(frame.validate().is_err());
        frame = video();
        frame.layout_epoch = value;
        assert!(frame.validate().is_err());
        frame = video();
        frame.sequence = value;
        assert!(frame.validate().is_err());
        let mut sound = audio();
        sound.connection_generation = value;
        assert!(sound.validate().is_err());
        sound = audio();
        sound.sequence = value;
        assert!(sound.validate().is_err());
    }
    for value in [0, i64::MAX as u64] {
        let mut frame = video();
        frame.pts_90khz = value;
        frame.source = u32::MAX;
        frame.validate()?;
        let mut sound = audio();
        sound.pts_48khz = value;
        sound.source = 0;
        sound.validate()?;
    }
    let mut frame = video();
    frame.pts_90khz = u64::MAX;
    assert!(frame.validate().is_err());
    let mut sound = audio();
    sound.pts_48khz = u64::MAX;
    assert!(sound.validate().is_err());
    frame = video();
    frame.schema_version = 2;
    assert_eq!(
        frame.validate().err().map(|e| e.code),
        Some(ErrorCode::ProtocolMismatch)
    );
    sound = audio();
    sound.schema_version = 2;
    assert_eq!(
        sound.validate().err().map(|e| e.code),
        Some(ErrorCode::ProtocolMismatch)
    );
    Ok(())
}
#[test]
fn vp8_flags_geometry_and_partition_bounds_must_match_envelope() -> Result {
    for (width, height) in [
        (0, 24),
        (32, 0),
        (8193, 1),
        (8192, 8192),
        (u32::MAX, u32::MAX),
    ] {
        let mut frame = video();
        frame.width = width;
        frame.height = height;
        assert!(frame.validate().is_err());
    }
    for length in 0..11 {
        let mut frame = video();
        frame.payload.truncate(length);
        assert!(frame.validate().is_err());
    }
    for (index, value) in [
        (0, 0x20),
        (0, 0x38),
        (0, 0x10),
        (2, 0xff),
        (3, 0),
        (6, 33),
        (7, 0x40),
    ] {
        let mut frame = video();
        frame.payload[index] = value;
        assert!(frame.validate().is_err());
    }
    let mut frame = video();
    frame.keyframe = false;
    assert!(frame.validate().is_err());
    frame.payload = vec![0x31, 0, 0, 0, 0];
    frame.validate()?;
    Ok(())
}
#[test]
fn received_and_serialized_envelopes_include_metadata_in_their_budgets() -> Result {
    let mut frame = video();
    frame.payload.resize(FRAME_BYTES as usize - 100, 0);
    let overhead = frame.encoded_len() - frame.payload.len();
    frame.payload.resize(FRAME_BYTES as usize - overhead, 0);
    let mut wire = frame.encode_validated()?;
    assert_eq!(wire.len(), FRAME_BYTES as usize);
    NativeVideo::decode_validated(&wire)?;
    wire.extend([0x78, 1]);
    assert_eq!(
        NativeVideo::decode_validated(&wire).err().map(|e| e.code),
        Some(ErrorCode::CapacityExceeded)
    );
    frame.payload.push(0);
    assert_eq!(
        frame.encode_validated().err().map(|e| e.code),
        Some(ErrorCode::CapacityExceeded)
    );
    assert!(NativeVideo::decode_validated(&[0xff]).is_err());
    assert!(NativeAudio::decode_validated(&[0xff]).is_err());
    assert!(NativeAudio::decode_validated(&vec![0; AUDIO_FRAME_BYTES as usize + 1]).is_err());
    Ok(())
}
#[test]
fn opus_packet_bytes_and_channel_identity_are_bounded() -> Result {
    for channels in [0, 3, u32::MAX] {
        let mut sound = audio();
        sound.channels = channels;
        assert!(sound.validate().is_err());
    }
    let mut sound = audio();
    sound.channels = 2;
    assert!(sound.validate().is_err());
    sound.payload[0] |= 4;
    sound.validate()?;
    sound.payload.clear();
    assert!(sound.validate().is_err());
    sound = audio();
    sound.payload.resize(OPUS_PACKET_BYTES as usize, 0);
    sound.validate()?;
    sound.payload.push(0);
    assert!(sound.validate().is_err());
    Ok(())
}
