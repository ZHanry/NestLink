//! Native reliable VP8/Opus envelopes. The session separately checks source
//! consent, current epochs, sequence/timestamp progression and codec state.
use crate::{
    AUDIO_FRAME_BYTES, ContractError, ErrorCode, FRAME_BYTES, NativeAudio, NativeVideo,
    NativeVideoFeedback, OPUS_PACKET_BYTES, RAW_FRAME_BYTES, SCHEMA_VERSION, VIDEO_DIMENSION,
    VIDEO_FEEDBACK_BYTES, VideoRecoveryReason, decode_bounded,
};
use prost::Message;

pub const H264_CAPABILITY: &str = "h264-baseline-v1";
pub fn negotiated_video_codec(claims: &crate::PermitClaims) -> crate::NativeVideoCodec {
    if claims
        .required_capabilities
        .iter()
        .any(|value| value == H264_CAPABILITY)
    {
        crate::NativeVideoCodec::H264Baseline
    } else {
        crate::NativeVideoCodec::Vp8
    }
}

fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}
fn common(schema: u32, epoch: u64, sequence: u64, pts: u64) -> Result<(), ContractError> {
    if schema != SCHEMA_VERSION {
        return Err(ContractError::new(
            ErrorCode::ProtocolMismatch,
            "unsupported native media schema",
        ));
    }
    if [epoch, sequence]
        .iter()
        .any(|value| *value == 0 || *value > i64::MAX as u64)
        || pts > i64::MAX as u64
    {
        return Err(invalid("invalid native media epoch, sequence or timestamp"));
    }
    Ok(())
}
fn budget(actual: usize, maximum: u64) -> Result<(), ContractError> {
    if actual as u64 > maximum {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "native media envelope exceeds byte budget",
        ));
    }
    Ok(())
}
impl NativeVideoFeedback {
    pub fn decode_validated(bytes: &[u8]) -> Result<Self, ContractError> {
        let message: Self = decode_bounded(bytes, VIDEO_FEEDBACK_BYTES)?;
        message.validate()?;
        Ok(message)
    }
    pub fn encode_validated(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        Ok(self.encode_to_vec())
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        common(
            self.schema_version,
            self.connection_generation,
            self.request_sequence,
            self.last_sequence,
        )?;
        budget(self.encoded_len(), VIDEO_FEEDBACK_BYTES)?;
        if self.layout_epoch == 0
            || self.layout_epoch > i64::MAX as u64
            || !matches!(
                VideoRecoveryReason::try_from(self.reason),
                Ok(VideoRecoveryReason::KeyframeMissing
                    | VideoRecoveryReason::ReferenceGap
                    | VideoRecoveryReason::DecoderFailure)
            )
        {
            return Err(invalid("invalid video feedback layout or reason"));
        }
        Ok(())
    }
}
impl NativeVideo {
    pub fn decode_validated(bytes: &[u8]) -> Result<Self, ContractError> {
        let frame: Self = decode_bounded(bytes, FRAME_BYTES)?;
        frame.validate()?;
        Ok(frame)
    }
    pub fn encode_validated(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        Ok(self.encode_to_vec())
    }
    /// Checks envelope and VP8 uncompressed framing; the decoder must still
    /// validate compressed syntax and never reuse a failed reference context.
    pub fn validate(&self) -> Result<(), ContractError> {
        common(
            self.schema_version,
            self.connection_generation,
            self.sequence,
            self.pts_90khz,
        )?;
        budget(self.encoded_len(), FRAME_BYTES)?;
        if self.layout_epoch == 0 || self.layout_epoch > i64::MAX as u64 {
            return Err(invalid("invalid native video layout epoch"));
        }
        if self.width == 0
            || self.height == 0
            || u64::from(self.width) > VIDEO_DIMENSION
            || u64::from(self.height) > VIDEO_DIMENSION
            || u64::from(self.width) * u64::from(self.height) * 4 > RAW_FRAME_BYTES
        {
            return Err(invalid("native video geometry exceeds raw frame budget"));
        }
        let packet = &self.payload;
        if self.repeated_source && !self.keyframe {
            return Err(invalid("repeated source recovery must be a keyframe"));
        }
        match crate::NativeVideoCodec::try_from(self.codec) {
            Ok(crate::NativeVideoCodec::Vp8) => {}
            Ok(crate::NativeVideoCodec::H264Baseline) => {
                if !(packet.starts_with(&[0, 0, 1]) || packet.starts_with(&[0, 0, 0, 1])) {
                    return Err(invalid("invalid H.264 envelope geometry or Annex B prefix"));
                }
                let idr = packet
                    .windows(4)
                    .any(|part| part[..3] == [0, 0, 1] && part[3] & 31 == 5);
                if idr != self.keyframe {
                    return Err(invalid("H.264 IDR flag differs from native envelope"));
                }
                // The media decoder additionally validates all parameter sets,
                // slice dependencies and SPS geometry before invoking the OS.
                return Ok(());
            }
            Err(_) => return Err(invalid("unknown native video codec")),
        }
        if packet.len() < 3 {
            return Err(invalid("missing VP8 frame header"));
        }
        let keyframe = packet[0] & 1 == 0;
        let header = if keyframe { 10 } else { 3 };
        let partition =
            (usize::from(packet[0]) | usize::from(packet[1]) << 8 | usize::from(packet[2]) << 16)
                >> 5;
        if keyframe != self.keyframe
            || packet[0] & 0x10 == 0
            || (packet[0] >> 1) & 7 > 3
            || packet.len() <= header
            || partition == 0
            || partition > packet.len() - header
        {
            return Err(invalid("invalid or inconsistent VP8 frame header"));
        }
        if keyframe
            && (packet[3..6] != [0x9d, 1, 0x2a]
                || packet[7] & 0xc0 != 0
                || packet[9] & 0xc0 != 0
                || u32::from(u16::from_le_bytes([packet[6], packet[7]])) != self.width
                || u32::from(u16::from_le_bytes([packet[8], packet[9]])) != self.height)
        {
            return Err(invalid(
                "VP8 keyframe geometry differs from native envelope",
            ));
        }
        Ok(())
    }
}
impl NativeAudio {
    pub fn decode_validated(bytes: &[u8]) -> Result<Self, ContractError> {
        let frame: Self = decode_bounded(bytes, AUDIO_FRAME_BYTES)?;
        frame.validate()?;
        Ok(frame)
    }
    pub fn encode_validated(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        Ok(self.encode_to_vec())
    }
    /// Payload parsing and the exact 20 ms duration are checked by the Opus
    /// codec before decoding; this layer never sizes PCM from packet metadata.
    pub fn validate(&self) -> Result<(), ContractError> {
        common(
            self.schema_version,
            self.connection_generation,
            self.sequence,
            self.pts_48khz,
        )?;
        budget(self.encoded_len(), AUDIO_FRAME_BYTES)?;
        if !(1..=2).contains(&self.channels)
            || self.payload.is_empty()
            || self.payload.len() as u64 > OPUS_PACKET_BYTES
        {
            return Err(invalid("invalid Opus channel count or packet length"));
        }
        if u32::from((self.payload[0] >> 2) & 1) + 1 != self.channels {
            return Err(invalid(
                "Opus channel identity differs from native envelope",
            ));
        }
        Ok(())
    }
}
