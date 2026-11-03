//! Finite actual software RGB444 work. This is functional capability evidence,
//! with no claim about capture, sustainable frame rate, GPU or HEVC 4:4:4.
use crate::{ExecutionDirection, VideoConfig, Vp9Rgb444Decoder, Vp9Rgb444Encoder};
use std::{io, sync::atomic::{AtomicBool, Ordering}, time::{Duration, Instant}};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug)]
pub struct Vp9Rgb444DirectionProbe {
    resource_id: [u8; 16],
    pub direction: ExecutionDirection,
    pub config: VideoConfig,
    pub output_frames: u32,
    pub elapsed: Duration,
    pub checked_close: bool,
}
impl Vp9Rgb444DirectionProbe {
    pub fn resource_id(self) -> [u8; 16] { self.resource_id }
}
fn pattern(config: VideoConfig) -> io::Result<Zeroizing<Vec<u8>>> {
    let bytes = crate::vp9::validate_config(config)?;
    let mut pixels = Zeroizing::new(Vec::new());
    pixels.try_reserve_exact(bytes).map_err(io::Error::other)?;
    pixels.resize(bytes, 0);
    for y in 0..config.height as usize {
        for x in 0..config.width as usize {
            // Full-size components alternate even on odd dimensions. A 4:2:0
            // roundtrip would blend these adjacent red/blue and green/gray pixels.
            let color = match (x & 1, y & 1) {
                (0, 0) => [16, 16, 240, 255],
                (1, 0) => [240, 16, 16, 255],
                (0, 1) => [16, 240, 16, 255],
                _ => [208, 208, 208, 255],
            };
            let offset = (y * config.width as usize + x) * 4;
            pixels[offset..offset + 4].copy_from_slice(&color);
        }
    }
    Ok(pixels)
}
fn verify(pixels: &[u8], expected: &[u8]) -> io::Result<()> {
    if pixels.len() != expected.len()
        || !pixels.chunks_exact(4).zip(expected.chunks_exact(4)).all(|(actual, target)| {
            actual[3] == 255 && actual[..3].iter().zip(&target[..3]).all(|(a, b)| a.abs_diff(*b) <= 48)
        }) {
        return Err(io::Error::other("VP9 RGB444 adjacent color components differ"));
    }
    Ok(())
}
/// Each direction creates its real libvpx context and independently checks the
/// opposite direction. Success requires 32 immediate outputs, exact geometry,
/// full-resolution RGB samples and checked close, inside the 10-second budget.
pub fn probe_vp9_rgb444_direction(direction: ExecutionDirection, config: VideoConfig) -> io::Result<Vp9Rgb444DirectionProbe> {
    probe_vp9_rgb444_direction_with_cancel(direction, config, &AtomicBool::new(false))
}
pub fn probe_vp9_rgb444_direction_with_cancel(direction: ExecutionDirection, config: VideoConfig, cancel: &AtomicBool) -> io::Result<Vp9Rgb444DirectionProbe> {
    if cancel.load(Ordering::Acquire) { return Err(io::Error::new(io::ErrorKind::Interrupted, "VP9 direction probe cancelled")); }
    let pixels = pattern(config)?;
    let started = Instant::now();
    let mut encoder = Vp9Rgb444Encoder::new(config)?;
    let mut decoder = match Vp9Rgb444Decoder::new(config.width, config.height) {
        Ok(value) => value,
        Err(error) => { encoder.close()?; return Err(error); }
    };
    let work = (|| {
        let encoded_owner = encoder.resource_id()?;
        let decoded_owner = decoder.resource_id()?;
        if encoded_owner == decoded_owner { return Err(io::Error::other("VP9 probe owners are not independent")); }
        for frame in 0..32u64 {
            if cancel.load(Ordering::Acquire) { return Err(io::Error::new(io::ErrorKind::Interrupted, "VP9 direction probe cancelled")); }
            if started.elapsed() >= Duration::from_secs(10) { return Err(io::Error::new(io::ErrorKind::TimedOut, "VP9 direction probe deadline")); }
            let pts = frame * 90_000 / u64::from(config.fps);
            let mut packet = encoder.encode(&pixels, pts)?;
            if packet.pts_90khz != pts || !packet.keyframe { return Err(io::Error::other("VP9 probe output PTS or keyframe differs")); }
            let decoded = Zeroizing::new(decoder.decode(&packet.data)?);
            use zeroize::Zeroize;
            packet.data.zeroize();
            verify(&decoded, &pixels)?;
            if encoder.resource_id()? != encoded_owner || decoder.resource_id()? != decoded_owner {
                return Err(io::Error::other("VP9 probe original owner changed"));
            }
        }
        if started.elapsed() >= Duration::from_secs(10) { return Err(io::Error::new(io::ErrorKind::TimedOut, "VP9 direction probe deadline")); }
        Ok(match direction { ExecutionDirection::Encode => encoded_owner, ExecutionDirection::Decode => decoded_owner })
    })();
    let encoder_close = encoder.close();
    let decoder_close = decoder.close();
    encoder_close?;
    decoder_close?;
    let resource_id = work?;
    if started.elapsed() >= Duration::from_secs(10) { return Err(io::Error::new(io::ErrorKind::TimedOut, "VP9 checked close exceeded probe deadline")); }
    Ok(Vp9Rgb444DirectionProbe { resource_id, direction, config, output_frames: 32, elapsed: started.elapsed(), checked_close: true })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_libvpx_rgb444_preserves_adjacent_colors_and_odd_geometry() -> io::Result<()> {
        for direction in [ExecutionDirection::Encode, ExecutionDirection::Decode] {
            let probe = probe_vp9_rgb444_direction(direction, VideoConfig { width: 65, height: 33, fps: 60, bitrate_kbps: 10_000 })?;
            assert_eq!(probe.output_frames, 32);
            assert!(probe.checked_close);
        }
        Ok(())
    }
    #[test]
    fn public_libvpx_parser_rejects_truncation_and_wrong_geometry() -> io::Result<()> {
        let config = VideoConfig { width: 65, height: 33, fps: 60, bitrate_kbps: 10_000 };
        let mut encoder = Vp9Rgb444Encoder::new(config)?;
        let packet = encoder.encode(&pattern(config)?, 0)?;
        crate::validate_vp9_rgb444_keyframe(&packet.data, 65, 33)?;
        assert!(crate::validate_vp9_rgb444_keyframe(&packet.data[..1], 65, 33).is_err());
        assert!(crate::validate_vp9_rgb444_keyframe(&packet.data, 64, 33).is_err());
        encoder.close()
    }
    #[test]
    fn actual_decoder_rejects_other_codec_and_resized_output() -> io::Result<()> {
        let config = VideoConfig { width: 64, height: 32, fps: 60, bitrate_kbps: 10_000 };
        let pixels = pattern(config)?;
        let mut vp8 = crate::Vp8Encoder::new(config)?;
        let foreign = vp8.encode(&pixels, 0, true)?;
        let mut decoder = Vp9Rgb444Decoder::new(64, 32)?;
        assert!(decoder.decode(&foreign.data).is_err());
        let mut encoder = Vp9Rgb444Encoder::new(config)?;
        let packet = encoder.encode(&pixels, 0)?;
        let mut resized = Vp9Rgb444Decoder::new(65, 33)?;
        assert!(resized.decode(&packet.data).is_err());
        // Rejected admission must not emit substituted or stale pixels.
        assert!(decoder.decode(&[]).is_err());
        let decoded = Zeroizing::new(decoder.decode(&packet.data)?);
        verify(&decoded, &pixels)?;
        decoder.close()?;
        resized.close()?;
        encoder.close()
    }
    #[test]
    fn actual_software_owner_seals_output_and_retires_receipts() -> io::Result<()> {
        use crate::{ExecutionOutput, SoftwareExecution, Vp9Rgb444ExecutionTarget};
        let config = VideoConfig { width: 65, height: 33, fps: 60, bitrate_kbps: 10_000 };
        let target = Vp9Rgb444ExecutionTarget::new(config, [9; 32])?;
        let mut encode = SoftwareExecution::start(ExecutionDirection::Encode, target)?;
        let mut decode = SoftwareExecution::start(ExecutionDirection::Decode, target)?;
        let encode_registration = encode.current()?;
        let decode_registration = decode.current()?;
        assert_ne!(encode_registration.identity()?.resource_id(), decode_registration.identity()?.resource_id());
        assert!(SoftwareExecution::start(ExecutionDirection::Encode, target).is_err());
        let pixels = pattern(config)?;
        let output = encode.submit_encode(pixels.to_vec(), 1500, true)?.wait()?;
        let ExecutionOutput::Encoded(step, Some(encoded_receipt)) = output else {
            return Err(io::Error::other("real VP9 owner produced no encoded receipt"));
        };
        let packet = step.output.ok_or_else(|| io::Error::other("real VP9 owner produced no access unit"))?;
        encoded_receipt.check_encoded(1500, true, &packet.data)?;
        assert!(encoded_receipt.check_encoded(1501, true, &packet.data).is_err());
        assert!(encoded_receipt.check_encoded(1500, false, &packet.data).is_err());
        assert!(encoded_receipt.check_encoded(1500, true, b"changed").is_err());
        let output = decode.submit_decode(packet.data, 1500)?.wait()?;
        let ExecutionOutput::Decoded(Some((decoded, pts, decoded_receipt))) = output else {
            return Err(io::Error::other("real VP9 owner produced no decoded receipt"));
        };
        let decoded = Zeroizing::new(decoded);
        assert_eq!(pts, 1500);
        decoded_receipt.check_decoded(pts, &decoded)?;
        verify(&decoded, &pixels)?;
        assert!(decoded_receipt.check_decoded(pts + 1, &decoded).is_err());
        encode.shutdown()?;
        decode.shutdown()?;
        assert!(encode_registration.retired_joined());
        assert!(decode_registration.retired_joined());
        assert!(encoded_receipt.check_current().is_err());
        assert!(decoded_receipt.check_current().is_err());
        let mut replacement = SoftwareExecution::start(ExecutionDirection::Encode, target)?;
        assert!(replacement.current()?.identity()?.generation() > encode_registration.identity()?.generation());
        assert_ne!(replacement.current()?.identity()?.resource_id(), encode_registration.identity()?.resource_id());
        replacement.shutdown()
    }
    #[test]
    fn cancelled_probe_does_not_report_capability() {
        let config = VideoConfig { width: 65, height: 33, fps: 60, bitrate_kbps: 10_000 };
        let result = probe_vp9_rgb444_direction_with_cancel(ExecutionDirection::Encode, config, &AtomicBool::new(true));
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Interrupted));
    }
}
