//! Actual finite CPU direction probes. Closed owners are historical evidence,
//! never a live resource lease or a sustained frame-rate qualification.
use crate::{
    H264Geometry, H264SpsInfo, H264Validator, MfH264Decoder, MfH264Encoder, OwnerObservation,
    VideoConfig,
};
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
pub struct CpuDirectionProbe {
    config: VideoConfig,
    sps: H264SpsInfo,
    geometry: H264Geometry,
    owner: OwnerObservation,
    outputs: u64,
}
impl CpuDirectionProbe {
    pub fn config(self) -> VideoConfig {
        self.config
    }
    pub fn sps(self) -> H264SpsInfo {
        self.sps
    }
    pub fn geometry(self) -> H264Geometry {
        self.geometry
    }
    pub fn owner(self) -> OwnerObservation {
        self.owner
    }
    pub fn outputs(self) -> u64 {
        self.outputs
    }
    pub fn owner_closed(self) -> bool {
        true
    }
    pub fn checked_flush(self) -> bool {
        true
    }
}
fn check(cancel: &AtomicBool, start: Instant) -> io::Result<()> {
    if cancel.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "CPU direction probe cancelled",
        ));
    }
    if start.elapsed() >= Duration::from_secs(10) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "CPU direction probe workload budget",
        ));
    }
    Ok(())
}
fn target(c: VideoConfig) -> io::Result<()> {
    if c.width == 0
        || c.height == 0
        || c.width > 8192
        || c.height > 8192
        || !c.width.is_multiple_of(2)
        || !c.height.is_multiple_of(2)
        || u64::from(c.width) * u64::from(c.height) * 4 > 64 * 1024 * 1024
        || !(1..=120).contains(&c.fps)
        || !(64..=100_000).contains(&c.bitrate_kbps)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid actual CPU probe target",
        ));
    }
    Ok(())
}
/// The observed UUID belongs to this exact configured software encoder, not
/// the independent decoder used to check its output. Both owners close here.
pub fn probe_cpu_encode(config: VideoConfig, cancel: &AtomicBool) -> io::Result<CpuDirectionProbe> {
    target(config)?;
    let start = Instant::now();
    check(cancel, start)?;
    let mut encoder = MfH264Encoder::new(config, false)?;
    let result = (|| {
        let before = encoder.owner_observation()?;
        let mut validator = H264Validator::new_sdr(config.width, config.height)?;
        let pixels = zeroize::Zeroizing::new(
            [16u8, 128, 240, 255].repeat((config.width * config.height) as usize),
        );
        let mut decoder = MfH264Decoder::with_config(config, false)?;
        let verified = (|| {
            let mut accepted = 0u64;
            let mut outputs = 0u64;
            let mut expected = std::collections::VecDeque::new();
            for _ in 0..256 {
                check(cancel, start)?;
                let step = encoder.encode_step(
                    &pixels,
                    1 + accepted * 90_000 / u64::from(config.fps),
                    true,
                )?;
                accepted += u64::from(step.accepted);
                if let Some(packet) = step.output {
                    let unit = validator.validate(&packet.data)?;
                    if !unit.keyframe || !packet.keyframe {
                        return Err(io::Error::other("CPU encoder probe lacks independent IDR"));
                    }
                    expected.push_back(packet.pts_90khz);
                    verify_pixels(
                        decoder.decode_frame(&packet.data, packet.pts_90khz)?,
                        &mut expected,
                        &mut outputs,
                        config,
                    )?;
                    for _ in 0..8 {
                        check(cancel, start)?;
                        verify_pixels(decoder.drain_frame()?, &mut expected, &mut outputs, config)?;
                    }
                    if outputs >= 16 {
                        break;
                    }
                }
                if accepted >= 24 {
                    break;
                }
            }
            for _ in 0..128 {
                if outputs >= 16 {
                    break;
                }
                check(cancel, start)?;
                verify_pixels(decoder.drain_frame()?, &mut expected, &mut outputs, config)?;
            }
            if outputs < 16 {
                return Err(io::Error::other(
                    "CPU encoder target lacks verified outputs",
                ));
            }
            Ok(outputs)
        })();
        let decoder_close = decoder.close();
        let outputs = match (verified, decoder_close) {
            (_, Err(e)) => return Err(e),
            (result, Ok(())) => result?,
        };
        let after = encoder.owner_observation()?;
        if !before.same_identity(after)
            || after.hardware_output
            || encoder.hardware()
            || after.adapter_luid.is_some()
            || after.driver_version.is_some()
        {
            return Err(io::Error::other(
                "CPU encoder target changed identity/backend",
            ));
        }
        Ok(CpuDirectionProbe {
            config,
            sps: validator
                .sps_info()
                .ok_or_else(|| io::Error::other("missing actual encoder SPS"))?,
            geometry: validator
                .sps_geometry()
                .ok_or_else(|| io::Error::other("missing actual encoder geometry"))?,
            owner: after,
            outputs,
        })
    })();
    let close = encoder.close();
    match (result, close) {
        (_, Err(e)) => Err(e),
        (result, Ok(())) => result,
    }
}
fn verify_pixels(
    output: Option<(Vec<u8>, u64)>,
    expected: &mut std::collections::VecDeque<u64>,
    count: &mut u64,
    c: VideoConfig,
) -> io::Result<()> {
    if let Some((pixels, pts)) = output {
        let pixels = zeroize::Zeroizing::new(pixels);
        if expected.pop_front() != Some(pts)
            || pixels.len() != (c.width * c.height * 4) as usize
            || !pixels.chunks_exact(4).all(|p| {
                p.iter()
                    .zip([16, 128, 240, 255])
                    .all(|(&a, b)| (i32::from(a) - b).abs() <= if b == 255 { 0 } else { 40 })
            })
        {
            return Err(io::Error::other(
                "CPU encoder independent output PTS/geometry/color mismatch",
            ));
        }
        *count += 1;
    }
    Ok(())
}
/// The receipt UUID belongs to a fresh independent CPU decoder. Fixture encoder
/// success never substitutes for this configured direction's decode workload.
pub fn probe_cpu_decode(config: VideoConfig, cancel: &AtomicBool) -> io::Result<CpuDirectionProbe> {
    target(config)?;
    let start = Instant::now();
    check(cancel, start)?;
    let fixture = crate::build_controller_probe_fixture(config)?;
    check(cancel, start)?;
    let receipt = crate::probe_controller_cpu(&fixture, false)?;
    check(cancel, start)?;
    let owner = receipt.owner();
    if !receipt.owner_closed()
        || !receipt.checked_flush()
        || receipt.decoded() < 16
        || receipt.color_verified() != receipt.decoded()
        || owner.hardware_output
        || owner.adapter_luid.is_some()
        || owner.driver_version.is_some()
    {
        return Err(io::Error::other(
            "CPU decoder target lacks exact software evidence",
        ));
    }
    Ok(CpuDirectionProbe {
        config: receipt.config(),
        sps: receipt.sps(),
        geometry: receipt.geometry(),
        owner,
        outputs: receipt.decoded(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cpu_direction_product_targets_keep_distinct_closed_owners_and_actual_sps() -> io::Result<()>
    {
        let cancel = AtomicBool::new(false);
        let mut previous = None;
        for config in [
            VideoConfig {
                width: 640,
                height: 480,
                fps: 30,
                bitrate_kbps: 4000,
            },
            VideoConfig {
                width: 640,
                height: 360,
                fps: 60,
                bitrate_kbps: 3000,
            },
        ] {
            let encode = probe_cpu_encode(config, &cancel)?;
            let decode = probe_cpu_decode(config, &cancel)?;
            assert_ne!(encode.owner().resource_id, decode.owner().resource_id);
            if let Some(previous) = previous {
                assert_ne!(encode.owner().resource_id, previous);
            }
            for receipt in [encode, decode] {
                assert!(receipt.owner_closed() && receipt.checked_flush());
                assert!(receipt.outputs() >= 16 && !receipt.owner().hardware_output);
                assert_eq!(receipt.sps().profile_idc, 66);
                let actual = receipt.config();
                let g = receipt.geometry();
                assert_eq!(
                    (actual.width, actual.height, actual.fps, actual.bitrate_kbps),
                    (config.width, config.height, config.fps, config.bitrate_kbps)
                );
                assert_eq!(
                    (
                        g.coded_width - g.crop[0] - g.crop[1],
                        g.coded_height - g.crop[2] - g.crop[3]
                    ),
                    (config.width, config.height)
                );
            }
            previous = Some(encode.owner().resource_id);
        }
        Ok(())
    }
    #[test]
    fn invalid_cpu_direction_target_fails_before_any_native_owner_creation() {
        let cancel = AtomicBool::new(false);
        for config in [
            VideoConfig {
                width: 321,
                height: 240,
                fps: 30,
                bitrate_kbps: 4000,
            },
            VideoConfig {
                width: 640,
                height: 480,
                fps: 0,
                bitrate_kbps: 4000,
            },
            VideoConfig {
                width: 640,
                height: 480,
                fps: 30,
                bitrate_kbps: 100001,
            },
        ] {
            assert!(probe_cpu_encode(config, &cancel).is_err());
            assert!(probe_cpu_decode(config, &cancel).is_err());
        }
    }
}
