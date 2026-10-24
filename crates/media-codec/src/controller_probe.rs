//! Bounded synthetic controller-direction execution probes. No desktop capture.
//! A receipt proves this finite configured workload, never sustained fps/scanout.
use crate::{
    EncodedVideo, GpuH264Presenter, GpuVideoSurface, H264Geometry, H264SpsInfo, H264Validator,
    MfH264Decoder, MfH264Encoder, OwnerObservation, VideoConfig,
};
use std::{
    io,
    time::{Duration, Instant},
};

const PACKETS: usize = 24;
const MIN_OUTPUTS: u64 = 16;
const FIXTURE_BYTES: usize = 32 * 1024 * 1024;
const WALL_BUDGET: Duration = Duration::from_secs(10);
const BGRA: [u8; 4] = [16, 128, 240, 255];

/// Private packets prevent callers relabeling arbitrary stream/config evidence.
pub struct ControllerProbeFixture {
    config: VideoConfig,
    sps: H264SpsInfo,
    geometry: H264Geometry,
    packets: Vec<EncodedVideo>,
}
impl Drop for ControllerProbeFixture {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for packet in &mut self.packets {
            packet.data.zeroize();
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerProbeBackend {
    CpuSoftware,
    CpuHardwareReadback,
    GpuPresenter,
}
#[derive(Clone, Copy, Debug)]
pub struct ControllerProbeReceipt {
    config: VideoConfig,
    sps: H264SpsInfo,
    geometry: H264Geometry,
    backend: ControllerProbeBackend,
    owner: OwnerObservation,
    accepted: u64,
    decoded: u64,
    color_verified: u64,
    submitted: u64,
    /// The actual same-generation owner was successfully closed before return.
    owner_closed: bool,
    performance_qualified: bool,
    pending_decodes_discarded: u64,
    pending_pictures_discarded: u64,
    checked_flush: bool,
    eos_complete: bool,
}
impl ControllerProbeReceipt {
    pub fn config(self) -> VideoConfig {
        self.config
    }
    pub fn sps(self) -> H264SpsInfo {
        self.sps
    }
    pub fn geometry(self) -> H264Geometry {
        self.geometry
    }
    pub fn backend(self) -> ControllerProbeBackend {
        self.backend
    }
    pub fn owner(self) -> OwnerObservation {
        self.owner
    }
    pub fn accepted(self) -> u64 {
        self.accepted
    }
    pub fn decoded(self) -> u64 {
        self.decoded
    }
    pub fn color_verified(self) -> u64 {
        self.color_verified
    }
    pub fn submitted(self) -> u64 {
        self.submitted
    }
    pub fn owner_closed(self) -> bool {
        self.owner_closed
    }
    pub fn pending_decodes_discarded(self) -> u64 {
        self.pending_decodes_discarded
    }
    pub fn pending_pictures_discarded(self) -> u64 {
        self.pending_pictures_discarded
    }
    pub fn checked_flush(self) -> bool {
        self.checked_flush
    }
    pub fn eos_complete(self) -> bool {
        self.eos_complete
    }
    pub fn performance_qualified(self) -> bool {
        self.performance_qualified
    }
}
fn timeout(started: Instant) -> io::Result<()> {
    if started.elapsed() >= WALL_BUDGET {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "controller probe wall budget",
        ));
    }
    Ok(())
}
fn target(config: VideoConfig) -> io::Result<()> {
    if config.width == 0
        || config.height == 0
        || config.width > 8192
        || config.height > 8192
        || !config.width.is_multiple_of(2)
        || !config.height.is_multiple_of(2)
        || u64::from(config.width) * u64::from(config.height) * 4 > 64 * 1024 * 1024
        || !(1..=120).contains(&config.fps)
        || !(64..=100_000).contains(&config.bitrate_kbps)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid actual controller probe target",
        ));
    }
    Ok(())
}
/// Execute on a disposable worker. The exact explicit product target is used;
/// no cached320x240 boolean or receiver placeholder config is consulted.
pub fn build_controller_probe_fixture(config: VideoConfig) -> io::Result<ControllerProbeFixture> {
    target(config)?;
    let mut encoder = MfH264Encoder::new(config, false)?;
    let result = (|| {
        let start = Instant::now();
        let pixels = zeroize::Zeroizing::new(BGRA.repeat((config.width * config.height) as usize));
        let mut validator = H264Validator::new_sdr(config.width, config.height)?;
        let mut packets = Vec::with_capacity(PACKETS);
        let mut submitted = 0u64;
        let mut bytes = 0usize;
        for _ in 0..256 {
            timeout(start)?;
            let step = encoder.encode_step(
                &pixels,
                1 + submitted * 90_000 / u64::from(config.fps),
                true,
            )?;
            submitted += u64::from(step.accepted);
            if let Some(packet) = step.output {
                let unit = validator.validate(&packet.data)?;
                if !packet.keyframe || !unit.keyframe {
                    return Err(io::Error::other(
                        "probe fixture requires independent actual IDRs",
                    ));
                }
                bytes = bytes
                    .checked_add(packet.data.len())
                    .ok_or_else(|| io::Error::other("fixture size overflow"))?;
                if bytes > FIXTURE_BYTES {
                    return Err(io::Error::other(
                        "controller probe fixture exceeds byte budget",
                    ));
                }
                packets.push(packet);
                if packets.len() == PACKETS {
                    break;
                }
            }
        }
        if packets.len() < MIN_OUTPUTS as usize {
            return Err(io::Error::other(
                "bounded fixture produced too few actual IDRs",
            ));
        }
        Ok(ControllerProbeFixture {
            config,
            sps: validator
                .sps_info()
                .ok_or_else(|| io::Error::other("fixture missing actual SPS"))?,
            geometry: validator
                .sps_geometry()
                .ok_or_else(|| io::Error::other("fixture missing actual SPS geometry"))?,
            packets,
        })
    })();
    let close = encoder.close();
    match (result, close) {
        (_, Err(error)) => Err(error),
        (result, Ok(())) => result,
    }
}

/// Independent CPU/readback decoder owner, never the fixture's encoder owner.
pub fn probe_controller_cpu(
    fixture: &ControllerProbeFixture,
    hardware_only: bool,
) -> io::Result<ControllerProbeReceipt> {
    let mut decoder = MfH264Decoder::with_config(fixture.config, hardware_only)?;
    let result = (|| {
        let start = Instant::now();
        let before = decoder.owner_observation()?;
        let mut decoded = 0u64;
        let mut expected = std::collections::VecDeque::new();
        for packet in &fixture.packets {
            timeout(start)?;
            expected.push_back(packet.pts_90khz);
            check_cpu_output(
                decoder.decode_frame(&packet.data, packet.pts_90khz)?,
                &mut expected,
                &mut decoded,
                fixture.config,
            )?;
            for _ in 0..8 {
                timeout(start)?;
                check_cpu_output(
                    decoder.drain_frame()?,
                    &mut expected,
                    &mut decoded,
                    fixture.config,
                )?;
            }
        }
        for _ in 0..128 {
            timeout(start)?;
            check_cpu_output(
                decoder.drain_frame()?,
                &mut expected,
                &mut decoded,
                fixture.config,
            )?;
        }
        let after = decoder.owner_observation()?;
        if !before.same_identity(after) || decoded < MIN_OUTPUTS {
            return Err(io::Error::other(
                "CPU probe changed owner or lacked bounded outputs",
            ));
        }
        if hardware_only {
            after.require_hardware_identity()?;
        } else if after.hardware_output {
            return Err(io::Error::other(
                "software probe unexpectedly changed backend",
            ));
        }
        Ok((after, decoded, expected.len() as u64))
    })();
    let close = decoder.close();
    let (owner, decoded, pending) = match (result, close) {
        (_, Err(error)) => return Err(error),
        (result, Ok(())) => result?,
    };
    Ok(ControllerProbeReceipt {
        config: fixture.config,
        sps: fixture.sps,
        geometry: fixture.geometry,
        backend: if hardware_only {
            ControllerProbeBackend::CpuHardwareReadback
        } else {
            ControllerProbeBackend::CpuSoftware
        },
        owner,
        accepted: fixture.packets.len() as u64,
        decoded,
        color_verified: decoded,
        submitted: 0,
        owner_closed: true,
        performance_qualified: false,
        pending_decodes_discarded: pending,
        pending_pictures_discarded: 0,
        checked_flush: true,
        eos_complete: false,
    })
}

fn check_cpu_output(
    output: Option<(Vec<u8>, u64)>,
    expected: &mut std::collections::VecDeque<u64>,
    decoded: &mut u64,
    config: VideoConfig,
) -> io::Result<()> {
    if let Some((pixels, pts)) = output {
        let pixels = zeroize::Zeroizing::new(pixels);
        if expected.pop_front() != Some(pts)
            || pixels.len() != (config.width * config.height * 4) as usize
            || !pixels.chunks_exact(4).all(|pixel| {
                pixel.iter().zip(BGRA).all(|(&actual, wanted)| {
                    (i32::from(actual) - i32::from(wanted)).abs()
                        <= if wanted == 255 { 0 } else { 40 }
                })
            })
        {
            return Err(io::Error::other(
                "controller CPU actual output PTS/geometry/color mismatch",
            ));
        }
        *decoded += 1;
    }
    Ok(())
}
fn count_gpu(
    step: crate::GpuDecodeStep,
    decoded: &mut u64,
    completed: &mut u64,
    submitted: &mut u64,
) {
    *decoded += u64::from(step.decoded.is_some());
    if let Some(picture) = step.picture {
        *completed += 1;
        *submitted += u64::from(picture.submitted_qpc.is_some());
    }
}

struct ProbeSurface(GpuVideoSurface);
impl Drop for ProbeSurface {
    fn drop(&mut self) {
        self.0.revoke();
        self.0.detach();
    }
}
/// Opens only its own synthetic NOACTIVATE window on this disposable worker.
/// GPU readback is explicitly probe-only; live presentation remains readback-free.
pub fn probe_controller_gpu(
    fixture: &ControllerProbeFixture,
) -> io::Result<ControllerProbeReceipt> {
    let c = fixture.config;
    let surface = ProbeSurface(GpuVideoSurface::probe_window(c.width, c.height)?);
    surface.0.place(0, 0, c.width, c.height, true)?;
    let mut presenter = GpuH264Presenter::with_config(&surface.0, c)?;
    let result = (|| {
        let start = Instant::now();
        let before = presenter.owner_observation()?;
        presenter.enable_probe_color(BGRA, 40)?;
        let mut accepted = 0u64;
        let mut decoded = 0u64;
        let mut completed = 0u64;
        let mut submitted = 0u64;
        for (index, packet) in fixture.packets.iter().enumerate() {
            loop {
                timeout(start)?;
                let step = presenter.submit(index as u64 + 1, packet.pts_90khz, &packet.data)?;
                let consumed = step.accepted;
                count_gpu(step, &mut decoded, &mut completed, &mut submitted);
                if consumed {
                    accepted += 1;
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        loop {
            timeout(start)?;
            count_gpu(
                presenter.poll()?,
                &mut decoded,
                &mut completed,
                &mut submitted,
            );
            // Query the exact native color-verification count rather than
            // assuming conversion/submission implies correct output pixels.
            if presenter.probe_color_count()? >= MIN_OUTPUTS {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let after = presenter.owner_observation()?;
        let colors = presenter.probe_color_count()?;
        after.require_hardware_identity()?;
        if !before.same_identity(after)
            || accepted < MIN_OUTPUTS
            || decoded < MIN_OUTPUTS
            || completed < MIN_OUTPUTS
            || submitted == 0
            || colors < MIN_OUTPUTS
        {
            return Err(io::Error::other(
                "GPU direction lacked same-owner output/color/submission",
            ));
        }
        Ok((after, accepted, decoded, colors, submitted, completed))
    })();
    let close = presenter.close();
    let (owner, accepted, decoded, colors, submitted, completed) = match (result, close) {
        (_, Err(error)) => return Err(error),
        (result, Ok(())) => result?,
    };
    Ok(ControllerProbeReceipt {
        config: c,
        sps: fixture.sps,
        geometry: fixture.geometry,
        backend: ControllerProbeBackend::GpuPresenter,
        owner,
        accepted,
        decoded,
        color_verified: colors,
        submitted,
        owner_closed: true,
        performance_qualified: false,
        pending_decodes_discarded: accepted.saturating_sub(decoded),
        pending_pictures_discarded: decoded.saturating_sub(completed),
        checked_flush: true,
        eos_complete: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_target_is_rejected_before_any_decoder_or_surface_probe() {
        for (width, height) in [(0, 240), (321, 241), (u32::MAX, u32::MAX), (8192, 8192)] {
            assert!(
                build_controller_probe_fixture(VideoConfig {
                    width,
                    height,
                    fps: 30,
                    bitrate_kbps: 1000
                })
                .is_err()
            );
        }
    }
    #[test]
    fn bad_cpu_pts_color_and_output_geometry_never_count_as_probe_evidence() {
        let config = VideoConfig {
            width: 2,
            height: 2,
            fps: 30,
            bitrate_kbps: 1000,
        };
        let wrong = vec![0; 16];
        let swapped = [BGRA[2], BGRA[1], BGRA[0], BGRA[3]].repeat(4);
        for (pixels, pts) in [
            (BGRA.repeat(4), 8),
            (wrong, 7),
            (swapped, 7),
            (BGRA.repeat(3), 7),
        ] {
            let mut expected = std::collections::VecDeque::from([7]);
            let mut counted = 0;
            assert!(
                check_cpu_output(Some((pixels, pts)), &mut expected, &mut counted, config).is_err()
            );
            assert_eq!(counted, 0);
        }
    }
}
