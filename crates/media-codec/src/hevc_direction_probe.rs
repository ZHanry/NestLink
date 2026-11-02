//! Finite actual hardware direction evidence with independent software decode.
//! Synthetic input is explicit; a closed probe never grants live execution,
//! desktop capture permission, sustained cadence or presentation qualification.
use crate::{
    ExecutionDirection, HevcMain8Admission, HevcMain8Contract, HevcProbeDecoder, HevcProbeEncoder,
    HevcProbePacket, HevcSyntheticSource, OwnerObservation, VideoConfig,
};
use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
pub struct HevcDirectionProbe {
    contract: HevcMain8Contract,
    direction: ExecutionDirection,
    owner: OwnerObservation,
    outputs: u64,
    encoder_backend: crate::HevcEncoderBackend,
    encoder_runtime: Option<u64>,
}
impl HevcDirectionProbe {
    pub fn contract(self) -> HevcMain8Contract {
        self.contract
    }
    pub fn direction(self) -> ExecutionDirection {
        self.direction
    }
    pub fn owner(self) -> OwnerObservation {
        self.owner
    }
    pub fn outputs(self) -> u64 {
        self.outputs
    }
    pub fn encoder_backend(self) -> crate::HevcEncoderBackend {
        self.encoder_backend
    }
    pub fn encoder_runtime_version(self) -> Option<u64> {
        self.encoder_runtime
    }
    pub fn owner_closed(self) -> bool {
        true
    }
    pub fn checked_flush(self) -> bool {
        true
    }
}
fn check(cancel: &AtomicBool, deadline: Instant) -> io::Result<()> {
    if cancel.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "HEVC direction probe cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "HEVC direction probe original workload budget",
        ));
    }
    Ok(())
}
fn picture(
    pixels: Vec<u8>,
    pts: u64,
    expected: &mut VecDeque<u64>,
    count: &mut u64,
    config: VideoConfig,
) -> io::Result<()> {
    let pixels = zeroize::Zeroizing::new(pixels);
    let width = config.width as usize;
    let height = config.height as usize;
    if expected.pop_front() != Some(pts) || pixels.len() != width * height * 4 {
        return Err(io::Error::other(
            "HEVC probe actual decoder PTS/geometry differs",
        ));
    }
    let colors = [
        [32i32, 96, 192, 255],
        [192, 96, 32, 255],
        [16, 16, 16, 255],
        [224, 224, 224, 255],
    ];
    for y in [height / 4, height * 3 / 4] {
        for x in [width / 4, width * 3 / 4] {
            let expected = colors[usize::from(x >= width / 2) + 2 * usize::from(y >= height / 2)];
            let pixel = &pixels[(y * width + x) * 4..(y * width + x) * 4 + 4];
            if (0..3).any(|i| (i32::from(pixel[i]) - expected[i]).abs() > 24) || pixel[3] != 255 {
                return Err(io::Error::other(
                    "HEVC probe independent BT709/range/quadrant output differs",
                ));
            }
        }
    }
    *count += 1;
    Ok(())
}
struct Workload {
    config: VideoConfig,
    bit_depth: u8,
    contract: Option<HevcMain8Contract>,
    admission: Option<HevcMain8Admission>,
    expected: [VecDeque<u64>; 2],
    decoded: [u64; 2],
    outputs: u64,
}
impl Workload {
    fn feed(
        &mut self,
        packet: HevcProbePacket,
        decoders: [&mut HevcProbeDecoder; 2],
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> io::Result<()> {
        if self.contract.is_none() {
            let contract = if self.bit_depth == 10 {
                HevcMain8Contract::observe_main10(&packet.data, self.config)
            } else {
                HevcMain8Contract::observe(&packet.data, self.config)
            }?;
            self.contract = Some(contract);
            self.admission = Some(HevcMain8Admission::new(contract));
        }
        self.admission
            .as_mut()
            .ok_or_else(|| io::Error::other("HEVC exact admission absent"))?
            .validate(&packet.data)?;
        self.outputs += 1;
        for (index, decoder) in decoders.into_iter().enumerate() {
            let input_deadline = deadline.min(Instant::now() + Duration::from_secs(2));
            loop {
                check(cancel, input_deadline)?;
                let (accepted, output) = decoder.submit(&packet)?;
                if accepted {
                    if self.expected[index].len() >= 16 {
                        return Err(io::Error::other("HEVC probe decoder ledger full"));
                    }
                    self.expected[index].push_back(packet.pts_90khz);
                }
                if let Some((pixels, pts)) = output {
                    picture(
                        pixels,
                        pts,
                        &mut self.expected[index],
                        &mut self.decoded[index],
                        self.config,
                    )?;
                }
                if accepted {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }
}
pub fn probe_hevc_direction(
    config: VideoConfig,
    direction: ExecutionDirection,
    cancel: &AtomicBool,
) -> io::Result<HevcDirectionProbe> {
    probe_hevc_direction_depth(config, direction, cancel, 8)
}
pub fn probe_hevc_direction_depth(
    config: VideoConfig,
    direction: ExecutionDirection,
    cancel: &AtomicBool,
    bit_depth: u8,
) -> io::Result<HevcDirectionProbe> {
    probe_hevc_direction_with_encoder(config, direction, cancel, bit_depth, crate::HevcEncoderBackend::SystemMf)
}
/// The original workload and acceptance with one explicitly selected encoder.
/// Decode remains the exact original MF hardware owner on the supplied device.
pub fn probe_hevc_direction_with_encoder(
    config: VideoConfig,
    direction: ExecutionDirection,
    cancel: &AtomicBool,
    bit_depth: u8,
    backend: crate::HevcEncoderBackend,
) -> io::Result<HevcDirectionProbe> {
    if !matches!(bit_depth, 8 | 10) {
        return Err(io::Error::other("unsupported HEVC probe depth"));
    }
    if bit_depth == 10 {
        HevcMain8Contract::validate_main10_config(config)?;
    } else {
        HevcMain8Contract::validate_config(config)?;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    check(cancel, deadline)?;
    let authority = Arc::new(AtomicBool::new(true));
    let source = HevcSyntheticSource::with_depth(config.width, config.height, bit_depth)?;
    let mut encoder = HevcProbeEncoder::new_with_backend(&source, config, authority.clone(), backend)?;
    let mut gpu =
        HevcProbeDecoder::with_depth(Some(&source), config, authority.clone(), bit_depth)?;
    let mut independent = HevcProbeDecoder::with_depth(None, config, authority.clone(), bit_depth)?;
    let result = (|| {
        let original_encoder = encoder.owner_observation()?;
        let original_decoder = gpu.owner_observation()?;
        let mut workload = Workload {
            config,
            bit_depth,
            contract: None,
            admission: None,
            expected: [VecDeque::new(), VecDeque::new()],
            decoded: [0; 2],
            outputs: 0,
        };
        let mut accepted = 0u64;
        while accepted < 32 {
            check(cancel, deadline)?;
            let pts = accepted * 90_000 / u64::from(config.fps);
            let (consumed, packet) = encoder.submit(&source, pts)?;
            accepted += u64::from(consumed);
            if let Some(packet) = packet {
                workload.feed(packet, [&mut gpu, &mut independent], cancel, deadline)?;
            }
            thread::sleep(Duration::from_millis(1));
        }
        // EOS is allowed to release tails, never to manufacture the first live output.
        if workload.outputs < 16 || workload.decoded.iter().any(|v| *v < 16) {
            return Err(io::Error::other(
                "HEVC direction lacks sixteen real outputs before EOS",
            ));
        }
        encoder.begin_drain()?;
        while encoder.pending_frames() != 0 || !encoder.backend()?.drain_complete {
            check(cancel, deadline)?;
            if let Some(packet) = encoder.poll()? {
                workload.feed(packet, [&mut gpu, &mut independent], cancel, deadline)?;
            }
            thread::sleep(Duration::from_millis(1));
        }
        gpu.begin_drain()?;
        independent.begin_drain()?;
        while gpu.pending_frames() != 0
            || independent.pending_frames() != 0
            || !gpu.backend()?.drain_complete
            || !independent.backend()?.drain_complete
        {
            check(cancel, deadline)?;
            for (index, decoder) in [&mut gpu, &mut independent].into_iter().enumerate() {
                if let Some((pixels, pts)) = decoder.poll()? {
                    picture(
                        pixels,
                        pts,
                        &mut workload.expected[index],
                        &mut workload.decoded[index],
                        config,
                    )?;
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        check(cancel, deadline)?;
        let encoded_owner = encoder.owner_observation()?;
        let decoded_owner = gpu.owner_observation()?;
        encoded_owner.require_hardware_identity()?;
        decoded_owner.require_hardware_identity()?;
        let software = independent.owner_observation()?;
        if !original_encoder.same_identity(encoded_owner)
            || !original_decoder.same_identity(decoded_owner)
            || encoded_owner.resource_id == decoded_owner.resource_id
            || encoded_owner.adapter_luid != decoded_owner.adapter_luid
            || encoded_owner.driver_version != decoded_owner.driver_version
            || software.hardware_output
            || software.adapter_luid.is_some()
            || software.driver_version.is_some()
            || !encoder.backend()?.gpu_input
            || !gpu.backend()?.d3d_manager
            || accepted != workload.outputs
            || workload.decoded != [workload.outputs; 2]
            || workload.expected.iter().any(|q| !q.is_empty())
            || encoder.poll()?.is_some()
            || gpu.poll()?.is_some()
            || independent.poll()?.is_some()
        {
            return Err(io::Error::other(
                "HEVC direction exact owner/backend/output accounting differs",
            ));
        }
        Ok(HevcDirectionProbe {
            encoder_backend: backend,
            encoder_runtime: encoder.runtime_version()?,
            contract: workload
                .contract
                .ok_or_else(|| io::Error::other("HEVC actual SPS absent"))?,
            direction,
            owner: match direction {
                ExecutionDirection::Encode => encoded_owner,
                ExecutionDirection::Decode => decoded_owner,
            },
            outputs: workload.outputs,
        })
    })();
    authority.store(false, Ordering::Release);
    let independent_close = independent.close();
    let gpu_close = gpu.close();
    let encoder_close = encoder.close();
    drop(source);
    independent_close.and(gpu_close).and(encoder_close)?;
    check(cancel, deadline)?;
    result
}
