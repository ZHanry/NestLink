//! Synthetic-only diagnostic. Missing MFT/device/parser support exits failure;
//! never a capability success by SKIP. No desktop capture or product transport.
#[cfg(windows)]
fn complete_accounting(
    accepted: u64,
    outputs: u64,
    decoded: [u64; 2],
    pending: [usize; 3],
    expected: [usize; 2],
) -> std::io::Result<()> {
    if accepted < 16
        || outputs != accepted
        || decoded != [outputs, outputs]
        || pending != [0; 3]
        || expected != [0; 2]
    {
        return Err(std::io::Error::other(
            "HEVC finite diagnostic accounting incomplete",
        ));
    }
    Ok(())
}
#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn incomplete_encoder_or_decoder_tails_cannot_pass() {
        assert!(complete_accounting(60, 59, [59, 59], [1, 0, 0], [0, 0]).is_err());
        assert!(complete_accounting(60, 60, [60, 59], [0, 0, 1], [0, 1]).is_err());
        assert!(complete_accounting(60, 60, [60, 60], [0, 0, 0], [1, 0]).is_err());
        assert!(complete_accounting(60, 60, [60, 60], [0; 3], [0; 2]).is_ok());
    }
}
#[cfg(windows)]
fn run(authority: std::sync::Arc<std::sync::atomic::AtomicBool>) -> std::io::Result<()> {
    use nestlink_media_codec::{
        HevcProbeDecoder, HevcProbeEncoder, HevcSyntheticSource, VideoConfig,
    };
    use std::{
        collections::VecDeque,
        io,
        sync::atomic::Ordering,
        time::{Duration, Instant},
    };
    let config = VideoConfig {
        width: 640,
        height: 480,
        fps: 30,
        bitrate_kbps: 2000,
    };
    let source = HevcSyntheticSource::new(config.width, config.height)?;
    let mut encoder = HevcProbeEncoder::new(&source, config, authority.clone())?;
    let mut gpu = HevcProbeDecoder::new(Some(&source), config, authority.clone())?;
    let mut independent = HevcProbeDecoder::new(None, config, authority.clone())?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let (mut accepted, mut outputs) = (0u64, 0u64);
    let mut decoded = [0u64; 2];
    let mut expected = [VecDeque::new(), VecDeque::new()];
    fn picture(
        pixels: Vec<u8>,
        pts: u64,
        expected: &mut VecDeque<u64>,
        count: &mut u64,
    ) -> io::Result<()> {
        use zeroize::Zeroizing;
        let pixels = Zeroizing::new(pixels);
        if expected.pop_front() != Some(pts) || pixels.len() != 640 * 480 * 4 {
            return Err(io::Error::other("actual HEVC decode PTS/size mismatch"));
        }
        let colors = [
            [32i32, 96, 192, 255],
            [192, 96, 32, 255],
            [16, 16, 16, 255],
            [224, 224, 224, 255],
        ];
        for y in (8..472usize).step_by(17) {
            for x in (8..632usize).step_by(17) {
                if x.abs_diff(320) < 8 || y.abs_diff(240) < 8 {
                    continue;
                }
                let target = colors[usize::from(x >= 320) + 2 * usize::from(y >= 240)];
                let p = &pixels[(y * 640 + x) * 4..(y * 640 + x) * 4 + 4];
                if (0..3).any(|i| (i32::from(p[i]) - target[i]).abs() > 24) || p[3] != 255 {
                    return Err(io::Error::other(
                        "HEVC decoded BT709/range/quadrant colors differ",
                    ));
                }
            }
        }
        *count += 1;
        Ok(())
    }
    fn feed(
        packet: &nestlink_media_codec::HevcProbePacket,
        decoders: [&mut HevcProbeDecoder; 2],
        expected: &mut [VecDeque<u64>; 2],
        decoded: &mut [u64; 2],
        wall: Instant,
    ) -> io::Result<()> {
        for (index, decoder) in decoders.into_iter().enumerate() {
            let limit = std::cmp::min(wall, Instant::now() + Duration::from_secs(2));
            loop {
                let (consumed, image) = decoder.submit(packet)?;
                if consumed {
                    if expected[index].len() >= 16 {
                        return Err(io::Error::other("HEVC validation ledger full"));
                    }
                    expected[index].push_back(packet.pts_90khz);
                }
                if let Some((pixels, pts)) = image {
                    picture(pixels, pts, &mut expected[index], &mut decoded[index])?;
                }
                if consumed {
                    break;
                }
                if Instant::now() > limit {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "HEVC decoder input backpressure",
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }
    while accepted < 60 {
        if Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HEVC diagnostic wall deadline",
            ));
        }
        let pts = accepted * 3000; // Deliberately includes actual PTS zero.
        let (consumed, packet) = encoder.submit(&source, pts)?;
        accepted += u64::from(consumed);
        if let Some(packet) = packet {
            outputs += 1;
            feed(
                &packet,
                [&mut gpu, &mut independent],
                &mut expected,
                &mut decoded,
                deadline,
            )?;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // A positive live stream must already exist before EOS can release tails.
    let live_decoded = decoded;
    if outputs < 16 || live_decoded[0] < 16 || live_decoded[1] < 16 {
        return Err(io::Error::other(
            "HEVC live output evidence insufficient before EOS",
        ));
    }
    encoder.begin_drain()?;
    while encoder.pending_frames() != 0 || !encoder.backend()?.drain_complete {
        if Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HEVC encoder EOS drain incomplete",
            ));
        }
        if let Some(packet) = encoder.poll()? {
            outputs += 1;
            feed(
                &packet,
                [&mut gpu, &mut independent],
                &mut expected,
                &mut decoded,
                deadline,
            )?;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    gpu.begin_drain()?;
    independent.begin_drain()?;
    while gpu.pending_frames() != 0
        || independent.pending_frames() != 0
        || !gpu.backend()?.drain_complete
        || !independent.backend()?.drain_complete
    {
        if Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HEVC decoder EOS drain incomplete",
            ));
        }
        for (index, decoder) in [&mut gpu, &mut independent].into_iter().enumerate() {
            if let Some((pixels, pts)) = decoder.poll()? {
                picture(pixels, pts, &mut expected[index], &mut decoded[index])?;
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // DrainComplete plus an empty accepted ledger must not hide an extra
    // buffered output. The shared ledger rejects unbound/duplicate actual PTS.
    if encoder.poll()?.is_some() || gpu.poll()?.is_some() || independent.poll()?.is_some() {
        return Err(io::Error::other(
            "unexpected HEVC output after complete drain",
        ));
    }
    complete_accounting(
        accepted,
        outputs,
        decoded,
        [
            encoder.pending_frames(),
            gpu.pending_frames(),
            independent.pending_frames(),
        ],
        [expected[0].len(), expected[1].len()],
    )?;
    let enc = encoder.backend()?;
    let gpu_backend = gpu.backend()?;
    let cpu_backend = independent.backend()?;
    let profile = encoder
        .profile()
        .ok_or_else(|| io::Error::other("no actual HEVC SPS"))?;
    println!(
        "hevc_actual_profile={profile:?} encoder={enc:?} gpu_decoder={gpu_backend:?} independent_decoder={cpu_backend:?}"
    );
    if accepted < 16
        || outputs < 16
        || decoded[0] < 16
        || decoded[1] < 16
        || !enc.actual_hardware_output
        || !enc.gpu_input
        || !gpu_backend.actual_hardware_output
        || !gpu_backend.d3d_manager
        || cpu_backend.actual_hardware_output
        || enc.adapter_luid.is_none()
        || enc.adapter_luid != gpu_backend.adapter_luid
    {
        return Err(io::Error::other(
            "HEVC positive GPU output/independent decode evidence incomplete",
        ));
    }
    authority.store(false, Ordering::Release);
    if encoder.submit(&source, accepted * 3000).is_ok()
        || gpu.poll().is_ok()
        || independent.poll().is_ok()
    {
        return Err(io::Error::other("revoked HEVC owner returned media"));
    }
    independent.close()?;
    gpu.close()?;
    encoder.close()?;
    drop(source);
    println!(
        "HEVC_SYNTHETIC_PASS accepted={accepted} actual_outputs={outputs} gpu_decoded={} independent_software_decoded={} pending_encoder=0 pending_gpu_decoder=0 pending_independent_decoder=0 expected_pts_pending=0 eos_drained=true live_gpu_decoded_before_eos={} live_independent_decoded_before_eos={} actual_pts_and_colors_verified=true revoked_rejected=true cleanup_confirmed=true cpu_upload=true validation_readback=true screen_capture=false scanout_verified=false performance_qualified=false product_transport_wired=false",
        decoded[0], decoded[1], live_decoded[0], live_decoded[1]
    );
    Ok(())
}
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };
    let authority = Arc::new(AtomicBool::new(true));
    let owner_authority = authority.clone();
    let owner = std::thread::Builder::new()
        .name("nestlink-hevc-diagnostic-owner".into())
        .spawn(move || run(owner_authority))?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while !owner.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !owner.is_finished() {
        authority.store(false, Ordering::Release);
        // Retain one bounded join owner until process teardown. Never assert a
        // join or kill a driver thread; external process watchdog remains required.
        static PENDING: std::sync::OnceLock<
            std::sync::Mutex<Option<std::thread::JoinHandle<std::io::Result<()>>>>,
        > = std::sync::OnceLock::new();
        let _ = PENDING.set(std::sync::Mutex::new(Some(owner)));
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "HEVC worker pending; cleanup/join unconfirmed",
        )
        .into());
    }
    owner
        .join()
        .map_err(|_| std::io::Error::other("HEVC diagnostic owner panicked"))??;
    println!("HEVC_OWNER_JOINED=true");
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("HEVC diagnostic requires Windows MF/D3D11");
    std::process::exit(1);
}
