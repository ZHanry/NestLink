#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nestlink_media_codec::{
        H264EncodingLimits, MfH264Decoder, MfH264Encoder, VideoConfig, probe_h264_encoder,
    };
    use std::{io, time::Instant};
    let args: Vec<_> = std::env::args().skip(1).collect();
    let width = args
        .first()
        .map_or(Ok(1280), |value| value.parse::<u32>())?;
    let height = args.get(1).map_or(Ok(720), |value| value.parse::<u32>())?;
    let frames = args.get(2).map_or(Ok(120), |value| value.parse::<u64>())?;
    let fps = args.get(3).map_or(Ok(30), |value| value.parse::<u32>())?;
    let bitrate_kbps = args.get(4).map_or(Ok(4000), |value| value.parse::<u32>())?;
    let config = VideoConfig {
        width,
        height,
        fps,
        bitrate_kbps,
    };
    let target_probe = probe_h264_encoder(
        config,
        Some(H264EncodingLimits {
            max_level_idc: 42,
            require_constrained_baseline: false,
        }),
    )?;
    println!(
        "target_probe width={width} height={height} fps={fps} bitrate_kbps={bitrate_kbps} actual_profile_level_id={} encoder_hardware_observed={} copy_path=cpu_bgra_nv12 performance_qualified=false browser_hardware_decode=unknown",
        target_probe.sps.profile_level_id(),
        target_probe.hardware
    );
    if !(12..=600).contains(&frames) {
        return Err(io::Error::other("probe requires 12-600 synthetic frames").into());
    }
    for hardware in [true, false] {
        let mut encoder = match MfH264Encoder::new(config, hardware) {
            Ok(encoder) => encoder,
            Err(error) => {
                println!(
                    "SKIP hardware_requested={hardware} encoder_creation=unavailable reason={error}"
                );
                continue;
            }
        };
        let mut decoder = match MfH264Decoder::new(width, height, hardware) {
            Ok(decoder) => decoder,
            Err(error) => {
                println!(
                    "SKIP hardware_requested={hardware} decoder_creation=unavailable reason={error}"
                );
                continue;
            }
        };
        let started = Instant::now();
        let mut encoded = 0;
        let mut decoded = 0;
        let mut encode_times = Vec::new();
        let mut decode_times = Vec::new();
        let mut reset_times = Vec::new();
        let pixels = [32, 160, 64, 255].repeat((width * height) as usize);
        for frame in 0..frames {
            let encoding = Instant::now();
            let packet = encoder.encode(
                &pixels,
                frame * 90_000 / u64::from(fps),
                frame.is_multiple_of(u64::from(fps)),
            )?;
            encode_times.push(encoding.elapsed().as_micros());
            if let Some(packet) = packet {
                encoded += 1;
                if encoded == 1 && !packet.keyframe {
                    return Err(io::Error::other("first encoded frame was not an IDR").into());
                }
                if encoded > 1 && packet.keyframe {
                    let resetting = Instant::now();
                    decoder.reset_for_keyframe()?;
                    reset_times.push(resetting.elapsed().as_micros());
                }
                let decoding = Instant::now();
                let result = decoder.decode(&packet.data, packet.pts_90khz)?;
                decode_times.push(decoding.elapsed().as_micros());
                if let Some(pixels) = result {
                    decoded += 1;
                    for pixel in pixels.chunks_exact(4).step_by(137) {
                        if (i32::from(pixel[0]) - 32).abs() > 18
                            || (i32::from(pixel[1]) - 160).abs() > 18
                            || (i32::from(pixel[2]) - 64).abs() > 18
                            || pixel[3] != 255
                        {
                            return Err(io::Error::other(
                                "decoded BT.709 color differs from synthetic source",
                            )
                            .into());
                        }
                    }
                }
            }
        }
        if decoded == 0 {
            return Err(io::Error::other("live codec resources produced no decoded frames").into());
        }
        encode_times.sort_unstable();
        decode_times.sort_unstable();
        reset_times.sort_unstable();
        let percentile =
            |times: &[u128], value: usize| times[(times.len() - 1) * value / 100] as f64 / 1000.0;
        println!(
            "encode_p50_ms={:.2} encode_p95_ms={:.2} decode_p50_ms={:.2} decode_p95_ms={:.2}",
            percentile(&encode_times, 50),
            percentile(&encode_times, 95),
            percentile(&decode_times, 50),
            percentile(&decode_times, 95)
        );
        if !reset_times.is_empty() {
            println!(
                "decoder_resets={} reset_p50_ms={:.2} reset_p95_ms={:.2}",
                reset_times.len(),
                percentile(&reset_times, 50),
                percentile(&reset_times, 95)
            );
        }
        println!(
            "actual_profile_level_id={}",
            encoder
                .sps_info()
                .ok_or_else(|| io::Error::other("missing actual SPS"))?
                .profile_level_id()
        );
        println!(
            "hardware_requested={hardware} encoder_hardware_observed={} decoder_hardware_observed={} encoded={encoded} decoded={decoded} width={width} height={height} elapsed_ms={} synthetic_pipeline_fps={:.1} copy_path=cpu_bgra_nv12",
            encoder.hardware(),
            decoder.hardware(),
            started.elapsed().as_millis(),
            decoded as f64 / started.elapsed().as_secs_f64()
        );
    }
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    println!("Media Foundation probe requires Windows");
}
