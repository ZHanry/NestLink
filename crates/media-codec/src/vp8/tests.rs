use super::*;

fn config(width: u32, height: u32) -> VideoConfig {
    VideoConfig {
        width,
        height,
        fps: 30,
        bitrate_kbps: 2000,
    }
}
fn pattern(width: u32, height: u32, phase: u8) -> Vec<u8> {
    let mut pixels = Vec::new();
    for y in 0..height {
        for x in 0..width {
            pixels.extend_from_slice(&[
                (x * 150 / width) as u8 + phase,
                (y * 180 / height) as u8,
                ((x + y) * 170 / (width + height)) as u8,
                255,
            ]);
        }
    }
    pixels
}
fn psnr(original: &[u8], decoded: &[u8]) -> f64 {
    let squared: f64 = original
        .chunks_exact(4)
        .zip(decoded.chunks_exact(4))
        .flat_map(|(a, b)| {
            (0..3).map(move |index| (f64::from(a[index]) - f64::from(b[index])).powi(2))
        })
        .sum();
    let mse = squared / (original.len() / 4 * 3) as f64;
    10.0 * (255.0_f64.powi(2) / mse.max(f64::EPSILON)).log10()
}

#[test]
fn bt601_limited_matrix_and_odd_chroma_edges_have_known_values() -> io::Result<()> {
    let red = [0, 0, 255, 37];
    let blue = [255, 0, 0, 53];
    let green = [0, 255, 0, 71];
    let white = [255, 255, 255, 0];
    let input: Vec<_> = [red, red, blue, red, red, blue, green, green, white]
        .into_iter()
        .flatten()
        .collect();
    let encoded = bgra_to_i420(3, 3, &input)?;
    assert_eq!(
        encoded,
        [
            82, 82, 41, 82, 82, 41, 144, 144, 235, 90, 240, 54, 128, 240, 110, 34, 128
        ]
    );
    let output = i420_to_bgra(3, 3, &encoded)?;
    assert!(output.chunks_exact(4).all(|p| p[3] == 255));
    assert!(psnr(&input, &output) > 43.0);
    assert_eq!(bgra_to_i420(1, 1, &[0, 0, 0, 0])?, [16, 128, 128]);
    assert_eq!(bgra_to_i420(1, 1, &white)?, [235, 128, 128]);
    assert_eq!(i420_to_bgra(1, 1, &[16, 128, 128])?, [0, 0, 0, 255]);
    assert_eq!(i420_to_bgra(1, 1, &[235, 128, 128])?, [255, 255, 255, 255]);
    assert!(bgra_to_i420(3, 3, &input[..35]).is_err());
    assert!(i420_to_bgra(3, 3, &encoded[..16]).is_err());
    Ok(())
}

#[test]
fn real_vp8_roundtrip_keyframes_deltas_odd_sizes_and_color_quality() -> io::Result<()> {
    for (width, height) in [(64, 48), (17, 19), (1, 1)] {
        let mut encoder = Vp8Encoder::new(config(width, height))?;
        let mut decoder = Vp8Decoder::new(width, height)?;
        let mut saw_delta = false;
        for index in 0..8 {
            let input = pattern(width, height, index as u8);
            let forced = index == 5;
            let encoded = encoder.encode(&input, index * 3000, forced)?;
            assert_eq!(encoded.pts_90khz, index * 3000);
            assert!(!encoded.data.is_empty() && encoded.data.len() <= PACKET_BYTES);
            assert_eq!(encoded.keyframe, encoded.data[0] & 1 == 0);
            assert_ne!(
                encoded.data[0] & 0x10,
                0,
                "hidden frames are outside the baseline"
            );
            if index == 0 || forced {
                assert!(encoded.keyframe);
            }
            saw_delta |= !encoded.keyframe;
            let output = decoder.decode(&encoded.data)?;
            assert_eq!(output.len(), input.len());
            assert!(output.chunks_exact(4).all(|p| p[3] == 255));
            assert!(
                psnr(&input, &output) > 28.0,
                "{width}x{height} frame {index} PSNR={}",
                psnr(&input, &output)
            );
            if forced {
                let mut fresh = Vp8Decoder::new(width, height)?;
                let independently_started = fresh.decode(&encoded.data)?;
                assert_eq!(independently_started, output);
            }
        }
        assert!(saw_delta, "fixture must exercise interframe references");
    }
    Ok(())
}

#[test]
fn live_bitrate_changes_preserve_decoding_references_and_timestamp_history() -> io::Result<()> {
    let mut encoder = Vp8Encoder::new(config(64, 48))?;
    let mut decoder = Vp8Decoder::new(64, 48)?;
    let mut previous = None;
    for (index, bitrate) in [2000, 64, 64, 100_000, 250, 2000].into_iter().enumerate() {
        encoder.set_bitrate(bitrate)?;
        let pts = 90_000 + index as u64 * 3_000;
        let input = pattern(64, 48, index as u8);
        let frame = encoder.encode(&input, pts, index == 4)?;
        assert_eq!(frame.pts_90khz, pts);
        if index == 0 || index == 4 {
            assert!(frame.keyframe);
        }
        assert_eq!(decoder.decode(&frame.data)?.len(), input.len());
        assert!(encoder.encode(&input, pts, false).is_err());
        previous = Some((pts, input));
        for invalid in [0, 63, 100_001, u32::MAX] {
            assert!(encoder.set_bitrate(invalid).is_err());
            assert_eq!(encoder.config.bitrate_kbps, bitrate);
        }
    }
    let (pts, input) = previous.ok_or_else(|| io::Error::other("no codec frames"))?;
    let frame = encoder.encode(&input, pts + 3_000, false)?;
    assert_eq!(decoder.decode(&frame.data)?.len(), input.len());
    Ok(())
}

#[test]
fn timestamp_input_bounds_and_failed_decoder_do_not_leak_partial_frames() -> io::Result<()> {
    for (width, height) in [
        (0, 1),
        (1, 0),
        (8193, 1),
        (8192, 8192),
        (u32::MAX, u32::MAX),
    ] {
        assert!(Vp8Encoder::new(config(width, height)).is_err());
        assert!(Vp8Decoder::new(width, height).is_err());
    }
    for (fps, bitrate) in [(0, 2000), (121, 2000), (30, 0), (30, 100001)] {
        let mut settings = config(32, 24);
        settings.fps = fps;
        settings.bitrate_kbps = bitrate;
        assert!(Vp8Encoder::new(settings).is_err());
    }
    let input = pattern(32, 24, 0);
    let mut encoder = Vp8Encoder::new(config(32, 24))?;
    assert!(encoder.encode(&input[..input.len() - 1], 0, false).is_err());
    let keyframe = encoder.encode(&input, 0, false)?;
    assert!(encoder.encode(&input, 0, false).is_err());
    assert!(encoder.encode(&input, u64::MAX, false).is_err());
    let delta = encoder.encode(&input, 3000, false)?;
    assert!(!delta.keyframe);
    assert!(encoder.encode(&input, 2999, false).is_err());
    assert_eq!(
        encoder.encode(&input, i64::MAX as u64, true)?.pts_90khz,
        i64::MAX as u64
    );
    let mut needs_keyframe = Vp8Decoder::new(32, 24)?;
    assert!(needs_keyframe.decode(&delta.data).is_err());
    assert!(
        needs_keyframe.decode(&keyframe.data).is_err(),
        "failed decoder must be replaced"
    );
    for bad in [
        &[][..],
        &[0x10][..],
        &keyframe.data[..9],
        &keyframe.data[..keyframe.data.len() / 2],
    ] {
        assert!(Vp8Decoder::new(32, 24)?.decode(bad).is_err());
    }
    let mut wrong_size = keyframe.data.clone();
    wrong_size[6] = 33;
    let mut corrupt_sync = keyframe.data.clone();
    corrupt_sync[3] ^= 1;
    let mut scaled = keyframe.data.clone();
    scaled[7] |= 0x40;
    let oversized_geometry = vec![0x10, 0, 0, 0x9d, 1, 0x2a, 0, 32, 0, 32];
    for bad in [
        wrong_size,
        corrupt_sync,
        scaled,
        oversized_geometry,
        vec![0; PACKET_BYTES + 1],
    ] {
        assert!(Vp8Decoder::new(32, 24)?.decode(&bad).is_err());
    }
    assert!(Vp8Decoder::new(33, 24)?.decode(&keyframe.data).is_err());
    Ok(())
}

#[test]
fn codec_contexts_can_move_to_their_own_worker() -> io::Result<()> {
    let encoder = Vp8Encoder::new(config(32, 24))?;
    let decoder = Vp8Decoder::new(32, 24)?;
    std::thread::spawn(move || {
        let (mut encoder, mut decoder) = (encoder, decoder);
        let input = pattern(32, 24, 0);
        let frame = encoder.encode(&input, 0, true)?;
        let output = decoder.decode(&frame.data)?;
        assert!(psnr(&input, &output) > 28.0);
        Ok::<_, io::Error>(())
    })
    .join()
    .map_err(|_| io::Error::other("owned codec worker panicked"))??;
    Ok(())
}

#[test]
fn external_pts_extremes_and_irregular_gaps_preserve_metadata() -> io::Result<()> {
    let input = pattern(32, 24, 0);
    for fps in [1, 29, 120] {
        for timestamps in [
            [0, 1, i64::MAX as u64 - 1, i64::MAX as u64],
            [
                i64::MAX as u64 - 3,
                i64::MAX as u64 - 2,
                i64::MAX as u64 - 1,
                i64::MAX as u64,
            ],
        ] {
            let mut settings = config(32, 24);
            settings.fps = fps;
            let mut encoder = Vp8Encoder::new(settings)?;
            let mut decoder = Vp8Decoder::new(32, 24)?;
            for pts in timestamps {
                let frame = encoder.encode(&input, pts, false)?;
                assert_eq!(frame.pts_90khz, pts);
                assert!(psnr(&input, &decoder.decode(&frame.data)?) > 28.0);
            }
        }
    }
    Ok(())
}

#[test]
fn truncated_partitions_and_corrupt_frame_headers_are_rejected() -> io::Result<()> {
    let input = pattern(32, 24, 0);
    let mut encoder = Vp8Encoder::new(config(32, 24))?;
    let encoded = encoder.encode(&input, 0, false)?;
    let frame = &encoded.data;
    let first_partition =
        (usize::from(frame[0]) | usize::from(frame[1]) << 8 | usize::from(frame[2]) << 16) >> 5;
    assert!(first_partition > 0 && first_partition + 10 < frame.len());
    for length in 0..first_partition + 10 {
        assert!(Vp8Decoder::new(32, 24)?.decode(&frame[..length]).is_err());
    }
    for header in [[0x10, 0, 0], [0xf0, 0xff, 0xff], [0xfe, 0xff, 0xff]] {
        let mut invalid = frame.clone();
        invalid[..3].copy_from_slice(&header);
        assert!(Vp8Decoder::new(32, 24)?.decode(&invalid).is_err());
    }
    Ok(())
}
