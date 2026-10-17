//! Local platform diagnostic only. No network, remote permit or raw audio files.
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nestlink_platform_audio::{
        WindowsAudioCapture, WindowsAudioEndpoint, WindowsAudioPlayback,
    };
    use nestlink_remote::audio::{
        AudioBinding, AudioCaptureDevice, AudioChunk, AudioDevice, AudioPlaybackDevice,
        CHUNK_FRAMES,
    };
    use std::{
        f64::consts::TAU,
        io, thread,
        time::{Duration, Instant},
    };
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("inventory");
    if !["inventory", "initialize", "roundtrip"].contains(&mode) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected inventory, initialize or roundtrip",
        )
        .into());
    }
    if mode == "roundtrip" && !args.iter().any(|a| a == "--allow-system-audio") {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "roundtrip reads the selected system playback mix and emits a test tone; requires --allow-system-audio").into());
    }
    let endpoints = WindowsAudioEndpoint::enumerate()?;
    if mode == "inventory" {
        if args.len() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "inventory takes no device or sound options",
            )
            .into());
        }
        let devices: Vec<_> = endpoints
            .iter()
            .map(|d| serde_json::json!({"name": d.name(), "id": d.device_id()}))
            .collect();
        println!(
            "{}",
            serde_json::json!({"scope":"local Windows render endpoint inventory", "product_acceptance":false, "audio_started":false, "endpoints":devices})
        );
        return Ok(());
    }
    let mut device_id = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--device" if device_id.is_none() => {
                index += 1;
                device_id = Some(
                    args.get(index)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "--device requires the exact local inventory ID",
                            )
                        })?
                        .clone(),
                );
            }
            "--allow-system-audio" if mode == "roundtrip" => {}
            _ => {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidInput, "unexpected probe option").into(),
                );
            }
        }
        index += 1;
    }
    let device_id = device_id.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "select a local render endpoint with --device ID",
        )
    })?;
    let endpoint = endpoints
        .into_iter()
        .find(|v| v.device_id() == device_id)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "selected endpoint is no longer active",
            )
        })?;
    let binding = AudioBinding {
        connection: 1,
        source: 1,
        channels: 2,
    }; // Local diagnostic, no remote identity.
    let mut capture = WindowsAudioCapture::open(endpoint.clone(), binding)?;
    let mut playback = WindowsAudioPlayback::open(endpoint.clone(), binding)?;
    if mode == "initialize" {
        capture.check()?;
        playback.check()?;
        capture.reset()?;
        playback.reset()?;
        println!(
            "{}",
            serde_json::json!({"scope":"WASAPI initialization and reset only", "product_acceptance":false, "audio_started":false, "sample_rate":48000, "channels":2, "endpoint":endpoint.name(), "passed":true})
        );
        return Ok(());
    }
    let start = Instant::now();
    let mut next = start;
    let mut pts = 0;
    let mut chunks = 0;
    let mut totals = [0u64; 2];
    let mut squares = [0.0; 2];
    let mut correlations = [[0.0; 2]; 2];
    let mut last = None;
    while start.elapsed() < Duration::from_secs(2) {
        if Instant::now() >= next {
            let samples: Vec<i16> = (0..CHUNK_FRAMES)
                .flat_map(|frame| {
                    [440.0, 880.0].map(|frequency| {
                        ((TAU * frequency * ((pts + frame as u64) as f64) / 48_000.0).sin()
                            * 6000.0) as i16
                    })
                })
                .collect();
            playback.enqueue(&AudioChunk {
                source: binding.source,
                channels: 2,
                pts_48khz: pts,
                samples,
            })?;
            pts += CHUNK_FRAMES as u64;
            next = next
                .checked_add(Duration::from_millis(20))
                .ok_or_else(|| io::Error::other("probe clock overflow"))?;
        }
        while let Some(packet) = capture.poll_chunk()? {
            packet.chunk.validate(binding)?;
            if last.is_some_and(|v| packet.chunk.pts_48khz <= v) {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidData, "captured clock regressed").into(),
                );
            }
            last = Some(packet.chunk.pts_48khz);
            chunks += 1;
            for (frame, values) in packet.chunk.samples.chunks_exact(2).enumerate() {
                for channel in 0..2 {
                    let value = f64::from(values[channel]);
                    let phase = TAU
                        * [440.0, 880.0][channel]
                        * ((packet.chunk.pts_48khz + frame as u64) as f64)
                        / 48_000.0;
                    totals[channel] += 1;
                    squares[channel] += value * value;
                    correlations[channel][0] += value * phase.sin();
                    correlations[channel][1] += value * phase.cos();
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    capture.reset()?;
    playback.reset()?;
    let stopped = capture.poll_chunk().is_err()
        && playback
            .enqueue(&AudioChunk {
                source: 1,
                channels: 2,
                pts_48khz: pts,
                samples: vec![0; CHUNK_FRAMES * 2],
            })
            .is_err();
    let rms = [0, 1].map(|ch| (squares[ch] / totals[ch].max(1) as f64).sqrt());
    let tones = [0, 1]
        .map(|ch| 2.0 * correlations[ch][0].hypot(correlations[ch][1]) / totals[ch].max(1) as f64);
    let passed = stopped && chunks >= 25 && tones.iter().all(|v| *v >= 500.0);
    println!(
        "{}",
        serde_json::json!({"scope":"local synthetic tone to selected WASAPI mix, no raw samples retained", "product_acceptance":false, "audio_started":true, "endpoint":endpoint.name(), "sample_rate":48000, "channels":2, "captured_chunks":chunks, "rms":rms, "detected_tone_amplitudes":tones, "stop_rejects_old_device":stopped, "passed":passed})
    );
    if !passed {
        return Err(io::Error::other(
            "selected endpoint did not pass the local tone/clock/stop probe",
        )
        .into());
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("PLATFORM_UNSUPPORTED: this local probe requires Windows WASAPI");
    std::process::exit(2);
}
