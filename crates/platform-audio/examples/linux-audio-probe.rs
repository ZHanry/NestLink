//! Local diagnostic. Inventory/initialize do not arm PCM; no raw samples saved.
#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use nestlink_platform_audio::{LinuxAudioCapture, LinuxAudioEndpoint, LinuxAudioPlayback};
    use nestlink_platform_session::LinuxDesktopSession;
    use nestlink_remote::audio::{
        AudioBinding, AudioCaptureDevice, AudioChunk, AudioDevice, AudioPlaybackDevice,
        CHUNK_FRAMES,
    };
    use std::{
        f64::consts::TAU,
        io,
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };
    let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("inventory");
    if !["inventory", "initialize", "roundtrip"].contains(&mode) {
        return Err(invalid("expected inventory, initialize or roundtrip").into());
    }
    let mut kind = std::env::var("XDG_SESSION_TYPE").unwrap_or_default();
    let mut pid = std::process::id();
    let mut selected = None;
    let mut serial = None;
    let mut channels = 2;
    let mut allow_audio = false;
    let mut seen = std::collections::HashSet::new();
    let mut index = 1;
    while index < args.len() {
        let option = &args[index];
        if !seen.insert(option) {
            return Err(invalid("duplicate probe option").into());
        }
        if option == "--allow-system-audio" && mode == "roundtrip" {
            allow_audio = true;
        } else {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| invalid("probe option needs a value"))?;
            match option.as_str() {
                "--session" if ["x11", "wayland"].contains(&value.as_str()) => kind = value.clone(),
                "--gui-pid" => pid = value.parse()?,
                "--device" if mode != "inventory" => selected = Some(value.clone()),
                "--serial" if mode != "inventory" => serial = Some(value.parse::<u64>()?),
                "--channels" if mode != "inventory" && ["1", "2"].contains(&value.as_str()) => {
                    channels = value.parse()?
                }
                _ => return Err(invalid("unexpected probe option or value").into()),
            }
        }
        index += 1;
    }
    if mode == "roundtrip" && !allow_audio {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "roundtrip reads the selected system playback mix and emits a tone; requires --allow-system-audio").into());
    }
    let desktop = Arc::new(match kind.as_str() {
        "x11" => LinuxDesktopSession::open(pid, &std::env::var("DISPLAY")?)?,
        "wayland" => LinuxDesktopSession::open_wayland(pid)?,
        _ => return Err(invalid("a real local x11/wayland GUI session is required").into()),
    });
    let endpoints = LinuxAudioEndpoint::enumerate(desktop)?;
    if mode == "inventory" {
        let devices: Vec<_> = endpoints.iter().map(|v| serde_json::json!({"name":v.name(), "description":v.description(), "serial":v.serial()})).collect();
        println!(
            "{}",
            serde_json::json!({"scope":"local PipeWire output inventory", "product_acceptance":false, "audio_started":false, "session":kind, "endpoints":devices})
        );
        return Ok(());
    }
    let selected =
        selected.ok_or_else(|| invalid("--device requires the exact local node name"))?;
    let serial =
        serial.ok_or_else(|| invalid("--serial requires its original inventory serial"))?;
    let endpoint = endpoints
        .into_iter()
        .find(|v| v.name() == selected && v.serial() == serial)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "selected output is no longer current",
            )
        })?;
    let binding = AudioBinding {
        source: 1,
        connection: 1,
        channels,
    }; // local diagnostic
    let mut capture = LinuxAudioCapture::open(endpoint.clone(), binding)?;
    let mut playback = LinuxAudioPlayback::open(endpoint.clone(), binding)?;
    if mode == "initialize" {
        capture.check()?;
        playback.check()?;
        capture.reset()?;
        playback.reset()?;
        println!(
            "{}",
            serde_json::json!({"scope":"inactive PipeWire link initialization/reset only", "product_acceptance":false, "audio_started":false, "sample_rate":48000, "channels":channels, "passed":true})
        );
        return Ok(());
    }
    let start = Instant::now();
    let mut next = start;
    let mut pts = 0;
    let mut chunks = 0;
    let mut frames = 0;
    let mut correlation = [[0.0f64; 2]; 2];
    let mut last = None;
    while start.elapsed() < Duration::from_secs(2) {
        if Instant::now() >= next {
            playback.enqueue(&AudioChunk {
                source: binding.source,
                channels,
                pts_48khz: pts,
                samples: (0..CHUNK_FRAMES)
                    .flat_map(|i| {
                        (0..channels).map(move |channel| {
                            (6000.0
                                * (TAU
                                    * [440.0, 880.0][usize::from(channel)]
                                    * (pts + i as u64) as f64
                                    / 48000.0)
                                    .sin()) as i16
                        })
                    })
                    .collect(),
            })?;
            pts += CHUNK_FRAMES as u64;
            next += Duration::from_millis(20);
        }
        while let Some(packet) = capture.poll_chunk()? {
            packet.chunk.validate(binding)?;
            if last.is_some_and(|pts| packet.chunk.pts_48khz <= pts) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "captured sample clock regressed",
                )
                .into());
            }
            last = Some(packet.chunk.pts_48khz);
            chunks += 1;
            frames += CHUNK_FRAMES;
            for (i, samples) in packet
                .chunk
                .samples
                .chunks_exact(usize::from(channels))
                .enumerate()
            {
                for (channel, sample) in samples.iter().enumerate() {
                    let phase =
                        TAU * [440.0, 880.0][channel] * (packet.chunk.pts_48khz + i as u64) as f64
                            / 48000.0;
                    correlation[channel][0] += f64::from(*sample) * phase.sin();
                    correlation[channel][1] += f64::from(*sample) * phase.cos();
                }
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
    capture.reset()?;
    playback.reset()?;
    let stop_rejected = capture.poll_chunk().is_err()
        && playback
            .enqueue(&AudioChunk {
                source: 1,
                channels,
                pts_48khz: pts,
                samples: vec![0; CHUNK_FRAMES * usize::from(channels)],
            })
            .is_err();
    let tones: Vec<_> = (0..usize::from(channels))
        .map(|ch| 2.0 * correlation[ch][0].hypot(correlation[ch][1]) / frames.max(1) as f64)
        .collect();
    let passed = stop_rejected && chunks >= 25 && tones.iter().all(|v| *v >= 500.0);
    println!(
        "{}",
        serde_json::json!({"scope":"local synthetic tone to selected PipeWire output; aggregate metrics only", "product_acceptance":false, "audio_started":true, "sample_rate":48000, "channels":channels, "captured_chunks":chunks, "detected_tone_amplitudes":tones, "stop_rejects_old_device":stop_rejected, "passed":passed})
    );
    if !passed {
        return Err(io::Error::other("selected output failed tone/clock/stop probe").into());
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("PLATFORM_UNSUPPORTED: this local probe requires Linux PipeWire and logind");
    std::process::exit(2);
}
