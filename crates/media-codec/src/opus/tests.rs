//! Real upstream codec tests using only owned, synthesized PCM.
use super::*;
use std::f64::consts::TAU;

fn sine(channels: u8, first_frame: usize, frames: usize) -> Vec<i16> {
    (first_frame..first_frame + frames)
        .flat_map(|index| {
            (0..channels).map(move |channel| {
                let frequency = if channel == 0 { 400.0 } else { 800.0 };
                (10_000.0 * (TAU * frequency * index as f64 / f64::from(OPUS_SAMPLE_RATE)).sin())
                    as i16
            })
        })
        .collect()
}
fn rms(samples: &[i16]) -> f64 {
    (samples.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / samples.len() as f64).sqrt()
}
fn amplitude(samples: &[i16], frequency: f64) -> f64 {
    let (sin, cos) = samples
        .iter()
        .enumerate()
        .fold((0.0, 0.0), |(sin, cos), (i, s)| {
            let phase = TAU * frequency * i as f64 / f64::from(OPUS_SAMPLE_RATE);
            (
                sin + f64::from(*s) * phase.sin(),
                cos + f64::from(*s) * phase.cos(),
            )
        });
    2.0 * sin.hypot(cos) / samples.len() as f64
}

#[test]
fn real_mono_and_stereo_preserve_length_volume_and_distinct_tones() -> io::Result<()> {
    for channels in [1, 2] {
        let config = OpusConfig {
            channels,
            bitrate: 96_000,
        };
        let mut encoder = OpusEncoder::new(config)?;
        let mut decoder = OpusDecoder::new(channels)?;
        assert_eq!(encoder.config(), config);
        assert_eq!(decoder.channels(), channels);
        let mut decoded = Vec::new();
        for index in 0..30 {
            let pcm = sine(
                channels,
                index * OPUS_SAMPLES_PER_CHANNEL,
                OPUS_SAMPLES_PER_CHANNEL,
            );
            let packet = encoder.encode(&pcm)?;
            assert!(!packet.is_empty() && packet.len() <= OPUS_MAX_PACKET_BYTES);
            let output = decoder.decode(&packet)?;
            assert_eq!(output.len(), pcm.len());
            // Discard the codec's initial lookahead when evaluating steady tones.
            if index >= 2 {
                decoded.extend(output);
            }
        }
        for channel in 0..channels {
            let pcm: Vec<_> = decoded
                .iter()
                .skip(usize::from(channel))
                .step_by(usize::from(channels))
                .copied()
                .collect();
            let frequency = if channel == 0 { 400.0 } else { 800.0 };
            let other = if channel == 0 { 800.0 } else { 400.0 };
            assert!(
                (5_000.0..=9_000.0).contains(&rms(&pcm)),
                "volume changed: {}",
                rms(&pcm)
            );
            assert!(
                (7_000.0..=12_000.0).contains(&amplitude(&pcm, frequency)),
                "intended tone missing"
            );
            assert!(
                amplitude(&pcm, other) < 2_000.0,
                "stereo channels were mixed or swapped"
            );
        }
    }
    Ok(())
}

#[test]
fn configuration_and_pcm_budgets_are_enforced_and_bitrate_edges_work() -> io::Result<()> {
    for channels in [0, 3, 255] {
        assert!(
            OpusEncoder::new(OpusConfig {
                channels,
                bitrate: 64_000
            })
            .is_err()
        );
        assert!(OpusDecoder::new(channels).is_err());
    }
    for bitrate in [0, 5999, 256001, u32::MAX] {
        assert!(
            OpusEncoder::new(OpusConfig {
                channels: 1,
                bitrate
            })
            .is_err()
        );
    }
    for channels in [1, 2] {
        for bitrate in [6_000, 256_000] {
            let mut encoder = OpusEncoder::new(OpusConfig { channels, bitrate })?;
            let mut decoder = OpusDecoder::new(channels)?;
            let samples = OPUS_SAMPLES_PER_CHANNEL * usize::from(channels);
            for count in [0, samples - 1, samples + 1, samples * 2] {
                assert_eq!(
                    encoder.encode(&vec![0; count]).err().map(|e| e.kind()),
                    Some(io::ErrorKind::InvalidInput)
                );
            }
            let packet = encoder.encode(&sine(channels, 0, OPUS_SAMPLES_PER_CHANNEL))?;
            assert_eq!(decoder.decode(&packet)?.len(), samples);
        }
    }
    Ok(())
}

#[test]
fn reset_removes_history_and_plc_is_an_explicit_single_interval() -> io::Result<()> {
    for channels in [1, 2] {
        let mut encoder = OpusEncoder::new(OpusConfig {
            channels,
            bitrate: 96_000,
        })?;
        let mut decoder = OpusDecoder::new(channels)?;
        let before_stream = decoder.conceal_loss()?;
        assert_eq!(
            before_stream.len(),
            OPUS_SAMPLES_PER_CHANNEL * usize::from(channels)
        );
        assert!(before_stream.iter().all(|s| *s == 0));
        decoder.reset()?;
        let pcm = sine(channels, 0, OPUS_SAMPLES_PER_CHANNEL);
        let first_packet = encoder.encode(&pcm)?;
        let first_decode = decoder.decode(&first_packet)?;
        for frame in 1..5 {
            let packet = encoder.encode(&sine(
                channels,
                frame * OPUS_SAMPLES_PER_CHANNEL,
                OPUS_SAMPLES_PER_CHANNEL,
            ))?;
            decoder.decode(&packet)?;
        }
        let concealed = decoder.conceal_loss()?;
        assert_eq!(concealed.len(), pcm.len());
        assert!(
            concealed.iter().any(|s| *s != 0),
            "PLC ignored actual decoder history"
        );
        assert!(
            decoder.decode(&[]).is_err(),
            "empty payload must not request PLC"
        );
        encoder.reset()?;
        decoder.reset()?;
        let replay = encoder.encode(&pcm)?;
        assert_eq!(
            replay, first_packet,
            "encoder reset retained the old stream history"
        );
        assert_eq!(
            decoder.decode(&replay)?,
            first_decode,
            "decoder reset retained the old stream history"
        );
        decoder.reset()?;
        assert!(decoder.conceal_loss()?.iter().all(|s| *s == 0));
    }
    Ok(())
}

#[test]
fn rejected_framing_and_wrong_channels_do_not_mutate_decoder_history() -> io::Result<()> {
    let mut mono = OpusEncoder::new(OpusConfig {
        channels: 1,
        bitrate: 64_000,
    })?;
    let mut stereo = OpusEncoder::new(OpusConfig {
        channels: 2,
        bitrate: 96_000,
    })?;
    let mono_packet = mono.encode(&sine(1, 0, OPUS_SAMPLES_PER_CHANNEL))?;
    let stereo_packet = stereo.encode(&sine(2, 0, OPUS_SAMPLES_PER_CHANNEL))?;
    for (channels, valid, wrong) in [
        (1, &mono_packet, &stereo_packet),
        (2, &stereo_packet, &mono_packet),
    ] {
        let mut baseline = OpusDecoder::new(channels)?;
        let mut decoder = OpusDecoder::new(channels)?;
        assert_eq!(baseline.decode(valid)?, decoder.decode(valid)?);
        decoder.validate_packet(valid)?;
        for malformed in [
            &[][..],
            &[3][..],
            &[0xf8][..], // 20 ms mono TOC with no coded frame: implicit PLC.
            &[0xfc][..], // Equivalent empty stereo frame.
            &[255, 255][..],
            &[255, 0][..],
            wrong.as_slice(),
            &vec![0; OPUS_MAX_PACKET_BYTES + 1],
        ] {
            assert_eq!(
                decoder.validate_packet(malformed).err().map(|e| e.kind()),
                Some(io::ErrorKind::InvalidData)
            );
            assert_eq!(
                decoder.decode(malformed).err().map(|e| e.kind()),
                Some(io::ErrorKind::InvalidData)
            );
        }
        assert_eq!(
            baseline.decode(valid)?,
            decoder.decode(valid)?,
            "rejected packet mutated decoder state"
        );
    }
    Ok(())
}

#[test]
fn full_budget_entropy_payloads_stay_bounded_and_reset_recovers() -> io::Result<()> {
    for channels in [1, 2] {
        let mut decoder = OpusDecoder::new(channels)?;
        let mut decoded = 0;
        for bytes in [2, 3, 31, 255, 1274, OPUS_MAX_PACKET_BYTES] {
            for seed in 0..16u32 {
                let mut state = seed + 1;
                let mut packet: Vec<_> = (0..bytes)
                    .map(|_| {
                        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                        (state >> 24) as u8
                    })
                    .collect();
                // CELT fullband, 20 ms, one nonempty coded frame. This passes
                // framing checks and actually exercises upstream entropy decode.
                packet[0] = if channels == 1 { 0xf8 } else { 0xfc };
                if let Ok(pcm) = decoder.decode(&packet) {
                    decoded += 1;
                    assert_eq!(pcm.len(), OPUS_SAMPLES_PER_CHANNEL * usize::from(channels));
                }
            }
        }
        assert!(decoded > 0, "corpus never reached actual upstream decoding");
        // Upstream entropy errors are not promised to preserve history. A
        // caller discontinuity/reset must give the same state as a fresh stream.
        decoder.reset()?;
        let mut fresh = OpusDecoder::new(channels)?;
        let mut encoder = OpusEncoder::new(OpusConfig {
            channels,
            bitrate: 96_000,
        })?;
        let packet = encoder.encode(&sine(channels, 0, OPUS_SAMPLES_PER_CHANNEL))?;
        assert_eq!(decoder.decode(&packet)?, fresh.decode(&packet)?);
    }
    Ok(())
}

// Direct public upstream APIs construct otherwise-valid durations that the
// production wrapper must reject. No production test seam weakens its contract.
unsafe extern "C" {
    fn opus_get_version_string() -> *const std::ffi::c_char;
    fn opus_encoder_create(
        rate: i32,
        channels: i32,
        application: i32,
        error: *mut i32,
    ) -> *mut c_void;
    fn opus_encoder_destroy(encoder: *mut c_void);
    fn opus_encode(
        encoder: *mut c_void,
        pcm: *const i16,
        frames: i32,
        packet: *mut u8,
        capacity: i32,
    ) -> i32;
    fn opus_packet_get_nb_samples(packet: *const u8, len: i32, rate: i32) -> i32;
    fn opus_repacketizer_create() -> *mut c_void;
    fn opus_repacketizer_destroy(repacketizer: *mut c_void);
    fn opus_repacketizer_cat(repacketizer: *mut c_void, packet: *const u8, len: i32) -> i32;
    fn opus_repacketizer_out(repacketizer: *mut c_void, packet: *mut u8, capacity: i32) -> i32;
}

#[test]
fn runtime_library_is_the_pinned_upstream_version() -> io::Result<()> {
    // SAFETY: official API returns a static, NUL-terminated version string.
    let pointer = unsafe { opus_get_version_string() };
    assert!(!pointer.is_null());
    // SAFETY: the checked, static upstream string remains live for this process.
    let version = unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_str()
        .map_err(io::Error::other)?;
    assert_eq!(version, "libopus 1.6.1");
    Ok(())
}
struct UpstreamEncoder(NonNull<c_void>);
impl UpstreamEncoder {
    fn new() -> io::Result<Self> {
        let mut code = 0;
        // SAFETY: scalar upstream config, valid error out pointer. 2049 is the
        // documented OPUS_APPLICATION_AUDIO constant from opus_defines.h.
        let pointer = unsafe { opus_encoder_create(48_000, 1, 2049, &mut code) };
        NonNull::new(pointer)
            .map(Self)
            .ok_or_else(|| error("fixture encoder", code))
    }
    fn encode(&mut self, frames: usize) -> io::Result<Vec<u8>> {
        // Silence keeps the repacketized 120 ms fixture under the independent
        // byte budget, isolating duration validation from bitrate/packet size.
        let pcm = vec![0; frames];
        let mut packet = vec![0; OPUS_MAX_PACKET_BYTES];
        // SAFETY: live exclusive fixture state and the full declared buffers.
        let bytes = unsafe {
            opus_encode(
                self.0.as_ptr(),
                pcm.as_ptr(),
                frames as i32,
                packet.as_mut_ptr(),
                packet.len() as i32,
            )
        };
        if bytes < 0 {
            return Err(error("fixture encoding", bytes));
        }
        assert!(bytes > 0 && bytes as usize <= packet.len());
        packet.truncate(bytes as usize);
        Ok(packet)
    }
}
impl Drop for UpstreamEncoder {
    fn drop(&mut self) {
        // SAFETY: unique owned fixture encoder.
        unsafe { opus_encoder_destroy(self.0.as_ptr()) };
    }
}
struct Repacketizer(NonNull<c_void>);
impl Drop for Repacketizer {
    fn drop(&mut self) {
        // SAFETY: unique owned fixture repacketizer.
        unsafe { opus_repacketizer_destroy(self.0.as_ptr()) };
    }
}

#[test]
fn actual_short_long_and_120ms_packets_are_rejected_before_decode() -> io::Result<()> {
    let mut decoder = OpusDecoder::new(1)?;
    for samples in [480, 1920, 2880] {
        let mut raw = UpstreamEncoder::new()?;
        let packet = raw.encode(samples)?;
        // SAFETY: nonempty fixture packet, bounded exact size.
        assert_eq!(
            unsafe { opus_packet_get_nb_samples(packet.as_ptr(), packet.len() as i32, 48_000) },
            samples as i32
        );
        assert_eq!(
            decoder.decode(&packet).err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidData)
        );
    }
    let mut raw = UpstreamEncoder::new()?;
    let packet = raw.encode(2880)?;
    // SAFETY: upstream allocator takes no arguments; RAII owns any result.
    let pointer = unsafe { opus_repacketizer_create() };
    let repacketizer =
        Repacketizer(NonNull::new(pointer).ok_or_else(|| io::Error::other("no repacketizer"))?);
    for _ in 0..2 {
        // SAFETY: packet stays alive until the repacketizer has copied output.
        assert_eq!(
            unsafe {
                opus_repacketizer_cat(
                    repacketizer.0.as_ptr(),
                    packet.as_ptr(),
                    packet.len() as i32,
                )
            },
            0
        );
    }
    let mut long = vec![0; OPUS_MAX_PACKET_BYTES];
    // SAFETY: initialized fixture repacketizer and declared writable capacity.
    let bytes = unsafe {
        opus_repacketizer_out(
            repacketizer.0.as_ptr(),
            long.as_mut_ptr(),
            long.len() as i32,
        )
    };
    assert!(bytes > 0 && bytes as usize <= long.len());
    long.truncate(bytes as usize);
    // SAFETY: actual owned nonempty Opus packet and its exact bounded size.
    assert_eq!(
        unsafe { opus_packet_get_nb_samples(long.as_ptr(), long.len() as i32, 48_000) },
        5760
    );
    assert_eq!(
        decoder.decode(&long).err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn owned_codecs_can_move_to_a_dedicated_worker() -> io::Result<()> {
    let encoder = OpusEncoder::new(OpusConfig {
        channels: 2,
        bitrate: 96_000,
    })?;
    let decoder = OpusDecoder::new(2)?;
    std::thread::spawn(move || -> io::Result<()> {
        let mut encoder = encoder;
        let mut decoder = decoder;
        let packet = encoder.encode(&sine(2, 0, OPUS_SAMPLES_PER_CHANNEL))?;
        assert_eq!(decoder.decode(&packet)?.len(), OPUS_SAMPLES_PER_CHANNEL * 2);
        Ok(())
    })
    .join()
    .map_err(|_| io::Error::other("media worker panicked"))?
}

#[cfg(target_os = "linux")]
#[test]
fn native_bridge_memory_bounds_under_asan_and_ubsan() -> io::Result<()> {
    use std::{
        fs,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let directory = tempfile::Builder::new()
        .prefix("nestlink-opus-asan-")
        .tempdir()?;
    let prefix = std::path::PathBuf::from(
        std::env::var_os("NESTLINK_CODEC_PREFIX")
            .ok_or_else(|| io::Error::other("native sanitizer requires NESTLINK_CODEC_PREFIX"))?,
    );
    let source = directory.path().join("bounds.c");
    fs::write(
        &source,
        r#"
#include "opus.c"
#include <assert.h>
#include <math.h>
int main(void) {
    void *invalid = (void *)(uintptr_t)1;
    assert(nl_opus_encoder_new(0, 64000, &invalid) == OPUS_BAD_ARG && invalid == NULL);
    assert(nl_opus_decoder_new(3, &invalid) == OPUS_BAD_ARG && invalid == NULL);
    assert(nl_opus_encoder_new(1, 6000, NULL) == OPUS_BAD_ARG);
    assert(nl_opus_decoder_new(1, NULL) == OPUS_BAD_ARG);
    assert(nl_opus_encoder_reset(NULL) == OPUS_BAD_ARG);
    assert(nl_opus_decoder_reset(NULL) == OPUS_BAD_ARG);
    nl_opus_encoder_free(NULL);
    nl_opus_decoder_free(NULL);
    for (uint32_t channels = 1; channels <= 2; ++channels) {
        void *encoder = NULL, *decoder = NULL;
        assert(nl_opus_encoder_new(channels, 96000, &encoder) == OPUS_OK);
        assert(nl_opus_decoder_new(channels, &decoder) == OPUS_OK);
        uint32_t samples = NL_OPUS_SAMPLES * channels;
        int16_t *input = calloc(samples, sizeof(*input));
        int16_t *guarded = calloc(samples + 2, sizeof(*guarded));
        uint8_t *packet = calloc(NL_OPUS_PACKET, 1);
        assert(input != NULL && guarded != NULL && packet != NULL);
        int16_t *pcm = guarded + 1;
        guarded[0] = 1234;
        guarded[samples + 1] = 4321;
        for (uint32_t i = 0; i < samples; ++i)
            input[i] = (int16_t)(10000.0 * sin(6.283185307179586 * 400.0 * (i / channels) / 48000.0));
        assert(nl_opus_encode(NULL, input, samples, packet, NL_OPUS_PACKET) == OPUS_BAD_ARG);
        assert(nl_opus_encode(encoder, NULL, samples, packet, NL_OPUS_PACKET) == OPUS_BAD_ARG);
        assert(nl_opus_encode(encoder, input, samples - 1, packet, NL_OPUS_PACKET) == OPUS_BAD_ARG);
        assert(nl_opus_encode(encoder, input, samples, NULL, NL_OPUS_PACKET) == OPUS_BAD_ARG);
        assert(nl_opus_encode(encoder, input, samples, packet, NL_OPUS_PACKET - 1) == OPUS_BAD_ARG);
        int32_t bytes = nl_opus_encode(encoder, input, samples, packet, NL_OPUS_PACKET);
        assert(bytes > 0 && bytes <= NL_OPUS_PACKET);
        assert(nl_opus_validate_packet(packet, (uint32_t)bytes, channels) == OPUS_OK);
        assert(nl_opus_validate_packet(packet, (uint32_t)bytes, 0) == OPUS_BAD_ARG);
        assert(nl_opus_validate_packet(NULL, 0, channels) == OPUS_INVALID_PACKET);
        assert(nl_opus_validate_packet(packet, NL_OPUS_PACKET + 1, channels) == OPUS_INVALID_PACKET);
        assert(nl_opus_decode(NULL, packet, (uint32_t)bytes, pcm, samples) == OPUS_BAD_ARG);
        assert(nl_opus_decode(decoder, packet, (uint32_t)bytes, NULL, samples) == OPUS_BAD_ARG);
        assert(nl_opus_decode(decoder, packet, (uint32_t)bytes, pcm, samples - 1) == OPUS_BAD_ARG);
        assert(nl_opus_decode(decoder, NULL, 0, pcm, samples) == OPUS_INVALID_PACKET);
        assert(nl_opus_decode(decoder, packet, NL_OPUS_PACKET + 1, pcm, samples) == OPUS_INVALID_PACKET);
        assert(nl_opus_decode(decoder, packet, (uint32_t)bytes, pcm, samples) == NL_OPUS_SAMPLES);
        assert(nl_opus_conceal(decoder, NULL, samples) == OPUS_BAD_ARG);
        assert(nl_opus_conceal(NULL, pcm, samples) == OPUS_BAD_ARG);
        assert(nl_opus_conceal(decoder, pcm, samples - 1) == OPUS_BAD_ARG);
        assert(nl_opus_conceal(decoder, pcm, samples) == NL_OPUS_SAMPLES);
        for (uint32_t length = 0; length <= NL_OPUS_PACKET; ++length) {
            uint32_t random = length + 1;
            for (uint32_t i = 0; i < length; ++i) {
                random = random * 1664525u + 1013904223u;
                packet[i] = (uint8_t)(random >> 24);
            }
            packet[0] = channels == 1 ? 0xf8 : 0xfc;
            int32_t parsed = nl_opus_validate_packet(packet, length, channels);
            assert(parsed == OPUS_OK || parsed == OPUS_INVALID_PACKET);
            int32_t result = nl_opus_decode(decoder, packet, length, pcm, samples);
            assert(result < 0 || result == NL_OPUS_SAMPLES);
            assert(guarded[0] == 1234 && guarded[samples + 1] == 4321);
        }
        assert(nl_opus_encoder_reset(encoder) == OPUS_OK);
        assert(nl_opus_decoder_reset(decoder) == OPUS_OK);
        assert(nl_opus_conceal(decoder, pcm, samples) == NL_OPUS_SAMPLES);
        for (uint32_t i = 0; i < samples; ++i) assert(pcm[i] == 0);
        free(packet);
        free(guarded);
        free(input);
        nl_opus_encoder_free(encoder);
        nl_opus_decoder_free(decoder);
    }
    return 0;
}
"#,
    )?;
    // Only our C bridge is instrumented here. The separately pinned upstream
    // static library is exercised, but this does not claim its own ASan build.
    let executable = directory.path().join("bounds");
    let mut compiler = Command::new("cc");
    compiler
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
            "-no-pie",
        ])
        .arg("-I")
        .arg(prefix.join("include"))
        .arg("-I")
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
        .arg(&source)
        .arg(prefix.join("lib/libopus.a"))
        .arg("-lm")
        .arg("-o")
        .arg(&executable);
    let run = |mut command: Command, label: &str| -> io::Result<()> {
        let log_path = directory.path().join(format!("{label}.log"));
        let log = fs::File::create(&log_path)?;
        let mut child = command
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        let result = (|| {
            let deadline = Instant::now() + Duration::from_secs(20);
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if Instant::now() >= deadline || fs::metadata(&log_path)?.len() > 1024 * 1024 {
                    return Err(io::Error::other(
                        "owned sanitizer exceeded time/output budget",
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            if fs::metadata(&log_path)?.len() > 1024 * 1024 {
                return Err(io::Error::other("owned sanitizer exceeded output budget"));
            }
            if !status.success() {
                return Err(io::Error::other(format!(
                    "{label}: {}",
                    fs::read_to_string(&log_path)?
                )));
            }
            Ok(())
        })();
        // Child owns this PID until wait/try_wait reaps it; Rust's Child avoids
        // signalling an already reaped process. Never signal a named process.
        let _ = child.kill();
        let _ = child.wait();
        result
    };
    run(compiler, "compile")?;
    let mut command = Command::new(executable);
    command
        .env("ASAN_OPTIONS", "detect_leaks=1:halt_on_error=1")
        .env("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1");
    run(command, "run")
}
