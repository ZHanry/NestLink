use jni::{
    JavaVM,
    objects::{GlobalRef, JByteArray, JLongArray, JObject, JValue},
};
use nestlink_app_core::{NativeAudioBinding, NativeAudioRole};
use nestlink_remote::audio::{
    AudioCaptureDevice, AudioChunk, AudioDevice, AudioPlaybackDevice, AudioPlaybackTiming,
    CHUNK_FRAMES, CapturedAudio,
};
use std::{
    io,
    time::{Duration, Instant},
};

const CHANNELS: u8 = 2;
const CAPTURE_HEADER_BYTES: usize = 16;
const PCM_BYTES: usize = CHUNK_FRAMES * CHANNELS as usize * 2;

/// JNI endpoint methods are intentionally tiny and nonblocking except for the
/// explicit, bounded reset acknowledgment. Kotlin owns AudioRecord/AudioTrack;
/// Rust owns only this adapter and the app-core media pipeline.
pub(crate) struct AndroidAudioDevice {
    vm: JavaVM,
    endpoint: GlobalRef,
    capture: bool,
    binding: NativeAudioBinding,
}

impl AndroidAudioDevice {
    pub(crate) fn new(
        vm: JavaVM,
        endpoint: GlobalRef,
        binding: NativeAudioBinding,
        capture: bool,
    ) -> Self {
        Self {
            vm,
            endpoint,
            binding,
            capture,
        }
    }

    fn call_bool(
        &self,
        method: &str,
        signature: &str,
        args: &[JValue<'_, '_>],
    ) -> io::Result<bool> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("Android audio JVM attachment failed"))?;
        match env
            .call_method(self.endpoint.as_obj(), method, signature, args)
            .and_then(|value| value.z())
        {
            Ok(value) => Ok(value),
            Err(_) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                Err(io::Error::other(
                    "Android audio endpoint rejected the operation",
                ))
            }
        }
    }

    fn accepted(&self, method: &str, signature: &str, args: &[JValue<'_, '_>]) -> io::Result<()> {
        if self.call_bool(method, signature, args)? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Android audio endpoint is stopped",
            ))
        }
    }
}

impl AudioDevice for AndroidAudioDevice {
    fn check(&mut self) -> io::Result<()> {
        self.accepted("isActive", "()Z", &[])?;
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("Android audio JVM attachment failed"))?;
        let request_id = env
            .new_string(&self.binding.request_id)
            .map_err(|_| io::Error::other("Android audio binding request could not be prepared"))?;
        let request_id = JObject::from(request_id);
        let role = match self.binding.role {
            NativeAudioRole::HostCapture => "HostCapture",
            NativeAudioRole::ControllerPlayback => "ControllerPlayback",
        };
        let role = env
            .new_string(role)
            .map_err(|_| io::Error::other("Android audio binding role could not be prepared"))?;
        let role = JObject::from(role);
        let generation = i64::try_from(self.binding.connection_generation).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Android audio generation exceeds JNI bounds",
            )
        })?;
        match env
            .call_method(
                self.endpoint.as_obj(),
                "matchesBinding",
                "(Ljava/lang/String;JLjava/lang/String;)Z",
                &[
                    JValue::Object(&request_id),
                    JValue::Long(generation),
                    JValue::Object(&role),
                ],
            )
            .and_then(|value| value.z())
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Android audio request binding changed",
            )),
            Err(_) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                Err(io::Error::other(
                    "Android audio request binding could not be checked",
                ))
            }
        }
    }

    fn reset(&mut self) -> io::Result<()> {
        self.accepted("resetAndAwait", "()Z", &[])
    }
}

impl AudioCaptureDevice for AndroidAudioDevice {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        if !self.capture {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Android playback endpoint cannot capture",
            ));
        }
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("Android audio JVM attachment failed"))?;
        let result = env
            .call_method(self.endpoint.as_obj(), "pollCaptureChunk", "()[B", &[])
            .and_then(|value| value.l());
        let object = match result {
            Ok(object) if object.is_null() => return Ok(None),
            Ok(object) => object,
            Err(_) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                return Err(io::Error::other("Android AudioRecord capture failed"));
            }
        };
        let array = JByteArray::from(object);
        let bytes = env.convert_byte_array(&array).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Android PCM capture packet is invalid",
            )
        })?;
        if bytes.len() != CAPTURE_HEADER_BYTES + PCM_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Android PCM capture packet changed its bounded format",
            ));
        }
        let pts = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Android PCM timestamp is invalid",
            )
        })?);
        let captured_nanos = i64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| io::Error::other("capture time format changed"))?,
        );
        let now_nanos = env
            .call_static_method("java/lang/System", "nanoTime", "()J", &[])
            .and_then(|value| value.j())
            .map_err(|_| io::Error::other("Android monotonic clock unavailable"))?;
        let Some(age) = now_nanos
            .checked_sub(captured_nanos)
            .filter(|age| *age >= 0 && *age <= 100_000_000)
        else {
            return Ok(None);
        };
        let captured_at = Instant::now()
            .checked_sub(Duration::from_nanos(age as u64))
            .ok_or_else(|| io::Error::other("capture time underflow"))?;
        let samples = bytes[CAPTURE_HEADER_BYTES..]
            .chunks_exact(2)
            .map(|sample| i16::from_le_bytes([sample[0], sample[1]]))
            .collect();
        Ok(Some(CapturedAudio {
            captured_at,
            chunk: AudioChunk {
                source: 0,
                channels: CHANNELS,
                pts_48khz: pts,
                samples,
            },
        }))
    }
}

impl AudioPlaybackDevice for AndroidAudioDevice {
    fn timing(&mut self) -> io::Result<AudioPlaybackTiming> {
        if self.capture {
            return Err(io::Error::other("capture endpoint has no playback timing"));
        }
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("audio JVM attachment failed"))?;
        let object = env
            .call_method(self.endpoint.as_obj(), "playbackTiming", "()[J", &[])
            .and_then(|value| value.l())
            .map_err(|_| io::Error::other("AudioTrack timing unavailable"))?;
        let array = JLongArray::from(object);
        if env
            .get_array_length(&array)
            .map_err(|_| io::Error::other("AudioTrack timing length unavailable"))?
            != 3
        {
            return Err(io::Error::other("AudioTrack timing format changed"));
        }
        let mut facts = [-1i64; 3];
        env.get_long_array_region(&array, 0, &mut facts)
            .map_err(|_| io::Error::other("AudioTrack timing copy failed"))?;
        if facts[0] < -1 || facts[0] > 1920 || facts[1] < -1 || facts[1] > 2880 || facts[2] != -1 {
            return Err(io::Error::other("AudioTrack timing exceeded queue budget"));
        }
        Ok(AudioPlaybackTiming {
            software_queued_frames: u32::try_from(facts[0]).ok(),
            hardware_queued_frames: u32::try_from(facts[1]).ok(),
            hardware_latency: None,
            observed_at: Some(Instant::now()),
        })
    }

    fn enqueue(&mut self, chunk: &AudioChunk) -> io::Result<()> {
        if self.capture {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Android capture endpoint cannot play",
            ));
        }
        let mut bytes = Vec::with_capacity(PCM_BYTES);
        for sample in &chunk.samples {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("Android audio JVM attachment failed"))?;
        let array = env
            .byte_array_from_slice(&bytes)
            .map_err(|_| io::Error::other("Android playback PCM could not be prepared"))?;
        let object = JObject::from(array);
        match env
            .call_method(
                self.endpoint.as_obj(),
                "enqueuePlaybackChunk",
                "([B)Z",
                &[JValue::Object(&object)],
            )
            .and_then(|value| value.z())
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Android AudioTrack endpoint is stopped",
            )),
            Err(_) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                Err(io::Error::other("Android AudioTrack playback failed"))
            }
        }
    }
}
