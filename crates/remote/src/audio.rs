//! Lease-bound local PCM capture and playback. OS adapters own bounded device
//! queues; codecs are a separate layer and never execute under the lease lock.
use crate::{LeaseControl, RemoteError, StopHandler, lifecycle::AudioDirection};
use nestlink_session::{StopEffects, StopReason};
use std::{
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const SAMPLE_RATE: u32 = 48_000;
pub const CHUNK_FRAMES: usize = 960;
pub const CAPTURE_AGE: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioBinding {
    pub connection: u64,
    pub source: u32,
    pub channels: u8,
}
impl AudioBinding {
    pub fn validate(self) -> io::Result<()> {
        if self.connection == 0
            || self.connection > i64::MAX as u64
            || !(1..=2).contains(&self.channels)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid audio binding",
            ));
        }
        Ok(())
    }
}
/// Exactly 20 ms of interleaved signed 16-bit PCM at 48 kHz. The sample clock
/// advances even when a local queue drops an old chunk; it never uses wall time.
pub struct AudioChunk {
    pub source: u32,
    pub channels: u8,
    pub pts_48khz: u64,
    pub samples: Vec<i16>,
}
impl AudioChunk {
    pub fn validate(&self, binding: AudioBinding) -> io::Result<()> {
        binding.validate()?;
        if self.source != binding.source
            || self.channels != binding.channels
            || self.samples.len() != CHUNK_FRAMES * usize::from(binding.channels)
            || self.pts_48khz > i64::MAX as u64
            || !self.pts_48khz.is_multiple_of(CHUNK_FRAMES as u64)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "audio source, format, clock or PCM budget changed",
            ));
        }
        Ok(())
    }
}
pub struct CapturedAudio {
    pub captured_at: Instant,
    pub chunk: AudioChunk,
}
/// Facts and reset must be bounded, must not reenter the lease and must not
/// access microphone/camera devices implicitly. Reset clears pending PCM and
/// stops this original OS device; a replaced endpoint requires a new session.
pub trait AudioDevice: Send + 'static {
    fn check(&mut self) -> io::Result<()>;
    fn reset(&mut self) -> io::Result<()>;
}
pub trait AudioCaptureDevice: AudioDevice {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>>;
}
/// Snapshot of independent queue/driver facts. Unknown device delay remains
/// None; successful enqueue does not prove audible completion.
#[derive(Clone, Copy, Debug, Default)]
pub struct AudioPlaybackTiming {
    pub software_queued_frames: Option<u32>,
    pub hardware_queued_frames: Option<u32>,
    pub hardware_latency: Option<Duration>,
    pub observed_at: Option<Instant>,
}
impl AudioPlaybackTiming {
    /// Sum only the known portions. The individual fields retain whether an
    /// unreported hardware delay is unknown; this is not an end-to-end latency.
    pub fn known_output_delay(self, now: Instant) -> Option<Duration> {
        let fresh = self
            .observed_at
            .is_some_and(|at| at <= now && now.duration_since(at) <= Duration::from_millis(100));
        let frames = u64::from(self.software_queued_frames.unwrap_or(0))
            + if fresh {
                u64::from(self.hardware_queued_frames.unwrap_or(0))
            } else {
                0
            };
        let latency = if fresh {
            self.hardware_latency.unwrap_or_default()
        } else {
            Duration::ZERO
        };
        if self.software_queued_frames.is_none()
            && !(fresh
                && (self.hardware_queued_frames.is_some() || self.hardware_latency.is_some()))
        {
            return None;
        }
        Duration::from_nanos(frames * 1_000_000_000 / u64::from(SAMPLE_RATE)).checked_add(latency)
    }
}

pub trait AudioPlaybackDevice: AudioDevice {
    fn timing(&mut self) -> io::Result<AudioPlaybackTiming> {
        Ok(AudioPlaybackTiming::default())
    }

    /// Copy/enqueue one 20 ms chunk without blocking on audible completion.
    /// Keep at most 100 ms locally, dropping old queued PCM under pressure.
    /// Borrowed samples must not survive the call; reset must flush the queue.
    fn enqueue(&mut self, chunk: &AudioChunk) -> io::Result<()>;
}
struct State<D> {
    device: D,
    last_pts: Option<u64>,
}
struct Cleanup<D>(Arc<Mutex<State<D>>>);
fn guarded<T>(operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
        .unwrap_or_else(|_| Err(io::Error::other("audio device operation panicked")))
}
impl<D: AudioDevice> StopHandler for Cleanup<D> {
    fn check(&mut self) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("audio state poisoned"))?;
        guarded(|| state.device.check())
    }
    fn stop(&mut self, _: StopReason, _: StopEffects) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("audio state poisoned"))?;
        guarded(|| state.device.reset())
    }
}
struct Controller<D: AudioDevice> {
    lease: LeaseControl,
    binding: AudioBinding,
    state: Arc<Mutex<State<D>>>,
}
impl<D: AudioDevice> Controller<D> {
    fn attach(
        lease: LeaseControl,
        device: D,
        binding: AudioBinding,
        direction: AudioDirection,
    ) -> Result<Self, RemoteError> {
        let mut device = device;
        if let Err(primary) = binding.validate() {
            return match guarded(|| device.reset()) {
                Ok(()) => Err(primary.into()),
                Err(cleanup) => Err(RemoteError::Cleanup(io::Error::new(
                    cleanup.kind(),
                    format!("audio binding rejected ({primary}); device cleanup failed: {cleanup}"),
                ))),
            };
        }
        let state = Arc::new(Mutex::new(State {
            device,
            last_pts: None,
        }));
        if let Err(primary) = lease.attach_audio(
            binding.connection,
            direction,
            Box::new(Cleanup(state.clone())),
        ) {
            let cleanup = state
                .lock()
                .map_err(|_| io::Error::other("audio state poisoned before attach cleanup"))
                .and_then(|mut state| guarded(|| state.device.reset()));
            return match cleanup {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(RemoteError::Cleanup(io::Error::new(
                    cleanup.kind(),
                    format!(
                        "audio attachment failed ({primary}); device cleanup failed: {cleanup}"
                    ),
                ))),
            };
        }
        Ok(Self {
            lease,
            binding,
            state,
        })
    }
    fn operation<T>(
        &self,
        operation: impl FnOnce(&mut State<D>) -> io::Result<T>,
    ) -> Result<T, RemoteError> {
        let result = self.lease.audio_operation(self.binding.connection, || {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("audio state poisoned"))?;
            // Catch inside the lock so a platform panic cannot poison reset.
            guarded(|| {
                state.device.check()?;
                operation(&mut state)
            })
        });
        if matches!(result, Err(RemoteError::Io(_))) {
            self.lease.stop(StopReason::PlatformChanged)?;
        }
        result
    }
}
impl<D: AudioDevice> Drop for Controller<D> {
    fn drop(&mut self) {
        let _ = self.lease.stop_if_running(StopReason::ExplicitExit);
    }
}
pub struct AudioCaptureController<D: AudioCaptureDevice>(Controller<D>);
impl<D: AudioCaptureDevice> AudioCaptureController<D> {
    pub fn attach(
        lease: LeaseControl,
        device: D,
        binding: AudioBinding,
    ) -> Result<Self, RemoteError> {
        Controller::attach(lease, device, binding, AudioDirection::Capture).map(Self)
    }
    pub fn poll(&self) -> Result<Option<CapturedAudio>, RemoteError> {
        self.0.operation(|state| {
            let Some(captured) = state.device.poll_chunk()? else {
                return Ok(None);
            };
            captured.chunk.validate(self.0.binding)?;
            if captured.captured_at > Instant::now()
                || state
                    .last_pts
                    .is_some_and(|pts| captured.chunk.pts_48khz <= pts)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "audio capture clock regressed",
                ));
            }
            state.last_pts = Some(captured.chunk.pts_48khz);
            if captured.captured_at.elapsed() > CAPTURE_AGE {
                return Ok(None);
            }
            Ok(Some(captured))
        })
    }
}
pub struct AudioPlaybackController<D: AudioPlaybackDevice>(Controller<D>);
impl<D: AudioPlaybackDevice> AudioPlaybackController<D> {
    pub fn attach(
        lease: LeaseControl,
        device: D,
        binding: AudioBinding,
    ) -> Result<Self, RemoteError> {
        Controller::attach(lease, device, binding, AudioDirection::Playback).map(Self)
    }
    pub fn timing(&self) -> Result<AudioPlaybackTiming, RemoteError> {
        self.0.operation(|state| state.device.timing())
    }
    pub fn play(&self, chunk: &AudioChunk) -> Result<(), RemoteError> {
        self.0.operation(|state| {
            chunk.validate(self.0.binding)?;
            if state.last_pts.is_some_and(|pts| chunk.pts_48khz <= pts) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "audio playback clock regressed",
                ));
            }
            state.device.enqueue(chunk)?;
            state.last_pts = Some(chunk.pts_48khz);
            Ok(())
        })
    }
}

#[cfg(test)]
mod timing_tests {
    use super::*;

    #[test]
    fn unknown_device_latency_is_distinct_from_measured_zero_and_software_queue() {
        let now = Instant::now();
        assert!(
            AudioPlaybackTiming::default()
                .known_output_delay(now)
                .is_none()
        );
        let software_only = AudioPlaybackTiming {
            software_queued_frames: Some(960),
            ..AudioPlaybackTiming::default()
        };
        assert_eq!(
            software_only.known_output_delay(now),
            Some(Duration::from_millis(20))
        );
        assert!(software_only.hardware_latency.is_none());
        let measured_zero = AudioPlaybackTiming {
            hardware_latency: Some(Duration::ZERO),
            observed_at: Some(now),
            ..AudioPlaybackTiming::default()
        };
        assert_eq!(measured_zero.known_output_delay(now), Some(Duration::ZERO));
    }

    #[test]
    fn stale_or_future_driver_facts_do_not_erase_fresh_software_queue() {
        let now = Instant::now();
        let facts = AudioPlaybackTiming {
            software_queued_frames: Some(960),
            hardware_queued_frames: Some(480),
            hardware_latency: Some(Duration::from_millis(5)),
            observed_at: Some(now),
        };
        assert_eq!(
            facts.known_output_delay(now),
            Some(Duration::from_millis(35))
        );
        assert_eq!(
            facts.known_output_delay(now + Duration::from_millis(101)),
            Some(Duration::from_millis(20))
        );
        assert_eq!(
            facts.known_output_delay(now - Duration::from_millis(1)),
            Some(Duration::from_millis(20))
        );
        assert!(
            AudioPlaybackTiming {
                software_queued_frames: None,
                ..facts
            }
            .known_output_delay(now + Duration::from_millis(101))
            .is_none()
        );
    }

    #[test]
    fn unrepresentable_output_delay_is_unknown_instead_of_panicking() {
        let now = Instant::now();
        let facts = AudioPlaybackTiming {
            software_queued_frames: Some(960),
            hardware_latency: Some(Duration::MAX),
            observed_at: Some(now),
            ..AudioPlaybackTiming::default()
        };
        assert!(facts.known_output_delay(now).is_none());
    }
}
