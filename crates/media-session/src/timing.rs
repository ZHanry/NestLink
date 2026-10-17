//! One capture origin and one controller playout mapping per proved session.
//! Native device facts remain separate from bounded software scheduling.
use std::{
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const PLAYOUT_DELAY: Duration = Duration::from_millis(60);
pub const MAX_PLAYOUT_AHEAD: Duration = Duration::from_millis(250);
pub const MAX_PLAYOUT_LATE: Duration = Duration::from_millis(40);

#[derive(Clone)]
pub struct SessionCaptureClock {
    origin: Instant,
}
impl Default for SessionCaptureClock {
    fn default() -> Self {
        Self::new()
    }
}
impl SessionCaptureClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
    pub fn video_pts(&self, captured_at: Instant) -> io::Result<u64> {
        self.ticks(captured_at, 90_000)
    }
    fn ticks(&self, at: Instant, rate: u64) -> io::Result<u64> {
        let elapsed = at
            .checked_duration_since(self.origin)
            .ok_or_else(|| io::Error::other("capture precedes session clock"))?;
        if at > Instant::now() {
            return Err(io::Error::other("capture timestamp is in the future"));
        }
        u64::try_from(elapsed.as_nanos() * u128::from(rate) / 1_000_000_000)
            .ok()
            .filter(|ticks| *ticks <= i64::MAX as u64)
            .ok_or_else(|| io::Error::other("session capture clock exhausted"))
    }
}

/// Retains hardware sample gaps. Corrections are one 20ms interval after a
/// sustained >60ms drift, at most once per second. A negative correction drops
/// a chunk rather than emitting a duplicate timestamp or stretching its PCM.
pub struct AudioCaptureTimeline {
    clock: SessionCaptureClock,
    first: Option<(u64, u64)>,
    last_raw: Option<u64>,
    last_wire: Option<u64>,
    correction: i64,
    last_adjusted: Option<Instant>,
}
impl AudioCaptureTimeline {
    pub fn new(clock: SessionCaptureClock) -> Self {
        Self {
            clock,
            first: None,
            last_raw: None,
            last_wire: None,
            correction: 0,
            last_adjusted: None,
        }
    }
    pub fn map(&mut self, raw: u64, captured_at: Instant) -> io::Result<Option<u64>> {
        const CHUNK: u64 = 960;
        if !raw.is_multiple_of(CHUNK) || self.last_raw.is_some_and(|last| raw <= last) {
            return Err(io::Error::other("audio capture sample replay"));
        }
        let observed = self.clock.ticks(captured_at, 48_000)?;
        let (first_raw, first_wire) = *self.first.get_or_insert((raw, (observed / CHUNK) * CHUNK));
        let elapsed = raw
            .checked_sub(first_raw)
            .ok_or_else(|| io::Error::other("audio origin regressed"))?;
        let nominal = first_wire
            .checked_add(elapsed)
            .ok_or_else(|| io::Error::other("audio sample clock exhausted"))?;
        let mut wire = i128::from(nominal) + i128::from(self.correction);
        let drift = i128::from(observed) - wire;
        if drift.abs() > 12_000 {
            return Err(io::Error::other(
                "hardware audio clock exceeded 250ms session drift budget",
            ));
        }
        if drift.abs() > 2880
            && self.last_adjusted.is_none_or(|last| {
                captured_at.saturating_duration_since(last) >= Duration::from_secs(1)
            })
        {
            self.correction = self
                .correction
                .checked_add(if drift > 0 { 960 } else { -960 })
                .ok_or_else(|| io::Error::other("audio drift correction exhausted"))?;
            wire = i128::from(nominal) + i128::from(self.correction);
            self.last_adjusted = Some(captured_at);
        }
        self.last_raw = Some(raw);
        let wire = u64::try_from(wire)
            .ok()
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or_else(|| io::Error::other("audio wire clock exhausted"))?;
        if self.last_wire.is_some_and(|last| wire <= last) {
            return Ok(None);
        }
        self.last_wire = Some(wire);
        Ok(Some(wire))
    }
}

#[derive(Clone, Default)]
pub struct SessionPlayoutClock {
    anchor: Arc<Mutex<Option<(u64, Instant)>>>,
}
#[derive(Clone, Copy, Debug)]
pub enum PlayoutDecision {
    At(Instant),
    DropLate,
    DropFuture,
}
impl SessionPlayoutClock {
    /// Map both rates through one immutable remote-to-local origin. Late audio
    /// device attachment never reanchors a video session or drains old PCM.
    pub fn schedule(&self, pts: u64, rate: u32, now: Instant) -> io::Result<PlayoutDecision> {
        if rate == 0 || pts > i64::MAX as u64 {
            return Err(io::Error::other("invalid media presentation clock"));
        }
        let nanos = u64::try_from(u128::from(pts) * 1_000_000_000 / u128::from(rate))
            .map_err(|_| io::Error::other("media clock exceeds duration"))?;
        let mut anchor = self
            .anchor
            .lock()
            .map_err(|_| io::Error::other("playout clock poisoned"))?;
        let (first, local) = *anchor.get_or_insert((nanos, now + PLAYOUT_DELAY));
        let due = if nanos >= first {
            local.checked_add(Duration::from_nanos(nanos - first))
        } else {
            local.checked_sub(Duration::from_nanos(first - nanos))
        };
        let Some(due) = due else {
            return Ok(PlayoutDecision::DropLate);
        };
        if due.saturating_duration_since(now) > MAX_PLAYOUT_AHEAD {
            return Ok(PlayoutDecision::DropFuture);
        }
        if now.saturating_duration_since(due) > MAX_PLAYOUT_LATE {
            return Ok(PlayoutDecision::DropLate);
        }
        Ok(PlayoutDecision::At(due))
    }
}

#[derive(Clone, Default)]
pub struct SessionMediaTiming {
    pub capture: SessionCaptureClock,
    pub playout: SessionPlayoutClock,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audio_and_video_use_one_origin_across_device_start_delays_and_switches() -> io::Result<()> {
        let origin = Instant::now() - Duration::from_secs(10);
        let clock = SessionCaptureClock { origin };
        let mut audio = AudioCaptureTimeline::new(clock.clone());
        assert_eq!(clock.video_pts(origin + Duration::from_secs(2))?, 180_000);
        assert_eq!(
            audio.map(0, origin + Duration::from_secs(3))?,
            Some(144_000)
        );
        assert_eq!(
            audio.map(960, origin + Duration::from_millis(3020))?,
            Some(144_960)
        );
        assert_eq!(
            audio.map(3840, origin + Duration::from_millis(3080))?,
            Some(147_840)
        );
        assert_eq!(clock.video_pts(origin + Duration::from_secs(4))?, 360_000);
        assert!(
            audio
                .map(3840, origin + Duration::from_millis(3100))
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn common_playout_mapping_bounds_future_and_stale_media_without_reanchoring() -> io::Result<()>
    {
        let clock = SessionPlayoutClock::default();
        let now = Instant::now();
        let PlayoutDecision::At(video) = clock.schedule(90_000, 90_000, now)? else {
            panic!("initial deadline")
        };
        let PlayoutDecision::At(audio) =
            clock.schedule(48_000, 48_000, now + Duration::from_millis(20))?
        else {
            panic!("audio deadline")
        };
        assert_eq!(video, audio);
        assert!(matches!(
            clock.schedule(0, 48_000, now)?,
            PlayoutDecision::DropLate
        ));
        assert!(matches!(
            clock.schedule(480_000, 48_000, now)?,
            PlayoutDecision::DropFuture
        ));
        assert!(matches!(
            clock.schedule(48_000, 48_000, now + Duration::from_secs(1))?,
            PlayoutDecision::DropLate
        ));
        let PlayoutDecision::At(after) =
            clock.schedule(180_000, 90_000, now + Duration::from_secs(1))?
        else {
            panic!("switch deadline")
        };
        assert_eq!(after.duration_since(video), Duration::from_secs(1));
        Ok(())
    }
    #[test]
    fn negative_drift_correction_drops_instead_of_replaying_pcm() -> io::Result<()> {
        let origin = Instant::now() - Duration::from_secs(10);
        let mut timeline = AudioCaptureTimeline::new(SessionCaptureClock { origin });
        assert_eq!(timeline.map(0, origin)?, Some(0));
        let mut dropped = 0;
        for i in 1..200 {
            if timeline
                .map(i * 960, origin + Duration::from_millis(i * 19))?
                .is_none()
            {
                dropped += 1;
            }
        }
        assert!(dropped > 0 && dropped <= 4);
        Ok(())
    }
}
