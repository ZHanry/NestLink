//! Local producer control. Queue delay and codec cost are distinct signals;
//! QUIC/WebRTC remain responsible for transport congestion control.
use std::time::{Duration, Instant};

pub struct VideoQuality {
    maximum_fps: u32,
    maximum_kbps: u32,
    fps: u32,
    kbps: u32,
    next_adjustment: Instant,
    healthy_since: Instant,
    last_observation: Instant,
}
impl VideoQuality {
    pub fn new(fps: u32, kbps: u32, now: Instant) -> Self {
        let fps = fps.clamp(1, 120);
        let kbps = kbps.clamp(64, 100_000);
        Self {
            maximum_fps: fps,
            maximum_kbps: kbps,
            fps,
            kbps,
            next_adjustment: now,
            healthy_since: now,
            last_observation: now,
        }
    }
    pub fn fps(&self) -> u32 {
        self.fps
    }
    pub fn bitrate_kbps(&self) -> u32 {
        self.kbps
    }
    /// Returns a new bitrate only when it changed. Recovery requires four
    /// uninterrupted healthy seconds; a congested sample resets that window.
    pub fn observe(&mut self, now: Instant, encoding: Duration, enqueue: Duration) -> Option<u32> {
        let since_last = now.checked_duration_since(self.last_observation)?;
        // A paused/static producer supplies no evidence of a healthy path.
        // Resume requires a fresh uninterrupted observation window, and an old
        // timestamp cannot move that window or the adjustment deadline back.
        if since_last > Duration::from_secs(1) {
            self.healthy_since = now;
        }
        self.last_observation = now;
        let network_limited = enqueue >= Duration::from_millis(40);
        let encoder_limited = encoding > Duration::from_secs_f64(1.25 / f64::from(self.fps));
        if network_limited || encoder_limited {
            self.healthy_since = now;
        }
        if now < self.next_adjustment {
            return None;
        }
        let before = self.kbps;
        if network_limited {
            let minimum_kbps = self.maximum_kbps.min(800);
            self.kbps = (self.kbps * 3 / 4).max(minimum_kbps);
            if self.kbps == minimum_kbps {
                self.fps = (self.fps * 3 / 4).max(self.maximum_fps.min(15));
            }
        } else if encoder_limited {
            self.fps = (self.fps * 3 / 4).max(self.maximum_fps.min(15));
        } else if now.saturating_duration_since(self.healthy_since) >= Duration::from_secs(4) {
            self.kbps = (self.kbps + (self.kbps / 10).max(100)).min(self.maximum_kbps);
            self.fps = (self.fps + 5).min(self.maximum_fps);
            self.healthy_since = now;
        }
        self.next_adjustment = now + Duration::from_millis(500);
        (before != self.kbps).then_some(self.kbps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bandwidth_steps_reduce_within_two_seconds_and_recovery_does_not_oscillate() {
        let start = Instant::now();
        let mut quality = VideoQuality::new(60, 6000, start);
        for step in 0..4 {
            quality.observe(
                start + Duration::from_millis(step * 500),
                Duration::from_millis(4),
                Duration::from_millis(60),
            );
        }
        assert!(quality.bitrate_kbps() < 2000);
        assert_eq!(quality.fps(), 60);
        let low = quality.bitrate_kbps();
        for step in 4..=8 {
            quality.observe(start + Duration::from_millis(step * 500), Duration::from_millis(4), Duration::ZERO);
        }
        assert_eq!(quality.bitrate_kbps(), low);
        for step in 9..=12 {
            quality.observe(start + Duration::from_millis(step * 500), Duration::from_millis(4), Duration::ZERO);
        }
        assert!(quality.bitrate_kbps() > low && quality.bitrate_kbps() < 3000);
        quality.observe(
            start + Duration::from_millis(6500),
            Duration::from_millis(80),
            Duration::ZERO,
        );
        assert_eq!(quality.fps(), 45);
        assert!(quality.bitrate_kbps() < 3000);
    }
    #[test]
    fn low_rate_approval_is_never_raised_by_initialization_congestion_or_recovery() {
        let start = Instant::now();
        let mut quality = VideoQuality::new(5, 256, start);
        assert_eq!((quality.fps(), quality.bitrate_kbps()), (5, 256));
        for step in 0..=24 {
            let busy = step < 8;
            quality.observe(start + Duration::from_millis(step * 500), if busy {Duration::from_secs(1)} else {Duration::ZERO}, if busy {Duration::from_secs(1)} else {Duration::ZERO});
            assert!(quality.fps() <= 5 && quality.bitrate_kbps() <= 256);
        }
    }
    #[test]
    fn missing_or_old_observations_cannot_qualify_an_upgrade() {
        let start = Instant::now();
        let mut quality = VideoQuality::new(60, 6000, start);
        quality.observe(start, Duration::ZERO, Duration::from_millis(60));
        let reduced = quality.bitrate_kbps();
        let resumed = start + Duration::from_secs(30);
        assert_eq!(quality.observe(resumed, Duration::ZERO, Duration::ZERO), None);
        assert_eq!(quality.observe(start + Duration::from_secs(1), Duration::ZERO, Duration::ZERO), None);
        for step in 1..8 {
            assert_eq!(quality.observe(resumed + Duration::from_millis(step * 500), Duration::ZERO, Duration::ZERO), None);
        }
        assert_eq!(quality.bitrate_kbps(), reduced);
        assert!(quality.observe(resumed + Duration::from_secs(4), Duration::ZERO, Duration::ZERO).is_some());
        assert!(quality.bitrate_kbps() > reduced && quality.bitrate_kbps() <= 6000);
    }
}
