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
}
impl VideoQuality {
    pub fn new(fps: u32, kbps: u32, now: Instant) -> Self {
        let fps = fps.clamp(15, 120);
        let kbps = kbps.clamp(800, 100_000);
        Self {
            maximum_fps: fps,
            maximum_kbps: kbps,
            fps,
            kbps,
            next_adjustment: now,
            healthy_since: now,
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
            self.kbps = (self.kbps * 3 / 4).max(800);
            if self.kbps == 800 {
                self.fps = (self.fps * 3 / 4).max(15);
            }
        } else if encoder_limited {
            self.fps = (self.fps * 3 / 4).max(15);
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
        quality.observe(
            start + Duration::from_secs(4),
            Duration::from_millis(4),
            Duration::ZERO,
        );
        assert_eq!(quality.bitrate_kbps(), low);
        quality.observe(
            start + Duration::from_secs(6),
            Duration::from_millis(4),
            Duration::ZERO,
        );
        assert!(quality.bitrate_kbps() > low && quality.bitrate_kbps() < 3000);
        quality.observe(
            start + Duration::from_millis(6500),
            Duration::from_millis(80),
            Duration::ZERO,
        );
        assert_eq!(quality.fps(), 45);
        assert!(quality.bitrate_kbps() < 3000);
    }
}
