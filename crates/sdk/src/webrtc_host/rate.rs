//! Conservative adaptation within the already approved capture profile.
//!
//! Feedback arrives over this peer's authenticated RTCP transport. Callers
//! must match its video SSRC before passing a report here. Feedback changes
//! quality only; it carries no permission, renewal or path authority.
use std::time::{Duration, Instant};

const MIN_KBPS: u32 = 64;
const INCREASE_INTERVAL: Duration = Duration::from_secs(1);
const DECREASE_INTERVAL: Duration = Duration::from_millis(250);
const REMB_LIFETIME: Duration = Duration::from_secs(3);

pub(super) struct RateController {
    maximum: u32,
    target: u32,
    last_adjustment: Instant,
    last_report_sequence: Option<u32>,
    receiver_cap: Option<(u32, Instant)>,
}

impl RateController {
    pub(super) fn new(maximum: u32, now: Instant) -> Self {
        Self {
            maximum,
            target: maximum,
            last_adjustment: now,
            last_report_sequence: None,
            receiver_cap: None,
        }
    }

    pub(super) fn target_kbps(&self) -> u32 {
        self.target
    }

    pub(super) fn receiver_estimate(&mut self, bits_per_second: f32, now: Instant) {
        if !bits_per_second.is_finite() || bits_per_second < 0.0 {
            return;
        }
        // Leave room for RTP/SRTP, feedback and the independent audio stream.
        // The configured maximum remains the ceiling even if the peer asks
        // for an unbounded estimate. Zero bandwidth lowers to the codec floor.
        let cap =
            ((f64::from(bits_per_second) * 0.85 / 1000.0) as u32).clamp(MIN_KBPS, self.maximum);
        self.receiver_cap = Some((cap, now));
        if cap < self.target {
            self.set_target(cap, now);
        } else {
            self.increase(now);
        }
    }

    pub(super) fn receiver_report(&mut self, sequence: u32, fraction_lost: u8, now: Instant) {
        if let Some(previous) = self.last_report_sequence {
            let advance = sequence.wrapping_sub(previous);
            // Reject repeats and old reports, including around sequence wrap.
            if advance == 0 || advance > u32::MAX / 2 {
                return;
            }
        }
        self.last_report_sequence = Some(sequence);
        if fraction_lost >= 26 {
            if now.saturating_duration_since(self.last_adjustment) >= DECREASE_INTERVAL {
                self.set_target((self.target * 4 / 5).max(MIN_KBPS), now);
            }
        } else if fraction_lost <= 5 {
            self.increase(now);
        }
    }

    fn increase(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_adjustment) < INCREASE_INTERVAL {
            return;
        }
        let cap = self
            .receiver_cap
            .filter(|(_, observed)| now.saturating_duration_since(*observed) <= REMB_LIFETIME)
            .map_or(self.maximum, |(cap, _)| cap);
        // At most one 5% step per fresh observation after a full interval.
        // Neither duplicated feedback nor a long silence causes a jump.
        let next = self.target.saturating_add((self.target / 20).max(1));
        self.set_target(next.min(cap).min(self.maximum), now);
    }

    fn set_target(&mut self, target: u32, now: Instant) {
        self.target = target;
        self.last_adjustment = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_drop_is_immediate_but_recovery_is_paced_and_capped() {
        let started = Instant::now();
        let mut rate = RateController::new(4_000, started);
        rate.receiver_estimate(1_000_000.0, started);
        assert_eq!(rate.target_kbps(), 850);
        rate.receiver_estimate(100_000_000.0, started + Duration::from_millis(999));
        assert_eq!(rate.target_kbps(), 850);
        rate.receiver_estimate(100_000_000.0, started + Duration::from_secs(1));
        assert_eq!(rate.target_kbps(), 892);
        // Thousands of immediate repeated estimates cannot accelerate growth.
        for _ in 0..10_000 {
            rate.receiver_estimate(f32::MAX, started + Duration::from_secs(1));
        }
        assert_eq!(rate.target_kbps(), 892);
        for second in 2..200 {
            rate.receiver_estimate(f32::MAX, started + Duration::from_secs(second));
        }
        assert_eq!(rate.target_kbps(), 4_000);
    }

    #[test]
    fn malformed_estimates_do_not_change_rate_and_zero_uses_bounded_floor() {
        let started = Instant::now();
        let mut rate = RateController::new(4_000, started);
        for bits in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -1.0] {
            rate.receiver_estimate(bits, started + Duration::from_secs(1));
            assert_eq!(rate.target_kbps(), 4_000);
        }
        rate.receiver_estimate(0.0, started + Duration::from_secs(1));
        assert_eq!(rate.target_kbps(), MIN_KBPS);
        rate.receiver_estimate(f32::MAX, started + Duration::from_secs(200));
        assert_eq!(rate.target_kbps(), MIN_KBPS + 3);
    }

    #[test]
    fn loss_reports_are_fresh_rate_limited_and_do_not_overrule_receiver_cap() {
        let started = Instant::now();
        let mut rate = RateController::new(4_000, started);
        rate.receiver_report(100, 26, started + Duration::from_secs(1));
        assert_eq!(rate.target_kbps(), 3_200);
        for sequence in [100, 99, 98] {
            rate.receiver_report(sequence, 255, started + Duration::from_secs(2));
        }
        assert_eq!(rate.target_kbps(), 3_200);
        rate.receiver_report(101, 255, started + Duration::from_millis(1_001));
        assert_eq!(rate.target_kbps(), 3_200);
        rate.receiver_report(102, 255, started + Duration::from_millis(1_250));
        assert_eq!(rate.target_kbps(), 2_560);
        rate.receiver_estimate(1_000_000.0, started + Duration::from_secs(2));
        rate.receiver_report(103, 0, started + Duration::from_secs(3));
        assert_eq!(rate.target_kbps(), 850);
        rate.receiver_report(104, 0, started + Duration::from_secs(6));
        assert_eq!(rate.target_kbps(), 892);
    }

    #[test]
    fn report_sequence_wrap_is_fresh_and_silence_does_not_raise_rate() {
        let started = Instant::now();
        let mut rate = RateController::new(1_000, started);
        rate.receiver_report(u32::MAX - 2, 255, started + Duration::from_secs(1));
        rate.receiver_report(3, 255, started + Duration::from_secs(2));
        assert_eq!(rate.target_kbps(), 640);
        rate.receiver_report(u32::MAX - 1, 255, started + Duration::from_secs(3));
        assert_eq!(rate.target_kbps(), 640);
        assert_eq!(rate.target_kbps(), 640);
    }
}
