//! Local observations of an already proved path. None of these values grant
//! admission, choose a successor, refresh credentials or authorize migration.
use nestlink_protocol::{Path, api::Candidate, network::Purpose};
use std::time::Duration;

pub const OBSERVATION_FRESHNESS_MS: u64 = 3_000;

/// Original admission identity, frozen before observing the existing transport.
/// Legacy paths have no network PathGrant/group; routed paths without native
/// candidates have no candidate/network generation. Absence is not a wildcard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathObservationBinding {
    pub business_grant_digest: [u8; 32],
    pub business_generation: u64,
    pub path_grant_id: Option<String>,
    pub transport_group: Option<[u8; 32]>,
    pub route_binding: Option<[u8; 32]>,
    pub purpose: Purpose,
    pub path: Path,
    pub candidate: Option<Candidate>,
    pub network_generation: Option<u64>,
}

/// Differences of Quinn's cumulative counters between two consecutive polls.
/// Newly declared losses may refer to packets sent before this window. This is
/// not a same-cohort loss probability and must not be divided by sent_packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketLossWindow {
    pub duration_ms: u64,
    pub sent_packets: u64,
    pub newly_declared_lost_packets: u64,
}

/// Complete business payload bytes accepted by the original local transport in
/// this window, excluding proof/renewal, framing, encryption and retransmission.
/// This measures offered business TX, not delivery, goodput or available rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusinessThroughputWindow {
    pub duration_ms: u64,
    pub payload_bytes: u64,
}
impl BusinessThroughputWindow {
    pub fn bytes_per_second(self) -> Option<u64> {
        if self.duration_ms == 0 {
            return None;
        }
        u64::try_from(u128::from(self.payload_bytes) * 1_000 / u128::from(self.duration_ms)).ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathObservationSnapshot {
    pub binding: PathObservationBinding,
    pub stopped: bool,
    /// Quinn's smoothed RTT, refreshed only after a newly observed ACK frame.
    pub rtt: Option<Duration>,
    /// Absolute change between consecutive locally observed smoothed RTTs;
    /// this is not a one-way delay/jitter estimate.
    pub smoothed_rtt_change: Option<Duration>,
    pub packet_loss: Option<PacketLossWindow>,
    pub business_tx: Option<BusinessThroughputWindow>,
    /// No active capacity probe or trusted billing source is implemented.
    pub available_bytes_per_second: Option<u64>,
    pub cost: Option<u64>,
}

/// Plain local inputs. The production adapter supplies only counters from its
/// original Quinn connection and completed business writes on that connection.
#[derive(Clone, Copy, Debug)]
pub struct LocalQuicSample {
    pub rtt: Duration,
    pub received_ack_frames: u64,
    pub sent_packets: u64,
    pub lost_packets: u64,
    pub business_tx_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct Timed<T> {
    at_ms: u64,
    value: T,
}
impl<T: Copy> Timed<T> {
    fn fresh(self, now_ms: u64) -> Option<T> {
        now_ms
            .checked_sub(self.at_ms)
            .filter(|age| *age < OBSERVATION_FRESHNESS_MS)
            .map(|_| self.value)
    }
}

/// Bounded pure accumulator. Idle polls do not renew measurement timestamps.
/// A reset counter or reversed clock clears every old measurement.
#[derive(Clone, Debug, Default)]
pub struct LocalPathMeasurements {
    previous: Option<(u64, LocalQuicSample)>,
    rtt: Option<Timed<Duration>>,
    jitter: Option<Timed<Duration>>,
    loss: Option<Timed<PacketLossWindow>>,
    business_tx: Option<Timed<BusinessThroughputWindow>>,
}
impl LocalPathMeasurements {
    /// Actual ACK arrival time behind the currently fresh RTT, in the local
    /// accumulator clock domain. Reading never advances that timestamp.
    pub fn rtt_observed_at_ms(&self, now_ms: u64) -> Option<u64> {
        self.previous.filter(|(at, _)| now_ms >= *at)?;
        self.rtt.filter(|timed| timed.fresh(now_ms).is_some()).map(|timed| timed.at_ms)
    }
    pub fn observe(&mut self, now_ms: u64, sample: LocalQuicSample) {
        let previous = self.previous.replace((now_ms, sample));
        if let Some((at, old)) = previous {
            if now_ms <= at
                || sample.received_ack_frames < old.received_ack_frames
                || sample.sent_packets < old.sent_packets
                || sample.lost_packets < old.lost_packets
                || sample.business_tx_bytes < old.business_tx_bytes
            {
                *self = Self {
                    previous: Some((now_ms, sample)),
                    ..Self::default()
                };
                return;
            }
            if sample.received_ack_frames > old.received_ack_frames {
                if let Some(previous) = self.rtt.and_then(|value| value.fresh(now_ms)) {
                    self.jitter = Some(Timed {
                        at_ms: now_ms,
                        value: sample.rtt.abs_diff(previous),
                    });
                } else {
                    self.jitter = None;
                }
                self.rtt = Some(Timed {
                    at_ms: now_ms,
                    value: sample.rtt,
                });
            }
            let duration_ms = now_ms - at;
            let sent_packets = sample.sent_packets - old.sent_packets;
            let lost_packets = sample.lost_packets - old.lost_packets;
            if sent_packets > 0 || lost_packets > 0 {
                self.loss = Some(Timed {
                    at_ms: now_ms,
                    value: PacketLossWindow {
                        duration_ms,
                        sent_packets,
                        newly_declared_lost_packets: lost_packets,
                    },
                });
            }
            let payload_bytes = sample.business_tx_bytes - old.business_tx_bytes;
            if payload_bytes > 0 {
                self.business_tx = Some(Timed {
                    at_ms: now_ms,
                    value: BusinessThroughputWindow {
                        duration_ms,
                        payload_bytes,
                    },
                });
            }
        }
        // The first poll is only a baseline. Requiring a subsequent ACK also
        // excludes Quinn's initial RTT estimate before actual feedback arrives.
    }

    pub fn snapshot(
        &self,
        binding: &PathObservationBinding,
        now_ms: u64,
        stopped: bool,
    ) -> PathObservationSnapshot {
        let live = !stopped && self.previous.is_some_and(|(at, _)| now_ms >= at);
        PathObservationSnapshot {
            binding: binding.clone(),
            stopped,
            rtt: live
                .then(|| self.rtt.and_then(|value| value.fresh(now_ms)))
                .flatten(),
            smoothed_rtt_change: live
                .then(|| self.jitter.and_then(|value| value.fresh(now_ms)))
                .flatten(),
            packet_loss: live
                .then(|| self.loss.and_then(|value| value.fresh(now_ms)))
                .flatten(),
            business_tx: live
                .then(|| self.business_tx.and_then(|value| value.fresh(now_ms)))
                .flatten(),
            available_bytes_per_second: None,
            cost: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> PathObservationBinding {
        PathObservationBinding {
            business_grant_digest: [1; 32],
            business_generation: 7,
            path_grant_id: Some("original-path".into()),
            transport_group: Some([2; 32]),
            route_binding: Some([3; 32]),
            purpose: Purpose::RemoteControl,
            path: Path::Relay,
            candidate: None,
            network_generation: None,
        }
    }
    fn sample() -> LocalQuicSample {
        LocalQuicSample {
            rtt: Duration::from_millis(20),
            received_ack_frames: 1,
            sent_packets: 10,
            lost_packets: 0,
            business_tx_bytes: 0,
        }
    }
    #[test]
    fn initial_estimate_idle_and_expired_feedback_are_unknown_without_rebinding() {
        let binding = binding();
        let mut measurements = LocalPathMeasurements::default();
        measurements.observe(0, sample());
        assert_eq!(measurements.snapshot(&binding, 0, false).rtt, None);
        let next = LocalQuicSample {
            received_ack_frames: 2,
            sent_packets: 12,
            lost_packets: 1,
            business_tx_bytes: 1200,
            ..sample()
        };
        measurements.observe(500, next);
        let measured = measurements.snapshot(&binding, 500, false);
        assert_eq!(measured.rtt, Some(Duration::from_millis(20)));
        assert_eq!(
            measured.packet_loss,
            Some(PacketLossWindow {
                duration_ms: 500,
                sent_packets: 2,
                newly_declared_lost_packets: 1
            })
        );
        assert_eq!(
            measured
                .business_tx
                .and_then(BusinessThroughputWindow::bytes_per_second),
            Some(2400)
        );
        for at in [1000, 2000, 3500] {
            measurements.observe(at, next);
        }
        let expired = measurements.snapshot(&binding, 3500, false);
        assert_eq!(expired.rtt, None);
        assert_eq!(expired.packet_loss, None);
        assert_eq!(expired.business_tx, None);
        assert_eq!(expired.binding, binding);
        assert_eq!(expired.available_bytes_per_second, None);
        assert_eq!(expired.cost, None);
    }
    #[test]
    fn deferred_losses_have_no_fabricated_ratio_and_stop_clears_all_live_values() {
        let mut measurements = LocalPathMeasurements::default();
        let binding = binding();
        measurements.observe(0, sample());
        measurements.observe(
            500,
            LocalQuicSample {
                rtt: Duration::from_millis(25),
                received_ack_frames: 2,
                ..sample()
            },
        );
        measurements.observe(
            1000,
            LocalQuicSample {
                rtt: Duration::from_millis(22),
                received_ack_frames: 3,
                lost_packets: 4,
                ..sample()
            },
        );
        let live = measurements.snapshot(&binding, 1000, false);
        assert_eq!(live.smoothed_rtt_change, Some(Duration::from_millis(3)));
        assert_eq!(
            live.packet_loss
                .map(|window| (window.sent_packets, window.newly_declared_lost_packets)),
            Some((0, 4))
        );
        assert_eq!(live.business_tx, None);
        let stopped = measurements.snapshot(&binding, 1000, true);
        assert!(stopped.stopped);
        assert_eq!(stopped.rtt, None);
        assert_eq!(stopped.packet_loss, None);
        assert_eq!(stopped.binding, binding);
        measurements.observe(900, sample());
        assert_eq!(measurements.snapshot(&binding, 900, false).rtt, None);
        measurements.observe(
            1500,
            LocalQuicSample {
                received_ack_frames: 0,
                ..sample()
            },
        );
        assert_eq!(
            measurements.snapshot(&binding, 1500, false).packet_loss,
            None
        );
    }
    #[test]
    fn genuine_feedback_time_survives_cached_reads_and_idle_polls_until_expiry() {
        let mut measurements = LocalPathMeasurements::default();
        measurements.observe(0, sample());
        assert_eq!(measurements.rtt_observed_at_ms(0), None);
        let acknowledged = LocalQuicSample { received_ack_frames: 2, ..sample() };
        measurements.observe(500, acknowledged);
        for now in [500, 999, 2000, 3499] { assert_eq!(measurements.rtt_observed_at_ms(now), Some(500)); }
        measurements.observe(3000, acknowledged);
        assert_eq!(measurements.rtt_observed_at_ms(3000), Some(500));
        assert_eq!(measurements.rtt_observed_at_ms(2999), None);
        assert_eq!(measurements.rtt_observed_at_ms(3500), None);
        assert_eq!(measurements.rtt_observed_at_ms(499), None);
        measurements.observe(3501, LocalQuicSample { received_ack_frames: 3, ..sample() });
        assert_eq!(measurements.rtt_observed_at_ms(3501), Some(3501));
    }
}
