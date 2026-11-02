//! Bounded actual DXGI-submit timestamps from one exact receiver worker.
//! These are local QPC values, never capture-to-display latency or scanout.
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const MAX_RECENT: usize = 512;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmissionCadence {
    first_qpc: Option<u64>,
    last_qpc: Option<u64>,
    frame_count: u64,
    invalid_timestamps: u64,
    recent_qpc: VecDeque<u64>,
}
impl SubmissionCadence {
    /// O(1), bounded, no clock reads, storage, statistics or authorization work.
    /// Invalid native timestamps stay visible without affecting media delivery.
    pub(crate) fn record(&mut self, qpc: u64) {
        if self.last_qpc.is_some_and(|previous| qpc <= previous) {
            self.invalid_timestamps = self.invalid_timestamps.saturating_add(1);
            return;
        }
        self.first_qpc.get_or_insert(qpc);
        self.last_qpc = Some(qpc);
        self.frame_count = self.frame_count.saturating_add(1);
        if self.recent_qpc.len() == MAX_RECENT {
            self.recent_qpc.pop_front();
        }
        self.recent_qpc.push_back(qpc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_lifetime_is_retained_when_the_actual_recent_window_rotates() {
        let mut value = SubmissionCadence::default();
        for qpc in 0..4097 {
            value.record(qpc * 1000);
        }
        assert_eq!(value.first_qpc, Some(0));
        assert_eq!(value.last_qpc, Some(4_096_000));
        assert_eq!(value.frame_count, 4097);
        assert_eq!(value.recent_qpc.len(), MAX_RECENT);
        assert_eq!(value.recent_qpc.front(), Some(&3_585_000));
        assert_eq!(value.recent_qpc.back(), Some(&4_096_000));
    }
    #[test]
    fn duplicate_or_reversed_native_clock_is_visible_and_does_not_replace_history() {
        let mut value = SubmissionCadence::default();
        value.record(10);
        value.record(10);
        value.record(9);
        value.record(u64::MAX);
        value.record(0);
        assert_eq!(value.frame_count, 2);
        assert_eq!(value.invalid_timestamps, 3);
        assert_eq!(value.recent_qpc, VecDeque::from([10, u64::MAX]));
    }
}
