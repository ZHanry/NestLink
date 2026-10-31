//! An authenticated live edge must keep advancing its original signed lease.
//! This local availability cap can only shorten the independent publication
//! deadline. It neither signs authority nor changes the original byte budget.
use super::*;

pub(super) struct RenewalFreshness {
    sequence: u64,
    deadline: Instant,
}
impl RenewalFreshness {
    pub(super) fn new(sequence: u64, now: Instant) -> Self {
        Self {
            sequence,
            deadline: now + Duration::from_millis(SERVICE_RESOURCE_MS),
        }
    }
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }
    /// The caller first verifies the pinned issuer, exact target and original
    /// publication binding. Replays cannot reset this stream's observation cap.
    pub(super) fn advanced(&mut self, sequence: u64, now: Instant) -> Result<(), SdkError> {
        if now >= self.deadline {
            return Err(SdkError::Timeout);
        }
        if sequence > self.sequence {
            self.sequence = sequence;
            self.deadline = now + Duration::from_millis(SERVICE_RESOURCE_MS);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_edge_progress_gap_and_replays_cannot_extend_or_revive_health()
    -> Result<(), SdkError> {
        let start = Instant::now();
        let mut observation = RenewalFreshness::new(7, start);
        let original = start + Duration::from_millis(SERVICE_RESOURCE_MS);
        observation.advanced(7, start + Duration::from_millis(500))?;
        observation.advanced(6, start + Duration::from_millis(1000))?;
        assert_eq!(observation.deadline(), original);
        let progressed = start + Duration::from_millis(1500);
        observation.advanced(8, progressed)?;
        assert_eq!(
            observation.deadline(),
            progressed + Duration::from_millis(SERVICE_RESOURCE_MS)
        );
        let final_deadline = observation.deadline();
        observation.advanced(8, final_deadline - Duration::from_millis(1))?;
        assert_eq!(observation.deadline(), final_deadline);
        assert!(observation.advanced(9, final_deadline).is_err());
        assert!(
            observation
                .advanced(10, final_deadline + Duration::from_millis(1))
                .is_err()
        );
        assert_eq!(observation.deadline(), final_deadline);
        Ok(())
    }
}
