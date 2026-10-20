//! Bounded deduplication of authenticated signaling observations. A prepared
//! HTTP response is not evidence that the remote endpoint consumed its body.
use nestlink_protocol::diagnostics::{ConnectionStage, SignalSummary, request_hash};
use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const OBSERVATION_LIMIT: usize = 1024;

#[derive(PartialEq, Eq)]
struct ObservationKey {
    request: String,
    observer: String,
    sender: String,
    connection: u64,
    stage: ConnectionStage,
    signal: SignalSummary,
}

pub(crate) struct SignalDiagnostics {
    started: Instant,
    seen: Mutex<VecDeque<ObservationKey>>,
}
impl Default for SignalDiagnostics {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            seen: Mutex::new(VecDeque::new()),
        }
    }
}
impl SignalDiagnostics {
    fn first(&self, key: ObservationKey) -> bool {
        let Ok(mut seen) = self.seen.lock() else {
            return false;
        };
        if seen.contains(&key) {
            return false;
        }
        if seen.len() == OBSERVATION_LIMIT {
            seen.pop_front();
        }
        seen.push_back(key);
        true
    }
    pub(crate) fn record(
        &self,
        request: &str,
        observer_session: &str,
        sender_device: &str,
        stage: ConnectionStage,
        connection_generation: u64,
        signal: SignalSummary,
    ) {
        let request_sha256 = request_hash(request);
        let observer_sha256 = request_hash(observer_session);
        let sender_sha256 = request_hash(sender_device);
        if !self.first(ObservationKey {
            request: request_sha256.clone(),
            observer: observer_sha256.clone(),
            sender: sender_sha256.clone(),
            connection: connection_generation,
            stage,
            signal,
        }) {
            return;
        }
        tracing::info!(event = "connection_timeline", role = "server",
            request_sha256, observer_session_sha256 = observer_sha256, sender_device_sha256 = sender_sha256,
            connection_generation,
            elapsed_ms = self.started.elapsed().as_millis() as u64,
            unix_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_millis() as u64),
            stage = ?stage, network_generation = signal.network_generation,
            sequence = signal.sequence, description_sequence = signal.description_sequence,
            lease_sequence = signal.lease_sequence, candidate_count = signal.candidate_count,
            end_of_candidates = signal.end_of_candidates,
            "authenticated signaling observation");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(sequence: u64, observer: &str) -> ObservationKey {
        ObservationKey {
            request: request_hash("request"),
            observer: request_hash(observer),
            sender: request_hash("sender"),
            connection: 9,
            stage: ConnectionStage::SignalResponsePrepared,
            signal: SignalSummary {
                network_generation: 1,
                sequence,
                description_sequence: 1,
                lease_sequence: 1,
                candidate_count: 2,
                end_of_candidates: false,
            },
        }
    }
    #[test]
    fn repeated_poll_is_deduplicated_per_reader_and_history_is_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let trace = SignalDiagnostics::default();
        assert!(trace.first(key(1, "reader-one")));
        assert!(!trace.first(key(1, "reader-one")));
        assert!(trace.first(key(1, "reader-two")));
        for sequence in 2..1100 {
            assert!(trace.first(key(sequence, "reader-one")));
        }
        assert_eq!(
            trace.seen.lock().map_err(|_| "diagnostics poisoned")?.len(),
            OBSERVATION_LIMIT
        );
        assert!(!trace.first(key(1099, "reader-one")));
        assert!(trace.first(key(1, "reader-one")));
        assert_eq!(
            trace.seen.lock().map_err(|_| "diagnostics poisoned")?.len(),
            OBSERVATION_LIMIT
        );
        Ok(())
    }
}
