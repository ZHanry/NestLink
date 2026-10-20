//! Redacted observations only. These records never grant authority and contain
//! no SDP, addresses, keys, credentials, device names or free-form errors.
use crate::api::SignalPayload;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

pub const TIMELINE_EVENT_LIMIT: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStage {
    RequestStarted,
    IdentityReady,
    RequestSubmitting,
    RequestSubmitted,
    AwaitApproval,
    ApprovalGranted,
    AwaitHostReadiness,
    HostReady,
    PermitReceived,
    PeerCreating,
    PeerCreated,
    LocalDescriptionSet,
    SignalSubmitted,
    SignalAccepted,
    SignalResponsePrepared,
    SignalConsumed,
    RemoteDescriptionSet,
    LocalCandidates,
    RemoteCandidates,
    GatherComplete,
    PathVerified,
    EndpointProved,
    RunningAuthorized,
    DisplaySelected,
    FirstPacketObserved,
    FirstDecodedFrameObserved,
    FirstVideoProgressObserved,
    IceRestart,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionFailure {
    Unclassified,
    InvalidConfiguration,
    InvalidAuthorization,
    AuthorizationExpired,
    StartupAuthorizationExpired,
    EndpointMismatch,
    CodecUnavailable,
    TrackNotAuthorized,
    PathNotPermitted,
    RelayUnavailable,
    NoSelectedPair,
    SelectedPairRejected,
    SignalingRejected,
    AnswerNotConsumed,
    IceCheckTimeout,
    ProofTimeout,
    FirstFrameTimeout,
    OperationTimeout,
    BrowserUnavailable,
    BrowserOperation,
    Cancelled,
    ManagementTransport,
    ManagementRejected,
    SignInRequired,
    AuthorizationRevoked,
    InvalidResponse,
    IdentityStorageUnavailable,
    IdentityInvalid,
    ApprovalTimeout,
    ApprovalRejected,
    HostReadinessTimeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalSummary {
    pub network_generation: u64,
    pub sequence: u64,
    pub description_sequence: u64,
    pub lease_sequence: u64,
    pub candidate_count: usize,
    pub end_of_candidates: bool,
}
impl SignalSummary {
    pub fn from_payload(payload: &SignalPayload) -> Self {
        Self {
            network_generation: payload.network_generation,
            sequence: payload.sequence,
            description_sequence: payload.description_sequence(),
            lease_sequence: payload.lease_sequence,
            candidate_count: payload.ice.as_ref().map_or_else(
                || {
                    payload
                        .description
                        .as_ref()
                        .map_or(payload.candidates.len(), |description| {
                            description
                                .sdp
                                .lines()
                                .filter(|line| line.starts_with("a=candidate:"))
                                .count()
                        })
                },
                |ice| ice.candidates.len(),
            ),
            end_of_candidates: payload
                .ice
                .as_ref()
                .is_some_and(|ice| ice.end_of_candidates),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionObservation {
    pub elapsed_ms: u64,
    pub stage: ConnectionStage,
    pub signal: Option<SignalSummary>,
    pub failure: Option<ConnectionFailure>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionTimeline {
    pub schema_version: u8,
    pub request_sha256: String,
    pub connection_generation: u64,
    pub local_device_sha256: Option<String>,
    pub remote_device_sha256: Option<String>,
    /// An anchor for log correlation, not a cross-machine latency sample.
    pub started_unix_ms: u64,
    pub events: VecDeque<ConnectionObservation>,
    pub dropped_events: u64,
    pub first_failure: Option<ConnectionObservation>,
}
impl ConnectionTimeline {
    pub fn new(request: &str, generation: u64, started_unix_ms: u64) -> Self {
        Self {
            schema_version: 1,
            request_sha256: request_hash(request),
            connection_generation: generation,
            local_device_sha256: None,
            remote_device_sha256: None,
            started_unix_ms,
            events: VecDeque::new(),
            dropped_events: 0,
            first_failure: None,
        }
    }
    /// Attach a verified permit's correlation keys to pre-permit observations.
    /// A failed diagnostic binding never mutates or authorizes the session.
    pub fn bind_authority(
        &mut self,
        request: &str,
        generation: u64,
        local: &str,
        remote: &str,
    ) -> bool {
        let local = request_hash(local);
        let remote = request_hash(remote);
        if generation == 0
            || self.request_sha256 != request_hash(request)
            || (self.connection_generation != 0 && self.connection_generation != generation)
            || self
                .local_device_sha256
                .as_ref()
                .is_some_and(|value| value != &local)
            || self
                .remote_device_sha256
                .as_ref()
                .is_some_and(|value| value != &remote)
        {
            return false;
        }
        self.connection_generation = generation;
        self.local_device_sha256 = Some(local);
        self.remote_device_sha256 = Some(remote);
        true
    }
    pub fn observe(&mut self, event: ConnectionObservation) {
        // A regressed local clock is missing evidence, never a negative latency
        // or a reason to change the live authorization/session state.
        if self
            .events
            .back()
            .is_some_and(|last| event.elapsed_ms < last.elapsed_ms)
        {
            return;
        }
        if event.failure.is_some() && self.first_failure.is_none() {
            self.first_failure = Some(event);
        }
        if self.events.back().is_some_and(|last| {
            last.stage == event.stage
                && last.signal == event.signal
                && last.failure == event.failure
        }) {
            return;
        }
        if self.events.len() == TIMELINE_EVENT_LIMIT {
            self.events.pop_front();
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.events.push_back(event);
    }
}

pub fn request_hash(request: &str) -> String {
    Sha256::digest(request.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preflight_binding_cannot_mix_requests_generations_or_endpoint_identities()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut trace = ConnectionTimeline::new("request", 0, 1000);
        trace.remote_device_sha256 = Some(request_hash("host"));
        for (request, generation, local, remote) in [
            ("other", 1, "controller", "host"),
            ("request", 0, "controller", "host"),
            ("request", 1, "controller", "other-host"),
        ] {
            let before = serde_json::to_value(&trace)?;
            assert!(!trace.bind_authority(request, generation, local, remote));
            assert_eq!(serde_json::to_value(&trace)?, before);
        }
        assert!(trace.bind_authority("request", 7, "controller", "host"));
        assert!(trace.bind_authority("request", 7, "controller", "host"));
        for (generation, local, remote) in [
            (8, "controller", "host"),
            (7, "other", "host"),
            (7, "controller", "other"),
        ] {
            let before = serde_json::to_value(&trace)?;
            assert!(!trace.bind_authority("request", generation, local, remote));
            assert_eq!(serde_json::to_value(&trace)?, before);
        }
        Ok(())
    }
    #[test]
    fn signal_summary_never_serializes_description_or_candidate_secrets()
    -> Result<(), Box<dyn std::error::Error>> {
        let payload = SignalPayload {
            connection_generation: 9, lease_sequence: 2, network_generation: 3, sequence: 4,
            candidates: Vec::new(), ice: None,
            description: Some(crate::api::WebRtcDescription { kind: "answer".into(),
                sdp: "a=ice-pwd:private-credential\r\na=candidate:1 1 UDP 100 192.0.2.1 5000 typ host\r\n".into(),
                dtls_sha256: vec![7;32], in_reply_to_sequence: Some(1) }),
        };
        let summary = SignalSummary::from_payload(&payload);
        assert_eq!(
            (
                summary.sequence,
                summary.lease_sequence,
                summary.candidate_count
            ),
            (4, 2, 1)
        );
        let serialized = serde_json::to_string(&summary)?;
        for private in ["private-credential", "192.0.2.1", "5000", "sdp", "dtls"] {
            assert!(!serialized.contains(private));
        }
        Ok(())
    }
    #[test]
    fn bounded_timeline_retains_first_failure_and_never_rewinds_clock()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut trace = ConnectionTimeline::new("private-request", 9, 1000);
        let first = ConnectionObservation {
            elapsed_ms: 1,
            stage: ConnectionStage::PathVerified,
            signal: None,
            failure: Some(ConnectionFailure::IceCheckTimeout),
        };
        trace.observe(first);
        for elapsed_ms in 2..300 {
            trace.observe(ConnectionObservation {
                elapsed_ms,
                stage: if elapsed_ms % 2 == 0 {
                    ConnectionStage::IceRestart
                } else {
                    ConnectionStage::SignalSubmitted
                },
                signal: None,
                failure: None,
            });
        }
        assert_eq!(trace.events.len(), TIMELINE_EVENT_LIMIT);
        assert_eq!(trace.first_failure, Some(first));
        let last = *trace.events.back().ok_or("missing last event")?;
        trace.observe(first);
        trace.observe(last);
        assert_eq!(trace.events.back(), Some(&last));
        assert_eq!(trace.events.len(), TIMELINE_EVENT_LIMIT);
        let json = serde_json::to_string(&trace)?;
        assert!(!json.contains("private-request"));
        assert_eq!(trace.request_sha256.len(), 64);
        assert!(trace.dropped_events > 0);
        Ok(())
    }
}
