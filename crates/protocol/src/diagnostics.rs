//! Redacted observations only. These records never grant authority and contain
//! no SDP, addresses, keys, credentials, device names or free-form errors.
use crate::api::SignalPayload;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

pub const TIMELINE_EVENT_LIMIT: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    PathChecking,
    TurnBindingExpired,
    TurnBindingReady,
    TurnCredentialsRefresh,
    TurnBindingRead,
    TurnBindingValidate,
    TurnBindingSign,
    TrackAwaitAuthorization,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub candidate_profile: CandidateProfile,
}

/// Counts from signed signaling only; no address, port, foundation or SDP is
/// retained. These observations never grant candidate or relay authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateProfile {
    pub host_v4: usize,
    pub host_v6: usize,
    pub host_mdns: usize,
    pub srflx_v4: usize,
    pub srflx_v6: usize,
    pub relay_v4: usize,
    pub relay_v6: usize,
    pub tcp: usize,
    pub other: usize,
}
impl CandidateProfile {
    fn add(&mut self, candidate: &str) {
        let candidate = candidate
            .trim_start_matches("a=")
            .trim_start_matches("candidate:");
        let fields: Vec<_> = candidate.split_ascii_whitespace().collect();
        if fields.len() < 8 || fields[6] != "typ" {
            self.other += 1;
            return;
        }
        if fields[2].eq_ignore_ascii_case("tcp") {
            self.tcp += 1;
            return;
        }
        if !fields[2].eq_ignore_ascii_case("udp") {
            self.other += 1;
            return;
        }
        use std::net::IpAddr;
        let counter = match (fields[7], fields[4].parse::<IpAddr>()) {
            ("host", Ok(IpAddr::V4(_))) => &mut self.host_v4,
            ("host", Ok(IpAddr::V6(_))) => &mut self.host_v6,
            ("host", Err(_)) if fields[4].ends_with(".local") => &mut self.host_mdns,
            ("srflx", Ok(IpAddr::V4(_))) => &mut self.srflx_v4,
            ("srflx", Ok(IpAddr::V6(_))) => &mut self.srflx_v6,
            ("relay", Ok(IpAddr::V4(_))) => &mut self.relay_v4,
            ("relay", Ok(IpAddr::V6(_))) => &mut self.relay_v6,
            _ => &mut self.other,
        };
        *counter += 1;
    }
}
impl SignalSummary {
    pub fn from_payload(payload: &SignalPayload) -> Self {
        let mut candidate_profile = CandidateProfile::default();
        if let Some(ice) = &payload.ice {
            for candidate in &ice.candidates {
                candidate_profile.add(&candidate.candidate);
            }
        } else if let Some(description) = &payload.description {
            for candidate in description
                .sdp
                .lines()
                .filter(|line| line.starts_with("a=candidate:"))
            {
                candidate_profile.add(candidate);
            }
        }
        Self {
            candidate_profile,
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

/// Aggregate ICE checks only. No candidate IDs, addresses, ports or SDP.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceCheckPath {
    pub pairs: u64,
    pub in_progress: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub nominated: u64,
    /// None means the implementation does not expose an implemented counter.
    pub requests_sent: Option<u64>,
    pub requests_received: Option<u64>,
    pub responses_sent: Option<u64>,
    pub responses_received: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceCheckSnapshot {
    pub elapsed_ms: u64,
    pub direct: IceCheckPath,
    pub relay: IceCheckPath,
    pub unknown: IceCheckPath,
}
impl IceCheckSnapshot {
    /// Closing a peer may return an empty report. Retain the last checklist
    /// instead of replacing the only useful failure evidence with that report.
    pub fn retain_latest(previous: &mut Option<Self>, next: Self) {
        let has_pairs = next.direct.pairs > 0 || next.relay.pairs > 0 || next.unknown.pairs > 0;
        if has_pairs || previous.is_none() {
            *previous = Some(next);
        }
    }
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
    pub last_ice_check: Option<IceCheckSnapshot>,
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
            last_ice_check: None,
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
    fn closing_report_preserves_last_checks_but_live_checks_can_advance() {
        let mut last = None;
        IceCheckSnapshot::retain_latest(&mut last, IceCheckSnapshot::default());
        let checked = IceCheckSnapshot {
            elapsed_ms: 100,
            direct: IceCheckPath {
                pairs: 3,
                failed: 3,
                requests_sent: Some(21),
                ..Default::default()
            },
            ..Default::default()
        };
        IceCheckSnapshot::retain_latest(&mut last, checked);
        IceCheckSnapshot::retain_latest(
            &mut last,
            IceCheckSnapshot {
                elapsed_ms: 200,
                ..Default::default()
            },
        );
        assert_eq!(last, Some(checked));
        let advanced = IceCheckSnapshot {
            elapsed_ms: 300,
            relay: IceCheckPath {
                pairs: 1,
                succeeded: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        IceCheckSnapshot::retain_latest(&mut last, advanced);
        assert_eq!(last, Some(advanced));
    }
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
            rendezvous: None,
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
        assert_eq!(summary.candidate_profile.host_v4, 1);
        for private in ["private-credential", "192.0.2.1", "5000", "sdp", "dtls"] {
            assert!(!serialized.contains(private));
        }
        Ok(())
    }
    #[test]
    fn candidate_profile_counts_address_families_and_transport_without_retaining_them()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut profile = CandidateProfile::default();
        for candidate in [
            "a=candidate:1 1 UDP 100 192.0.2.1 5000 typ host",
            "candidate:2 1 udp 100 2001:db8::1 5001 typ host",
            "candidate:3 1 UDP 100 private-name.local 5002 typ host",
            "candidate:4 1 UDP 100 192.0.2.2 5003 typ srflx",
            "candidate:5 1 UDP 100 2001:db8::2 5004 typ srflx",
            "candidate:6 1 UDP 100 192.0.2.3 5005 typ relay",
            "candidate:7 1 UDP 100 2001:db8::3 5006 typ relay",
            "candidate:8 1 TCP 100 192.0.2.4 5007 typ host tcptype active",
            "malformed",
        ] {
            profile.add(candidate);
        }
        assert_eq!(
            profile,
            CandidateProfile {
                host_v4: 1,
                host_v6: 1,
                host_mdns: 1,
                srflx_v4: 1,
                srflx_v6: 1,
                relay_v4: 1,
                relay_v6: 1,
                tcp: 1,
                other: 1,
            }
        );
        let json = serde_json::to_string(&profile)?;
        for private in ["192.0.2", "2001:db8", "private-name", "5000"] {
            assert!(!json.contains(private));
        }
        let legacy: SignalSummary = serde_json::from_str(
            r#"{"network_generation":1,"sequence":1,"description_sequence":1,"lease_sequence":1,"candidate_count":1,"end_of_candidates":false}"#,
        )?;
        assert_eq!(legacy.candidate_profile, CandidateProfile::default());
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
