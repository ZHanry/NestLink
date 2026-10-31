//! Projection of the original session's read-only local observations. This
//! module cannot dial, renew credentials, select a successor or close owners.
use super::*;
use crate::{
    NativeBusinessTxWindow, NativePacketObservationWindow, NativePathObservationBindingView,
    NativePathQualityView,
};
use nestlink_protocol::api::Candidate;
use nestlink_remote::PathObservationSnapshot;

pub(super) fn selected_carrier(
    candidate: &Candidate,
    bilateral_ice: bool,
) -> NativePathQualityView {
    NativePathQualityView {
        transport: candidate.transport,
        candidate_kind: candidate.kind,
        network_generation: candidate.generation,
        bilateral_ice,
        original_binding: None,
        rtt_us: None,
        smoothed_rtt_change_us: None,
        packet_window: None,
        business_tx: None,
        available_bytes_per_second: None,
        cost: None,
    }
}

pub(super) fn selected_routed_carrier() -> NativePathQualityView {
    NativePathQualityView {
        transport: nestlink_protocol::api::Transport::Quic,
        candidate_kind: nestlink_protocol::api::CandidateKind::Relay,
        // Routed authority has no ICE network generation. Zero is the existing
        // unknown value; the exact signed route binding follows in observations.
        network_generation: 0,
        bilateral_ice: false,
        original_binding: None,
        rtt_us: None,
        smoothed_rtt_change_us: None,
        packet_window: None,
        business_tx: None,
        available_bytes_per_second: None,
        cost: None,
    }
}

fn micros(value: Duration) -> Option<u64> {
    u64::try_from(value.as_micros()).ok()
}

fn current_quality(
    session: &NativeSessionView,
    original: Option<(&str, u64)>,
    sample: Option<&PathObservationSnapshot>,
) -> Option<NativePathQualityView> {
    if session.status != NativeSessionStatus::Connected
        || original != Some((session.request_id.as_str(), session.connection_generation))
    {
        return None;
    }
    let mut quality = session.quality.clone()?;
    let Some(sample) = sample else {
        // TLS/WSS has selected-carrier facts but no Quinn measurement source.
        return quality.original_binding.is_none().then_some(quality);
    };
    let binding = &sample.binding;
    let carrier_matches = match &binding.candidate {
        Some(candidate) => {
            candidate.transport == quality.transport
                && candidate.kind == quality.candidate_kind
                && candidate.generation == quality.network_generation
                && Some(candidate.generation) == binding.network_generation
        }
        None => {
            binding.path == nestlink_protocol::Path::Relay
                && binding.path_grant_id.is_some()
                && binding.transport_group.is_some()
                && binding.route_binding.is_some()
                && binding.network_generation.is_none()
                && quality.transport == nestlink_protocol::api::Transport::Quic
                && quality.candidate_kind == nestlink_protocol::api::CandidateKind::Relay
                && quality.network_generation == 0
                && !quality.bilateral_ice
        }
    };
    if sample.stopped
        || binding.business_generation != session.connection_generation
        || Some(binding.path as i32) != session.path
        || binding.purpose != nestlink_protocol::network::Purpose::RemoteControl
        || !carrier_matches
    {
        return None;
    }
    let original_binding = NativePathObservationBindingView {
        business_grant_sha256: binding.business_grant_digest,
        business_generation: binding.business_generation,
        path_grant_id: binding.path_grant_id.clone(),
        transport_group: binding.transport_group,
        route_binding: binding.route_binding,
    };
    if quality
        .original_binding
        .as_ref()
        .is_some_and(|original| *original != original_binding)
    {
        return None;
    }
    quality.original_binding = Some(original_binding);
    quality.rtt_us = sample.rtt.and_then(micros);
    quality.smoothed_rtt_change_us = sample.smoothed_rtt_change.and_then(micros);
    quality.packet_window = sample
        .packet_loss
        .map(|window| NativePacketObservationWindow {
            duration_ms: window.duration_ms,
            sent_packets: window.sent_packets,
            newly_declared_lost_packets: window.newly_declared_lost_packets,
        });
    quality.business_tx = sample.business_tx.map(|window| NativeBusinessTxWindow {
        duration_ms: window.duration_ms,
        payload_bytes: window.payload_bytes,
        bytes_per_second: window.bytes_per_second(),
    });
    quality.available_bytes_per_second = sample.available_bytes_per_second;
    quality.cost = sample.cost;
    Some(quality)
}

impl Actor {
    pub(super) fn poll_native_quality(&mut self) {
        let Some(session) = self.view.native_session.data.as_ref() else {
            return;
        };
        let current = self.view.lifecycle == Lifecycle::Running
            && self.view.generation == self.shared.generation.load(Ordering::Acquire)
            && !self.shared.closing.load(Ordering::Acquire)
            && !self.retire
            && self.boundary.is_none();
        let quality = if current {
            self.native_session_control.as_ref().and_then(|control| {
                let sample = control
                    .path_observation()
                    .map(|observation| observation.snapshot());
                current_quality(
                    session,
                    self.native_session_key
                        .as_ref()
                        .map(|key| (key.request_id.as_str(), key.connection_generation)),
                    sample.as_ref(),
                )
            })
        } else {
            None
        };
        if session.quality != quality {
            let mut session = session.as_ref().clone();
            session.quality = quality;
            self.view.native_session.data = Some(Arc::new(session));
            self.publish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_protocol::{
        Path,
        api::{CandidateKind, Transport},
        network::Purpose,
    };
    use nestlink_remote::{BusinessThroughputWindow, PacketLossWindow, PathObservationBinding};

    #[test]
    fn routed_observation_requires_all_signed_group_bindings_and_has_no_ice_generation() {
        let mut session = session();
        session.path = Some(Path::Relay as i32);
        session.quality = Some(selected_routed_carrier());
        let mut observation = sample();
        observation.binding.path = Path::Relay;
        observation.binding.candidate = None;
        observation.binding.network_generation = None;
        observation.binding.path_grant_id = Some("fixed original path".into());
        observation.binding.transport_group = Some([7; 32]);
        observation.binding.route_binding = Some([8; 32]);
        let projected =
            current_quality(&session, Some(("original-request", 7)), Some(&observation));
        assert!(projected.is_some());
        session.quality = projected;
        for mutation in 0..5 {
            let mut forged = observation.clone();
            match mutation {
                0 => forged.binding.path_grant_id = None,
                1 => forged.binding.transport_group = None,
                2 => forged.binding.route_binding = None,
                3 => forged.binding.network_generation = Some(1),
                _ => forged.binding.route_binding = Some([9; 32]),
            }
            assert!(
                current_quality(&session, Some(("original-request", 7)), Some(&forged)).is_none()
            );
        }
    }

    fn session() -> NativeSessionView {
        NativeSessionView {
            request_id: "original-request".into(),
            connection_generation: 7,
            lease_sequence: 2,
            status: NativeSessionStatus::Connected,
            host_view_authorized: false,
            path: Some(Path::Direct as i32),
            quality: Some(selected_carrier(
                &Candidate {
                    address: std::net::SocketAddr::from(([192, 0, 2, 1], 1234)),
                    transport: Transport::Quic,
                    kind: CandidateKind::Reflexive,
                    generation: 5,
                },
                true,
            )),
            stop_reason: None,
            stop_effects: None,
            cleanup: None,
            failure: None,
        }
    }

    fn sample() -> PathObservationSnapshot {
        PathObservationSnapshot {
            binding: PathObservationBinding {
                business_grant_digest: [3; 32],
                business_generation: 7,
                path_grant_id: None,
                transport_group: None,
                route_binding: None,
                purpose: Purpose::RemoteControl,
                path: Path::Direct,
                candidate: Some(Candidate {
                    address: std::net::SocketAddr::from(([192, 0, 2, 1], 1234)),
                    transport: Transport::Quic,
                    kind: CandidateKind::Reflexive,
                    generation: 5,
                }),
                network_generation: Some(5),
            },
            stopped: false,
            rtt: Some(Duration::from_millis(23)),
            smoothed_rtt_change: Some(Duration::from_millis(4)),
            packet_loss: Some(PacketLossWindow {
                duration_ms: 500,
                sent_packets: 2,
                newly_declared_lost_packets: 3,
            }),
            business_tx: Some(BusinessThroughputWindow {
                duration_ms: 500,
                payload_bytes: 2000,
            }),
            available_bytes_per_second: None,
            cost: None,
        }
    }

    #[test]
    fn terminal_and_replacement_generations_cannot_reuse_original_measurements() {
        let mut session = session();
        let sample = sample();
        session.quality = current_quality(&session, Some(("original-request", 7)), Some(&sample));
        assert!(session.quality.is_some());
        // An ordinary renewal keeps the original observation binding rather
        // than relabeling measurements with the new permit sequence.
        session.lease_sequence += 1;
        assert_eq!(
            current_quality(&session, Some(("original-request", 7)), Some(&sample)),
            session.quality
        );
        assert!(current_quality(&session, Some(("other-request", 7)), Some(&sample)).is_none());
        assert!(current_quality(&session, Some(("original-request", 8)), Some(&sample)).is_none());
        let mut stopped = sample.clone();
        stopped.stopped = true;
        assert!(current_quality(&session, Some(("original-request", 7)), Some(&stopped)).is_none());
        let mut replacement = sample.clone();
        replacement.binding.business_grant_digest = [9; 32];
        assert!(
            current_quality(&session, Some(("original-request", 7)), Some(&replacement)).is_none()
        );
        for status in [
            NativeSessionStatus::Establishing,
            NativeSessionStatus::Stopping,
            NativeSessionStatus::Stopped,
            NativeSessionStatus::Failed,
        ] {
            session.status = status;
            assert!(
                current_quality(&session, Some(("original-request", 7)), Some(&sample)).is_none()
            );
        }
    }

    #[test]
    fn expiration_remains_unknown_and_counters_are_not_fabricated_probabilities()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut session = session();
        let mut sample = sample();
        let measured = current_quality(&session, Some(("original-request", 7)), Some(&sample))
            .ok_or("original live observation missing")?;
        assert_eq!(
            measured
                .business_tx
                .and_then(|window| window.bytes_per_second),
            Some(4000)
        );
        assert_eq!(
            measured
                .packet_window
                .map(|window| window.newly_declared_lost_packets),
            Some(3)
        );
        session.quality = Some(measured);
        sample.rtt = None;
        sample.smoothed_rtt_change = None;
        sample.packet_loss = None;
        sample.business_tx = None;
        let expired = current_quality(&session, Some(("original-request", 7)), Some(&sample))
            .ok_or("carrier missing after measurements expire")?;
        assert_eq!(expired.rtt_us, None);
        assert_eq!(expired.packet_window, None);
        assert_eq!(expired.business_tx, None);
        assert_eq!(expired.available_bytes_per_second, None);
        assert_eq!(expired.cost, None);
        Ok(())
    }

    #[test]
    fn candidate_and_network_generation_must_match_the_original_selected_carrier() {
        let session = session();
        for mutation in 0..5 {
            let mut sample = sample();
            match mutation {
                0 => sample.binding.network_generation = None,
                1 => sample.binding.network_generation = Some(6),
                2 => sample.binding.candidate = None,
                3 => {
                    if let Some(candidate) = &mut sample.binding.candidate {
                        candidate.generation = 6;
                    }
                    sample.binding.network_generation = Some(6);
                }
                _ => {
                    if let Some(candidate) = &mut sample.binding.candidate {
                        candidate.transport = Transport::Tls;
                    }
                }
            }
            assert!(
                current_quality(&session, Some(("original-request", 7)), Some(&sample)).is_none()
            );
        }
    }

    #[test]
    fn old_ipc_session_without_quality_still_decodes() -> Result<(), serde_json::Error> {
        let decoded: NativeSessionView = serde_json::from_str(
            r#"{
            "request_id":"old-session", "connection_generation":7,
            "lease_sequence":2, "status":"connected", "host_view_authorized":false,
            "path":1, "stop_reason":null, "stop_effects":null, "cleanup":null, "failure":null
        }"#,
        )?;
        assert_eq!(decoded.quality, None);
        Ok(())
    }
}
