//! Cumulative Trickle ICE for the existing last-value signed signaling store.
//! The immutable SDP and logical description sequence are retained in each
//! snapshot. Lost polls need no unbounded log, retransmission or pre-SDP queue.
use crate::{CANDIDATE_COUNT, ContractError, ErrorCode, PermitClaims, api::*};

pub const TRICKLE_CAPABILITY: &str = "webrtc-trickle-v1";
pub const SETUP_CAPABILITY: &str = "setup-budget-v1";
pub const SETUP_BUDGET_MS: u64 = 30_000;

/// Empty features retain the v0.6 transcript byte-for-byte. Nonempty feature
/// claims are covered by the host's device signature, not a server guess.
pub fn readiness_payload(generation: u64, features: &[String]) -> Result<Vec<u8>, ContractError> {
    if features.len() > 2
        || features.iter().enumerate().any(|(i, feature)| {
            !matches!(feature.as_str(), TRICKLE_CAPABILITY | SETUP_CAPABILITY)
                || features[..i].contains(feature)
        })
    {
        return Err(invalid());
    }
    if features.is_empty() {
        return Ok(generation.to_be_bytes().to_vec());
    }
    serde_json::to_vec(&(generation, features)).map_err(|_| invalid())
}

fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid ICE snapshot")
}

impl SignalPayload {
    pub fn description_sequence(&self) -> u64 {
        self.ice
            .as_ref()
            .map_or(self.sequence, |ice| ice.description_sequence)
    }
    pub fn validate_ice(&self, permit: &PermitClaims) -> Result<(), ContractError> {
        let Some(ice) = &self.ice else {
            return Ok(());
        };
        let description = self.description.as_ref().ok_or_else(invalid)?;
        if !permit
            .required_capabilities
            .iter()
            .any(|c| c == TRICKLE_CAPABILITY)
            || ice.description_sequence == 0
            || ice.description_sequence > self.sequence
            || ice.candidates.len() > CANDIDATE_COUNT as usize
        {
            return Err(invalid());
        }
        // Validate strings through the same address/path policy used by SDP.
        // The index and ufrag bind each candidate to one immutable SDP section.
        let sections = media_sections(&description.sdp);
        for (index, candidate) in ice.candidates.iter().enumerate() {
            let Some((mid, ufrag)) = sections.get(usize::from(candidate.sdp_m_line_index)) else {
                return Err(invalid());
            };
            if candidate.candidate.len() > 2048
                || !candidate.candidate.starts_with("candidate:")
                || candidate.candidate.contains(['\r', '\n', '\0'])
                || candidate.sdp_mid.as_deref() != mid.as_deref()
                || candidate.username_fragment != *ufrag
                || candidate
                    .candidate
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .windows(2)
                    .any(|pair| pair[0] == "ufrag" && pair[1] != ufrag)
                || ufrag.is_empty()
                || ice.candidates[..index].contains(candidate)
            {
                return Err(invalid());
            }
            let mut validation = description.clone();
            validation
                .sdp
                .push_str(&format!("a={}\r\n", candidate.candidate));
            validation.validate(permit)?;
        }
        Ok(())
    }
}

pub fn media_sections(sdp: &str) -> Vec<(Option<String>, String)> {
    let mut session_ufrag = String::new();
    let mut sections: Vec<(Option<String>, String)> = Vec::new();
    for line in sdp.lines() {
        if line.starts_with("m=") {
            sections.push((None, session_ufrag.clone()));
        } else if let Some(value) = line.strip_prefix("a=ice-ufrag:") {
            if let Some(section) = sections.last_mut() {
                section.1 = value.into();
            } else {
                session_ufrag = value.into();
            }
        } else if let Some(value) = line.strip_prefix("a=mid:")
            && let Some(section) = sections.last_mut()
        {
            section.0 = Some(value.into());
        }
    }
    sections
}

/// Extract the latest browser/library local SDP into a snapshot. The original
/// signed description remains unchanged when later candidates are published.
pub fn snapshot(
    sdp: &str,
    description_sequence: u64,
    complete: bool,
) -> Result<WebRtcIceSnapshot, ContractError> {
    let sections = media_sections(sdp);
    let mut candidates = Vec::new();
    let mut section = None;
    for line in sdp.lines() {
        if line.starts_with("m=") {
            section = Some(section.map_or(0usize, |i| i + 1));
        }
        if let Some(value) = line.strip_prefix("a=candidate:") {
            let index = section.ok_or_else(invalid)?;
            let (mid, ufrag) = sections.get(index).ok_or_else(invalid)?;
            let candidate = WebRtcIceCandidate {
                candidate: format!("candidate:{value}"),
                sdp_mid: mid.clone(),
                sdp_m_line_index: u16::try_from(index).map_err(|_| invalid())?,
                username_fragment: ufrag.clone(),
            };
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
            if candidates.len() > CANDIDATE_COUNT as usize {
                return Err(invalid());
            }
        }
    }
    Ok(WebRtcIceSnapshot {
        description_sequence,
        candidates,
        end_of_candidates: complete,
    })
}

pub fn without_candidates(sdp: &str) -> String {
    sdp.lines()
        .filter(|line| !line.starts_with("a=candidate:") && *line != "a=end-of-candidates")
        .map(|line| format!("{line}\r\n"))
        .collect()
}

/// One remote SDP generation. A later signed snapshot may only grow the
/// candidate set, and completion cannot be undone. Returns newly seen entries.
#[derive(Default)]
pub struct IceSnapshotCursor {
    previous: Option<WebRtcIceSnapshot>,
}
impl IceSnapshotCursor {
    pub fn reset(&mut self) {
        self.previous = None;
    }
    pub fn apply(
        &mut self,
        fresh: &WebRtcIceSnapshot,
    ) -> Result<Vec<WebRtcIceCandidate>, ContractError> {
        if let Some(previous) = &self.previous
            && (previous.description_sequence != fresh.description_sequence
                || (previous.end_of_candidates && !fresh.end_of_candidates)
                || (previous.end_of_candidates
                    && fresh.candidates.len() != previous.candidates.len())
                || previous
                    .candidates
                    .iter()
                    .any(|c| !fresh.candidates.contains(c)))
        {
            return Err(invalid());
        }
        let additions = fresh
            .candidates
            .iter()
            .filter(|candidate| {
                self.previous
                    .as_ref()
                    .is_none_or(|old| !old.candidates.contains(candidate))
            })
            .cloned()
            .collect();
        self.previous = Some(fresh.clone());
        Ok(additions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_lost_poll_is_repaired_by_the_next_snapshot_and_completion_is_monotonic()
    -> Result<(), ContractError> {
        let sdp = "v=0\r\na=ice-ufrag:abc123\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\na=candidate:1 1 udp 100 192.168.1.1 5000 typ host\r\n";
        let first = snapshot(sdp, 1, false)?;
        let second = snapshot(
            &format!("{sdp}a=candidate:2 1 udp 90 8.8.8.8 5001 typ srflx\r\n"),
            1,
            true,
        )?;
        let mut cursor = IceSnapshotCursor::default();
        assert_eq!(cursor.apply(&second)?.len(), 2);
        assert!(cursor.apply(&second)?.is_empty());
        assert!(cursor.apply(&first).is_err());
        let mut changed = second.clone();
        changed.description_sequence = 2;
        assert!(cursor.apply(&changed).is_err());
        cursor.reset();
        assert_eq!(cursor.apply(&first)?.len(), 1);
        Ok(())
    }
}
