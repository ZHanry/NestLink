//! Restricted VP8/Opus WebRTC profile and bounded peer control messages.
use crate::{ContractError, ErrorCode, Permission, PermitClaims, SCHEMA_VERSION};
use std::collections::BTreeSet;

include!("../../../protocol-spec/webrtc-control.rs");

impl WebRtcControl {
    pub fn decode_validated(bytes: &[u8], claims: &PermitClaims) -> Result<Self, ContractError> {
        if bytes.len() > MAX_WEBRTC_CONTROL_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "WebRTC control budget exceeded",
            ));
        }
        let message: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("malformed WebRTC control message"))?;
        message.validate(claims)?;
        Ok(message)
    }

    pub fn encode_validated(&self, claims: &PermitClaims) -> Result<Vec<u8>, ContractError> {
        self.validate(claims)?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| invalid("malformed WebRTC control message"))?;
        if bytes.len() > MAX_WEBRTC_CONTROL_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "WebRTC control budget exceeded",
            ));
        }
        Ok(bytes)
    }

    pub fn validate(&self, claims: &PermitClaims) -> Result<(), ContractError> {
        match self {
            Self::EndpointProof {
                schema_version,
                session_id,
                connection_generation,
                lease_sequence,
                proof,
            } => {
                validate_control_binding(
                    *schema_version,
                    session_id,
                    *connection_generation,
                    *lease_sequence,
                    claims,
                )?;
                let transcript = proof
                    .transcript
                    .as_ref()
                    .ok_or_else(|| invalid("missing WebRTC endpoint transcript"))?;
                if transcript.schema_version != SCHEMA_VERSION
                    || transcript.permit_sha256.len() != 32
                    || transcript.challenge.len() != 32
                    || transcript.controller_key_sha256 != claims.controller_key_sha256
                    || transcript.host_key_sha256 != claims.host_key_sha256
                    || transcript.connection_generation != claims.connection_generation
                    || !claims.paths.contains(&transcript.path)
                    || proof.signature.len() != 64
                    || !matches!(proof.peer_transcript_signature.len(), 0 | 64)
                {
                    return Err(invalid("invalid WebRTC endpoint transcript"));
                }
            }
            Self::EndpointProofAccepted {
                schema_version,
                session_id,
                connection_generation,
                lease_sequence,
            } => {
                validate_control_binding(
                    *schema_version,
                    session_id,
                    *connection_generation,
                    *lease_sequence,
                    claims,
                )?;
            }
            Self::HostRenewalSignature {
                schema_version,
                session_id,
                connection_generation,
                lease_sequence,
                signature,
            } => {
                if *schema_version != SCHEMA_VERSION {
                    return Err(ContractError::new(
                        ErrorCode::ProtocolMismatch,
                        "unsupported WebRTC control schema",
                    ));
                }
                if session_id != &claims.session_id
                    || *connection_generation != claims.connection_generation
                    || claims.lease_sequence.checked_add(1) != Some(*lease_sequence)
                    || *lease_sequence > i64::MAX as u64
                    || signature.len() != 86
                    || !signature
                        .bytes()
                        .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_'))
                {
                    return Err(invalid("WebRTC renewal signature binding invalid"));
                }
            }
            Self::HostInputLayout {
                schema_version,
                session_id,
                connection_generation,
                lease_sequence,
                input_epoch,
                layout_epoch,
                left,
                top,
                width,
                height,
            } => {
                validate_input_binding(
                    *schema_version,
                    session_id,
                    *connection_generation,
                    *lease_sequence,
                    *input_epoch,
                    *layout_epoch,
                    claims,
                )?;
                if *width == 0
                    || *height == 0
                    || *width > 32768
                    || *height > 32768
                    || left.checked_add_unsigned(*width).is_none()
                    || top.checked_add_unsigned(*height).is_none()
                {
                    return Err(invalid("invalid WebRTC input layout"));
                }
            }
            Self::InputEvent {
                schema_version,
                session_id,
                connection_generation,
                lease_sequence,
                input_epoch,
                layout_epoch,
                sequence,
                action,
            } => {
                validate_input_binding(
                    *schema_version,
                    session_id,
                    *connection_generation,
                    *lease_sequence,
                    *input_epoch,
                    *layout_epoch,
                    claims,
                )?;
                if *sequence == 0 || *sequence > i64::MAX as u64 {
                    return Err(invalid("invalid WebRTC input sequence"));
                }
                match action {
                    WebRtcInputAction::Key { usage, .. } if (4..=0xe7).contains(usage) => {}
                    WebRtcInputAction::Pointer { button, down, .. }
                        if button.is_none_or(|value| (1..=5).contains(&value))
                            && (button.is_some() || !*down) => {}
                    WebRtcInputAction::Scroll { x, y } if crate::valid_scroll(*x, *y) => {}
                    WebRtcInputAction::Text { text }
                        if !text.is_empty()
                            && text.len() <= 1800
                            && !text.chars().any(|character| {
                                character.is_control() && !matches!(character, '\n' | '\t')
                            }) => {}
                    _ => return Err(invalid("input action outside the browser capability")),
                }
            }
            Self::InputReleaseAll {
                schema_version,
                session_id,
                connection_generation,
                lease_sequence,
                input_epoch,
                layout_epoch,
            } => {
                validate_input_binding(
                    *schema_version,
                    session_id,
                    *connection_generation,
                    *lease_sequence,
                    *input_epoch,
                    *layout_epoch,
                    claims,
                )?;
            }
        }
        Ok(())
    }
}

fn validate_input_binding(
    schema_version: u32,
    session_id: &str,
    connection_generation: u64,
    lease_sequence: u64,
    input_epoch: u64,
    layout_epoch: u64,
    claims: &PermitClaims,
) -> Result<(), ContractError> {
    validate_control_binding(
        schema_version,
        session_id,
        connection_generation,
        lease_sequence,
        claims,
    )?;
    if !claims.permissions.contains(&(Permission::Input as i32)) {
        return Err(ContractError::new(
            ErrorCode::PermissionRequired,
            "WebRTC control requires Input permission",
        ));
    }
    if [input_epoch, layout_epoch]
        .iter()
        .any(|value| *value == 0 || *value > i64::MAX as u64)
    {
        return Err(invalid("invalid WebRTC input epoch"));
    }
    Ok(())
}

fn validate_control_binding(
    schema_version: u32,
    session_id: &str,
    connection_generation: u64,
    lease_sequence: u64,
    claims: &PermitClaims,
) -> Result<(), ContractError> {
    if schema_version != SCHEMA_VERSION {
        return Err(ContractError::new(
            ErrorCode::ProtocolMismatch,
            "unsupported WebRTC control schema",
        ));
    }
    if session_id != claims.session_id
        || connection_generation != claims.connection_generation
        || lease_sequence != claims.lease_sequence
    {
        return Err(invalid("WebRTC control binding invalid"));
    }
    Ok(())
}

fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}

/// Filter a locally generated offer before setLocalDescription and signing.
/// Only VP8, its RTX repair payload, and Opus can enter this product profile.
pub fn restrict_media_sdp(sdp: &str, permissions: &[i32]) -> Result<String, ContractError> {
    if sdp.len() > 65_536 || sdp.contains('\0') {
        return Err(invalid("invalid SDP budget"));
    }
    let lines: Vec<_> = sdp.lines().collect();
    let mut output = Vec::new();
    let mut start = 0;
    while start < lines.len() {
        if !lines[start].starts_with("m=") {
            output.push(lines[start].to_owned());
            start += 1;
            continue;
        }
        let end = (start + 1..lines.len())
            .find(|index| lines[*index].starts_with("m="))
            .unwrap_or(lines.len());
        filter_section(&lines[start..end], permissions, &mut output)?;
        start = end;
    }
    Ok(format!("{}\r\n", output.join("\r\n")))
}

/// Remote answers must already conform; filtering remote SDP would invalidate
/// the exact signed description and can hide an unapproved codec negotiation.
pub fn validate_media_sdp(sdp: &str, permissions: &[i32]) -> Result<(), ContractError> {
    let restricted = restrict_media_sdp(sdp, permissions)?;
    if restricted.lines().eq(sdp.lines()) {
        Ok(())
    } else {
        Err(ContractError::new(
            ErrorCode::CodecUnsupported,
            "SDP exceeds VP8/Opus profile",
        ))
    }
}

fn filter_section(
    lines: &[&str],
    permissions: &[i32],
    output: &mut Vec<String>,
) -> Result<(), ContractError> {
    let fields: Vec<_> = lines[0].split_ascii_whitespace().collect();
    let (permission, codec) = match fields.first().copied() {
        Some("m=video") => (Permission::View, "vp8/90000"),
        Some("m=audio") => (Permission::Audio, "opus/48000/2"),
        Some("m=application") => {
            output.extend(lines.iter().map(|line| (*line).to_owned()));
            return Ok(());
        }
        _ => return Err(invalid("unsupported SDP media section")),
    };
    if fields.len() < 4 {
        return Err(invalid("malformed SDP media section"));
    }
    let mut advertised = BTreeSet::new();
    if fields[3..].iter().any(|payload| {
        payload.parse::<u8>().map_or(true, |value| value > 127) || !advertised.insert(*payload)
    }) {
        return Err(invalid("invalid or duplicate SDP RTP payload"));
    }
    if !permissions.contains(&(permission as i32)) {
        return Err(ContractError::new(
            ErrorCode::PermissionRequired,
            "SDP requests unapproved media",
        ));
    }
    let mut primary = BTreeSet::new();
    let mut repair = BTreeSet::new();
    let mut mappings = BTreeSet::new();
    for line in lines {
        if let Some(value) = line.strip_prefix("a=rtpmap:") {
            let Some((payload, mapping)) = value.split_once(' ') else {
                return Err(invalid("malformed SDP RTP mapping"));
            };
            if !mappings.insert(payload) {
                return Err(invalid("duplicate SDP RTP mapping"));
            }
            if mapping.eq_ignore_ascii_case(codec) && fields[3..].contains(&payload) {
                primary.insert(payload);
            }
            if permission == Permission::View && mapping.eq_ignore_ascii_case("rtx/90000") {
                repair.insert(payload);
            }
        }
    }
    if primary.is_empty() {
        return Err(ContractError::new(
            ErrorCode::CodecUnsupported,
            "required VP8/Opus codec unavailable",
        ));
    }
    let mut keep = primary.clone();
    for line in lines {
        if let Some(value) = line.strip_prefix("a=fmtp:")
            && let Some((payload, parameters)) = value.split_once(' ')
            && repair.contains(payload)
            && fields[3..].contains(&payload)
            && repair_base(parameters).is_some_and(|base| primary.contains(base))
        {
            keep.insert(payload);
        }
    }
    let payloads: Vec<_> = fields[3..]
        .iter()
        .filter(|payload| keep.contains(**payload))
        .copied()
        .collect();
    output.push(format!("{} {}", fields[..3].join(" "), payloads.join(" ")));
    for line in &lines[1..] {
        let payload_attribute = ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix));
        if let Some(value) = payload_attribute {
            let payload = value
                .split_ascii_whitespace()
                .next()
                .ok_or_else(|| invalid("malformed SDP payload attribute"))?;
            if payload != "*" && !keep.contains(payload) {
                continue;
            }
        }
        output.push((*line).to_owned());
    }
    Ok(())
}

fn repair_base(parameters: &str) -> Option<&str> {
    let mut targets = parameters
        .split(';')
        .filter_map(|parameter| parameter.trim().strip_prefix("apt="));
    let base = targets.next()?;
    if targets.next().is_some() {
        return None;
    }
    Some(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96 97 102 103\r\na=rtpmap:96 VP8/90000\r\na=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=96\r\na=rtcp-fb:96 nack pli\r\na=rtpmap:102 H264/90000\r\na=rtpmap:103 rtx/90000\r\na=fmtp:103 apt=102\r\na=rtcp-fb:102 nack\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\n";

    #[test]
    fn filter_removes_prohibited_codecs_and_their_repair_payloads() -> Result<(), ContractError> {
        let permissions = &[Permission::View as i32, Permission::Audio as i32];
        let result = restrict_media_sdp(OFFER, permissions)?;
        assert!(result.contains("m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n"));
        assert!(result.contains("a=fmtp:97 apt=96\r\n"));
        assert!(result.contains("a=rtcp-fb:96 nack pli\r\n"));
        assert!(!result.contains("102"));
        assert!(!result.contains("103"));
        assert!(!result.contains("PCMU"));
        assert!(validate_media_sdp(OFFER, permissions).is_err());
        validate_media_sdp(&result, permissions)
    }

    #[test]
    fn audio_media_cannot_be_requested_with_only_view_permission() {
        assert_eq!(
            restrict_media_sdp(OFFER, &[Permission::View as i32])
                .err()
                .map(|error| error.code),
            Some(ErrorCode::PermissionRequired)
        );
    }

    #[test]
    fn repair_without_a_baseline_codec_is_rejected() {
        assert!(restrict_media_sdp("v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 97\r\na=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=102\r\n", &[Permission::View as i32]).is_err());
    }

    #[test]
    fn ambiguous_mapping_cannot_hide_a_prohibited_codec_behind_an_allowed_payload() {
        let malicious = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtpmap:96 VP8/90000\r\na=rtpmap:96 H264/90000\r\n";
        assert!(validate_media_sdp(malicious, &[Permission::View as i32]).is_err());
        let ambiguous_repair = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96 97\r\na=rtpmap:96 VP8/90000\r\na=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=96;apt=102\r\n";
        assert!(validate_media_sdp(ambiguous_repair, &[Permission::View as i32]).is_err());
    }

    #[test]
    fn renewal_control_rejects_wrong_generation_duplicate_sequence_and_unknown_fields()
    -> Result<(), ContractError> {
        let claims = PermitClaims {
            session_id: "session".into(),
            connection_generation: 4,
            lease_sequence: 9,
            ..Default::default()
        };
        let control = WebRtcControl::HostRenewalSignature {
            schema_version: SCHEMA_VERSION,
            session_id: claims.session_id.clone(),
            connection_generation: 4,
            lease_sequence: 10,
            signature: "A".repeat(86),
        };
        let bytes = control.encode_validated(&claims)?;
        assert_eq!(WebRtcControl::decode_validated(&bytes, &claims)?, control);
        let stale = PermitClaims {
            lease_sequence: 10,
            ..claims.clone()
        };
        assert!(WebRtcControl::decode_validated(&bytes, &stale).is_err());
        let other = PermitClaims {
            connection_generation: 5,
            ..claims.clone()
        };
        assert!(WebRtcControl::decode_validated(&bytes, &other).is_err());
        let mut value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid test JSON"))?;
        value["extra"] = serde_json::json!(true);
        assert!(WebRtcControl::decode_validated(value.to_string().as_bytes(), &claims).is_err());
        assert!(
            WebRtcControl::decode_validated(&vec![b'a'; MAX_WEBRTC_CONTROL_BYTES + 1], &claims)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn input_control_is_permission_epoch_layout_and_sequence_bound() -> Result<(), ContractError> {
        let claims = PermitClaims {
            session_id: "session".into(),
            connection_generation: 4,
            lease_sequence: 9,
            permissions: vec![Permission::View as i32, Permission::Input as i32],
            ..Default::default()
        };
        let layout = WebRtcControl::HostInputLayout {
            schema_version: SCHEMA_VERSION,
            session_id: claims.session_id.clone(),
            connection_generation: claims.connection_generation,
            lease_sequence: claims.lease_sequence,
            input_epoch: 1,
            layout_epoch: 1,
            left: -1920,
            top: 0,
            width: 1920,
            height: 1080,
        };
        let layout_bytes = layout.encode_validated(&claims)?;
        assert_eq!(
            WebRtcControl::decode_validated(&layout_bytes, &claims)?,
            layout
        );
        let input = WebRtcControl::InputEvent {
            schema_version: SCHEMA_VERSION,
            session_id: claims.session_id.clone(),
            connection_generation: claims.connection_generation,
            lease_sequence: claims.lease_sequence,
            input_epoch: 1,
            layout_epoch: 1,
            sequence: 1,
            action: WebRtcInputAction::Pointer {
                button: Some(1),
                down: true,
                x: -1,
                y: 10,
            },
        };
        let bytes = input.encode_validated(&claims)?;
        assert_eq!(WebRtcControl::decode_validated(&bytes, &claims)?, input);

        let view_only = PermitClaims {
            permissions: vec![Permission::View as i32],
            ..claims.clone()
        };
        assert_eq!(
            layout
                .encode_validated(&view_only)
                .err()
                .map(|error| error.code),
            Some(ErrorCode::PermissionRequired)
        );
        assert_eq!(
            input
                .encode_validated(&view_only)
                .err()
                .map(|error| error.code),
            Some(ErrorCode::PermissionRequired)
        );
        let release = WebRtcControl::InputReleaseAll {
            schema_version: SCHEMA_VERSION,
            session_id: claims.session_id.clone(),
            connection_generation: claims.connection_generation,
            lease_sequence: claims.lease_sequence,
            input_epoch: 1,
            layout_epoch: 1,
        };
        assert_eq!(
            release
                .encode_validated(&view_only)
                .err()
                .map(|error| error.code),
            Some(ErrorCode::PermissionRequired)
        );

        let stale_layout = WebRtcControl::InputEvent {
            schema_version: SCHEMA_VERSION,
            session_id: claims.session_id.clone(),
            connection_generation: claims.connection_generation,
            lease_sequence: claims.lease_sequence,
            input_epoch: 2,
            layout_epoch: 1,
            sequence: 1,
            action: WebRtcInputAction::Key {
                usage: 4,
                down: true,
            },
        };
        assert!(stale_layout.validate(&claims).is_ok()); // The live controller owns epoch freshness.
        let invalid_layout = WebRtcControl::HostInputLayout {
            schema_version: SCHEMA_VERSION,
            session_id: claims.session_id.clone(),
            connection_generation: claims.connection_generation,
            lease_sequence: claims.lease_sequence,
            input_epoch: 1,
            layout_epoch: 1,
            left: i32::MAX,
            top: 0,
            width: 1,
            height: 1,
        };
        assert!(invalid_layout.validate(&claims).is_err());
        Ok(())
    }

    #[test]
    fn display_control_binds_the_proved_view_lease_and_catalog() -> Result<(), ContractError> {
        const SESSION: &str = "00000000-0000-4000-8000-000000000001";
        let claims = PermitClaims {
            session_id: SESSION.into(),
            connection_generation: 4,
            lease_sequence: 9,
            permissions: vec![Permission::View as i32],
            ..Default::default()
        };
        let displays = vec![crate::native_displays::DisplayDescriptor {
            source: 7,
            left: -1920,
            top: 0,
            width: 1920,
            height: 1080,
            label: "Side monitor".into(),
        }];
        let catalog = crate::native_displays::catalog_key(SESSION, 4, 1, &displays)?;
        let control = WebRtcDisplayControl {
            schema_version: SCHEMA_VERSION,
            session_id: SESSION.into(),
            connection_generation: 4,
            lease_sequence: 9,
            message: crate::native_displays::DisplayEnvelope::CatalogBegin {
                catalog: catalog.clone(),
                count: 1,
            },
        };
        let bytes = control.encode_validated(&claims)?;
        assert_eq!(
            WebRtcDisplayControl::decode_validated(&bytes, &claims)?,
            control
        );

        let stale_lease = PermitClaims {
            lease_sequence: 10,
            ..claims.clone()
        };
        let stale_connection = PermitClaims {
            connection_generation: 5,
            ..claims.clone()
        };
        let no_view = PermitClaims {
            permissions: vec![Permission::Input as i32],
            ..claims.clone()
        };
        assert!(WebRtcDisplayControl::decode_validated(&bytes, &stale_lease).is_err());
        assert!(WebRtcDisplayControl::decode_validated(&bytes, &stale_connection).is_err());
        assert!(WebRtcDisplayControl::decode_validated(&bytes, &no_view).is_err());

        let wrong_catalog = crate::native_displays::catalog_key(
            "00000000-0000-4000-8000-000000000002",
            4,
            1,
            &displays,
        )?;
        let wrong_session = WebRtcDisplayControl {
            message: crate::native_displays::DisplayEnvelope::CatalogAck(wrong_catalog),
            ..control.clone()
        };
        assert!(wrong_session.encode_validated(&claims).is_err());

        let recovery = WebRtcDisplayControl {
            message: crate::native_displays::DisplayEnvelope::Recovery(Default::default()),
            ..control.clone()
        };
        assert!(recovery.encode_validated(&claims).is_err());

        let mut noncanonical = bytes;
        noncanonical.push(0);
        assert!(WebRtcDisplayControl::decode_validated(&noncanonical, &claims).is_err());
        Ok(())
    }

    #[test]
    fn display_selection_input_epoch_matches_the_signed_permission_set() -> Result<(), ContractError>
    {
        const SESSION: &str = "00000000-0000-4000-8000-000000000003";
        let claims = PermitClaims {
            session_id: SESSION.into(),
            connection_generation: 8,
            lease_sequence: 2,
            permissions: vec![Permission::View as i32, Permission::Input as i32],
            ..Default::default()
        };
        let displays = vec![crate::native_displays::DisplayDescriptor {
            source: 0,
            left: 0,
            top: 0,
            width: 1280,
            height: 720,
            label: "Main display".into(),
        }];
        let catalog = crate::native_displays::catalog_key(SESSION, 8, 1, &displays)?;
        let selected = WebRtcDisplayControl {
            schema_version: SCHEMA_VERSION,
            session_id: SESSION.into(),
            connection_generation: 8,
            lease_sequence: 2,
            message: crate::native_displays::DisplayEnvelope::Selected(
                crate::native_displays::DisplaySelection {
                    catalog,
                    sequence: 1,
                    source: 0,
                    layout_epoch: 2,
                    input_epoch: 2,
                },
            ),
        };
        let bytes = selected.encode_validated(&claims)?;
        assert_eq!(
            WebRtcDisplayControl::decode_validated(&bytes, &claims)?,
            selected
        );

        let view_only = PermitClaims {
            permissions: vec![Permission::View as i32],
            ..claims.clone()
        };
        assert!(selected.encode_validated(&view_only).is_err());
        let no_input_epoch = WebRtcDisplayControl {
            message: crate::native_displays::DisplayEnvelope::SelectionAck(
                crate::native_displays::DisplaySelection {
                    catalog: match &selected.message {
                        crate::native_displays::DisplayEnvelope::Selected(selection) => {
                            selection.catalog.clone()
                        }
                        _ => unreachable!(),
                    },
                    sequence: 1,
                    source: 0,
                    layout_epoch: 2,
                    input_epoch: 0,
                },
            ),
            ..selected
        };
        assert!(no_input_epoch.encode_validated(&claims).is_err());
        Ok(())
    }
}
