//! Permit-bound file and clipboard WebRTC data envelopes.
use crate::{ContractError, ErrorCode, Permission, PermitClaims, SCHEMA_VERSION};
use prost::Message;
use zeroize::Zeroize;

include!("../../../protocol-spec/webrtc-data.rs");

fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}

/// Immutable identity established when mutual endpoint proof succeeds.
/// Construct one binding per direction and business DataChannel, then retain it
/// for that peer connection even when the control plane renews the live lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebRtcDataBinding {
    channel: WebRtcDataChannel,
    permit_sha256: [u8; 32],
    session_id: String,
    connection_generation: u64,
    lease_sequence: u64,
}

impl WebRtcDataBinding {
    /// Capture the original verified permit identity for one business channel.
    /// `proved_permit_sha256` must be the digest used by the completed endpoint
    /// proof, not a digest recomputed after a later lease renewal.
    pub fn for_permit(
        claims: &PermitClaims,
        proved_permit_sha256: [u8; 32],
        channel: WebRtcDataChannel,
    ) -> Result<Self, ContractError> {
        claims.validate()?;
        let permission = channel.permission();
        if !claims.permissions.contains(&(permission as i32)) {
            return Err(ContractError::new(
                ErrorCode::PermissionRequired,
                "WebRTC data channel is not permitted",
            ));
        }
        Ok(Self {
            channel,
            permit_sha256: proved_permit_sha256,
            session_id: claims.session_id.clone(),
            connection_generation: claims.connection_generation,
            lease_sequence: claims.lease_sequence,
        })
    }

    pub fn channel(&self) -> WebRtcDataChannel {
        self.channel
    }

    pub fn label(&self) -> &'static str {
        self.channel.label()
    }

    pub fn permit_sha256(&self) -> &[u8; 32] {
        &self.permit_sha256
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn connection_generation(&self) -> u64 {
        self.connection_generation
    }

    pub fn lease_sequence(&self) -> u64 {
        self.lease_sequence
    }
}

impl WebRtcDataChannel {
    pub const fn label(self) -> &'static str {
        match self {
            Self::FileRead => WEBRTC_FILE_READ_LABEL,
            Self::FileWrite => WEBRTC_FILE_WRITE_LABEL,
            Self::ClipboardRead => WEBRTC_CLIPBOARD_READ_LABEL,
            Self::ClipboardWrite => WEBRTC_CLIPBOARD_WRITE_LABEL,
            Self::Unspecified => "",
        }
    }

    pub const fn permission(self) -> Permission {
        match self {
            Self::FileRead => Permission::FileRead,
            Self::FileWrite => Permission::FileWrite,
            Self::ClipboardRead => Permission::ClipboardRead,
            Self::ClipboardWrite => Permission::ClipboardWrite,
            Self::Unspecified => Permission::Unspecified,
        }
    }

    pub fn from_label(label: &str) -> Result<Self, ContractError> {
        match label {
            WEBRTC_FILE_READ_LABEL => Ok(Self::FileRead),
            WEBRTC_FILE_WRITE_LABEL => Ok(Self::FileWrite),
            WEBRTC_CLIPBOARD_READ_LABEL => Ok(Self::ClipboardRead),
            WEBRTC_CLIPBOARD_WRITE_LABEL => Ok(Self::ClipboardWrite),
            _ => Err(invalid("unknown WebRTC business DataChannel label")),
        }
    }
}

/// Serializes one native business message into consecutive SCTP-sized pieces.
/// Send each returned vector without interleaving it with another message.
pub struct WebRtcDataFragmenter {
    binding: WebRtcDataBinding,
    next_sequence: u64,
    exhausted: bool,
}

impl WebRtcDataFragmenter {
    pub fn new(binding: WebRtcDataBinding) -> Self {
        Self {
            binding,
            next_sequence: 1,
            exhausted: false,
        }
    }

    pub fn binding(&self) -> &WebRtcDataBinding {
        &self.binding
    }

    pub fn fragment(&mut self, envelope: &[u8]) -> Result<(u64, Vec<Vec<u8>>), ContractError> {
        if self.exhausted {
            return Err(invalid("WebRTC data message sequence exhausted"));
        }
        if envelope.is_empty() {
            return Err(invalid("empty native WebRTC data envelope"));
        }
        if envelope.len() > MAX_WEBRTC_DATA_ENVELOPE_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "native WebRTC data envelope exceeds budget",
            ));
        }

        let message_sequence = self.next_sequence;
        let fragment_count = envelope.len().div_ceil(WEBRTC_DATA_FRAGMENT_PAYLOAD_BYTES);
        if fragment_count > MAX_WEBRTC_DATA_FRAGMENTS {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "native WebRTC data fragment count exceeds budget",
            ));
        }
        let original_len = u32::try_from(envelope.len()).map_err(|_| {
            ContractError::new(
                ErrorCode::CapacityExceeded,
                "native WebRTC data envelope exceeds budget",
            )
        })?;
        let mut fragments = Vec::with_capacity(fragment_count);
        for (index, payload) in envelope
            .chunks(WEBRTC_DATA_FRAGMENT_PAYLOAD_BYTES)
            .enumerate()
        {
            let fragment = WebRtcDataFragment {
                schema_version: SCHEMA_VERSION,
                permit_sha256: self.binding.permit_sha256.to_vec(),
                session_id: self.binding.session_id.clone(),
                connection_generation: self.binding.connection_generation,
                lease_sequence: self.binding.lease_sequence,
                channel: self.binding.channel as i32,
                message_sequence,
                fragment_index: u32::try_from(index)
                    .map_err(|_| invalid("invalid fragment index"))?,
                fragment_count: u32::try_from(fragment_count)
                    .map_err(|_| invalid("invalid fragment count"))?,
                original_len,
                payload: payload.to_vec(),
            };
            let wire = fragment.encode_to_vec();
            if wire.len() > MAX_WEBRTC_DATA_FRAGMENT_BYTES {
                return Err(ContractError::new(
                    ErrorCode::CapacityExceeded,
                    "encoded WebRTC data fragment exceeds SCTP budget",
                ));
            }
            fragments.push(wire);
        }

        if message_sequence == i64::MAX as u64 {
            self.exhausted = true;
        } else {
            self.next_sequence += 1;
        }
        Ok((message_sequence, fragments))
    }
}

/// Completed native envelope returned after every ordered fragment is checked.
#[derive(Debug, PartialEq, Eq)]
pub struct ReassembledWebRtcData {
    pub message_sequence: u64,
    pub payload: Vec<u8>,
}

struct PartialMessage {
    message_sequence: u64,
    fragment_count: usize,
    original_len: usize,
    next_fragment: usize,
    payload: Vec<u8>,
}

impl Drop for PartialMessage {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

/// Strictly ordered one-message reassembler with a fixed 65,536-byte budget.
/// An invalid fragment poisons the receiver so a rejected partial cannot be
/// resumed or spliced with a later message on the same channel.
pub struct WebRtcDataReassembler {
    binding: WebRtcDataBinding,
    next_sequence: u64,
    exhausted: bool,
    partial: Option<PartialMessage>,
    failed: bool,
}

impl WebRtcDataReassembler {
    pub fn new(binding: WebRtcDataBinding) -> Self {
        Self {
            binding,
            next_sequence: 1,
            exhausted: false,
            partial: None,
            failed: false,
        }
    }

    pub fn binding(&self) -> &WebRtcDataBinding {
        &self.binding
    }

    pub fn pending_bytes(&self) -> usize {
        self.partial
            .as_ref()
            .map_or(0, |partial| partial.payload.len())
    }

    pub fn push(&mut self, wire: &[u8]) -> Result<Option<ReassembledWebRtcData>, ContractError> {
        if self.failed {
            return Err(invalid(
                "WebRTC data reassembler is closed after a protocol error",
            ));
        }
        match self.push_inner(wire) {
            Ok(message) => Ok(message),
            Err(error) => {
                self.partial = None;
                self.failed = true;
                Err(error)
            }
        }
    }

    fn push_inner(&mut self, wire: &[u8]) -> Result<Option<ReassembledWebRtcData>, ContractError> {
        let fragment: WebRtcDataFragment =
            crate::decode_bounded(wire, MAX_WEBRTC_DATA_FRAGMENT_BYTES as u64)?;
        self.validate_fragment(&fragment)?;
        if self.exhausted {
            return Err(invalid("WebRTC data message sequence exhausted"));
        }

        let sequence = fragment.message_sequence;
        let index = fragment.fragment_index as usize;
        let count = fragment.fragment_count as usize;
        let original_len = fragment.original_len as usize;
        if self.partial.is_none() {
            if index != 0 || sequence != self.next_sequence {
                return Err(ContractError::new(
                    ErrorCode::ReplayRejected,
                    "WebRTC data fragment is missing or out of sequence",
                ));
            }
            self.partial = Some(PartialMessage {
                message_sequence: sequence,
                fragment_count: count,
                original_len,
                next_fragment: 0,
                payload: Vec::with_capacity(original_len),
            });
        }

        let partial = self
            .partial
            .as_mut()
            .ok_or_else(|| invalid("missing WebRTC partial message"))?;
        if partial.message_sequence != sequence
            || partial.fragment_count != count
            || partial.original_len != original_len
            || partial.next_fragment != index
        {
            return Err(ContractError::new(
                ErrorCode::ReplayRejected,
                "WebRTC data fragments are interleaved or out of order",
            ));
        }
        let expected_size = expected_payload_size(original_len, index, count)?;
        if fragment.payload.len() != expected_size
            || partial.payload.len().saturating_add(fragment.payload.len()) > original_len
        {
            return Err(invalid("WebRTC data fragment length mismatch"));
        }
        partial.payload.extend_from_slice(&fragment.payload);
        partial.next_fragment += 1;

        if partial.next_fragment != partial.fragment_count {
            return Ok(None);
        }
        if partial.payload.len() != partial.original_len {
            return Err(invalid(
                "WebRTC data message did not reach its declared length",
            ));
        }
        let mut partial = self
            .partial
            .take()
            .ok_or_else(|| invalid("missing completed WebRTC message"))?;
        if sequence == i64::MAX as u64 {
            self.exhausted = true;
        } else {
            self.next_sequence += 1;
        }
        // PartialMessage normally zeroes on drop; ownership now transfers to the
        // caller, which places clipboard payloads into its zeroizing queue.
        let payload = std::mem::take(&mut partial.payload);
        Ok(Some(ReassembledWebRtcData {
            message_sequence: sequence,
            payload,
        }))
    }

    fn validate_fragment(&self, fragment: &WebRtcDataFragment) -> Result<(), ContractError> {
        if fragment.schema_version != SCHEMA_VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "unsupported WebRTC data schema",
            ));
        }
        if fragment.permit_sha256.as_slice() != &self.binding.permit_sha256[..]
            || fragment.session_id != self.binding.session_id
            || fragment.connection_generation != self.binding.connection_generation
            || fragment.lease_sequence != self.binding.lease_sequence
            || fragment.channel != self.binding.channel as i32
        {
            return Err(invalid("WebRTC data fragment binding mismatch"));
        }
        let channel = WebRtcDataChannel::try_from(fragment.channel)
            .map_err(|_| invalid("unknown WebRTC data channel"))?;
        if channel == WebRtcDataChannel::Unspecified
            || fragment.message_sequence == 0
            || fragment.message_sequence > i64::MAX as u64
            || fragment.fragment_count == 0
            || fragment.fragment_count as usize > MAX_WEBRTC_DATA_FRAGMENTS
            || fragment.original_len == 0
            || fragment.original_len as usize > MAX_WEBRTC_DATA_ENVELOPE_BYTES
            || fragment.permit_sha256.len() != 32
            || fragment.payload.is_empty()
            || fragment.payload.len() > WEBRTC_DATA_FRAGMENT_PAYLOAD_BYTES
        {
            return Err(invalid("invalid WebRTC data fragment fields"));
        }
        let original_len = fragment.original_len as usize;
        let count = original_len.div_ceil(WEBRTC_DATA_FRAGMENT_PAYLOAD_BYTES);
        if fragment.fragment_count as usize != count {
            return Err(invalid(
                "WebRTC data fragment count does not match envelope",
            ));
        }
        let index = fragment.fragment_index as usize;
        let expected_size = expected_payload_size(original_len, index, count)?;
        if fragment.payload.len() != expected_size
            || fragment.encoded_len() > MAX_WEBRTC_DATA_FRAGMENT_BYTES
        {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "WebRTC data fragment exceeds its encoded budget",
            ));
        }
        Ok(())
    }
}

fn expected_payload_size(
    original_len: usize,
    index: usize,
    count: usize,
) -> Result<usize, ContractError> {
    if index >= count || count == 0 {
        return Err(invalid("WebRTC data fragment index out of range"));
    }
    let offset = index
        .checked_mul(WEBRTC_DATA_FRAGMENT_PAYLOAD_BYTES)
        .ok_or_else(|| invalid("WebRTC data fragment offset overflow"))?;
    original_len
        .checked_sub(offset)
        .map(|remaining| remaining.min(WEBRTC_DATA_FRAGMENT_PAYLOAD_BYTES))
        .filter(|size| *size > 0)
        .ok_or_else(|| invalid("WebRTC data fragment length mismatch"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(permission: Permission) -> PermitClaims {
        let id = |n: u32| format!("{n:08}-1111-4111-8111-111111111111");
        PermitClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            session_id: id(2),
            account_id: id(3),
            controller_device_id: id(4),
            host_device_id: id(5),
            resource_id: id(6),
            controller_key_sha256: vec![7; 32],
            host_key_sha256: vec![8; 32],
            capability_sha256: vec![9; 32],
            permissions: vec![Permission::View as i32, permission as i32],
            paths: vec![crate::Path::Direct as i32],
            security_epoch: 1,
            policy_revision: 1,
            connection_generation: 4,
            lease_sequence: 9,
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            ..Default::default()
        }
    }

    fn binding(channel: WebRtcDataChannel) -> WebRtcDataBinding {
        WebRtcDataBinding::for_permit(&claims(channel.permission()), [0xa5; 32], channel)
            .unwrap_or_else(|error| panic!("valid fixture binding failed: {error}"))
    }

    #[test]
    fn labels_are_fixed_and_permission_specific() {
        let cases = [
            (
                WebRtcDataChannel::FileRead,
                WEBRTC_FILE_READ_LABEL,
                Permission::FileRead,
            ),
            (
                WebRtcDataChannel::FileWrite,
                WEBRTC_FILE_WRITE_LABEL,
                Permission::FileWrite,
            ),
            (
                WebRtcDataChannel::ClipboardRead,
                WEBRTC_CLIPBOARD_READ_LABEL,
                Permission::ClipboardRead,
            ),
            (
                WebRtcDataChannel::ClipboardWrite,
                WEBRTC_CLIPBOARD_WRITE_LABEL,
                Permission::ClipboardWrite,
            ),
        ];
        for (channel, label, permission) in cases {
            assert_eq!(channel.label(), label);
            assert_eq!(channel.permission(), permission);
            assert_eq!(WebRtcDataChannel::from_label(label), Ok(channel));
        }
        assert!(WebRtcDataChannel::from_label("nestlink-control-v1").is_err());
    }

    #[test]
    fn fragments_and_reassembles_the_maximum_native_envelope() {
        let binding = binding(WebRtcDataChannel::FileWrite);
        let mut fragmenter = WebRtcDataFragmenter::new(binding.clone());
        let payload = (0..MAX_WEBRTC_DATA_ENVELOPE_BYTES)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let (sequence, fragments) = fragmenter
            .fragment(&payload)
            .unwrap_or_else(|error| panic!("valid maximum message failed: {error}"));
        assert_eq!(sequence, 1);
        assert_eq!(fragments.len(), MAX_WEBRTC_DATA_FRAGMENTS);
        assert!(
            fragments
                .iter()
                .all(|fragment| fragment.len() <= MAX_WEBRTC_DATA_FRAGMENT_BYTES)
        );

        let mut reassembler = WebRtcDataReassembler::new(binding);
        let mut complete = None;
        for fragment in fragments {
            complete = reassembler
                .push(&fragment)
                .unwrap_or_else(|error| panic!("valid fragment failed: {error}"));
            if complete.is_none() {
                assert!(reassembler.pending_bytes() <= MAX_WEBRTC_DATA_ENVELOPE_BYTES);
            }
        }
        let message = complete.unwrap_or_else(|| panic!("message did not complete"));
        assert_eq!(message.message_sequence, 1);
        assert_eq!(message.payload, payload);
        assert_eq!(reassembler.pending_bytes(), 0);
    }

    #[test]
    fn envelopes_and_fragment_sequences_are_bounded() {
        let mut fragmenter = WebRtcDataFragmenter::new(binding(WebRtcDataChannel::ClipboardRead));
        assert!(fragmenter.fragment(&[]).is_err());
        assert!(
            fragmenter
                .fragment(&vec![0; MAX_WEBRTC_DATA_ENVELOPE_BYTES + 1])
                .is_err()
        );
        let (first, _) = fragmenter
            .fragment(b"one")
            .unwrap_or_else(|error| panic!("small message failed: {error}"));
        let (second, _) = fragmenter
            .fragment(b"two")
            .unwrap_or_else(|error| panic!("next message failed: {error}"));
        assert_eq!((first, second), (1, 2));
    }

    #[test]
    fn wrong_label_binding_and_fragment_order_poison_the_reassembler() {
        let expected_binding = binding(WebRtcDataChannel::FileRead);
        let mut fragmenter = WebRtcDataFragmenter::new(expected_binding.clone());
        let (_, mut fragments) = fragmenter
            .fragment(&vec![3; WEBRTC_DATA_FRAGMENT_PAYLOAD_BYTES + 1])
            .unwrap_or_else(|error| panic!("fixture fragmentation failed: {error}"));

        let mut wrong_channel: WebRtcDataFragment =
            WebRtcDataFragment::decode(fragments[0].as_slice())
                .unwrap_or_else(|error| panic!("fixture fragment decode failed: {error}"));
        wrong_channel.channel = WebRtcDataChannel::FileWrite as i32;
        let wrong_channel = wrong_channel.encode_to_vec();
        let mut receiver = WebRtcDataReassembler::new(expected_binding.clone());
        assert!(receiver.push(&wrong_channel).is_err());
        assert!(receiver.push(&fragments[0]).is_err());

        let mut receiver = WebRtcDataReassembler::new(expected_binding);
        assert!(receiver.push(&fragments[1]).is_err());

        fragments.reverse();
        let mut receiver = WebRtcDataReassembler::new(binding(WebRtcDataChannel::FileRead));
        assert!(receiver.push(&fragments[0]).is_err());
    }

    #[test]
    fn each_permission_must_be_in_the_signed_permit() {
        let permit = claims(Permission::FileRead);
        assert!(
            WebRtcDataBinding::for_permit(&permit, [1; 32], WebRtcDataChannel::FileRead).is_ok()
        );
        assert_eq!(
            WebRtcDataBinding::for_permit(&permit, [1; 32], WebRtcDataChannel::ClipboardWrite)
                .err()
                .map(|error| error.code),
            Some(ErrorCode::PermissionRequired)
        );
    }
}
