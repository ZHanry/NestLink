/// Reliable, ordered peer control channel. It never carries account credentials.
pub const WEBRTC_CONTROL_LABEL: &str = "nestlink-control-v1";
pub const MAX_WEBRTC_CONTROL_BYTES: usize = 4096;

/// Binary, permit-bound wrapper for the native display transaction on the
/// reliable control DataChannel. The fixed wrapper adds the active schema,
/// proved session, connection generation and current lease sequence around a
/// bounded `DisplayEnvelope` payload.
#[derive(Debug, Clone, PartialEq)]
pub struct WebRtcDisplayControl {
    pub schema_version: u32,
    pub session_id: String,
    pub connection_generation: u64,
    pub lease_sequence: u64,
    pub message: crate::native_displays::DisplayEnvelope,
}

impl WebRtcDisplayControl {
    const MAGIC: &'static [u8; 4] = b"NLDB";
    const VERSION: u8 = 1;
    const HEADER_BYTES: usize = 4 + 1 + 4 + 16 + 8 + 8;

    pub fn decode_validated(
        bytes: &[u8],
        claims: &crate::PermitClaims,
    ) -> Result<Self, crate::ContractError> {
        use crate::{ContractError, ErrorCode};

        if bytes.len() < Self::HEADER_BYTES + 6 || bytes.len() > MAX_WEBRTC_CONTROL_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "WebRTC display control budget exceeded",
            ));
        }
        if &bytes[..4] != Self::MAGIC || bytes[4] != Self::VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "unsupported WebRTC display envelope",
            ));
        }
        let schema_version = u32::from_be_bytes(bytes[5..9].try_into().map_err(|_| {
            ContractError::new(ErrorCode::InvalidMessage, "invalid display schema")
        })?);
        let session_id = uuid::Uuid::from_slice(&bytes[9..25])
            .map_err(|_| ContractError::new(ErrorCode::InvalidMessage, "invalid display session"))?
            .hyphenated()
            .to_string();
        let connection_generation = u64::from_be_bytes(bytes[25..33].try_into().map_err(|_| {
            ContractError::new(ErrorCode::InvalidMessage, "invalid display generation")
        })?);
        let lease_sequence = u64::from_be_bytes(bytes[33..41].try_into().map_err(|_| {
            ContractError::new(ErrorCode::InvalidMessage, "invalid display lease")
        })?);
        let message = crate::native_displays::DisplayEnvelope::decode(&bytes[Self::HEADER_BYTES..])?;
        let control = Self {
            schema_version,
            session_id,
            connection_generation,
            lease_sequence,
            message,
        };
        control.validate(claims)?;
        if control.encode_validated(claims)?.as_slice() != bytes {
            return Err(ContractError::new(
                ErrorCode::InvalidMessage,
                "non-canonical WebRTC display envelope",
            ));
        }
        Ok(control)
    }

    pub fn encode_validated(
        &self,
        claims: &crate::PermitClaims,
    ) -> Result<Vec<u8>, crate::ContractError> {
        use crate::{ContractError, ErrorCode};

        self.validate(claims)?;
        let session = uuid::Uuid::parse_str(&self.session_id)
            .map_err(|_| ContractError::new(ErrorCode::InvalidMessage, "invalid display session"))?;
        let mut bytes = Vec::with_capacity(Self::HEADER_BYTES + 256);
        bytes.extend_from_slice(Self::MAGIC);
        bytes.push(Self::VERSION);
        bytes.extend_from_slice(&self.schema_version.to_be_bytes());
        bytes.extend_from_slice(session.as_bytes());
        bytes.extend_from_slice(&self.connection_generation.to_be_bytes());
        bytes.extend_from_slice(&self.lease_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.message.encode()?);
        if bytes.len() > MAX_WEBRTC_CONTROL_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "WebRTC display control budget exceeded",
            ));
        }
        Ok(bytes)
    }

    pub fn validate(&self, claims: &crate::PermitClaims) -> Result<(), crate::ContractError> {
        use crate::{ContractError, ErrorCode, Permission, SCHEMA_VERSION};

        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "unsupported WebRTC display schema",
            ));
        }
        if self.session_id != claims.session_id
            || self.connection_generation != claims.connection_generation
            || self.lease_sequence != claims.lease_sequence
            || !claims.permissions.contains(&(Permission::View as i32))
        {
            return Err(ContractError::new(
                ErrorCode::InvalidMessage,
                "WebRTC display control binding invalid",
            ));
        }
        let key = match &self.message {
            crate::native_displays::DisplayEnvelope::Recovery(_) => {
                return Err(ContractError::new(
                    ErrorCode::InvalidMessage,
                    "video recovery is outside display selection control",
                ));
            }
            crate::native_displays::DisplayEnvelope::CatalogBegin { catalog, .. }
            | crate::native_displays::DisplayEnvelope::CatalogEntry { catalog, .. }
            | crate::native_displays::DisplayEnvelope::CatalogCommit(catalog)
            | crate::native_displays::DisplayEnvelope::CatalogAck(catalog)
            | crate::native_displays::DisplayEnvelope::Select { catalog, .. }
            | crate::native_displays::DisplayEnvelope::Selected(
                crate::native_displays::DisplaySelection { catalog, .. },
            )
            | crate::native_displays::DisplayEnvelope::SelectionAck(
                crate::native_displays::DisplaySelection { catalog, .. },
            ) => catalog,
        };
        key.validate()?;
        if key.request_id != claims.session_id
            || key.connection_generation != claims.connection_generation
        {
            return Err(ContractError::new(
                ErrorCode::InvalidMessage,
                "WebRTC display catalogue belongs to another session",
            ));
        }
        if let crate::native_displays::DisplayEnvelope::Selected(selection)
        | crate::native_displays::DisplayEnvelope::SelectionAck(selection) = &self.message
        {
            selection.validate()?;
            let has_input = claims.permissions.contains(&(Permission::Input as i32));
            if has_input != (selection.input_epoch != 0) {
                return Err(ContractError::new(
                    ErrorCode::PermissionRequired,
                    "WebRTC display input epoch does not match the permit",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebRtcControl {
    /// Reuses the native mutual challenge/proof transcript on DTLS/SCTP.
    EndpointProof {
        schema_version: u32,
        session_id: String,
        connection_generation: u64,
        lease_sequence: u64,
        proof: crate::NativeProof,
    },
    EndpointProofAccepted {
        schema_version: u32,
        session_id: String,
        connection_generation: u64,
        lease_sequence: u64,
    },
    /// `lease_sequence` is the next sequence, signed against the current lease.
    HostRenewalSignature {
        schema_version: u32,
        session_id: String,
        connection_generation: u64,
        lease_sequence: u64,
        signature: String,
    },
    /// Host-to-controller input bounds are sent only after mutual endpoint
    /// proof and only when Input is present in the signed permit.
    HostInputLayout {
        schema_version: u32,
        session_id: String,
        connection_generation: u64,
        lease_sequence: u64,
        input_epoch: u64,
        layout_epoch: u64,
        left: i32,
        top: i32,
        width: u32,
        height: u32,
    },
    /// Controller-to-host input is lease-, connection-, layout- and sequence-bound.
    InputEvent {
        schema_version: u32,
        session_id: String,
        connection_generation: u64,
        lease_sequence: u64,
        input_epoch: u64,
        layout_epoch: u64,
        sequence: u64,
        action: WebRtcInputAction,
    },
    /// Focus loss is explicit so held keys/buttons are released immediately.
    InputReleaseAll {
        schema_version: u32,
        session_id: String,
        connection_generation: u64,
        lease_sequence: u64,
        input_epoch: u64,
        layout_epoch: u64,
    },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebRtcInputAction {
    Scroll { x: i32, y: i32 },
    Key { usage: u16, down: bool },
    Pointer {
        button: Option<u8>,
        down: bool,
        x: i32,
        y: i32,
    },
    Text { text: String },
}
