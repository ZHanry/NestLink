//! Explicit format proposal/acknowledgement on the authenticated feedback route.
//! This module never grants authority and never falls back from malformed NLMF.
use crate::{
    ContractError, ErrorCode,
    media_format::{FormatSet, VideoFormat},
    native_displays::{DisplayEnvelope, DisplaySelection},
};
const MAX_BYTES: usize = 512;
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid native format envelope")
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatSelection {
    pub display: DisplaySelection,
    pub format_epoch: u64,
    pub format: VideoFormat,
    pub format_sha256: [u8; 32],
}
impl FormatSelection {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.display.validate()?;
        if self.format_epoch == 0
            || self.format_epoch > i64::MAX as u64
            || self.format.digest()? != self.format_sha256
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn authorized(
        &self,
        display: &DisplaySelection,
        formats: &FormatSet,
    ) -> Result<(), ContractError> {
        self.validate()?;
        if &self.display != display || !formats.contains(&self.format) {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatEnvelope {
    Propose(FormatSelection),
    Ack(FormatSelection),
}
impl FormatEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, ContractError> {
        let (kind, value) = match self {
            Self::Propose(v) => (1, v),
            Self::Ack(v) => (2, v),
        };
        value.validate()?;
        // The embedded exact NLDF Selected encoding reuses its canonical UUID,
        // catalogue digest, source, selection and layout/input epoch contract.
        let display = DisplayEnvelope::Selected(value.display.clone()).encode()?;
        let mut out = b"NLMF".to_vec();
        out.extend_from_slice(&[1, kind]);
        out.extend_from_slice(&(display.len() as u16).to_be_bytes());
        out.extend_from_slice(&display);
        out.extend_from_slice(&value.format_epoch.to_be_bytes());
        out.extend_from_slice(&value.format_sha256);
        out.extend_from_slice(&value.format.encode()?);
        if out.len() > MAX_BYTES {
            return Err(invalid());
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() < 8
            || bytes.len() > MAX_BYTES
            || &bytes[..4] != b"NLMF"
            || bytes[4] != 1
            || !matches!(bytes[5], 1 | 2)
        {
            return Err(invalid());
        }
        let length = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
        let end = 8usize.checked_add(length).ok_or_else(invalid)?;
        if end.checked_add(8 + 32 + 57) != Some(bytes.len()) {
            return Err(invalid());
        }
        let DisplayEnvelope::Selected(display) = DisplayEnvelope::decode(&bytes[8..end])? else {
            return Err(invalid());
        };
        let value = FormatSelection {
            display,
            format_epoch: u64::from_be_bytes(
                bytes[end..end + 8].try_into().map_err(|_| invalid())?,
            ),
            format_sha256: bytes[end + 8..end + 40].try_into().map_err(|_| invalid())?,
            format: VideoFormat::decode(&bytes[end + 40..])?,
        };
        value.validate()?;
        let result = if bytes[5] == 1 {
            Self::Propose(value)
        } else {
            Self::Ack(value)
        };
        if result.encode()?.as_slice() != bytes {
            return Err(invalid());
        }
        Ok(result)
    }
}
/// One proposal at a time; no overwrite, implicit ACK or wrapping epoch.
#[derive(Default)]
pub struct FormatConfirmation {
    pending: Option<FormatSelection>,
    confirmed: Option<FormatSelection>,
    last_epoch: u64,
}
impl FormatConfirmation {
    pub fn next_epoch(&self) -> Result<u64, ContractError> {
        self.last_epoch
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or_else(invalid)
    }
    pub fn pending(&self) -> Option<&FormatSelection> {
        self.pending.as_ref()
    }
    pub fn confirmed(&self) -> Option<&FormatSelection> {
        if self.pending.is_some() {
            None
        } else {
            self.confirmed.as_ref()
        }
    }
    pub fn stage(
        &mut self,
        value: FormatSelection,
        display: &DisplaySelection,
        formats: &FormatSet,
    ) -> Result<(), ContractError> {
        value.authorized(display, formats)?;
        if self.pending.is_some() || self.last_epoch.checked_add(1) != Some(value.format_epoch) {
            return Err(invalid());
        }
        self.pending = Some(value);
        Ok(())
    }
    pub fn acknowledge(&mut self, value: &FormatSelection) -> Result<(), ContractError> {
        value.validate()?;
        if self.pending.as_ref() != Some(value) {
            return Err(invalid());
        }
        self.last_epoch = value.format_epoch;
        self.confirmed = self.pending.take();
        Ok(())
    }
    /// Cancelling a proposal does not reuse its epoch in the same route lifetime.
    pub fn cancel(&mut self) {
        if let Some(value) = self.pending.take() {
            self.last_epoch = value.format_epoch;
        }
        self.confirmed = None;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{media_format::FrameRate, native_displays::DisplayCatalogKey};
    fn value() -> FormatSelection {
        let format =
            VideoFormat::legacy_h264(30, 320, 240, FrameRate::new(30, 1).unwrap(), 1000).unwrap();
        FormatSelection {
            display: DisplaySelection {
                catalog: DisplayCatalogKey {
                    request_id: "12345678-1234-4234-8234-123456789abc".into(),
                    connection_generation: 1,
                    revision: 1,
                    sha256: [7; 32],
                },
                sequence: 1,
                source: 0,
                layout_epoch: 1,
                input_epoch: 0,
            },
            format_epoch: 1,
            format,
            format_sha256: format.digest().unwrap(),
        }
    }
    #[test]
    fn exact_canonical_roundtrip_rejects_tail_kind_version_hash_and_truncation() {
        let envelope = FormatEnvelope::Propose(value());
        let bytes = envelope.encode().unwrap();
        assert_eq!(FormatEnvelope::decode(&bytes).unwrap(), envelope);
        for end in 0..bytes.len() {
            assert!(FormatEnvelope::decode(&bytes[..end]).is_err());
        }
        let mut tail = bytes.clone();
        tail.push(0);
        assert!(FormatEnvelope::decode(&tail).is_err());
        for (index, byte) in [
            (0, b'X'),
            (4, 2),
            (5, 3),
            (bytes.len() - 58, bytes[bytes.len() - 58] ^ 1),
        ] {
            let mut bad = bytes.clone();
            bad[index] = byte;
            assert!(FormatEnvelope::decode(&bad).is_err());
        }
    }
    #[test]
    fn proposal_ack_requires_exact_signed_format_and_binding_and_never_overwrites() {
        let first = value();
        let formats = FormatSet::new(vec![first.format]).unwrap();
        let mut state = FormatConfirmation::default();
        assert!(state.acknowledge(&first).is_err());
        state
            .stage(first.clone(), &first.display, &formats)
            .unwrap();
        assert!(
            state
                .stage(first.clone(), &first.display, &formats)
                .is_err()
        );
        let mut wrong = first.clone();
        wrong.display.layout_epoch += 1;
        assert!(state.acknowledge(&wrong).is_err());
        assert!(state.confirmed().is_none());
        state.acknowledge(&first).unwrap();
        assert_eq!(state.confirmed(), Some(&first));
        assert!(
            state
                .stage(first.clone(), &first.display, &formats)
                .is_err()
        );
        let mut second = first.clone();
        second.format_epoch = 2;
        state
            .stage(second.clone(), &second.display, &formats)
            .unwrap();
        state.cancel();
        assert!(state.confirmed().is_none());
        assert!(
            state
                .stage(second.clone(), &second.display, &formats)
                .is_err()
        );
        second.format_epoch = 3;
        let empty = FormatSet::new(vec![]).unwrap();
        assert!(
            state
                .stage(second.clone(), &second.display, &empty)
                .is_err()
        );
        state
            .stage(second.clone(), &second.display, &formats)
            .unwrap();
        state.acknowledge(&second).unwrap();
    }
}
/// Explicit outer discriminator; malformed recognized envelopes never fall back.
#[derive(Clone, Debug, PartialEq)]
pub enum FeedbackEnvelope {
    Display(DisplayEnvelope),
    Format(FormatEnvelope),
}
impl FeedbackEnvelope {
    pub fn decode(bytes: &[u8], format_negotiated: bool) -> Result<Self, ContractError> {
        match bytes.get(..4) {
            Some(b"NLDF") => Ok(Self::Display(DisplayEnvelope::decode(bytes)?)),
            Some(b"NLMF") if format_negotiated => Ok(Self::Format(FormatEnvelope::decode(bytes)?)),
            _ => Err(invalid()),
        }
    }
}
