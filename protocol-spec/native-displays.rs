// Sole native display/VideoFeedback wire contract. All integers are big endian.
// Every message starts NLDF, version 1, kind u8; unknown versions/kinds and any
// trailing bytes fail. There is no heuristic or raw-protobuf fallback.
use crate::{ContractError, ErrorCode, NativeVideoFeedback, VIDEO_FEEDBACK_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DISPLAY_COUNT_MAX: usize = 64;
pub const DISPLAY_LABEL_BYTES: usize = 80;
pub const DISPLAY_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAGIC: &[u8; 4] = b"NLDF";
const VERSION: u8 = 1;

fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid native display envelope")
}
fn epoch(value: u64) -> bool {
    value > 0 && value <= i64::MAX as u64
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayDescriptor {
    pub source: u32,
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
    pub label: String,
}
impl DisplayDescriptor {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.width == 0
            || self.height == 0
            || self.width > 8192
            || self.height > 8192
            || u64::from(self.width) * u64::from(self.height) * 4 > 64 * 1024 * 1024
            || self.left.checked_add_unsigned(self.width).is_none()
            || self.top.checked_add_unsigned(self.height).is_none()
            || self.label.is_empty()
            || self.label.len() > DISPLAY_LABEL_BYTES
            || self.label.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayCatalogKey {
    pub request_id: String,
    pub connection_generation: u64,
    pub revision: u64,
    pub sha256: [u8; 32],
}
impl DisplayCatalogKey {
    pub fn validate(&self) -> Result<(), ContractError> {
        if !crate::valid_id(&self.request_id)
            || !epoch(self.connection_generation)
            || !epoch(self.revision)
            || self.sha256 == [0; 32]
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Hash is SHA-256(domain || canonical request UUID bytes || connection ||
/// revision || count || sorted descriptor bytes). Local approval and transport
/// catalogue acknowledgement use exactly this key, never just a source number.
pub fn catalog_key(
    request_id: &str,
    connection_generation: u64,
    revision: u64,
    displays: &[DisplayDescriptor],
) -> Result<DisplayCatalogKey, ContractError> {
    validate_candidates(displays)?;
    let id = uuid::Uuid::parse_str(request_id).map_err(|_| invalid())?;
    if !crate::valid_id(request_id) || !epoch(connection_generation) || !epoch(revision) {
        return Err(invalid());
    }
    let mut canonical = b"NestLink/native-displays/v1\0".to_vec();
    canonical.extend_from_slice(id.as_bytes());
    canonical.extend_from_slice(&connection_generation.to_be_bytes());
    canonical.extend_from_slice(&revision.to_be_bytes());
    canonical.push(displays.len() as u8);
    for display in displays {
        write_display(&mut canonical, display);
    }
    Ok(DisplayCatalogKey {
        request_id: request_id.to_owned(),
        connection_generation,
        revision,
        sha256: Sha256::digest(canonical).into(),
    })
}
/// Read-only enumeration may exceed the approved capture memory budget: the
/// local owner can choose a bounded subset before any capture is opened.
pub fn validate_candidates(displays: &[DisplayDescriptor]) -> Result<(), ContractError> {
    if displays.is_empty() || displays.len() > DISPLAY_COUNT_MAX {
        return Err(invalid());
    }
    let mut last = None;
    for display in displays {
        display.validate()?;
        if last.is_some_and(|source| source >= display.source) {
            return Err(invalid());
        }
        last = Some(display.source);
    }
    Ok(())
}
/// Applied to the exact granted/captured set, before transport acknowledgement.
pub fn validate_displays(displays: &[DisplayDescriptor]) -> Result<(), ContractError> {
    validate_candidates(displays)?;
    let total: u64 = displays
        .iter()
        .map(|d| u64::from(d.width) * u64::from(d.height) * 4)
        .sum();
    if total > DISPLAY_TOTAL_BYTES {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplaySelection {
    pub catalog: DisplayCatalogKey,
    pub sequence: u64,
    pub source: u32,
    pub layout_epoch: u64,
    /// Zero only when this proved session has no Input permission.
    pub input_epoch: u64,
}
impl DisplaySelection {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.catalog.validate()?;
        if !epoch(self.sequence) || !epoch(self.layout_epoch) || self.input_epoch > i64::MAX as u64
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum DisplayEnvelope {
    Recovery(NativeVideoFeedback),
    CatalogBegin {
        catalog: DisplayCatalogKey,
        count: u8,
    },
    CatalogEntry {
        catalog: DisplayCatalogKey,
        index: u8,
        display: DisplayDescriptor,
    },
    CatalogCommit(DisplayCatalogKey),
    CatalogAck(DisplayCatalogKey),
    Select {
        catalog: DisplayCatalogKey,
        sequence: u64,
        source: u32,
    },
    Selected(DisplaySelection),
    SelectionAck(DisplaySelection),
}
impl DisplayEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, ContractError> {
        let kind = match self {
            Self::Recovery(_) => 0,
            Self::CatalogBegin { .. } => 1,
            Self::CatalogEntry { .. } => 2,
            Self::CatalogCommit(_) => 3,
            Self::CatalogAck(_) => 4,
            Self::Select { .. } => 5,
            Self::Selected(_) => 6,
            Self::SelectionAck(_) => 7,
        };
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&[VERSION, kind]);
        match self {
            Self::Recovery(value) => bytes.extend_from_slice(&value.encode_validated()?),
            Self::CatalogBegin { catalog, count } => {
                write_key(&mut bytes, catalog)?;
                if *count == 0 || usize::from(*count) > DISPLAY_COUNT_MAX {
                    return Err(invalid());
                }
                bytes.push(*count);
            }
            Self::CatalogEntry {
                catalog,
                index,
                display,
            } => {
                write_key(&mut bytes, catalog)?;
                display.validate()?;
                if usize::from(*index) >= DISPLAY_COUNT_MAX {
                    return Err(invalid());
                }
                bytes.push(*index);
                write_display(&mut bytes, display);
            }
            Self::CatalogCommit(key) | Self::CatalogAck(key) => write_key(&mut bytes, key)?,
            Self::Select {
                catalog,
                sequence,
                source,
            } => {
                write_key(&mut bytes, catalog)?;
                if !epoch(*sequence) {
                    return Err(invalid());
                }
                bytes.extend_from_slice(&sequence.to_be_bytes());
                bytes.extend_from_slice(&source.to_be_bytes());
            }
            Self::Selected(selection) | Self::SelectionAck(selection) => {
                selection.validate()?;
                write_key(&mut bytes, &selection.catalog)?;
                bytes.extend_from_slice(&selection.sequence.to_be_bytes());
                bytes.extend_from_slice(&selection.source.to_be_bytes());
                bytes.extend_from_slice(&selection.layout_epoch.to_be_bytes());
                bytes.extend_from_slice(&selection.input_epoch.to_be_bytes());
            }
        }
        if bytes.len() as u64 > VIDEO_FEEDBACK_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() < 6 || bytes.len() as u64 > VIDEO_FEEDBACK_BYTES || &bytes[..4] != MAGIC {
            return Err(invalid());
        }
        if bytes[4] != VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "native display version",
            ));
        }
        // Only the explicit Recovery discriminant admits the protobuf format.
        // Canonical re-encoding rejects unknown protobuf fields and duplicate
        // singular fields; malformed bytes never enter another message parser.
        if bytes[5] == 0 {
            let value = NativeVideoFeedback::decode_validated(&bytes[6..])?;
            if value.encode_validated()?.as_slice() != &bytes[6..] {
                return Err(invalid());
            }
            return Ok(Self::Recovery(value));
        }
        let mut reader = Reader(&bytes[6..]);
        let catalog = reader.key()?;
        let message = match bytes[5] {
            1 => Self::CatalogBegin {
                catalog,
                count: reader.byte()?,
            },
            2 => Self::CatalogEntry {
                catalog,
                index: reader.byte()?,
                display: reader.display()?,
            },
            3 => Self::CatalogCommit(catalog),
            4 => Self::CatalogAck(catalog),
            5 => Self::Select {
                catalog,
                sequence: reader.u64()?,
                source: reader.u32()?,
            },
            6 | 7 => {
                let selection = DisplaySelection {
                    catalog,
                    sequence: reader.u64()?,
                    source: reader.u32()?,
                    layout_epoch: reader.u64()?,
                    input_epoch: reader.u64()?,
                };
                if bytes[5] == 6 {
                    Self::Selected(selection)
                } else {
                    Self::SelectionAck(selection)
                }
            }
            _ => return Err(invalid()),
        };
        if !reader.0.is_empty() || message.encode()?.as_slice() != bytes {
            return Err(invalid());
        }
        Ok(message)
    }
}
fn write_key(bytes: &mut Vec<u8>, key: &DisplayCatalogKey) -> Result<(), ContractError> {
    key.validate()?;
    bytes.extend_from_slice(
        uuid::Uuid::parse_str(&key.request_id)
            .map_err(|_| invalid())?
            .as_bytes(),
    );
    bytes.extend_from_slice(&key.connection_generation.to_be_bytes());
    bytes.extend_from_slice(&key.revision.to_be_bytes());
    bytes.extend_from_slice(&key.sha256);
    Ok(())
}
fn write_display(bytes: &mut Vec<u8>, display: &DisplayDescriptor) {
    bytes.extend_from_slice(&display.source.to_be_bytes());
    bytes.extend_from_slice(&display.left.to_be_bytes());
    bytes.extend_from_slice(&display.top.to_be_bytes());
    bytes.extend_from_slice(&display.width.to_be_bytes());
    bytes.extend_from_slice(&display.height.to_be_bytes());
    bytes.push(display.label.len() as u8);
    bytes.extend_from_slice(display.label.as_bytes());
}
struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], ContractError> {
        let bytes = self.0.get(..N).ok_or_else(invalid)?;
        let result = bytes.try_into().map_err(|_| invalid())?;
        self.0 = &self.0[N..];
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8, ContractError> {
        Ok(self.take::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64, ContractError> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn u32(&mut self) -> Result<u32, ContractError> {
        Ok(u32::from_be_bytes(self.take()?))
    }
    fn key(&mut self) -> Result<DisplayCatalogKey, ContractError> {
        Ok(DisplayCatalogKey {
            request_id: uuid::Uuid::from_bytes(self.take()?)
                .hyphenated()
                .to_string(),
            connection_generation: self.u64()?,
            revision: self.u64()?,
            sha256: self.take()?,
        })
    }
    fn display(&mut self) -> Result<DisplayDescriptor, ContractError> {
        let source = self.u32()?;
        let left = i32::from_be_bytes(self.take()?);
        let top = i32::from_be_bytes(self.take()?);
        let width = self.u32()?;
        let height = self.u32()?;
        let length = usize::from(self.byte()?);
        if length > DISPLAY_LABEL_BYTES {
            return Err(invalid());
        }
        let label = std::str::from_utf8(self.0.get(..length).ok_or_else(invalid)?)
            .map_err(|_| invalid())?
            .to_owned();
        self.0 = &self.0[length..];
        Ok(DisplayDescriptor {
            source,
            left,
            top,
            width,
            height,
            label,
        })
    }
}

/// At most one bounded transaction is assembled. A catalogue cannot partially
/// replace the allowlist; verify count, order, geometry and hash before ACK.
#[derive(Default)]
pub struct CatalogAssembler {
    pending: Option<(DisplayCatalogKey, u8, Vec<DisplayDescriptor>)>,
}
impl CatalogAssembler {
    pub fn begin(&mut self, key: DisplayCatalogKey, count: u8) -> Result<(), ContractError> {
        key.validate()?;
        if self.pending.is_some() || count == 0 || usize::from(count) > DISPLAY_COUNT_MAX {
            return Err(invalid());
        }
        self.pending = Some((key, count, Vec::with_capacity(usize::from(count))));
        Ok(())
    }
    pub fn entry(
        &mut self,
        key: DisplayCatalogKey,
        index: u8,
        display: DisplayDescriptor,
    ) -> Result<(), ContractError> {
        display.validate()?;
        let (current, count, entries) = self.pending.as_mut().ok_or_else(invalid)?;
        if current != &key || usize::from(index) != entries.len() || index >= *count {
            return Err(invalid());
        }
        entries.push(display);
        Ok(())
    }
    pub fn commit(
        &mut self,
        key: &DisplayCatalogKey,
    ) -> Result<Vec<DisplayDescriptor>, ContractError> {
        let (current, count, entries) = self.pending.take().ok_or_else(invalid)?;
        validate_displays(&entries)?;
        if &current != key
            || entries.len() != usize::from(count)
            || catalog_key(
                &key.request_id,
                key.connection_generation,
                key.revision,
                &entries,
            )? != *key
        {
            return Err(invalid());
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn displays() -> Vec<DisplayDescriptor> {
        vec![
            DisplayDescriptor {
                source: 3,
                left: -1920,
                top: 0,
                width: 1920,
                height: 1080,
                label: "左屏".into(),
            },
            DisplayDescriptor {
                source: 8,
                left: 0,
                top: 0,
                width: 2560,
                height: 1440,
                label: "主屏".into(),
            },
        ]
    }
    #[test]
    fn envelopes_are_strict_and_fit_the_existing_feedback_budget() -> Result<(), ContractError> {
        let d = displays();
        let key = catalog_key("12345678-1234-4234-8234-123456789abc", 2, 1, &d)?;
        let selection = DisplaySelection {
            catalog: key.clone(),
            sequence: 2,
            source: 8,
            layout_epoch: 2,
            input_epoch: 2,
        };
        let messages = [
            DisplayEnvelope::Recovery(NativeVideoFeedback {
                schema_version: crate::SCHEMA_VERSION,
                connection_generation: 2,
                layout_epoch: 2,
                source: 8,
                request_sequence: 1,
                last_sequence: 1,
                reason: crate::VideoRecoveryReason::DecoderFailure as i32,
            }),
            DisplayEnvelope::CatalogBegin {
                catalog: key.clone(),
                count: 2,
            },
            DisplayEnvelope::CatalogEntry {
                catalog: key.clone(),
                index: 1,
                display: d[1].clone(),
            },
            DisplayEnvelope::CatalogCommit(key.clone()),
            DisplayEnvelope::CatalogAck(key.clone()),
            DisplayEnvelope::Select {
                catalog: key.clone(),
                sequence: 2,
                source: 8,
            },
            DisplayEnvelope::Selected(selection.clone()),
            DisplayEnvelope::SelectionAck(selection),
        ];
        for message in messages {
            let bytes = message.encode()?;
            assert!(bytes.len() <= 256);
            assert_eq!(DisplayEnvelope::decode(&bytes)?, message);
            for length in 0..bytes.len() {
                assert!(DisplayEnvelope::decode(&bytes[..length]).is_err());
            }
            let mut tail = bytes.clone();
            tail.push(0);
            assert!(DisplayEnvelope::decode(&tail).is_err());
            let mut version = bytes;
            version[4] = 2;
            assert!(DisplayEnvelope::decode(&version).is_err());
        }
        Ok(())
    }
    #[test]
    fn catalog_is_atomic_exact_and_cannot_reorder_or_expand_authority() -> Result<(), ContractError> {
        let d = displays();
        let key = catalog_key("12345678-1234-4234-8234-123456789abc", 2, 1, &d)?;
        let mut assembler = CatalogAssembler::default();
        assembler.begin(key.clone(), 2)?;
        assert!(assembler.entry(key.clone(), 1, d[0].clone()).is_err());
        assembler.entry(key.clone(), 0, d[0].clone())?;
        assert!(assembler.commit(&key).is_err());
        assembler.begin(key.clone(), 2)?;
        assembler.entry(key.clone(), 0, d[0].clone())?;
        assembler.entry(key.clone(), 1, d[1].clone())?;
        assert_eq!(assembler.commit(&key)?, d);
        let mut tampered = key.clone();
        tampered.sha256[0] ^= 1;
        assert_ne!(key, tampered);
        assembler.begin(tampered.clone(), 2)?;
        assembler.entry(tampered.clone(), 0, d[0].clone())?;
        assembler.entry(tampered.clone(), 1, d[1].clone())?;
        assert!(assembler.commit(&tampered).is_err());
        assert!(catalog_key(&key.request_id, 2, 1, &[d[1].clone(), d[0].clone()]).is_err());
        Ok(())
    }
    #[test]
    fn read_only_candidates_can_exceed_the_approved_capture_budget() -> Result<(), ContractError> {
        let displays: Vec<_> = (0..3)
            .map(|source| DisplayDescriptor {
                source,
                left: 0,
                top: 0,
                width: 4096,
                height: 4096,
                label: format!("screen {source}"),
            })
            .collect();
        let key = catalog_key("12345678-1234-4234-8234-123456789abc", 2, 1, &displays)?;
        assert!(validate_candidates(&displays).is_ok());
        assert!(validate_displays(&displays).is_err());
        assert!(validate_displays(&displays[..2]).is_ok());
        let mut assembler = CatalogAssembler::default();
        assembler.begin(key.clone(), 3)?;
        for (index, display) in displays.into_iter().enumerate() {
            assembler.entry(key.clone(), index as u8, display)?;
        }
        assert!(assembler.commit(&key).is_err());
        Ok(())
    }
}
