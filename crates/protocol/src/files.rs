//! Portable relative paths and bounded native FileRead envelopes.
use crate::{
    ContractError, ErrorCode, FILE_CHUNK_BYTES, FILE_PATH_BYTES, FILE_PATH_DEPTH,
    FILE_PAYLOAD_BYTES, FILE_SIZE_BYTES, FileReadErrorCode, NativeFileRead, SCHEMA_VERSION,
    decode_bounded, native_file_read::Action, valid_id,
};
use prost::Message;

fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}

/// Use the same namespace on every platform. No path normalization or escaping
/// is applied after this validation. OS adapters still resolve from a root handle.
pub fn validate_relative_path(path: &str) -> Result<(), ContractError> {
    if path.is_empty() || path.len() as u64 > FILE_PATH_BYTES {
        return Err(invalid("invalid file path length"));
    }
    let mut depth = 0;
    for component in path.split('/') {
        depth += 1;
        let stem = component.split('.').next().unwrap_or_default();
        let upper = stem.trim_end_matches(['.', ' ']).to_ascii_uppercase();
        let reserved = matches!(
            upper.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            upper.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
        if depth > FILE_PATH_DEPTH
            || component.is_empty()
            || component.len() > 255
            || matches!(component, "." | "..")
            || component.ends_with(['.', ' '])
            || component.chars().any(|c| {
                c.is_control() || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
            })
            || reserved
        {
            return Err(invalid("file path is not a portable relative path"));
        }
    }
    Ok(())
}

impl NativeFileRead {
    pub fn decode_validated(bytes: &[u8]) -> Result<Self, ContractError> {
        let message: Self = decode_bounded(bytes, FILE_CHUNK_BYTES)?;
        message.validate()?;
        Ok(message)
    }
    pub fn encode_validated(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        Ok(self.encode_to_vec())
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "unsupported file schema",
            ));
        }
        if !valid_id(&self.transfer_id)
            || [self.connection_generation, self.sequence]
                .iter()
                .any(|v| *v == 0 || *v > i64::MAX as u64)
        {
            return Err(invalid("invalid file transfer identity or generation"));
        }
        if self.encoded_len() as u64 > FILE_CHUNK_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "file envelope exceeds byte budget",
            ));
        }
        match self
            .action
            .as_ref()
            .ok_or_else(|| invalid("missing file action"))?
        {
            Action::Open(open) => {
                validate_relative_path(&open.path)?;
                if !valid_id(&open.root_id)
                    || open.offset > FILE_SIZE_BYTES
                    || !(open.expected_sha256.len() == 32
                        || (open.offset == 0 && open.expected_sha256.is_empty()))
                {
                    return Err(invalid("invalid file open or resume"));
                }
            }
            Action::Next(next) if next.offset <= FILE_SIZE_BYTES => {}
            Action::Cancel(true) | Action::Cancelled(true) => {}
            Action::Manifest(manifest)
                if manifest.size <= FILE_SIZE_BYTES
                    && manifest.offset <= manifest.size
                    && manifest.sha256.len() == 32 => {}
            Action::Chunk(chunk)
                if !chunk.data.is_empty()
                    && chunk.data.len() as u64 <= FILE_PAYLOAD_BYTES
                    && chunk.sha256.len() == 32
                    && chunk
                        .offset
                        .checked_add(chunk.data.len() as u64)
                        .is_some_and(|end| end <= FILE_SIZE_BYTES) => {}
            Action::End(end) if end.size <= FILE_SIZE_BYTES && end.sha256.len() == 32 => {}
            Action::Failure(failure)
                if FileReadErrorCode::try_from(failure.code)
                    .is_ok_and(|code| code != FileReadErrorCode::FileReadErrorUnspecified) => {}
            Action::BrowseBegin(begin) => begin.validate()?,
            Action::BrowseNext(next) => next.validate()?,
            Action::BrowsePage(page) => page.validate()?,
            Action::RootsRequest(request) => request.validate()?,
            Action::Roots(roots) => roots.validate_file_read()?,
            _ => return Err(invalid("invalid file action fields")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn portable_paths_reject_traversal_devices_streams_and_ambiguous_names() {
        for path in ["中文/文件.txt", "nested/.hidden", "file", "COM10.txt"] {
            assert!(validate_relative_path(path).is_ok(), "{path}");
        }
        for path in [
            "",
            "/etc/passwd",
            "../secret",
            "a/../b",
            "a//b",
            "a/./b",
            "C:/file",
            "\\\\server\\file",
            "file:stream",
            "a\\b",
            "NUL.txt",
            "con",
            "com1.txt",
            "LPT³",
            "file.",
            "file ",
            "a\0b",
            "a\nb",
            "a/*",
        ] {
            assert!(validate_relative_path(path).is_err(), "{path:?}");
        }
        assert!(
            validate_relative_path(&std::iter::repeat_n("a", 33).collect::<Vec<_>>().join("/"))
                .is_err()
        );
        assert!(validate_relative_path(&"a".repeat(256)).is_err());
    }
    #[test]
    fn file_messages_require_bounded_payloads_and_resume_identity() {
        let mut message = NativeFileRead {
            schema_version: SCHEMA_VERSION,
            connection_generation: 1,
            sequence: 1,
            transfer_id: "00000001-1111-4111-8111-111111111111".into(),
            action: Some(Action::Open(crate::FileReadOpen {
                root_id: "00000002-1111-4111-8111-111111111111".into(),
                path: "file.txt".into(),
                offset: 10,
                expected_sha256: vec![],
            })),
        };
        assert!(message.validate().is_err());
        if let Some(Action::Open(open)) = &mut message.action {
            open.expected_sha256 = vec![1; 32];
        }
        let bytes = message.encode_validated();
        assert!(bytes.is_ok());
        message.action = Some(Action::Chunk(crate::FileReadChunk {
            offset: 0,
            data: vec![1; FILE_PAYLOAD_BYTES as usize],
            sha256: vec![1; 32],
        }));
        assert!(message.encode_validated().is_ok());
        if let Some(Action::Chunk(chunk)) = &mut message.action {
            chunk.data.push(1);
        }
        assert!(message.validate().is_err());
        assert!(NativeFileRead::decode_validated(&vec![0; FILE_CHUNK_BYTES as usize + 1]).is_err());
        message.action = Some(Action::Cancel(false));
        assert!(message.validate().is_err());
    }
}
