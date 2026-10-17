//! One bounded FileWrite envelope. Paths carry no ambient filesystem authority.
use crate::{
    ContractError, ErrorCode, FILE_CHUNK_BYTES, FILE_PAYLOAD_BYTES, FILE_SIZE_BYTES,
    FileWriteErrorCode, FileWriteState, NativeFileWrite, SCHEMA_VERSION, decode_bounded,
    files::validate_relative_path, native_file_write::Action, valid_id,
};
use prost::Message;

fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}
impl FileWriteState {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.confirmed_bytes > FILE_SIZE_BYTES
            || (self.temporary_removed && !self.file_closed)
            || (self.directory_synced && (!self.published || !self.temporary_removed))
        {
            return Err(invalid("inconsistent file write state"));
        }
        Ok(())
    }
}
impl NativeFileWrite {
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
                "unsupported file write schema",
            ));
        }
        if !valid_id(&self.transfer_id)
            || [self.connection_generation, self.sequence]
                .iter()
                .any(|v| *v == 0 || *v > i64::MAX as u64)
        {
            return Err(invalid("invalid file write identity or generation"));
        }
        if self.encoded_len() as u64 > FILE_CHUNK_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "file write envelope exceeds budget",
            ));
        }
        match self
            .action
            .as_ref()
            .ok_or_else(|| invalid("missing file write action"))?
        {
            Action::Open(open) => {
                validate_relative_path(&open.path)?;
                if !valid_id(&open.root_id)
                    || open.size > FILE_SIZE_BYTES
                    || open.sha256.len() != 32
                {
                    return Err(invalid("invalid file write open"));
                }
            }
            Action::Chunk(chunk)
                if !chunk.data.is_empty()
                    && chunk.data.len() as u64 <= FILE_PAYLOAD_BYTES
                    && chunk.sha256.len() == 32
                    && chunk
                        .offset
                        .checked_add(chunk.data.len() as u64)
                        .is_some_and(|end| end <= FILE_SIZE_BYTES) => {}
            Action::Commit(commit)
                if commit.size <= FILE_SIZE_BYTES && commit.sha256.len() == 32 => {}
            Action::Cancel(true) => {}
            Action::Ready(ready)
                if ready.size <= FILE_SIZE_BYTES
                    && ready.sha256.len() == 32
                    && ready.offset == 0 => {}
            Action::Ack(ack) if ack.offset <= FILE_SIZE_BYTES => {}
            Action::Committed(receipt)
                if receipt.size <= FILE_SIZE_BYTES && receipt.sha256.len() == 32 =>
            {
                let state = receipt
                    .state
                    .as_ref()
                    .ok_or_else(|| invalid("missing committed file facts"))?;
                state.validate()?;
                if state.confirmed_bytes != receipt.size
                    || !state.published
                    || !state.file_closed
                    || !state.temporary_removed
                    || state.poisoned
                {
                    return Err(invalid("file was not completely committed and cleaned"));
                }
            }
            Action::Cancelled(cancelled) => {
                let state = cancelled
                    .state
                    .as_ref()
                    .ok_or_else(|| invalid("missing cancelled file facts"))?;
                state.validate()?;
                if !state.file_closed || !state.temporary_removed {
                    return Err(invalid("file cancellation did not close and clean storage"));
                }
            }
            Action::Failure(failure)
                if FileWriteErrorCode::try_from(failure.code)
                    .is_ok_and(|code| code != FileWriteErrorCode::FileWriteErrorUnspecified) =>
            {
                if let Some(state) = &failure.state {
                    state.validate()?;
                }
            }
            Action::RootsRequest(request) => request.validate()?,
            Action::Roots(roots) => roots.validate_file_write()?,
            _ => return Err(invalid("invalid file write fields")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uploads_are_bounded_and_require_a_complete_manifest() -> Result<(), ContractError> {
        let mut envelope = NativeFileWrite {
            schema_version: SCHEMA_VERSION,
            connection_generation: 9,
            sequence: 1,
            transfer_id: "00000001-1111-4111-8111-111111111111".into(),
            action: Some(Action::Open(crate::FileWriteOpen {
                root_id: "00000002-1111-4111-8111-111111111111".into(),
                path: "文档/file.txt".into(),
                size: 3,
                sha256: vec![2; 32],
            })),
        };
        assert!(envelope.encode_validated().is_ok());
        if let Some(Action::Open(open)) = &mut envelope.action {
            open.path = "../escape".into();
        }
        assert!(envelope.validate().is_err());
        envelope.action = Some(Action::Chunk(crate::FileWriteChunk {
            offset: 0,
            data: vec![1; FILE_PAYLOAD_BYTES as usize],
            sha256: vec![2; 32],
        }));
        let wire = envelope.encode_validated()?;
        assert_eq!(NativeFileWrite::decode_validated(&wire)?, envelope);
        if let Some(Action::Chunk(chunk)) = &mut envelope.action {
            chunk.data.push(1);
        }
        assert!(envelope.validate().is_err());
        assert!(
            NativeFileWrite::decode_validated(&vec![0; FILE_CHUNK_BYTES as usize + 1]).is_err()
        );
        envelope.action = Some(Action::Cancel(false));
        assert!(envelope.validate().is_err());
        Ok(())
    }
    #[test]
    fn publication_and_cleanup_are_separate_wire_facts() {
        let partial = FileWriteState {
            confirmed_bytes: 4,
            published: true,
            file_closed: false,
            temporary_removed: false,
            directory_synced: false,
            poisoned: false,
        };
        assert!(partial.validate().is_ok());
        let mut invalid = partial;
        invalid.directory_synced = true;
        assert!(invalid.validate().is_err());
    }
}
