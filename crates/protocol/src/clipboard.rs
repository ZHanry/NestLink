//! Typed text clipboard messages; UTF-8 and envelope consume the same budget.
use crate::{
    CLIPBOARD_BYTES, ClipboardErrorCode, ClipboardWriteEffect, ContractError, ErrorCode,
    NativeClipboard, SCHEMA_VERSION, decode_bounded, native_clipboard::Action,
};
use prost::Message;
use zeroize::Zeroize;

fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}
/// Platform adapters cannot preserve embedded NUL text consistently. Empty
/// text is an intentional clipboard clear; no text format is a distinct None.
pub fn validate_text(text: &str) -> Result<(), ContractError> {
    if text.as_bytes().contains(&0) {
        return Err(invalid("clipboard text contains NUL"));
    }
    if text.len() as u64 > CLIPBOARD_BYTES {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "clipboard text exceeds budget",
        ));
    }
    Ok(())
}
impl NativeClipboard {
    pub fn decode_validated(bytes: &[u8]) -> Result<Self, ContractError> {
        let mut message: Self = decode_bounded(bytes, CLIPBOARD_BYTES)?;
        if let Err(error) = message.validate() {
            match &mut message.action {
                Some(Action::Write(text)) => text.zeroize(),
                Some(Action::Text(text)) => {
                    if let Some(text) = &mut text.text {
                        text.zeroize();
                    }
                }
                _ => {}
            }
            return Err(error);
        }
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
                "unsupported clipboard schema",
            ));
        }
        if [self.connection_generation, self.sequence]
            .iter()
            .any(|value| *value == 0 || *value > i64::MAX as u64)
        {
            return Err(invalid("invalid clipboard generation or sequence"));
        }
        if self.encoded_len() as u64 > CLIPBOARD_BYTES {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "clipboard text and envelope exceed budget",
            ));
        }
        match self
            .action
            .as_ref()
            .ok_or_else(|| invalid("missing clipboard action"))?
        {
            Action::Read(true)
            | Action::Cancel(true)
            | Action::Written(true)
            | Action::Cancelled(true) => {}
            Action::Write(text) => validate_text(text)?,
            Action::Text(text) => {
                if let Some(text) = &text.text {
                    validate_text(text)?;
                }
            }
            Action::Failure(failure)
                if ClipboardErrorCode::try_from(failure.code)
                    .is_ok_and(|code| code != ClipboardErrorCode::ClipboardErrorUnspecified)
                    && ClipboardWriteEffect::try_from(failure.write_effect).is_ok() => {}
            _ => return Err(invalid("invalid clipboard action fields")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_utf8_envelope_budget_and_distinct_empty_format() -> Result<(), ContractError> {
        let mut message = NativeClipboard {
            schema_version: SCHEMA_VERSION,
            connection_generation: i64::MAX as u64,
            sequence: i64::MAX as u64,
            action: Some(Action::Write("界".repeat(CLIPBOARD_BYTES as usize / 3))),
        };
        assert!(message.encode_validated().is_err());
        message.action = Some(Action::Write(
            "界".repeat((CLIPBOARD_BYTES as usize - 128) / 3),
        ));
        let bytes = message.encode_validated()?;
        assert!(bytes.len() <= CLIPBOARD_BYTES as usize);
        assert_eq!(NativeClipboard::decode_validated(&bytes)?, message);
        message.action = Some(Action::Text(crate::ClipboardText { text: None }));
        let unavailable = message.encode_validated()?;
        message.action = Some(Action::Text(crate::ClipboardText {
            text: Some(String::new()),
        }));
        let cleared = message.encode_validated()?;
        assert_ne!(unavailable, cleared);
        message.action = Some(Action::Write("a\0b".into()));
        assert!(message.validate().is_err());
        assert!(NativeClipboard::decode_validated(&vec![0; CLIPBOARD_BYTES as usize + 1]).is_err());
        Ok(())
    }
    #[test]
    fn unknown_errors_actions_and_generations_are_rejected() {
        let mut message = NativeClipboard {
            schema_version: SCHEMA_VERSION,
            connection_generation: 1,
            sequence: 1,
            action: Some(Action::Read(false)),
        };
        assert!(message.validate().is_err());
        message.action = Some(Action::Failure(crate::ClipboardFailure {
            code: 123456,
            write_effect: 0,
        }));
        assert!(message.validate().is_err());
        message.action = Some(Action::Read(true));
        message.connection_generation = 0;
        assert!(message.validate().is_err());
    }
}
