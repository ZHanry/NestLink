//! Shared native/browser input envelope. Layout bounds are checked by the host.
use crate::{
    ContractError, ErrorCode, INPUT_BYTES, InputCommand, NativeInputLayout, SCHEMA_VERSION,
    input_command::Action,
};
use prost::Message;
impl InputCommand {
    pub fn validate(&self) -> Result<(), ContractError> {
        let invalid = |reason| ContractError::new(ErrorCode::InvalidMessage, reason);
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "unsupported input schema",
            ));
        }
        if self.encoded_len() > INPUT_BYTES as usize {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "input envelope exceeds budget",
            ));
        }
        if [
            self.input_epoch,
            self.layout_epoch,
            self.connection_generation,
            self.sequence,
        ]
        .iter()
        .any(|n| *n == 0 || *n > i64::MAX as u64)
        {
            return Err(invalid("invalid input epoch or sequence"));
        }
        match self.action.as_ref() {
            Some(Action::ReleaseAll(true)) => Ok(()),
            Some(Action::Key(key)) if (4..=0xe7).contains(&key.hid_usage) => Ok(()),
            Some(Action::Pointer(pointer))
                if pointer.button.is_none_or(|b| (1..=5).contains(&b))
                    && (pointer.button.is_some() || !pointer.down) =>
            {
                Ok(())
            }
            Some(Action::Text(text))
                if !text.is_empty()
                    && !text
                        .chars()
                        .any(|c| c.is_control() && c != '\n' && c != '\t') =>
            {
                Ok(())
            }
            _ => Err(invalid("unknown mandatory or invalid input action")),
        }
    }
}

impl NativeInputLayout {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractError::new(
                ErrorCode::ProtocolMismatch,
                "unsupported input layout schema",
            ));
        }
        if self.encoded_len() > INPUT_BYTES as usize
            || [
                self.connection_generation,
                self.input_epoch,
                self.layout_epoch,
            ]
            .iter()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
            || self.width == 0
            || self.height == 0
            || self.width > 32768
            || self.height > 32768
            || self.left.checked_add_unsigned(self.width).is_none()
            || self.top.checked_add_unsigned(self.height).is_none()
        {
            return Err(ContractError::new(
                ErrorCode::InvalidMessage,
                "invalid native input layout",
            ));
        }
        Ok(())
    }
}
