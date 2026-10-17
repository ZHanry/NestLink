//! Single-page, consent-scoped discovery of locally approved file roots.
use crate::{
    ContractError, ErrorCode, FILE_READ_ROOTS, FILE_ROOT_DISPLAY_NAME_BYTES, FILE_WRITE_ROOTS,
    FileRoots, FileRootsRequest, valid_id,
};

fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}

impl FileRootsRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

impl FileRoots {
    /// Validate the bounded one-page directory or upload-root response.
    pub fn validate_for(&self, maximum: u64) -> Result<(), ContractError> {
        if self.roots.len() as u64 > maximum {
            return Err(ContractError::new(
                ErrorCode::CapacityExceeded,
                "too many approved file roots",
            ));
        }
        for root in &self.roots {
            if !valid_id(&root.root_id)
                || root.display_name.is_empty()
                || root.display_name.len() as u64 > FILE_ROOT_DISPLAY_NAME_BYTES
                || root.display_name.trim() != root.display_name
                || root.display_name.chars().any(|character| {
                    character.is_control() || matches!(character, '/' | '\\' | ':')
                })
            {
                return Err(invalid("invalid approved file root label"));
            }
        }
        if self
            .roots
            .windows(2)
            .any(|pair| pair[0].root_id >= pair[1].root_id)
        {
            return Err(invalid("file roots must be unique and sorted by identity"));
        }
        Ok(())
    }

    pub fn validate_file_read(&self) -> Result<(), ContractError> {
        self.validate_for(FILE_READ_ROOTS)
    }

    pub fn validate_file_write(&self) -> Result<(), ContractError> {
        self.validate_for(FILE_WRITE_ROOTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileRoot;

    fn roots() -> FileRoots {
        FileRoots {
            roots: vec![
                FileRoot {
                    root_id: "00000001-1111-4111-8111-111111111111".into(),
                    display_name: "Documents".into(),
                },
                FileRoot {
                    root_id: "00000002-1111-4111-8111-111111111111".into(),
                    display_name: "Selected folder".into(),
                },
            ],
        }
    }

    #[test]
    fn root_discovery_is_single_page_bounded_sorted_and_contains_only_labels() {
        assert!(roots().validate_file_read().is_ok());
        let mut value = roots();
        value.roots.reverse();
        assert!(value.validate_file_read().is_err());
        let mut value = roots();
        value.roots[1].display_name = "C:\\Users\\Alice".into();
        assert!(value.validate_file_read().is_err());
        let mut value = roots();
        value.roots[0].display_name = "  Documents".into();
        assert!(value.validate_file_read().is_err());
        let mut value = roots();
        value.roots = (0..=FILE_WRITE_ROOTS)
            .map(|index| FileRoot {
                root_id: format!("{index:08x}-1111-4111-8111-111111111111"),
                display_name: format!("Root {index}"),
            })
            .collect();
        assert!(value.validate_file_write().is_err());
    }
}
