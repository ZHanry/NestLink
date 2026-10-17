//! Metadata-only directory pages on the already authorized FileRead channel.
use crate::{
    ContractError, DIRECTORY_ENTRIES, DIRECTORY_PAGE_ENTRIES, DIRECTORY_TOKEN_BYTES,
    DirectoryBrowseBegin, DirectoryBrowseNext, DirectoryBrowsePage, DirectoryEntryKind, ErrorCode,
    FILE_SIZE_BYTES, files::validate_relative_path, valid_id,
};

fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}
fn directory(path: &str) -> Result<(), ContractError> {
    if path.is_empty() {
        Ok(())
    } else {
        validate_relative_path(path)
    }
}
fn maximum(value: u32) -> Result<(), ContractError> {
    if value == 0 || u64::from(value) > DIRECTORY_PAGE_ENTRIES {
        Err(invalid("invalid directory page maximum"))
    } else {
        Ok(())
    }
}
pub fn valid_token(token: &[u8]) -> bool {
    token.len() as u64 == DIRECTORY_TOKEN_BYTES && token.iter().any(|byte| *byte != 0)
}
impl DirectoryBrowseBegin {
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_id(&self.root_id) {
            return Err(invalid("invalid directory root identity"));
        }
        directory(&self.directory)?;
        maximum(self.maximum)
    }
}
impl DirectoryBrowseNext {
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_token(&self.cursor) {
            return Err(invalid("invalid directory cursor"));
        }
        maximum(self.maximum)
    }
}
impl DirectoryBrowsePage {
    pub fn validate(&self) -> Result<(), ContractError> {
        if !valid_id(&self.root_id) || !valid_token(&self.snapshot_id) {
            return Err(invalid("invalid directory snapshot identity"));
        }
        directory(&self.directory)?;
        let end = u64::from(self.offset) + self.entries.len() as u64;
        if u64::from(self.total_entries) > DIRECTORY_ENTRIES
            || self.entries.len() as u64 > DIRECTORY_PAGE_ENTRIES
            || end > u64::from(self.total_entries)
            || (self.entries.is_empty() && self.total_entries != 0)
            || (end == u64::from(self.total_entries)) != self.next_cursor.is_empty()
            || (!self.next_cursor.is_empty() && !valid_token(&self.next_cursor))
        {
            return Err(invalid("invalid directory page extent or continuation"));
        }
        for entry in &self.entries {
            validate_relative_path(&entry.name)?;
            if entry.name.contains('/') {
                return Err(invalid("directory entry is not a component"));
            }
            match DirectoryEntryKind::try_from(entry.kind) {
                Ok(DirectoryEntryKind::DirectoryEntryFile)
                    if entry.size.is_some_and(|size| size <= FILE_SIZE_BYTES) => {}
                Ok(DirectoryEntryKind::DirectoryEntryDirectory) if entry.size.is_none() => {}
                _ => return Err(invalid("invalid directory entry kind or size")),
            }
            let path = if self.directory.is_empty() {
                entry.name.clone()
            } else {
                format!("{}/{}", self.directory, entry.name)
            };
            validate_relative_path(&path)?;
        }
        if self
            .entries
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            return Err(invalid("directory entries are not strictly sorted"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn page() -> DirectoryBrowsePage {
        DirectoryBrowsePage {
            root_id: "00000002-1111-4111-8111-111111111111".into(),
            directory: String::new(),
            snapshot_id: vec![1; 32],
            offset: 0,
            total_entries: 2,
            entries: vec![crate::DirectoryEntry {
                name: "a.txt".into(),
                kind: DirectoryEntryKind::DirectoryEntryFile as i32,
                size: Some(12),
                modified_unix_ms: -1,
            }],
            next_cursor: vec![2; 32],
        }
    }
    #[test]
    fn directory_pages_require_complete_extent_portable_metadata_and_sorted_names() {
        let original = page();
        assert!(original.validate().is_ok());
        let mut value = original.clone();
        value.next_cursor.clear();
        assert!(value.validate().is_err());
        let mut value = original.clone();
        value.offset = 2;
        assert!(value.validate().is_err());
        let mut value = original.clone();
        value.entries[0].name = "a/b".into();
        assert!(value.validate().is_err());
        let mut value = original.clone();
        value.entries[0].size = None;
        assert!(value.validate().is_err());
        let mut value = original.clone();
        value.entries.push(value.entries[0].clone());
        value.next_cursor.clear();
        assert!(value.validate().is_err());
        let mut value = original;
        value.snapshot_id = vec![0; 32];
        assert!(value.validate().is_err());
    }
    #[test]
    fn browse_requests_are_bounded_and_allow_the_selected_root() {
        let mut value = DirectoryBrowseBegin {
            root_id: "00000002-1111-4111-8111-111111111111".into(),
            directory: String::new(),
            maximum: 128,
        };
        assert!(value.validate().is_ok());
        value.maximum = 129;
        assert!(value.validate().is_err());
        value.maximum = 1;
        value.directory = "../private".into();
        assert!(value.validate().is_err());
        assert!(
            DirectoryBrowseNext {
                cursor: vec![1; 31],
                maximum: 1
            }
            .validate()
            .is_err()
        );
    }
}
