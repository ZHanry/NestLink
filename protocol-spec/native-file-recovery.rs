// One source for local durable download facts and authenticated-user IPC.
// These structures are never permits or transport/client/session bindings.
pub const DOWNLOAD_RECOVERY_TASKS: usize = 128;
pub const DOWNLOAD_RECOVERY_METADATA_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRecoveryScope {
    pub deployment_id: String,
    pub security_epoch: u64,
    pub account_id: String,
    pub controller_device_id: String,
    pub host_device_id: String,
    pub controller_key_sha256: [u8; 32],
    pub host_key_sha256: [u8; 32],
    pub resource_id: String,
}
impl DownloadRecoveryScope {
    pub fn validate(&self) -> Result<(), crate::ContractError> {
        if [
            &self.deployment_id,
            &self.account_id,
            &self.controller_device_id,
            &self.host_device_id,
            &self.resource_id,
        ]
        .iter()
        .any(|id| !crate::valid_id(id))
            || self.security_epoch == 0
            || self.controller_device_id == self.host_device_id
            || self.controller_key_sha256 == self.host_key_sha256
        {
            return Err(crate::ContractError::new(
                crate::ErrorCode::InvalidMessage,
                "invalid download recovery identity facts",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRecoveryFacts {
    pub scope: DownloadRecoveryScope,
    pub root_id: String,
    pub relative_path: String,
    pub size: u64,
    pub sha256: [u8; 32],
}
impl DownloadRecoveryFacts {
    pub fn validate(&self) -> Result<(), crate::ContractError> {
        self.scope.validate()?;
        if !crate::valid_id(&self.root_id) || self.size > crate::FILE_SIZE_BYTES {
            return Err(crate::ContractError::new(
                crate::ErrorCode::InvalidMessage,
                "invalid download recovery source facts",
            ));
        }
        crate::files::validate_relative_path(&self.relative_path)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRecoveryResume {
    pub facts: DownloadRecoveryFacts,
    pub checkpoint_bytes: u64,
}
impl DownloadRecoveryResume {
    pub fn validate(&self) -> Result<(), crate::ContractError> {
        self.facts.validate()?;
        if self.checkpoint_bytes > self.facts.size {
            return Err(crate::ContractError::new(
                crate::ErrorCode::InvalidMessage,
                "download checkpoint exceeds original size",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRecoveryView {
    pub task_id: String,
    pub local_name: String,
    pub remote_path: String,
    pub host_device_id: String,
    pub checkpoint_bytes: u64,
    pub total_bytes: u64,
    pub phase: String,
    pub owner_active: bool,
    pub published: bool,
    pub temporary_removed: bool,
    pub file_synced: bool,
    pub directory_synced: bool,
    pub error: Option<String>,
    pub cleanup_error: Option<String>,
    pub last_export: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum DownloadRecoveryCommand {
    List,
    Cancel {
        task_id: String,
    },
    ExportPartial {
        task_id: String,
        fresh_directory: String,
        local_name: String,
        acknowledge_partial: bool,
    },
    /// The binding is supplied only now, from the current proved Core route.
    Resume {
        task_id: String,
        request_id: String,
        connection_generation: u64,
        approve_local_resume: bool,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum DownloadRecoveryReply {
    Tasks {
        tasks: Vec<DownloadRecoveryView>,
        reserved_bytes: u64,
    },
    Resumed {
        recovery_id: String,
        task_id: String,
    },
    Refused {
        reason: String,
    },
}
