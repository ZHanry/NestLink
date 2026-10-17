//! Public installation generations route new runtimes away from retained keys.
//!
//! The UUID is only a state namespace. Each daemon still creates its own random
//! device ID and private key. An installer must hold installation admission
//! exclusively while replacing this marker; callers retain Startup's shared
//! admission until the actual daemon/UI lifetime lease has been acquired.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
};

pub const MARKER: &str = "installation-instance.json";
const MAX_INSTANCES: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationInstance {
    pub schema_version: u16,
    pub namespace: String,
    pub instance_id: String,
    pub active: bool,
}

pub fn valid_instance_id(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

/// Read a bounded public marker through a non-following handle. Linux markers
/// are root-owned/readable by normal users; they contain no seed or credential.
pub fn read_instance(root: &Path) -> Result<InstallationInstance> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let file: File = options.open(root.join(MARKER))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 1024 {
        return Err(Error::Protocol);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (metadata.uid() != 0 && metadata.uid() != rustix::process::geteuid().as_raw())
            || metadata.mode() & 0o022 != 0
        {
            return Err(Error::Protocol);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(Error::Protocol);
        }
    }
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err(Error::Protocol);
    }
    let value: InstallationInstance =
        serde_json::from_slice(&bytes).map_err(|_| Error::Protocol)?;
    if value.schema_version != 1
        || value.namespace != "NestLink-v15"
        || !valid_instance_id(&value.instance_id)
    {
        return Err(Error::Protocol);
    }
    Ok(value)
}

pub(crate) fn resolve_state(root: Option<&Path>, base: &Path) -> Result<PathBuf> {
    if !base.is_absolute()
        || base
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(
            io::Error::other("state root must be absolute without parent traversal").into(),
        );
    }
    let Some(root) = root else {
        return Ok(base.to_owned());
    };
    let instance = read_instance(root)?;
    if !instance.active {
        return Err(Error::Maintenance);
    }
    // The desktop passes the exact resolved directory to chooser and daemon
    // children. Reject retained generations instead of appending another UUID.
    if base
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "instances")
    {
        if base.file_name().and_then(|name| name.to_str()) != Some(instance.instance_id.as_str()) {
            return Err(Error::Maintenance);
        }
        let parent = base.parent().ok_or(Error::Protocol)?;
        nestlink_platform_security::check_private_directory(parent)?;
        nestlink_platform_security::check_private_directory(
            parent.parent().ok_or(Error::Protocol)?,
        )?;
        crate::initialize_directory(base)?;
        return Ok(base.to_owned());
    }
    crate::initialize_directory(base)?;
    let instances = base.join("instances");
    crate::initialize_directory(&instances)?;
    let directory = instances.join(instance.instance_id);
    crate::initialize_directory(&directory)?;
    Ok(directory)
}

#[derive(Serialize)]
pub struct RetainedInstance {
    pub instance_id: Option<String>,
    pub active: bool,
    pub device_id: Option<String>,
    pub public_key_sha256: Option<[u8; 32]>,
}

/// Explicit offline review of public device descriptors, including the legacy
/// pre-generation leaf. Never reads a private key, authorization or ledger.
pub fn retained_instances(base: &Path, active: Option<&str>) -> Result<Vec<RetainedInstance>> {
    if !base.is_absolute() {
        return Err(Error::Protocol);
    }
    nestlink_platform_security::check_private_directory(base)?;
    let mut output = Vec::new();
    if let Some(value) = descriptor(base, None, false)? {
        output.push(value);
    }
    let parent = base.join("instances");
    match std::fs::symlink_metadata(&parent) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(output),
        Err(error) => return Err(error.into()),
        Ok(_) => nestlink_platform_security::check_private_directory(&parent)?,
    }
    for entry in std::fs::read_dir(parent)? {
        if output.len() >= MAX_INSTANCES {
            return Err(Error::Protocol);
        }
        let entry = entry?;
        let id = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::Protocol)?;
        if !valid_instance_id(&id) {
            return Err(Error::Protocol);
        }
        nestlink_platform_security::check_private_directory(&entry.path())?;
        let active = active == Some(id.as_str());
        output.push(
            descriptor(&entry.path(), Some(id.clone()), active)?.unwrap_or(RetainedInstance {
                instance_id: Some(id),
                active,
                device_id: None,
                public_key_sha256: None,
            }),
        );
    }
    output.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
    Ok(output)
}

fn descriptor(
    directory: &Path,
    instance_id: Option<String>,
    active: bool,
) -> Result<Option<RetainedInstance>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Device {
        schema_version: u16,
        device_id: String,
        public_key_sha256: [u8; 32],
    }
    let bytes = match nestlink_platform_security::read_private(
        &directory.join("installation-device.json"),
        1024,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let value: Device = serde_json::from_slice(&bytes).map_err(|_| Error::Protocol)?;
    if value.schema_version != 1 || !nestlink_protocol::valid_id(&value.device_id) {
        return Err(Error::Protocol);
    }
    Ok(Some(RetainedInstance {
        instance_id,
        active,
        device_id: Some(value.device_id),
        public_key_sha256: Some(value.public_key_sha256),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;
    const FIRST: &str = "147eb612-b6c7-4a75-ae12-a91fe7df36fd";
    const SECOND: &str = "292b8868-d739-4273-a556-65b7fe82c32c";

    fn marker(root: &Path, id: &str, active: bool) -> TestResult {
        std::fs::write(
            root.join(MARKER),
            serde_json::to_vec(&InstallationInstance {
                schema_version: 1,
                namespace: "NestLink-v15".into(),
                instance_id: id.into(),
                active,
            })?,
        )?;
        Ok(())
    }

    #[test]
    fn reinstall_selects_a_fresh_namespace_and_preserves_old_private_bytes() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("install");
        let base = temporary.path().join("state");
        crate::initialize_directory(&root)?;
        marker(&root, FIRST, true)?;
        let old = resolve_state(Some(&root), &base)?;
        nestlink_platform_security::create_private(
            &old.join("installation-device.key"),
            b"retain exact old key",
        )?;
        assert_eq!(resolve_state(Some(&root), &base)?, old);
        assert_eq!(resolve_state(Some(&root), &old)?, old);
        marker(&root, FIRST, false)?;
        assert!(matches!(
            resolve_state(Some(&root), &base),
            Err(Error::Maintenance)
        ));
        marker(&root, SECOND, true)?;
        let new = resolve_state(Some(&root), &base)?;
        assert_ne!(new, old);
        assert!(!new.join("installation-device.key").exists());
        assert_eq!(
            std::fs::read(old.join("installation-device.key"))?,
            b"retain exact old key"
        );
        assert!(matches!(
            resolve_state(Some(&root), &old),
            Err(Error::Maintenance)
        ));
        Ok(())
    }

    #[test]
    fn missing_invalid_and_duplicate_instance_markers_fail_closed() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let base = temporary.path().join("state");
        assert!(resolve_state(Some(temporary.path()), &base).is_err());
        for bytes in [
            b"{}".as_slice(),
            b"{\"schema_version\":1,\"schema_version\":1}",
            b"[]",
        ] {
            std::fs::write(temporary.path().join(MARKER), bytes)?;
            assert!(resolve_state(Some(temporary.path()), &base).is_err());
        }
        for id in [
            "../escape",
            "00000000-0000-0000-0000-000000000000",
            "147EB612-b6c7-4a75-ae12-a91fe7df36fd",
        ] {
            assert!(!valid_instance_id(id));
        }
        assert!(!base.exists());
        Ok(())
    }

    #[test]
    fn development_directories_keep_explicit_paths() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let base = temporary.path().join("state");
        assert_eq!(resolve_state(None, &base)?, base);
        assert!(!base.exists());
        assert!(resolve_state(None, Path::new("relative")).is_err());
        Ok(())
    }

    #[test]
    fn explicit_review_reads_public_descriptor_and_never_opens_key_bytes() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("install");
        let base = temporary.path().join("state");
        crate::initialize_directory(&root)?;
        marker(&root, FIRST, true)?;
        let state = resolve_state(Some(&root), &base)?;
        // A directory where a private key file would be proves review does not
        // open or deserialize the private key at all.
        crate::initialize_directory(&state.join("installation-device.key"))?;
        let device = serde_json::json!({"schema_version":1,"device_id":nestlink_auth::random_id(),"public_key_sha256":vec![0_u8;32]});
        nestlink_platform_security::create_private(
            &state.join("installation-device.json"),
            &serde_json::to_vec(&device)?,
        )?;
        let review = retained_instances(&base, Some(FIRST))?;
        assert_eq!(review.len(), 1);
        assert!(review[0].active);
        assert_eq!(review[0].device_id.as_deref(), device["device_id"].as_str());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn linked_or_group_writable_marker_is_rejected_without_changing_target() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("install");
        crate::initialize_directory(&root)?;
        marker(&root, FIRST, true)?;
        let target = root.join("public-marker.json");
        std::fs::rename(root.join(MARKER), &target)?;
        let original = std::fs::read(&target)?;
        std::os::unix::fs::symlink(&target, root.join(MARKER))?;
        assert!(read_instance(&root).is_err());
        assert_eq!(std::fs::read(&target)?, original);
        std::fs::remove_file(root.join(MARKER))?;
        std::fs::rename(target, root.join(MARKER))?;
        std::fs::set_permissions(root.join(MARKER), std::fs::Permissions::from_mode(0o666))?;
        assert!(read_instance(&root).is_err());
        Ok(())
    }
}
