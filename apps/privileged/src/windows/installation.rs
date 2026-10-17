#![allow(unsafe_code)]
use super::security;
use serde::{Deserialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr::null_mut,
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, READ_CONTROL,
    },
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_ProgramFilesX64, SHGetKnownFolderPath},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    pub schema_version: u16,
    pub version: String,
    pub release_sequence: u64,
    pub source_revision: String,
    pub desktop_sha256: String,
    pub daemon_sha256: String,
    pub privileged_sha256: String,
    pub payload_manifest_sha256: String,
    pub update_certificate_sha256: String,
    pub windows_certificate_sha256: String,
}
pub(super) struct Installation {
    pub directory: PathBuf,
    // Retained share-read-only handles deny writes/deletion for this lifetime.
    _locks: Vec<File>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema_version: u16,
    namespace: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Instance {
    schema_version: u16,
    namespace: String,
    instance_id: String,
    active: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Accepted {
    directory: String,
    version: String,
    release_sequence: u64,
    source_revision: String,
    payload_manifest_sha256: String,
    update_certificate_sha256: String,
    windows_certificate_sha256: String,
    state_compatibility: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: u16,
    current: Option<Accepted>,
    previous: Option<Accepted>,
    maximum_sequence: u64,
    maximum_accepted: Option<Accepted>,
    instance_id: Option<String>,
    active: bool,
}
pub(super) fn hex32(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(security::denied());
    }
    let mut result = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte: u8| {
            if byte.is_ascii_digit() {
                byte - b'0'
            } else {
                byte.to_ascii_lowercase() - b'a' + 10
            }
        };
        result[index] = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(result)
}
pub(super) fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn program_files() -> io::Result<PathBuf> {
    let mut raw = null_mut();
    // SAFETY: fixed system known-folder ID, no environment/remote path input.
    let status =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFilesX64, 0, null_mut(), &mut raw) };
    if status < 0 || raw.is_null() {
        return Err(security::denied());
    }
    struct KnownFolder(*mut u16);
    impl Drop for KnownFolder {
        fn drop(&mut self) {
            // SAFETY: SHGetKnownFolderPath documents CoTaskMemFree ownership.
            unsafe { CoTaskMemFree(self.0.cast()) };
        }
    }
    let allocation = KnownFolder(raw);
    let mut length = 0;
    // SAFETY: the OS returns a terminated folder path; enforce its fixed bound.
    while length < 32760 && unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    if length == 32760 {
        return Err(security::denied());
    }
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map_err(|_| security::denied())?;
    drop(allocation);
    Ok(PathBuf::from(value))
}
fn open_protected(path: &Path, directory: bool) -> io::Result<File> {
    let share = if directory {
        FILE_SHARE_READ
            | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE
            | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE
    } else {
        FILE_SHARE_READ
    };
    let file = OpenOptions::new()
        .read(true)
        .access_mode(0x80000000 | READ_CONTROL)
        .share_mode(share)
        .custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        )
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & 0x400 != 0
        || metadata.is_dir() != directory
        || (!directory && !metadata.is_file())
    {
        return Err(security::denied());
    }
    security::protected_acl(file.as_raw_handle().cast())?;
    Ok(file)
}
fn hash_locked(file: &mut File, expected: &str) -> io::Result<()> {
    let expected = hex32(expected)?;
    let length = file.metadata()?.len();
    if length == 0 || length > 512 * 1024 * 1024 {
        return Err(security::denied());
    }
    let mut digest = Sha256::new();
    let mut bytes = [0; 65536];
    let mut read = 0u64;
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > length {
            return Err(security::denied());
        }
        digest.update(&bytes[..count]);
    }
    let actual: [u8; 32] = digest.finalize().into();
    if actual != expected || read != length || file.metadata()?.len() != length {
        return Err(security::denied());
    }
    Ok(())
}
fn read_json<T: DeserializeOwned>(file: &mut File) -> io::Result<T> {
    let mut bytes = Vec::new();
    file.take(262145).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > 262144 {
        return Err(security::denied());
    }
    serde_json::from_slice(&bytes).map_err(|_| security::denied())
}
impl Installation {
    pub fn current(expected_name: &str) -> io::Result<Self> {
        if !matches!(
            expected_name,
            "nestlink-daemon.exe" | "nestlink-privileged.exe"
        ) {
            return Err(security::denied());
        }
        let current = std::env::current_exe()?;
        if current.file_name().and_then(|name| name.to_str()) != Some(expected_name) {
            return Err(security::denied());
        }
        let directory = current.parent().ok_or_else(security::denied)?.to_owned();
        let program_files = program_files()?;
        let base = program_files.join("NestLink-v15-Privileged");
        let versions = base.join("versions");
        if directory.parent() != Some(versions.as_path()) {
            return Err(security::denied());
        }
        let leaf = directory
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(security::denied)?;
        if !leaf.starts_with("15.")
            || leaf.len() > 96
            || !leaf
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
        {
            return Err(security::denied());
        }
        let mut locks = Vec::new();
        for folder in [&program_files, &base, &versions, &directory] {
            locks.push(open_protected(folder, true)?);
        }
        // Holding this read-only handle denies an installer's write admission
        // while the exact cohort is in use. Installation refuses active peers.
        let admission = open_protected(&base.join("installation-admission.lock"), false)?;
        if admission.metadata()?.len() != 0 {
            return Err(security::denied());
        }
        locks.push(admission);
        match std::fs::symlink_metadata(base.join("installation-incomplete.json")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(security::denied()),
        }
        let mut marker_file = open_protected(&base.join("installation-v15.json"), false)?;
        let marker: Marker = read_json(&mut marker_file)?;
        if marker.schema_version != 1 || marker.namespace != "NestLink-v15" {
            return Err(security::denied());
        }
        locks.push(marker_file);
        let mut receipt_file = open_protected(&base.join("installation.json"), false)?;
        let receipt: Receipt = read_json(&mut receipt_file)?;
        let mut instance_file = open_protected(&base.join("installation-instance.json"), false)?;
        let instance: Instance = read_json(&mut instance_file)?;
        if receipt.schema_version != 1
            || !receipt.active
            || !instance.active
            || instance.schema_version != 1
            || instance.namespace != "NestLink-v15"
            || !nestlink_protocol::valid_id(&instance.instance_id)
            || receipt.instance_id.as_deref() != Some(instance.instance_id.as_str())
            || receipt.maximum_sequence == 0
            || receipt.maximum_sequence > (1 << 53) - 1
        {
            return Err(security::denied());
        }
        locks.push(receipt_file);
        locks.push(instance_file);
        let mut policy_file = open_protected(&directory.join("broker-package.json"), false)?;
        let mut bytes = Vec::new();
        (&mut policy_file).take(65537).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > 65536 {
            return Err(security::denied());
        }
        let policy: Policy = serde_json::from_slice(&bytes).map_err(|_| security::denied())?;
        if policy.schema_version != 1
            || policy.release_sequence == 0
            || policy.release_sequence > (1 << 53) - 1
            || format!("{}-r{}", policy.version, policy.release_sequence) != leaf
            || policy.source_revision.len() != 40
            || !policy
                .source_revision
                .bytes()
                .all(|value| value.is_ascii_hexdigit())
        {
            return Err(security::denied());
        }
        for digest in [
            &policy.desktop_sha256,
            &policy.daemon_sha256,
            &policy.privileged_sha256,
            &policy.payload_manifest_sha256,
            &policy.update_certificate_sha256,
            &policy.windows_certificate_sha256,
        ] {
            hex32(digest)?;
        }
        if policy.update_certificate_sha256 == policy.windows_certificate_sha256 {
            return Err(security::denied());
        }
        let current = receipt.current.as_ref().ok_or_else(security::denied)?;
        for entry in [
            receipt.current.as_ref(),
            receipt.previous.as_ref(),
            receipt.maximum_accepted.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if entry.release_sequence == 0
                || entry.release_sequence > receipt.maximum_sequence
                || entry.directory != format!("{}-r{}", entry.version, entry.release_sequence)
                || entry.source_revision.len() != 40
                || !entry
                    .source_revision
                    .bytes()
                    .all(|value| value.is_ascii_hexdigit())
                || entry.state_compatibility.is_empty()
                || entry.state_compatibility.len() > 128
            {
                return Err(security::denied());
            }
            for value in [
                &entry.payload_manifest_sha256,
                &entry.update_certificate_sha256,
                &entry.windows_certificate_sha256,
            ] {
                hex32(value)?;
            }
        }
        if current.directory != leaf
            || current.version != policy.version
            || current.release_sequence != policy.release_sequence
            || current.source_revision != policy.source_revision
            || current.payload_manifest_sha256 != policy.payload_manifest_sha256
            || current.update_certificate_sha256 != policy.update_certificate_sha256
            || current.windows_certificate_sha256 != policy.windows_certificate_sha256
            || receipt
                .maximum_accepted
                .as_ref()
                .is_none_or(|entry| entry.release_sequence != receipt.maximum_sequence)
        {
            return Err(security::denied());
        }
        locks.push(policy_file);
        for (name, expected) in [
            ("nestlink-desktop.exe", &policy.desktop_sha256),
            ("nestlink-daemon.exe", &policy.daemon_sha256),
            ("nestlink-privileged.exe", &policy.privileged_sha256),
            ("payload.json", &policy.payload_manifest_sha256),
        ] {
            let mut file = open_protected(&directory.join(name), false)?;
            hash_locked(&mut file, expected)?;
            locks.push(file);
        }
        Ok(Self {
            directory,
            _locks: locks,
        })
    }
    pub fn daemon(&self) -> PathBuf {
        self.directory.join("nestlink-daemon.exe")
    }
    pub fn broker(&self) -> PathBuf {
        self.directory.join("nestlink-privileged.exe")
    }
}
